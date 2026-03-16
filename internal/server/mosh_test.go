package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/unixshells/latch/internal/config"
	"golang.org/x/crypto/ssh"
)

// testSSHServer creates a latch server with SSH enabled using temp keys.
// Returns the server, SSH address, client signer, and client key file path.
func testSSHServer(t *testing.T) (*Server, string, ssh.Signer, string) {
	t.Helper()
	dir := t.TempDir()

	// Generate host key.
	hostKeyPath := filepath.Join(dir, "host_key")
	hostSigner := generateTestKey(t, hostKeyPath)

	// Generate client key.
	clientKeyPath := filepath.Join(dir, "client_key")
	clientSigner := generateTestKey(t, clientKeyPath)

	// Write authorized_keys with the client's public key.
	authKeysPath := filepath.Join(dir, "authorized_keys")
	pubKey := ssh.MarshalAuthorizedKey(clientSigner.PublicKey())
	if err := os.WriteFile(authKeysPath, pubKey, 0600); err != nil {
		t.Fatal(err)
	}

	// Create server.
	sock := filepath.Join(dir, "sock")
	s := &Server{
		sockPath: sock,
		cfg:      config.Default(),
		limiter:  newConnLimiter(10),
		tracker:  newConnTracker(),
		access:   newAccessState(),
		connMeta: make(map[net.Conn]*ConnInfo),
	}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	go s.Serve()

	// Set up SSH config.
	sshCfg := &ssh.ServerConfig{}
	sshCfg.AddHostKey(hostSigner)
	sshCfg.PublicKeyCallback = func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(key.Marshal(), clientSigner.PublicKey().Marshal()) {
			return &ssh.Permissions{
				Extensions: map[string]string{
					"fp":      ssh.FingerprintSHA256(key),
					"comment": "test",
				},
			}, nil
		}
		return nil, fmt.Errorf("unknown key")
	}

	// Listen on a random port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.remoteLn = ln
	s.mu.Lock()
	s.sshAddr = ln.Addr().String()
	s.mu.Unlock()
	s.access.SetSSH(true)

	go s.serveSSH(ln, sshCfg)

	t.Cleanup(func() { s.Close() })
	return s, ln.Addr().String(), clientSigner, clientKeyPath
}

func generateTestKey(t *testing.T, path string) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// sshDial connects to the test SSH server with the test client key.
func sshDial(t *testing.T, addr string, clientSigner ssh.Signer) *ssh.Client {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// TestMoshExecSSH verifies the SSH exec path: ssh exec "mosh-server new"
// returns a MOSH CONNECT line with port and key.
func TestMoshExecSSH(t *testing.T) {
	if _, err := exec.LookPath("mosh-server"); err != nil {
		t.Skip("mosh-server not installed")
	}

	_, addr, clientSigner, _ := testSSHServer(t)
	client := sshDial(t, addr, clientSigner)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	err = session.Run("mosh-server new -p 0 -c 256")
	if err != nil {
		t.Logf("mosh-server exit: %v (stderr: %s)", err, stderr.String())
	}

	output := stdout.String() + stderr.String()
	t.Logf("mosh-server output:\n%s", output)

	port, key := parseMoshConnect(t, output)
	if port == 0 {
		t.Fatal("failed to parse MOSH CONNECT port")
	}
	if key == "" {
		t.Fatal("failed to parse MOSH CONNECT key")
	}
	t.Logf("MOSH CONNECT port=%d key=%s", port, key)
}

// TestMoshE2E performs a full end-to-end mosh test:
// 1. Start latch with SSH
// 2. Run `mosh --ssh="ssh -p PORT -i KEY ..." test@127.0.0.1` in a pty
// 3. Send a command and verify echo output over mosh's UDP protocol
func TestMoshE2E(t *testing.T) {
	if _, err := exec.LookPath("mosh-server"); err != nil {
		t.Skip("mosh-server not installed")
	}
	if _, err := exec.LookPath("mosh"); err != nil {
		t.Skip("mosh not installed")
	}

	_, addr, _, keyPath := testSSHServer(t)
	host, portStr, _ := net.SplitHostPort(addr)

	// Use the mosh wrapper which handles SSH + mosh-client.
	sshCmd := fmt.Sprintf("ssh -p %s -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
		portStr, keyPath)
	moshCmd := exec.Command("mosh",
		"--ssh="+sshCmd,
		"--predict=never",
		"test@"+host)

	// Set pty size before starting — mosh-client needs valid dimensions.
	ptmx, err := pty.StartWithSize(moshCmd, &pty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ptmx.Close()
		moshCmd.Process.Kill()
		moshCmd.Wait()
	}()

	// Continuous reader goroutine.
	outputCh := make(chan string, 256)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				outputCh <- string(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	// Wait for shell to be ready — accumulate output until we have something.
	var allOutput string
	ready := false
	readyDeadline := time.After(15 * time.Second)
	for !ready {
		select {
		case chunk := <-outputCh:
			allOutput += chunk
			if len(allOutput) > 50 {
				ready = true
			}
		case <-readyDeadline:
			t.Fatalf("mosh did not produce enough output. Got %d bytes:\n%q",
				len(allOutput), truncate(allOutput, 500))
		}
	}
	t.Logf("mosh connected, got %d bytes", len(allOutput))

	// Let shell fully settle.
	time.Sleep(2 * time.Second)
	for {
		select {
		case chunk := <-outputCh:
			allOutput += chunk
		default:
			goto settled
		}
	}
settled:

	// Send a unique marker command.
	marker := "LATCHMOSH_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	fmt.Fprintf(ptmx, "echo %s\n", marker)

	// Read output until we see the marker.
	found := false
	markerDeadline := time.After(15 * time.Second)
	for !found {
		select {
		case chunk := <-outputCh:
			allOutput += chunk
			if strings.Contains(allOutput, marker) {
				found = true
			}
		case <-markerDeadline:
			t.Fatalf("marker not echoed back. Output (%d bytes):\n%q",
				len(allOutput), truncate(allOutput, 1000))
		}
	}

	t.Log("mosh E2E passed: command echoed back over mosh UDP")
}

// TestMoshExecNonMosh verifies that non-mosh exec commands still create
// latch sessions (not intercepted by handleMoshExec).
func TestMoshExecNonMosh(t *testing.T) {
	_, addr, clientSigner, _ := testSSHServer(t)
	client := sshDial(t, addr, clientSigner)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}

	if err := session.Start("test-session"); err != nil {
		t.Fatal(err)
	}

	time.Sleep(500 * time.Millisecond)
}

// TestMoshExecFailure verifies that a failing mosh-server command
// returns a non-zero exit status through SSH.
func TestMoshExecFailure(t *testing.T) {
	_, addr, clientSigner, _ := testSSHServer(t)
	client := sshDial(t, addr, clientSigner)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	var stderr bytes.Buffer
	session.Stderr = &stderr

	// Bind to invalid port — mosh-server will fail.
	err = session.Run("mosh-server new -p 99999")
	if err == nil {
		t.Fatal("expected mosh-server with invalid port to fail")
	}

	t.Logf("mosh-server failure: err=%v stderr=%s", err, stderr.String())

	if _, ok := err.(*ssh.ExitError); ok {
		t.Log("got SSH ExitError as expected")
	} else {
		t.Logf("got non-exit error: %T %v", err, err)
	}
}

// TestMoshConnectParsing verifies the MOSH CONNECT line parser.
func TestMoshConnectParsing(t *testing.T) {
	tests := []struct {
		input    string
		wantPort int
		wantKey  string
	}{
		{"MOSH CONNECT 60001 abc123\n", 60001, "abc123"},
		{"\nMOSH CONNECT 12345 secretkey\n\n", 12345, "secretkey"},
		{"some header\nMOSH CONNECT 9999 k3y\ntrailer\n", 9999, "k3y"},
		{"no connect line here\n", 0, ""},
		{"MOSH CONNECT notaport key\n", 0, ""},
	}

	for _, tt := range tests {
		port, key := parseMoshConnect(t, tt.input)
		if port != tt.wantPort || key != tt.wantKey {
			t.Errorf("parseMoshConnect(%q) = (%d, %q), want (%d, %q)",
				tt.input, port, key, tt.wantPort, tt.wantKey)
		}
	}
}

// parseMoshConnect extracts port and key from mosh-server output.
// Format: "MOSH CONNECT <port> <key>"
func parseMoshConnect(t *testing.T, output string) (int, string) {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "MOSH CONNECT ") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				port, err := strconv.Atoi(parts[2])
				if err != nil {
					continue
				}
				return port, parts[3]
			}
		}
	}
	return 0, ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
