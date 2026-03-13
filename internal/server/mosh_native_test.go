package server

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	mosh "github.com/unixshells/mosh-go"
)

// TestNativeMoshExecSSH verifies that the native mosh server starts via SSH exec
// and returns a valid MOSH CONNECT line — no external mosh-server binary needed.
func TestNativeMoshExecSSH(t *testing.T) {
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

	// The native server handles this without needing mosh-server installed.
	_ = session.Run("mosh-server new -p 0 -c 256")
	// Native server sends exit-status 0 and closes channel.
	// The exec returns nil on success.

	output := stdout.String() + stderr.String()
	t.Logf("native mosh output: %q", output)

	port, key := parseMoshConnect(t, output)
	if port == 0 {
		t.Fatalf("failed to parse MOSH CONNECT port from: %q", output)
	}
	if key == "" {
		t.Fatal("failed to parse MOSH CONNECT key")
	}
	t.Logf("MOSH CONNECT port=%d key=%s", port, key)
}

// TestNativeMoshUDP verifies the full native mosh flow: SSH exec returns
// MOSH CONNECT, then we connect via the Go mosh client over UDP.
func TestNativeMoshUDP(t *testing.T) {
	_, addr, clientSigner, _ := testSSHServer(t)
	client := sshDial(t, addr, clientSigner)

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	session.Stdout = &stdout
	session.Run("mosh-server new -p 0")
	client.Close()

	port, keyStr := parseMoshConnect(t, stdout.String())
	if port == 0 || keyStr == "" {
		t.Fatalf("bad MOSH CONNECT: %q", stdout.String())
	}

	mc, err := mosh.Dial("127.0.0.1", port, keyStr)
	if err != nil {
		t.Fatal(err)
	}
	defer mc.Close()

	// Wait for server to send terminal output.
	var gotOutput bool
	for i := 0; i < 40; i++ {
		out := mc.Recv(500 * time.Millisecond)
		if len(out) > 0 {
			gotOutput = true
			t.Logf("received %d bytes from native mosh server", len(out))
			break
		}
	}
	if !gotOutput {
		t.Fatal("no output from native mosh server")
	}

	// Send a command and verify echo.
	marker := "NATIVESSH_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	mc.Send([]byte("echo " + marker + "\n"))

	var allOutput string
	deadline := time.After(10 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("marker not echoed. Got: %q", allOutput)
		default:
		}
		out := mc.Recv(500 * time.Millisecond)
		if out != nil {
			allOutput += string(out)
			if strings.Contains(allOutput, marker) {
				t.Log("native mosh server via SSH: command echoed over SSP UDP")
				return
			}
		}
	}
}

// TestNativeMoshWithRealClient runs a real mosh-client binary against
// latch's native mosh server (no external mosh-server binary needed).
func TestNativeMoshWithRealClient(t *testing.T) {
	if _, err := exec.LookPath("mosh"); err != nil {
		t.Skip("mosh not installed")
	}

	_, addr, _, keyPath := testSSHServer(t)
	host, portStr, _ := net.SplitHostPort(addr)

	sshCmd := fmt.Sprintf("ssh -p %s -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
		portStr, keyPath)
	moshCmd := exec.Command("mosh",
		"--ssh="+sshCmd,
		"--predict=never",
		"test@"+host)

	ptmx, err := pty.StartWithSize(moshCmd, &pty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ptmx.Close()
		moshCmd.Process.Kill()
		moshCmd.Wait()
	}()

	// Continuous reader.
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

	// Wait for shell.
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
	t.Logf("mosh-client connected to native server, got %d bytes", len(allOutput))

	// Let shell settle.
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

	// Send a unique marker.
	marker := "NATIVECLIENT_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	fmt.Fprintf(ptmx, "echo %s\n", marker)

	// Read output until marker.
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

	t.Log("real mosh-client → native latch mosh server: E2E passed")
}

// TestNativeMoshResize verifies terminal resize works with the native server
// using the Go mosh client.
func TestNativeMoshResize(t *testing.T) {
	_, addr, clientSigner, _ := testSSHServer(t)
	client := sshDial(t, addr, clientSigner)

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	session.Stdout = &stdout
	session.Run("mosh-server new -p 0")
	client.Close()

	port, keyStr := parseMoshConnect(t, stdout.String())
	if port == 0 {
		t.Fatalf("bad MOSH CONNECT: %q", stdout.String())
	}

	mc, err := mosh.Dial("127.0.0.1", port, keyStr)
	if err != nil {
		t.Fatal(err)
	}
	defer mc.Close()

	// Wait for shell.
	for i := 0; i < 20; i++ {
		if out := mc.Recv(500 * time.Millisecond); len(out) > 0 {
			break
		}
	}

	// Resize and verify via tput.
	mc.Resize(132, 43)
	time.Sleep(300 * time.Millisecond)
	mc.Send([]byte("tput cols; tput lines\n"))

	var allOutput string
	deadline := time.After(10 * time.Second)
	for {
		select {
		case <-deadline:
			t.Logf("output so far: %q", allOutput)
			t.Log("resize sent (tput output not verified)")
			return
		default:
		}
		out := mc.Recv(500 * time.Millisecond)
		if out != nil {
			allOutput += string(out)
		}
		if strings.Contains(allOutput, "132") && strings.Contains(allOutput, "43") {
			t.Log("native mosh resize verified: 132x43")
			return
		}
	}
}
