package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// TestSFTPSubsystem verifies that an SFTP client can connect through
// latch's SSH server, list directories, read files, and write files.
func TestSFTPSubsystem(t *testing.T) {
	_, addr, clientSigner, _ := testSSHServer(t)
	client := sshDial(t, addr, clientSigner)
	defer client.Close()

	sc, err := sftp.NewClient(client)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	// Stat a directory that definitely exists.
	info, err := sc.Stat("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatal("/tmp is not a directory")
	}
}

// TestSFTPReadFile creates a temp file and reads it back over SFTP.
func TestSFTPReadFile(t *testing.T) {
	_, addr, clientSigner, _ := testSSHServer(t)
	client := sshDial(t, addr, clientSigner)
	defer client.Close()

	sc, err := sftp.NewClient(client)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	// Create a temp file.
	dir := t.TempDir()
	path := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(path, []byte("latch sftp test"), 0644); err != nil {
		t.Fatal(err)
	}

	// Read it over SFTP.
	f, err := sc.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	buf := make([]byte, 64)
	n, err := f.Read(buf)
	if err != nil && err.Error() != "EOF" {
		t.Fatal(err)
	}
	got := string(buf[:n])
	if got != "latch sftp test" {
		t.Fatalf("got %q, want %q", got, "latch sftp test")
	}
}

// TestSFTPWriteFile writes a file over SFTP and reads it back locally.
func TestSFTPWriteFile(t *testing.T) {
	_, addr, clientSigner, _ := testSSHServer(t)
	client := sshDial(t, addr, clientSigner)
	defer client.Close()

	sc, err := sftp.NewClient(client)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "written.txt")

	f, err := sc.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("written via sftp")); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	// Read back locally.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "written via sftp" {
		t.Fatalf("got %q, want %q", data, "written via sftp")
	}
}

// TestSFTPReadDir lists a directory over SFTP.
func TestSFTPReadDir(t *testing.T) {
	_, addr, clientSigner, _ := testSSHServer(t)
	client := sshDial(t, addr, clientSigner)
	defer client.Close()

	sc, err := sftp.NewClient(client)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0644)
	os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b"), 0644)
	os.Mkdir(filepath.Join(dir, "subdir"), 0755)

	entries, err := sc.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}

	names := make(map[string]bool)
	for _, e := range entries {
		names[e.Name()] = true
	}
	for _, want := range []string{"a.txt", "b.txt", "subdir"} {
		if !names[want] {
			t.Errorf("missing entry %q", want)
		}
	}
}

// TestSFTPMkdirRemove tests mkdir and remove over SFTP.
func TestSFTPMkdirRemove(t *testing.T) {
	_, addr, clientSigner, _ := testSSHServer(t)
	client := sshDial(t, addr, clientSigner)
	defer client.Close()

	sc, err := sftp.NewClient(client)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	dir := t.TempDir()
	sub := filepath.Join(dir, "newdir")

	if err := sc.Mkdir(sub); err != nil {
		t.Fatal(err)
	}
	info, err := sc.Stat(sub)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatal("expected directory")
	}

	// Remove it.
	if err := sc.Remove(sub); err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Stat(sub); err == nil {
		t.Fatal("expected error after remove")
	}
}

// TestSFTPRename tests renaming a file over SFTP.
func TestSFTPRename(t *testing.T) {
	_, addr, clientSigner, _ := testSSHServer(t)
	client := sshDial(t, addr, clientSigner)
	defer client.Close()

	sc, err := sftp.NewClient(client)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()

	dir := t.TempDir()
	old := filepath.Join(dir, "old.txt")
	new := filepath.Join(dir, "new.txt")

	os.WriteFile(old, []byte("rename me"), 0644)

	if err := sc.Rename(old, new); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("old file still exists")
	}
	data, err := os.ReadFile(new)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "rename me" {
		t.Fatalf("got %q", data)
	}
}

// TestSFTPMultipleSessions verifies that SFTP and shell sessions work
// on the same SSH connection (different channels).
func TestSFTPMultipleSessions(t *testing.T) {
	_, addr, clientSigner, _ := testSSHServer(t)
	client := sshDial(t, addr, clientSigner)
	defer client.Close()

	// Open SFTP.
	sc, err := sftp.NewClient(client)
	if err != nil {
		t.Fatal(err)
	}

	// Open a shell session concurrently.
	session, err := client.NewSession()
	if err != nil {
		sc.Close()
		t.Fatal(err)
	}

	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		session.Close()
		sc.Close()
		t.Fatal(err)
	}
	if err := session.Shell(); err != nil {
		session.Close()
		sc.Close()
		t.Fatal(err)
	}

	// Use SFTP while shell is open.
	time.Sleep(200 * time.Millisecond)
	if _, err := sc.Stat("/tmp"); err != nil {
		session.Close()
		sc.Close()
		t.Fatal(err)
	}

	session.Close()
	sc.Close()
}

// TestSFTPUnauthorized verifies that an SSH client with an unknown key
// cannot connect (and therefore cannot use SFTP).
func TestSFTPUnauthorized(t *testing.T) {
	_, addr, _, _ := testSSHServer(t)

	// Generate a different key not in authorized_keys.
	badKeyPath := filepath.Join(t.TempDir(), "bad_key")
	badSigner := generateTestKey(t, badKeyPath)

	cfg := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(badSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	_, err := ssh.Dial("tcp", addr, cfg)
	if err == nil {
		t.Fatal("expected auth failure with unauthorized key")
	}
}

// TestSFTPAccessDisabled verifies that SFTP is blocked when SSH access
// is disabled on the server.
func TestSFTPAccessDisabled(t *testing.T) {
	s, addr, clientSigner, _ := testSSHServer(t)

	// Disable SSH access.
	s.access.SetSSH(false)

	cfg := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	conn, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		// Connection refused because access is off — this is correct.
		return
	}
	defer conn.Close()

	// If we got a connection, SFTP should fail because the server
	// closes the connection before accepting channels.
	_, err = sftp.NewClient(conn)
	if err == nil {
		t.Fatal("expected SFTP to fail with SSH access disabled")
	}
}
