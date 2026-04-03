package server

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unixshells/latch/internal/config"
	"github.com/unixshells/latch/pkg/proto"
)

func testServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "sock")
	cfg := config.Default()
	s := &Server{sockPath: sock, cfg: cfg, limiter: newConnLimiter(10), tracker: newConnTracker(), access: newAccessState(), connMeta: make(map[net.Conn]*ConnInfo)}
	s.access.SetAPI(cfg.APIEnabled)
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	go s.Serve()
	t.Cleanup(func() { s.Close() })
	return s, sock
}

func dial(t *testing.T, sock string) net.Conn {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestNewSessionAndList(t *testing.T) {
	_, sock := testServer(t)

	conn := dial(t, sock)
	proto.Encode(conn, proto.MsgNewSession, []byte("test"))

	// Wait for session + initial render
	time.Sleep(300 * time.Millisecond)

	// Detach
	proto.Encode(conn, proto.MsgDetach, nil)
	for {
		typ, _, err := proto.Decode(conn)
		if err != nil || typ == proto.MsgDetached {
			break
		}
	}
	conn.Close()

	// List
	conn2 := dial(t, sock)
	defer conn2.Close()
	proto.Encode(conn2, proto.MsgList, nil)

	typ, payload, err := proto.Decode(conn2)
	if err != nil {
		t.Fatal(err)
	}
	if typ != proto.MsgSessionList {
		t.Fatalf("type = %x, want %x", typ, proto.MsgSessionList)
	}
	if !strings.Contains(string(payload), "test") {
		t.Fatalf("list = %q, want to contain 'test'", payload)
	}
}

func TestAttachNonExistent(t *testing.T) {
	_, sock := testServer(t)

	conn := dial(t, sock)
	defer conn.Close()

	proto.Encode(conn, proto.MsgAttach, []byte("nope"))

	typ, payload, err := proto.Decode(conn)
	if err != nil {
		t.Fatal(err)
	}
	if typ != proto.MsgError {
		t.Fatalf("type = %x, want MsgError", typ)
	}
	if !strings.Contains(string(payload), "no session") {
		t.Fatalf("error = %q", payload)
	}
}

func TestKillSession(t *testing.T) {
	_, sock := testServer(t)

	conn := dial(t, sock)
	proto.Encode(conn, proto.MsgNewSession, []byte("killme"))
	time.Sleep(300 * time.Millisecond)
	proto.Encode(conn, proto.MsgDetach, nil)
	for {
		typ, _, err := proto.Decode(conn)
		if err != nil || typ == proto.MsgDetached {
			break
		}
	}
	conn.Close()

	conn2 := dial(t, sock)
	defer conn2.Close()
	proto.Encode(conn2, proto.MsgKillSession, []byte("killme"))

	typ, _, err := proto.Decode(conn2)
	if err != nil {
		t.Fatal(err)
	}
	if typ == proto.MsgError {
		t.Fatal("kill returned error")
	}
}

func TestSocketCleanup(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "sock")
	s := &Server{sockPath: sock, tracker: newConnTracker(), access: newAccessState(), connMeta: make(map[net.Conn]*ConnInfo)}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	s.Close()

	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatal("socket not cleaned up")
	}
}

func TestEnableSSH(t *testing.T) {
	s, sock := testServer(t)
	_ = s

	conn := dial(t, sock)
	defer conn.Close()

	// Enable SSH on a random port.
	proto.Encode(conn, proto.MsgEnableSSH, []byte(":0"))
	typ, payload, err := proto.Decode(conn)
	if err != nil {
		t.Fatal(err)
	}
	if typ == proto.MsgError {
		t.Fatalf("enable ssh failed: %s", payload)
	}
	if !strings.Contains(string(payload), "ssh listening") {
		t.Fatalf("unexpected response: %s", payload)
	}

	// Second enable should say "already listening".
	conn2 := dial(t, sock)
	defer conn2.Close()
	proto.Encode(conn2, proto.MsgEnableSSH, []byte(":0"))
	typ2, payload2, err := proto.Decode(conn2)
	if err != nil {
		t.Fatal(err)
	}
	if typ2 == proto.MsgError {
		t.Fatalf("second enable ssh failed: %s", payload2)
	}
	if !strings.Contains(string(payload2), "already listening") {
		t.Fatalf("expected already listening, got: %s", payload2)
	}
}

func TestEnableWeb(t *testing.T) {
	s, sock := testServer(t)
	_ = s

	conn := dial(t, sock)
	defer conn.Close()

	proto.Encode(conn, proto.MsgEnableWeb, []byte(":0"))
	typ, payload, err := proto.Decode(conn)
	if err != nil {
		t.Fatal(err)
	}
	if typ == proto.MsgError {
		t.Fatalf("enable web failed: %s", payload)
	}
	if !strings.Contains(string(payload), "web listening") {
		t.Fatalf("unexpected response: %s", payload)
	}

	// Second enable should say "already listening".
	conn2 := dial(t, sock)
	defer conn2.Close()
	proto.Encode(conn2, proto.MsgEnableWeb, []byte(":0"))
	typ2, payload2, err := proto.Decode(conn2)
	if err != nil {
		t.Fatal(err)
	}
	if typ2 == proto.MsgError {
		t.Fatalf("second enable web failed: %s", payload2)
	}
	if !strings.Contains(string(payload2), "already listening") {
		t.Fatalf("expected already listening, got: %s", payload2)
	}
}

// createDetachedSession creates a session and detaches, returning once ready.
func createDetachedSession(t *testing.T, sock, name string) {
	t.Helper()
	conn := dial(t, sock)
	proto.Encode(conn, proto.MsgNewSession, []byte(name))
	time.Sleep(300 * time.Millisecond)
	proto.Encode(conn, proto.MsgDetach, nil)
	for {
		typ, _, err := proto.Decode(conn)
		if err != nil || typ == proto.MsgDetached {
			break
		}
	}
	conn.Close()
}

func TestSendInput(t *testing.T) {
	_, sock := testServer(t)
	createDetachedSession(t, sock, "sendtest")

	conn := dial(t, sock)
	defer conn.Close()
	proto.Encode(conn, proto.MsgSendInput, []byte("sendtest\x00echo hi\n"))
	typ, payload, err := proto.Decode(conn)
	if err != nil {
		t.Fatal(err)
	}
	if typ == proto.MsgError {
		t.Fatalf("send failed: %s", payload)
	}
	if string(payload) != "ok" {
		t.Fatalf("payload = %q, want ok", payload)
	}
}

func TestSendInputNoSession(t *testing.T) {
	_, sock := testServer(t)

	conn := dial(t, sock)
	defer conn.Close()
	proto.Encode(conn, proto.MsgSendInput, []byte("nope\x00hello"))
	typ, _, err := proto.Decode(conn)
	if err != nil {
		t.Fatal(err)
	}
	if typ != proto.MsgError {
		t.Fatalf("type = %x, want MsgError", typ)
	}
}

func TestReadScreen(t *testing.T) {
	_, sock := testServer(t)
	createDetachedSession(t, sock, "screentest")

	conn := dial(t, sock)
	defer conn.Close()
	proto.Encode(conn, proto.MsgReadScreen, []byte("screentest"))
	typ, payload, err := proto.Decode(conn)
	if err != nil {
		t.Fatal(err)
	}
	if typ == proto.MsgError {
		t.Fatalf("screen failed: %s", payload)
	}
	if typ != proto.MsgScreenData {
		t.Fatalf("type = %x, want MsgScreenData", typ)
	}
	if len(payload) == 0 {
		t.Fatal("screen returned empty")
	}
}

func TestReadScreenNoSession(t *testing.T) {
	_, sock := testServer(t)

	conn := dial(t, sock)
	defer conn.Close()
	proto.Encode(conn, proto.MsgReadScreen, []byte("nope"))
	typ, _, err := proto.Decode(conn)
	if err != nil {
		t.Fatal(err)
	}
	if typ != proto.MsgError {
		t.Fatalf("type = %x, want MsgError", typ)
	}
}

func TestAPIAccessGating(t *testing.T) {
	s, sock := testServer(t)
	createDetachedSession(t, sock, "gatetest")

	// Disable API access.
	s.access.SetAPI(false)

	conn := dial(t, sock)
	defer conn.Close()
	proto.Encode(conn, proto.MsgSendInput, []byte("gatetest\x00hello"))
	typ, payload, err := proto.Decode(conn)
	if err != nil {
		t.Fatal(err)
	}
	if typ != proto.MsgError {
		t.Fatalf("type = %x, want MsgError", typ)
	}
	if !strings.Contains(string(payload), "api access disabled") {
		t.Fatalf("error = %q", payload)
	}

	// Screen should also be blocked.
	proto.Encode(conn, proto.MsgReadScreen, []byte("gatetest"))
	typ, payload, err = proto.Decode(conn)
	if err != nil {
		t.Fatal(err)
	}
	if typ != proto.MsgError {
		t.Fatalf("type = %x, want MsgError", typ)
	}

	// Re-enable and verify it works.
	s.access.SetAPI(true)
	proto.Encode(conn, proto.MsgReadScreen, []byte("gatetest"))
	typ, _, err = proto.Decode(conn)
	if err != nil {
		t.Fatal(err)
	}
	if typ != proto.MsgScreenData {
		t.Fatalf("type = %x, want MsgScreenData", typ)
	}
}
