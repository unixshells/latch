package server

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/unixshells/latch/internal/config"
	"github.com/unixshells/latch/pkg/proto"
)

// drainUntil reads messages until it sees the given type or an error.
func drainUntil(t *testing.T, conn interface {
	Read([]byte) (int, error)
}, typ byte) ([]byte, bool) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("timeout waiting for message type %x", typ)
			return nil, false
		default:
		}
		mt, payload, err := proto.Decode(conn)
		if err != nil {
			return nil, false
		}
		if mt == typ {
			return payload, true
		}
	}
}

func TestMaxSessions(t *testing.T) {
	_, sock := testServer(t)

	for i := 0; i < config.Default().MaxSessions; i++ {
		name := fmt.Sprintf("sess%03d", i)
		c := dial(t, sock)
		proto.Encode(c, proto.MsgNewSession, []byte(name))
		time.Sleep(10 * time.Millisecond)
		proto.Encode(c, proto.MsgDetach, nil)
		drainUntil(t, c, proto.MsgDetached)
		c.Close()
	}

	c := dial(t, sock)
	defer c.Close()
	proto.Encode(c, proto.MsgNewSession, []byte("overflow"))

	typ, payload, err := proto.Decode(c)
	if err != nil {
		t.Fatal(err)
	}
	if typ != proto.MsgError {
		t.Fatalf("expected MsgError, got %x: %s", typ, payload)
	}
	if !strings.Contains(string(payload), "too many") {
		t.Fatalf("error = %q, want 'too many'", payload)
	}
}

func TestMultiClientSameSession(t *testing.T) {
	_, sock := testServer(t)

	c1 := dial(t, sock)
	defer c1.Close()
	proto.Encode(c1, proto.MsgNewSession, []byte("shared"))
	time.Sleep(200 * time.Millisecond)

	c2 := dial(t, sock)
	defer c2.Close()
	proto.Encode(c2, proto.MsgAttach, []byte("shared"))
	time.Sleep(200 * time.Millisecond)

	proto.Encode(c1, proto.MsgResize, proto.EncodeResize(80, 24))
	time.Sleep(100 * time.Millisecond)

	proto.Encode(c1, proto.MsgDetach, nil)
	drainUntil(t, c1, proto.MsgDetached)

	proto.Encode(c2, proto.MsgDetach, nil)
	drainUntil(t, c2, proto.MsgDetached)
}

func TestSessionOperations(t *testing.T) {
	_, sock := testServer(t)

	c := dial(t, sock)
	defer c.Close()
	proto.Encode(c, proto.MsgNewSession, []byte("ops"))
	time.Sleep(200 * time.Millisecond)

	// Send resize
	proto.Encode(c, proto.MsgResize, proto.EncodeResize(120, 40))
	time.Sleep(50 * time.Millisecond)

	// New window
	proto.Encode(c, proto.MsgNewWindow, nil)
	time.Sleep(50 * time.Millisecond)

	// Close window
	proto.Encode(c, proto.MsgCloseWindow, nil)
	time.Sleep(50 * time.Millisecond)

	// Select window 0
	proto.Encode(c, proto.MsgSelectWin, []byte{0})
	time.Sleep(50 * time.Millisecond)

	// New window again
	proto.Encode(c, proto.MsgNewWindow, nil)
	time.Sleep(50 * time.Millisecond)

	// Next window
	proto.Encode(c, proto.MsgSelectWin, []byte{proto.WindowNext})
	time.Sleep(50 * time.Millisecond)

	// Prev window
	proto.Encode(c, proto.MsgSelectWin, []byte{proto.WindowPrev})
	time.Sleep(50 * time.Millisecond)

	// Detach cleanly
	proto.Encode(c, proto.MsgDetach, nil)
	drainUntil(t, c, proto.MsgDetached)
}

func TestCloseLastWindow(t *testing.T) {
	_, sock := testServer(t)

	c := dial(t, sock)
	defer c.Close()
	proto.Encode(c, proto.MsgNewSession, []byte("closeme"))
	time.Sleep(200 * time.Millisecond)

	// Close the only window — should get SessionDead
	proto.Encode(c, proto.MsgCloseWindow, nil)
	_, ok := drainUntil(t, c, proto.MsgSessionDead)
	if !ok {
		t.Fatal("expected MsgSessionDead")
	}
}

func TestKillNonexistent(t *testing.T) {
	_, sock := testServer(t)

	c := dial(t, sock)
	defer c.Close()
	proto.Encode(c, proto.MsgKillSession, []byte("nope"))

	typ, payload, err := proto.Decode(c)
	if err != nil {
		t.Fatal(err)
	}
	if typ != proto.MsgError {
		t.Fatalf("expected MsgError, got %x", typ)
	}
	if !strings.Contains(string(payload), "no session") {
		t.Fatalf("error = %q", payload)
	}
}

func TestDuplicateSessionName(t *testing.T) {
	_, sock := testServer(t)

	c1 := dial(t, sock)
	proto.Encode(c1, proto.MsgNewSession, []byte("dup"))
	time.Sleep(200 * time.Millisecond)
	proto.Encode(c1, proto.MsgDetach, nil)
	drainUntil(t, c1, proto.MsgDetached)
	c1.Close()

	c2 := dial(t, sock)
	proto.Encode(c2, proto.MsgNewSession, []byte("dup"))
	time.Sleep(200 * time.Millisecond)
	proto.Encode(c2, proto.MsgDetach, nil)
	drainUntil(t, c2, proto.MsgDetached)
	c2.Close()

	c3 := dial(t, sock)
	defer c3.Close()
	proto.Encode(c3, proto.MsgList, nil)

	typ, payload, err := proto.Decode(c3)
	if err != nil {
		t.Fatal(err)
	}
	if typ != proto.MsgSessionList {
		t.Fatalf("expected MsgSessionList, got %x", typ)
	}
	count := strings.Count(string(payload), "dup")
	if count != 1 {
		t.Fatalf("expected 1 'dup' in list, got %d: %q", count, payload)
	}
}
