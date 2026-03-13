package mux

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestNewPane(t *testing.T) {
	p, err := NewPane(1, 80, 24, "/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	if p.Dead() {
		t.Fatal("pane should not be dead")
	}
	if p.ID != 1 {
		t.Fatalf("ID = %d, want 1", p.ID)
	}
}

func TestPaneWriteRead(t *testing.T) {
	p, err := NewPane(1, 80, 24, "/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	var buf syncBuf
	p.AddWriter(&buf)

	p.WriteInput([]byte("echo hello\n"))

	deadline := time.After(3 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for output")
		default:
		}
		if strings.Contains(buf.String(), "hello") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPaneSnapshot(t *testing.T) {
	p, err := NewPane(1, 80, 24, "/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// Wait for shell prompt
	time.Sleep(200 * time.Millisecond)

	snap := p.Snapshot()
	if len(snap) == 0 {
		t.Fatal("snapshot should not be empty")
	}
	// Should start with RIS
	if snap[0] != '\x1b' || snap[1] != 'c' {
		t.Fatal("snapshot should start with ESC c")
	}
}

func TestPaneResize(t *testing.T) {
	p, err := NewPane(1, 80, 24, "/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.Resize(120, 40)
}

func TestPaneTitle(t *testing.T) {
	p, err := NewPane(1, 80, 24, "/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	if p.Title() != "shell" {
		t.Fatalf("default title = %q, want %q", p.Title(), "shell")
	}
}

func TestPaneRemoveWriter(t *testing.T) {
	p, err := NewPane(1, 80, 24, "/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	var buf bytes.Buffer
	p.AddWriter(&buf)
	p.RemoveWriter(&buf)
}

func TestPaneResizeZero(t *testing.T) {
	p, err := NewPane(1, 80, 24, "/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// Resize to 0x0 should not panic (clamp should handle it).
	p.Resize(0, 0)

	// Verify the pane is still functional.
	if p.Dead() {
		t.Fatal("pane should not be dead after 0x0 resize")
	}
}

func TestPaneResizeLarge(t *testing.T) {
	p, err := NewPane(1, 80, 24, "/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// Resize to 10000x10000. clamp should bound it to maxCols x maxRows.
	p.Resize(10000, 10000)

	// Verify the pane is still alive (no OOM, no panic).
	if p.Dead() {
		t.Fatal("pane should not be dead after large resize")
	}

	// Screen dimensions should be clamped.
	s := p.Screen()
	if s.W > maxCols {
		t.Fatalf("width %d exceeds maxCols %d", s.W, maxCols)
	}
	if s.H > maxRows {
		t.Fatalf("height %d exceeds maxRows %d", s.H, maxRows)
	}
}

func TestPaneProcessExit(t *testing.T) {
	// Use a command that exits immediately.
	p, err := NewPane(1, 80, 24, "/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// Write "exit" to make the shell exit.
	p.WriteInput([]byte("exit\n"))

	// Wait for the pane to detect the process exit.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for pane to detect process exit")
		default:
		}
		if p.Dead() {
			return // success
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRingBuffer(t *testing.T) {
	var r ringBuffer
	r.buf = make([]byte, 8)

	r.Write([]byte("hello"))
	got := string(r.Bytes())
	if got != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}

	// After writing "worldx", total stream is "helloworldx" (11 bytes).
	// An 8-byte ring should contain the last 8: "loworldx".
	r.Write([]byte("worldx"))
	got = string(r.Bytes())
	if got != "loworldx" {
		t.Fatalf("got %q, want %q", got, "loworldx")
	}
}

func TestRingBufferWrap(t *testing.T) {
	var r ringBuffer
	r.buf = make([]byte, 4)

	r.Write([]byte("abcdef"))
	got := r.Bytes()
	if string(got) != "cdef" {
		t.Fatalf("got %q, want %q", string(got), "cdef")
	}
}
