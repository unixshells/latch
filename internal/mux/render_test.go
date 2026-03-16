package mux

import (
	"strings"
	"testing"
	"time"
)

func TestRenderSinglePane(t *testing.T) {
	s, err := NewSession("test", 40, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	time.Sleep(100 * time.Millisecond)

	frame := Render(s, 40, 10, nil)
	if len(frame) == 0 {
		t.Fatal("empty frame")
	}
	output := string(frame)
	if !strings.Contains(output, "\x1b[") {
		t.Fatal("should contain ANSI escape sequences")
	}
	// Bracketed paste is now enabled once at attach time, not per-frame.
	if strings.Contains(output, "\x1b[?2004h") {
		t.Fatal("should not enable bracketed paste per-frame")
	}
	if !strings.Contains(output, "\x1b[?25h") {
		t.Fatal("should show cursor")
	}
}

func TestRenderHUD(t *testing.T) {
	s, err := NewSession("work", 80, 24, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.NewWindow()

	time.Sleep(100 * time.Millisecond)

	hud := &HUDInfo{
		SSHAddr:   ":2222",
		PrefixKey: 0x1d,
	}
	frame := Render(s, 80, 24, hud)
	output := string(frame)
	if !strings.Contains(output, "ssh") {
		t.Fatal("HUD should contain ssh info")
	}
	if !strings.Contains(output, "web") {
		t.Fatal("HUD should contain web info")
	}
	if !strings.Contains(output, "C-]") {
		t.Fatal("HUD should show prefix key")
	}
	if !strings.Contains(output, "detach") {
		t.Fatal("HUD should show keybindings")
	}
	if !strings.Contains(output, "work") {
		t.Fatal("HUD bottom bar should show session name")
	}
}

func TestRenderNoHUD(t *testing.T) {
	s, err := NewSession("test", 80, 24, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	time.Sleep(100 * time.Millisecond)

	frame := Render(s, 80, 24, nil)
	output := string(frame)
	if strings.Contains(output, "\x1b[7m") {
		t.Fatal("should not have status bar without HUD")
	}
}

func TestRenderTooSmall(t *testing.T) {
	s, err := NewSession("test", 80, 24, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	frame := Render(s, 0, 0, nil)
	if frame != nil {
		t.Fatal("should return nil for tiny terminal")
	}
}

func TestRenderNoMouseSequences(t *testing.T) {
	s, err := NewSession("nomouse", 40, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	time.Sleep(100 * time.Millisecond)

	frame := Render(s, 40, 10, nil)
	output := string(frame)

	if strings.Contains(output, "\x1b[?1000h") {
		t.Fatal("Render should not emit mouse sequences")
	}
	// Bracketed paste is now enabled once at attach time, not per-frame.
	if strings.Contains(output, "\x1b[?2004h") {
		t.Fatal("should not emit bracketed paste per-frame")
	}
}

func TestPadOrTruncate(t *testing.T) {
	s := padOrTruncate("hello", 5)
	if s != "hello" {
		t.Fatalf("exact: got %q", s)
	}

	s = padOrTruncate("hi", 5)
	if s != "hi   " {
		t.Fatalf("pad: got %q", s)
	}

	s = padOrTruncate("hello world", 5)
	if len(s) > 5 {
		t.Fatalf("truncate: got %q (len %d)", s, len(s))
	}
}

func BenchmarkRender(b *testing.B) {
	s, err := NewSession("bench", 120, 40, "")
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()

	time.Sleep(200 * time.Millisecond)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Render(s, 120, 40, nil)
	}
}
