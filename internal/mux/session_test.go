package mux

import (
	"sync"
	"testing"
	"time"
)

func TestSessionNewWindow(t *testing.T) {
	s, err := NewSession("test", 80, 24, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if len(s.Windows()) != 1 {
		t.Fatalf("expected 1 window, got %d", len(s.Windows()))
	}

	s.NewWindow()
	if len(s.Windows()) != 2 {
		t.Fatalf("expected 2 windows, got %d", len(s.Windows()))
	}
	if s.ActiveWindowIndex() != 1 {
		t.Fatalf("expected active window 1, got %d", s.ActiveWindowIndex())
	}
}

func TestSessionWindowNav(t *testing.T) {
	s, err := NewSession("test", 80, 24, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.NewWindow()
	s.NewWindow()

	s.SelectWindow(0)
	if s.ActiveWindowIndex() != 0 {
		t.Fatal("should be window 0")
	}

	s.NextWindow()
	if s.ActiveWindowIndex() != 1 {
		t.Fatal("should be window 1")
	}

	s.PrevWindow()
	if s.ActiveWindowIndex() != 0 {
		t.Fatal("should be window 0 again")
	}
}

func TestSessionRender(t *testing.T) {
	s, err := NewSession("test", 80, 24, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	time.Sleep(100 * time.Millisecond)

	frame := Render(s, 80, 24, nil)
	if len(frame) == 0 {
		t.Fatal("render should produce output")
	}
}

func TestSessionCloseActiveWindow(t *testing.T) {
	s, err := NewSession("test", 80, 24, "")
	if err != nil {
		t.Fatal(err)
	}

	empty := s.CloseActiveWindow()
	if !empty {
		t.Fatal("session should be empty after closing only window")
	}
}

func TestSessionAccessFlags(t *testing.T) {
	s, err := NewSession("test", 80, 24, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Defaults are true.
	if !s.AllowSSH() || !s.AllowWeb() || !s.AllowRelay() {
		t.Fatal("expected all access flags true by default")
	}

	s.SetAllowSSH(false)
	if s.AllowSSH() {
		t.Fatal("expected AllowSSH = false")
	}
	s.SetAllowWeb(false)
	if s.AllowWeb() {
		t.Fatal("expected AllowWeb = false")
	}
	s.SetAllowRelay(false)
	if s.AllowRelay() {
		t.Fatal("expected AllowRelay = false")
	}
}

func TestSessionAccessFlagsConcurrent(t *testing.T) {
	s, err := NewSession("test", 80, 24, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func() { defer wg.Done(); s.SetAllowSSH(!s.AllowSSH()) }()
		go func() { defer wg.Done(); s.SetAllowWeb(!s.AllowWeb()) }()
		go func() { defer wg.Done(); s.SetAllowRelay(!s.AllowRelay()) }()
	}
	wg.Wait()
}
