package mux

import (
	"testing"
)

func TestNewWindow(t *testing.T) {
	w, err := NewWindow(0, 80, 24, "")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	if w.ActivePane() == nil {
		t.Fatal("no active pane")
	}
	if w.Dead() {
		t.Fatal("window should be alive")
	}
}

func TestWindowClose(t *testing.T) {
	w, err := NewWindow(0, 80, 24, "")
	if err != nil {
		t.Fatal(err)
	}

	w.Close()
	if !w.Dead() {
		t.Fatal("window should be dead after close")
	}
}

func TestWindowTitle(t *testing.T) {
	w, err := NewWindow(0, 80, 24, "")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	title := w.Title()
	if title == "" {
		t.Fatal("title should not be empty")
	}
}
