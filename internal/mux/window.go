package mux

import (
	"fmt"
	"sync"
)

// Window manages a single pane within a session.
type Window struct {
	ID int

	mu    sync.Mutex
	pane  *Pane
	shell string
}

// NewWindow creates a window with a single pane of the given size.
func NewWindow(id int, cols, rows int, shell string) (*Window, error) {
	pane, err := NewPane(0, cols, rows, shell)
	if err != nil {
		return nil, fmt.Errorf("new pane: %w", err)
	}
	return &Window{
		ID:    id,
		pane:  pane,
		shell: shell,
	}, nil
}

// ActivePane returns the pane.
func (w *Window) ActivePane() *Pane {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.pane
}

// Panes returns the single pane as a slice.
func (w *Window) Panes() []*Pane {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pane == nil {
		return nil
	}
	return []*Pane{w.pane}
}

// Title returns the pane's title.
func (w *Window) Title() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pane == nil {
		return ""
	}
	return w.pane.Title()
}

// Resize updates the pane dimensions.
func (w *Window) Resize(cols, rows int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pane != nil {
		w.pane.Resize(cols, rows)
	}
}

// Dead reports whether the pane has exited.
func (w *Window) Dead() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.pane == nil || w.pane.Dead()
}

// Close closes the pane.
func (w *Window) Close() {
	w.mu.Lock()
	p := w.pane
	w.mu.Unlock()
	if p != nil {
		p.Close()
	}
}

// Snapshot returns the pane for rendering.
func (w *Window) Snapshot() *Pane {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.pane
}
