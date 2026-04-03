package mux

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
)

// Session is a named collection of windows.
type Session struct {
	Name  string
	ID    uint64
	Shell string // shell to spawn in new panes

	mu        sync.Mutex
	windows   []*Window
	activeWin int
	nextWinID int
	cols      int
	rows      int

	// Per-session access control. True means accessible.
	// Defaults to true for all. Access via getters/setters.
	allowSSH   bool
	allowWeb   bool
	allowRelay bool
	allowAPI   bool
}

// ValidateSessionName checks that a session name is non-empty, printable
// ASCII, and at most 64 bytes.
func ValidateSessionName(name string) error {
	if name == "" {
		return fmt.Errorf("session name must not be empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("session name too long: %d bytes (max 64)", len(name))
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] > 0x7e {
			return fmt.Errorf("session name contains invalid byte 0x%02x at position %d", name[i], i)
		}
	}
	return nil
}

// NewSession creates a session with one window at the given dimensions.
func NewSession(name string, cols, rows int, shell string) (*Session, error) {
	if err := ValidateSessionName(name); err != nil {
		return nil, err
	}

	var buf [8]byte
	rand.Read(buf[:])
	id := binary.BigEndian.Uint64(buf[:])

	s := &Session{
		Name:       name,
		ID:         id,
		Shell:      shell,
		cols:       cols,
		rows:       rows,
		allowSSH:   true,
		allowWeb:   true,
		allowRelay: true,
		allowAPI:   true,
	}

	win, err := NewWindow(0, cols, rows, shell)
	if err != nil {
		return nil, fmt.Errorf("new window: %w", err)
	}
	s.windows = append(s.windows, win)
	s.nextWinID = 1

	return s, nil
}

// ActiveWindow returns the currently selected window.
func (s *Session) ActiveWindow() *Window {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.windows) == 0 {
		return nil
	}
	return s.windows[s.activeWin]
}

// ActiveWindowIndex returns the index of the active window.
func (s *Session) ActiveWindowIndex() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeWin
}

// Windows returns a copy of the window list.
func (s *Session) Windows() []*Window {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Window, len(s.windows))
	copy(out, s.windows)
	return out
}

// NewWindow creates a new window and makes it active.
func (s *Session) NewWindow() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	win, err := NewWindow(s.nextWinID, s.cols, s.rows, s.Shell)
	if err != nil {
		return err
	}
	s.nextWinID++
	s.windows = append(s.windows, win)
	s.activeWin = len(s.windows) - 1
	return nil
}

// SelectWindow switches to the window at the given index.
func (s *Session) SelectWindow(idx int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if idx >= 0 && idx < len(s.windows) {
		s.activeWin = idx
	}
}

// NextWindow cycles to the next window.
func (s *Session) NextWindow() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.windows) > 1 {
		s.activeWin = (s.activeWin + 1) % len(s.windows)
	}
}

// PrevWindow cycles to the previous window.
func (s *Session) PrevWindow() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.windows) > 1 {
		s.activeWin = (s.activeWin - 1 + len(s.windows)) % len(s.windows)
	}
}

// CloseActiveWindow closes the active window. Returns true if the
// session is empty.
func (s *Session) CloseActiveWindow() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.windows) == 0 {
		return true
	}
	win := s.windows[s.activeWin]
	win.Close()
	s.windows = append(s.windows[:s.activeWin], s.windows[s.activeWin+1:]...)
	if len(s.windows) == 0 {
		return true
	}
	if s.activeWin >= len(s.windows) {
		s.activeWin = len(s.windows) - 1
	}
	return false
}

// ReapDead removes all dead windows. Returns true if session is empty.
func (s *Session) ReapDead() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	alive := s.windows[:0]
	for _, w := range s.windows {
		if w.Dead() {
			w.Close()
		} else {
			alive = append(alive, w)
		}
	}
	s.windows = alive
	if s.activeWin >= len(s.windows) && len(s.windows) > 0 {
		s.activeWin = len(s.windows) - 1
	}
	return len(s.windows) == 0
}

// Resize updates session dimensions and resizes all windows.
func (s *Session) Resize(cols, rows int) {
	s.mu.Lock()
	s.cols = cols
	s.rows = rows
	windows := make([]*Window, len(s.windows))
	copy(windows, s.windows)
	s.mu.Unlock()

	for _, win := range windows {
		win.Resize(cols, rows)
	}
}

// Pane returns the active pane.
func (s *Session) Pane() *Pane {
	win := s.ActiveWindow()
	if win == nil {
		return nil
	}
	return win.ActivePane()
}

// Dead reports whether the session has no live windows.
func (s *Session) Dead() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, w := range s.windows {
		if !w.Dead() {
			return false
		}
	}
	return len(s.windows) == 0
}

// Close closes all windows in the session.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, w := range s.windows {
		w.Close()
	}
}

// AllowSSH returns whether SSH access is permitted for this session.
func (s *Session) AllowSSH() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allowSSH
}

// AllowWeb returns whether web access is permitted for this session.
func (s *Session) AllowWeb() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allowWeb
}

// AllowRelay returns whether relay access is permitted for this session.
func (s *Session) AllowRelay() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allowRelay
}

// SetAllowSSH toggles SSH access for this session.
func (s *Session) SetAllowSSH(v bool) {
	s.mu.Lock()
	s.allowSSH = v
	s.mu.Unlock()
}

// SetAllowWeb toggles web access for this session.
func (s *Session) SetAllowWeb(v bool) {
	s.mu.Lock()
	s.allowWeb = v
	s.mu.Unlock()
}

// SetAllowRelay toggles relay access for this session.
func (s *Session) SetAllowRelay(v bool) {
	s.mu.Lock()
	s.allowRelay = v
	s.mu.Unlock()
}

// AllowAPI returns whether API access (send/screen) is permitted for this session.
func (s *Session) AllowAPI() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allowAPI
}

// SetAllowAPI toggles API access for this session.
func (s *Session) SetAllowAPI(v bool) {
	s.mu.Lock()
	s.allowAPI = v
	s.mu.Unlock()
}

// Title returns the active window's title.
func (s *Session) Title() string {
	win := s.ActiveWindow()
	if win == nil {
		return ""
	}
	return win.Title()
}
