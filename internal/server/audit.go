package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEvent is a single audit log entry.
type AuditEvent struct {
	Time       string `json:"time"`
	Event      string `json:"event"`                 // "connect", "disconnect", "reject"
	Source     string `json:"source"`                // "local", "ssh", "web", "relay", "web-relay"
	RemoteAddr string `json:"remote_addr,omitempty"` // client IP:port
	KeyFP      string `json:"key_fp,omitempty"`      // SSH key fingerprint
	KeyComment string `json:"key_comment,omitempty"` // SSH key comment
	Session    string `json:"session,omitempty"`
	Duration   string `json:"duration,omitempty"` // only on disconnect
	Reason     string `json:"reason,omitempty"`   // only on reject
}

type auditLog struct {
	mu   sync.Mutex
	f    *os.File
	enc  *json.Encoder
	path string
}

func newAuditLog() *auditLog {
	dir := os.Getenv("HOME")
	if dir == "" {
		return &auditLog{}
	}
	path := filepath.Join(dir, ".latch", "audit.log")
	return &auditLog{path: path}
}

func (a *auditLog) open() error {
	if a.path == "" {
		return nil
	}
	if a.f != nil {
		return nil
	}
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	a.f = f
	a.enc = json.NewEncoder(f)
	return nil
}

func (a *auditLog) emit(ev AuditEvent) {
	if a == nil || a.path == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.open(); err != nil {
		return
	}
	if ev.Time == "" {
		ev.Time = time.Now().UTC().Format(time.RFC3339)
	}
	a.enc.Encode(ev)
}

func (a *auditLog) close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f != nil {
		a.f.Close()
		a.f = nil
	}
}
