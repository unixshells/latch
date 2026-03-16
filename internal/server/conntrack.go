package server

import (
	"io"
	"sort"
	"sync"
	"time"
)

// ConnInfo describes an active client connection.
type ConnInfo struct {
	ID          uint64
	Source      string // "local", "ssh", "relay"
	RemoteAddr  string
	KeyComment  string
	KeyFP       string
	Session     string
	ConnectedAt time.Time
	closer      io.Closer
}

type connTracker struct {
	mu    sync.Mutex
	conns map[uint64]*ConnInfo
	next  uint64
}

func newConnTracker() *connTracker {
	return &connTracker{conns: make(map[uint64]*ConnInfo)}
}

func (t *connTracker) register(info *ConnInfo) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.next++
	info.ID = t.next
	info.ConnectedAt = time.Now()
	t.conns[info.ID] = info
	return info.ID
}

func (t *connTracker) deregister(id uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.conns, id)
}

func (t *connTracker) list() []ConnInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]ConnInfo, 0, len(t.conns))
	for _, c := range t.conns {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (t *connTracker) kick(id uint64) bool {
	t.mu.Lock()
	c, ok := t.conns[id]
	t.mu.Unlock()
	if !ok {
		return false
	}
	if c.closer != nil {
		c.closer.Close()
	}
	return true
}

func (t *connTracker) hasLocal() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, c := range t.conns {
		if c.Source == "local" {
			return true
		}
	}
	return false
}
