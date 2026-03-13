package server

import (
	"io"
	"sync"
	"testing"
)

func TestConnTrackerRegisterList(t *testing.T) {
	tr := newConnTracker()
	id := tr.register(&ConnInfo{Source: "ssh", RemoteAddr: "1.2.3.4"})
	if id == 0 {
		t.Fatal("expected nonzero ID")
	}
	conns := tr.list()
	if len(conns) != 1 {
		t.Fatalf("got %d conns, want 1", len(conns))
	}
	if conns[0].Source != "ssh" {
		t.Fatalf("source = %q, want ssh", conns[0].Source)
	}
}

func TestConnTrackerDeregister(t *testing.T) {
	tr := newConnTracker()
	id := tr.register(&ConnInfo{Source: "local"})
	tr.deregister(id)
	if len(tr.list()) != 0 {
		t.Fatal("expected empty after deregister")
	}
}

func TestConnTrackerKick(t *testing.T) {
	tr := newConnTracker()

	pr, pw := io.Pipe()
	defer pr.Close()

	id := tr.register(&ConnInfo{Source: "ssh", closer: pw})
	if !tr.kick(id) {
		t.Fatal("kick returned false")
	}
	// The writer should be closed now.
	if _, err := pw.Write([]byte("test")); err == nil {
		t.Fatal("expected write error after kick")
	}
}

func TestConnTrackerKickNotFound(t *testing.T) {
	tr := newConnTracker()
	if tr.kick(999) {
		t.Fatal("kick should return false for unknown ID")
	}
}

func TestConnTrackerHasLocal(t *testing.T) {
	tr := newConnTracker()
	if tr.hasLocal() {
		t.Fatal("should not have local initially")
	}
	id := tr.register(&ConnInfo{Source: "ssh"})
	if tr.hasLocal() {
		t.Fatal("ssh should not count as local")
	}
	_ = id

	id2 := tr.register(&ConnInfo{Source: "local"})
	if !tr.hasLocal() {
		t.Fatal("should have local")
	}
	tr.deregister(id2)
	if tr.hasLocal() {
		t.Fatal("should not have local after deregister")
	}
}

func TestConnLimiterMaxConnections(t *testing.T) {
	lim := newConnLimiter(3)
	ip := "192.168.1.1"

	// Acquire up to the limit.
	for i := 0; i < 3; i++ {
		if !lim.acquire(ip) {
			t.Fatalf("acquire %d should succeed", i)
		}
	}

	// The next should be rejected.
	if lim.acquire(ip) {
		t.Fatal("acquire beyond limit should fail")
	}

	// Different IP should still work.
	if !lim.acquire("10.0.0.1") {
		t.Fatal("different IP should succeed")
	}
}

func TestConnLimiterCleanup(t *testing.T) {
	lim := newConnLimiter(1)
	ip := "192.168.1.1"

	if !lim.acquire(ip) {
		t.Fatal("first acquire should succeed")
	}
	if lim.acquire(ip) {
		t.Fatal("second acquire should fail (limit=1)")
	}

	// Release frees the slot.
	lim.release(ip)

	if !lim.acquire(ip) {
		t.Fatal("acquire after release should succeed")
	}
}

func TestConnLimiterConcurrent(t *testing.T) {
	lim := newConnLimiter(100)
	ip := "192.168.1.1"

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if lim.acquire(ip) {
					lim.release(ip)
				}
			}
		}()
	}
	wg.Wait()

	// After all goroutines finish, the IP should have no active connections.
	lim.mu.Lock()
	count := lim.conns[ip]
	lim.mu.Unlock()
	if count != 0 {
		t.Fatalf("expected 0 active connections, got %d", count)
	}
}
