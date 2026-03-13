package relay

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestNewUDPRelay(t *testing.T) {
	r := NewUDPRelay()
	if r == nil {
		t.Fatal("nil relay")
	}
	if r.sessions == nil {
		t.Fatal("nil sessions map")
	}
}

func TestCreateSession(t *testing.T) {
	r := NewUDPRelay()
	_, stream := net.Pipe()
	t.Cleanup(func() { stream.Close() })

	s, err := r.CreateSession("sess1", stream)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.CloseSession("sess1") })

	if s.RelayPort == 0 {
		t.Fatal("RelayPort should be > 0")
	}
	if s.ID != "sess1" {
		t.Fatalf("ID = %q", s.ID)
	}

	r.mu.Lock()
	_, ok := r.sessions["sess1"]
	r.mu.Unlock()
	if !ok {
		t.Fatal("session not tracked")
	}
}

func TestCloseSession(t *testing.T) {
	r := NewUDPRelay()
	_, stream := net.Pipe()

	_, err := r.CreateSession("sess1", stream)
	if err != nil {
		t.Fatal(err)
	}

	r.CloseSession("sess1")

	r.mu.Lock()
	_, ok := r.sessions["sess1"]
	r.mu.Unlock()
	if ok {
		t.Fatal("session should be removed")
	}
}

func TestCloseSessionIdempotent(t *testing.T) {
	r := NewUDPRelay()
	_, stream := net.Pipe()

	_, err := r.CreateSession("sess1", stream)
	if err != nil {
		t.Fatal(err)
	}

	r.CloseSession("sess1")
	r.CloseSession("sess1") // should not panic
}

func TestCloseSessionNotFound(t *testing.T) {
	r := NewUDPRelay()
	r.CloseSession("nonexistent") // should not panic
}

func TestForwardClientToDevice(t *testing.T) {
	r := NewUDPRelay()
	clientSide, stream := net.Pipe()

	s, err := r.CreateSession("fwd-c2d", stream)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.CloseSession("fwd-c2d") })

	// Send a UDP datagram to the relay port.
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: s.RelayPort,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	payload := []byte("hello")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}

	// Read framed data from the pipe: [len:2][data].
	var hdr [2]byte
	clientSide.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(clientSide, hdr[:]); err != nil {
		t.Fatal(err)
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if int(n) != len(payload) {
		t.Fatalf("frame length = %d, want %d", n, len(payload))
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(clientSide, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("data = %q", buf)
	}
}

func TestForwardDeviceToClient(t *testing.T) {
	r := NewUDPRelay()
	clientSide, stream := net.Pipe()

	s, err := r.CreateSession("fwd-d2c", stream)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.CloseSession("fwd-d2c") })

	// Send a UDP packet to establish clientAddr.
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: s.RelayPort,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	if _, err := conn.Write([]byte("init")); err != nil {
		t.Fatal(err)
	}

	// Drain the framed "init" from the pipe.
	clientSide.SetDeadline(time.Now().Add(2 * time.Second))
	var initHdr [2]byte
	if _, err := io.ReadFull(clientSide, initHdr[:]); err != nil {
		t.Fatal(err)
	}
	initN := binary.BigEndian.Uint16(initHdr[:])
	discard := make([]byte, initN)
	if _, err := io.ReadFull(clientSide, discard); err != nil {
		t.Fatal(err)
	}

	// Clear deadline for writes.
	clientSide.SetDeadline(time.Time{})

	// Write framed data to the pipe (device -> client).
	payload := []byte("world")
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	if _, err := clientSide.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := clientSide.Write(payload); err != nil {
		t.Fatal(err)
	}

	// Read the UDP datagram.
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "world" {
		t.Fatalf("data = %q", buf[:n])
	}
}

func TestSessionTimeout(t *testing.T) {
	r := NewUDPRelay()
	r.Timeout = 100 * time.Millisecond

	_, stream := net.Pipe()

	_, err := r.CreateSession("timeout-sess", stream)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for timeout to fire.
	time.Sleep(300 * time.Millisecond)

	r.mu.Lock()
	_, ok := r.sessions["timeout-sess"]
	r.mu.Unlock()
	if ok {
		t.Fatal("session should have been cleaned up by timeout")
	}
}
