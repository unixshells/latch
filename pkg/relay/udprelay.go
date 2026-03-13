package relay

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

// UDPRelay manages UDP relay sessions for mosh.
// Each session binds a local UDP port and forwards datagrams
// to a device via a QUIC stream.
type UDPRelay struct {
	mu       sync.Mutex
	sessions map[string]*UDPSession

	// Timeout is the session idle timeout. Zero means 10 minutes.
	Timeout time.Duration
}

// NewUDPRelay creates a new UDP relay manager.
func NewUDPRelay() *UDPRelay {
	return &UDPRelay{
		sessions: make(map[string]*UDPSession),
	}
}

// UDPSession represents an active mosh UDP relay session.
type UDPSession struct {
	ID         string
	RelayPort  int
	udpConn    *net.UDPConn
	quicStream io.ReadWriteCloser
	done       chan struct{}

	mu         sync.Mutex
	clientAddr *net.UDPAddr
}

// CreateSession creates a new UDP relay session.
// It binds a local UDP port and starts forwarding datagrams
// between the UDP port and the QUIC stream.
func (r *UDPRelay) CreateSession(id string, stream io.ReadWriteCloser) (*UDPSession, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", ":0")
	if err != nil {
		stream.Close()
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		stream.Close()
		return nil, err
	}

	s := &UDPSession{
		ID:         id,
		RelayPort:  udpConn.LocalAddr().(*net.UDPAddr).Port,
		udpConn:    udpConn,
		quicStream: stream,
		done:       make(chan struct{}),
	}

	r.mu.Lock()
	r.sessions[id] = s
	r.mu.Unlock()

	go s.forwardClientToDevice()
	go s.forwardDeviceToClient()

	timeout := r.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	go func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-timer.C:
			r.CloseSession(id)
		case <-s.done:
		}
	}()

	return s, nil
}

// CloseSession closes and removes a session.
func (r *UDPRelay) CloseSession(id string) {
	r.mu.Lock()
	s, ok := r.sessions[id]
	if ok {
		delete(r.sessions, id)
	}
	r.mu.Unlock()

	if ok {
		s.close()
	}
}

func (s *UDPSession) close() {
	select {
	case <-s.done:
		return
	default:
		close(s.done)
	}
	s.udpConn.Close()
	s.quicStream.Close()
}

// forwardClientToDevice reads UDP datagrams from the client,
// frames them as [len:2][data], and sends over the QUIC stream.
func (s *UDPSession) forwardClientToDevice() {
	buf := make([]byte, 65536)
	for {
		select {
		case <-s.done:
			return
		default:
		}

		s.udpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, addr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}

		s.mu.Lock()
		s.clientAddr = addr
		s.mu.Unlock()

		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(n))
		if _, err := s.quicStream.Write(hdr[:]); err != nil {
			return
		}
		if _, err := s.quicStream.Write(buf[:n]); err != nil {
			return
		}
	}
}

// datagramPool reuses buffers for UDP datagrams to reduce GC pressure.
var datagramPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2048)
		return &b
	},
}

// forwardDeviceToClient reads framed datagrams from the QUIC stream
// and sends them as UDP datagrams to the client.
func (s *UDPSession) forwardDeviceToClient() {
	var hdr [2]byte
	for {
		select {
		case <-s.done:
			return
		default:
		}

		if _, err := io.ReadFull(s.quicStream, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint16(hdr[:])

		// Use pooled buffer when possible.
		bp := datagramPool.Get().(*[]byte)
		buf := *bp
		if int(n) > cap(buf) {
			buf = make([]byte, n)
		} else {
			buf = buf[:n]
		}
		if _, err := io.ReadFull(s.quicStream, buf); err != nil {
			*bp = buf
			datagramPool.Put(bp)
			return
		}

		s.mu.Lock()
		addr := s.clientAddr
		s.mu.Unlock()

		if addr != nil {
			s.udpConn.WriteToUDP(buf, addr)
		}
		*bp = buf
		datagramPool.Put(bp)
	}
}
