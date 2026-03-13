package relay

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// Stream wraps a QUIC stream as a net.Conn.
// The relay sends the original client IP at the start of each stream:
// [ip_len:2][ip_string].
type Stream struct {
	*quic.Stream
	remote  net.Addr // actual QUIC remote addr
	claimed net.Addr // IP from stream header (relay-provided)
	local   net.Addr
}

// WrapStream reads the client IP header and returns a net.Conn.
// quicRemoteAddr is the actual QUIC connection's remote address;
// the claimed address from the stream header is stored separately.
func WrapStream(s *quic.Stream, localAddr, quicRemoteAddr net.Addr) (*Stream, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(s, hdr[:]); err != nil {
		s.CancelRead(0)
		return nil, fmt.Errorf("read stream header: %w", err)
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if n > 512 {
		s.CancelRead(0)
		return nil, fmt.Errorf("stream header too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(s, buf); err != nil {
		s.CancelRead(0)
		return nil, fmt.Errorf("read client addr: %w", err)
	}
	addr, err := net.ResolveTCPAddr("tcp", string(buf))
	if err != nil {
		addr = &net.TCPAddr{}
	}
	return &Stream{Stream: s, remote: quicRemoteAddr, claimed: addr, local: localAddr}, nil
}

func (s *Stream) Read(p []byte) (int, error)  { return s.Stream.Read(p) }
func (s *Stream) Write(p []byte) (int, error) { return s.Stream.Write(p) }
func (s *Stream) Close() error                { return s.Stream.Close() }
func (s *Stream) RemoteAddr() net.Addr        { return s.remote }
func (s *Stream) ClaimedAddr() net.Addr       { return s.claimed }
func (s *Stream) LocalAddr() net.Addr         { return s.local }

func (s *Stream) SetDeadline(t time.Time) error      { return nil }
func (s *Stream) SetReadDeadline(t time.Time) error  { return nil }
func (s *Stream) SetWriteDeadline(t time.Time) error { return nil }

var _ net.Conn = (*Stream)(nil)
