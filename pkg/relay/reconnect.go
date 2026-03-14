package relay

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/ssh"
)

// PersistentConn maintains a persistent relay connection with auto-reconnect.
type PersistentConn struct {
	addr   string
	user   string
	device string
	signer ssh.Signer
	tlsCfg *tls.Config

	mu   sync.Mutex
	conn *Conn
	stop chan struct{}
	done chan struct{}

	// StreamFunc is called for each accepted SSH stream.
	StreamFunc func(*Stream)

	// UDPFunc is called for each accepted UDP forward stream.
	// The stream has the type byte consumed; next bytes are [targetPort:2][ipLen:2][ipString].
	UDPFunc func(*quic.Stream)

	// WebFunc is called for each accepted web terminal stream.
	WebFunc func(*quic.Stream)
}

// NewPersistentConn creates a new persistent relay connection.
func NewPersistentConn(addr, user, device string, signer ssh.Signer, tlsCfg *tls.Config, fn func(*Stream)) *PersistentConn {
	return &PersistentConn{
		addr:       addr,
		user:       user,
		device:     device,
		signer:     signer,
		tlsCfg:     tlsCfg,
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
		StreamFunc: fn,
	}
}

// Start begins the connection loop in a goroutine.
func (p *PersistentConn) Start() {
	go p.run()
}

// Stop closes the connection and stops reconnecting.
func (p *PersistentConn) Stop() {
	close(p.stop)
	p.mu.Lock()
	if p.conn != nil {
		p.conn.Close()
	}
	p.mu.Unlock()
	<-p.done
}

func (p *PersistentConn) run() {
	defer close(p.done)

	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for {
		select {
		case <-p.stop:
			return
		default:
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := Dial(ctx, p.addr, p.user, p.device, p.signer, p.tlsCfg)
		cancel()

		if err != nil {
			fmt.Fprintf(os.Stderr, "relay: %v (retry in %s)\n", err, backoff)
			select {
			case <-p.stop:
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		// Connected — reset backoff.
		backoff = time.Second

		p.mu.Lock()
		p.conn = conn
		p.mu.Unlock()

		p.acceptLoop(conn)

		p.mu.Lock()
		p.conn = nil
		p.mu.Unlock()
	}
}

// OpenStream opens a device-initiated QUIC stream on the current connection.
// Returns an error if not currently connected.
func (p *PersistentConn) OpenStream(ctx context.Context) (*quic.Stream, error) {
	p.mu.Lock()
	c := p.conn
	p.mu.Unlock()
	if c == nil {
		return nil, fmt.Errorf("not connected to relay")
	}
	return c.OpenStream(ctx)
}

func (p *PersistentConn) acceptLoop(conn *Conn) {
	for {
		select {
		case <-p.stop:
			conn.Close()
			return
		default:
		}

		raw, err := conn.AcceptRawStream(context.Background())
		if err != nil {
			return
		}

		// Read stream type byte.
		var typ [1]byte
		if _, err := io.ReadFull(raw, typ[:]); err != nil {
			raw.Close()
			continue
		}

		switch typ[0] {
		case 0x00:
			// SSH stream — wrap with IP header.
			stream, err := WrapStream(raw, conn.LocalAddr(), conn.RemoteAddr())
			if err != nil {
				continue
			}
			go p.StreamFunc(stream)
		case 0x01:
			// UDP forward stream.
			if p.UDPFunc != nil {
				go p.UDPFunc(raw)
			} else {
				raw.Close()
			}
		case 0x02:
			// Web terminal stream.
			if p.WebFunc != nil {
				go p.WebFunc(raw)
			} else {
				raw.Close()
			}
		default:
			raw.Close()
		}
	}
}
