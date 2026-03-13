package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/ssh"
)

const domainSeparator = "latch-relay-auth-v1:"

// Conn wraps a QUIC connection to the relay server.
type Conn struct {
	qconn *quic.Conn
}

// TLSConfig returns a TLS config for connecting to the relay server.
// If caFile is provided, it is used as the CA certificate pool.
// Otherwise, the system root CAs are used.
func TLSConfig(caFile string) (*tls.Config, error) {
	cfg := &tls.Config{
		NextProtos: []string{"latch-relay"},
		MinVersion: tls.VersionTLS13,
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read relay CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("relay CA: no valid certificates found in %s", caFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// Dial connects to the relay server and authenticates.
// The handshake:
//  1. Client opens a control stream
//  2. Client sends: [userLen:1][user][deviceLen:1][device][pubkeyLen:2][pubkey]
//  3. Server sends: [challengeLen:1][challenge]
//  4. Client signs domainSeparator+challenge with relay key, sends: [sigLen:2][sig]
//  5. Server sends: [1] on success, closes stream on failure
func Dial(ctx context.Context, addr string, user, device string, signer ssh.Signer, tlsCfg *tls.Config) (*Conn, error) {
	quicCfg := &quic.Config{
		KeepAlivePeriod: 30 * time.Second,
	}

	qconn, err := quic.DialAddr(ctx, addr, tlsCfg, quicCfg)
	if err != nil {
		return nil, fmt.Errorf("quic dial: %w", err)
	}

	// Open control stream for auth.
	stream, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		qconn.CloseWithError(1, "open stream")
		return nil, fmt.Errorf("open control stream: %w", err)
	}

	// Send identity.
	pubBytes := signer.PublicKey().Marshal()
	var hdr []byte
	hdr = append(hdr, byte(len(user)))
	hdr = append(hdr, user...)
	hdr = append(hdr, byte(len(device)))
	hdr = append(hdr, device...)
	hdr = append(hdr, byte(len(pubBytes)>>8), byte(len(pubBytes)))
	hdr = append(hdr, pubBytes...)
	if _, err := stream.Write(hdr); err != nil {
		qconn.CloseWithError(1, "write identity")
		return nil, fmt.Errorf("write identity: %w", err)
	}

	// Read challenge.
	var chLenBuf [1]byte
	if _, err := io.ReadFull(stream, chLenBuf[:]); err != nil {
		qconn.CloseWithError(1, "read challenge len")
		return nil, fmt.Errorf("read challenge: %w", err)
	}
	challenge := make([]byte, chLenBuf[0])
	if _, err := io.ReadFull(stream, challenge); err != nil {
		qconn.CloseWithError(1, "read challenge")
		return nil, fmt.Errorf("read challenge: %w", err)
	}

	// Sign with domain separator.
	msg := append([]byte(domainSeparator), challenge...)
	sig, err := signer.Sign(nil, msg)
	if err != nil {
		qconn.CloseWithError(1, "sign")
		return nil, fmt.Errorf("sign challenge: %w", err)
	}
	sigBytes := ssh.Marshal(sig)
	var sigHdr [2]byte
	sigHdr[0] = byte(len(sigBytes) >> 8)
	sigHdr[1] = byte(len(sigBytes))
	if _, err := stream.Write(sigHdr[:]); err != nil {
		qconn.CloseWithError(1, "write sig len")
		return nil, fmt.Errorf("write signature: %w", err)
	}
	if _, err := stream.Write(sigBytes); err != nil {
		qconn.CloseWithError(1, "write sig")
		return nil, fmt.Errorf("write signature: %w", err)
	}

	// Read result.
	var result [1]byte
	if _, err := io.ReadFull(stream, result[:]); err != nil {
		qconn.CloseWithError(1, "read result")
		return nil, fmt.Errorf("auth failed: %w", err)
	}
	if result[0] != 1 {
		qconn.CloseWithError(1, "auth rejected")
		return nil, fmt.Errorf("auth rejected by relay")
	}

	stream.Close()
	return &Conn{qconn: qconn}, nil
}

// AcceptStream accepts an incoming stream from the relay (a routed SSH connection).
func (c *Conn) AcceptStream(ctx context.Context) (*Stream, error) {
	s, err := c.qconn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return WrapStream(s, c.qconn.LocalAddr(), c.qconn.RemoteAddr())
}

// AcceptRawStream accepts a raw QUIC stream without reading any header.
func (c *Conn) AcceptRawStream(ctx context.Context) (*quic.Stream, error) {
	return c.qconn.AcceptStream(ctx)
}

// LocalAddr returns the local address of the QUIC connection.
func (c *Conn) LocalAddr() net.Addr {
	return c.qconn.LocalAddr()
}

// RemoteAddr returns the remote address of the QUIC connection.
func (c *Conn) RemoteAddr() net.Addr {
	return c.qconn.RemoteAddr()
}

// OpenStream opens a new device-initiated QUIC stream to the relay.
func (c *Conn) OpenStream(ctx context.Context) (*quic.Stream, error) {
	return c.qconn.OpenStreamSync(ctx)
}

// Close closes the QUIC connection.
func (c *Conn) Close() error {
	return c.qconn.CloseWithError(0, "")
}
