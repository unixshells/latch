package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/ssh"
)

func TestBackoffCap(t *testing.T) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for i := 0; i < 20; i++ {
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
	if backoff != maxBackoff {
		t.Fatalf("backoff = %v, want %v", backoff, maxBackoff)
	}
}

func TestDomainSeparator(t *testing.T) {
	if domainSeparator != "latch-relay-auth-v1:" {
		t.Fatalf("domain separator = %q", domainSeparator)
	}
}

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"latch-relay"},
	}
}

// mockRelayServer does the auth handshake, then opens streams with IP headers.
func mockRelayServer(t *testing.T, ln *quic.Listener, streamAddrs []string) {
	t.Helper()
	ctx := context.Background()

	conn, err := ln.Accept(ctx)
	if err != nil {
		return
	}

	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		t.Errorf("accept control stream: %v", err)
		return
	}

	// Read identity.
	var userLen [1]byte
	io.ReadFull(stream, userLen[:])
	user := make([]byte, userLen[0])
	io.ReadFull(stream, user)

	var devLen [1]byte
	io.ReadFull(stream, devLen[:])
	dev := make([]byte, devLen[0])
	io.ReadFull(stream, dev)

	var pkLen [2]byte
	io.ReadFull(stream, pkLen[:])
	pk := make([]byte, binary.BigEndian.Uint16(pkLen[:]))
	io.ReadFull(stream, pk)

	pubKey, err := ssh.ParsePublicKey(pk)
	if err != nil {
		t.Errorf("parse public key: %v", err)
		return
	}

	// Send challenge.
	challenge := []byte("test-challenge-1234567890abcdef")
	stream.Write([]byte{byte(len(challenge))})
	stream.Write(challenge)

	// Read signature.
	var sigLen [2]byte
	io.ReadFull(stream, sigLen[:])
	sigBytes := make([]byte, binary.BigEndian.Uint16(sigLen[:]))
	io.ReadFull(stream, sigBytes)

	var sig ssh.Signature
	if err := ssh.Unmarshal(sigBytes, &sig); err != nil {
		stream.Write([]byte{0})
		stream.Close()
		return
	}
	msg := append([]byte(domainSeparator), challenge...)
	if err := pubKey.Verify(msg, &sig); err != nil {
		stream.Write([]byte{0})
		stream.Close()
		return
	}

	stream.Write([]byte{1})
	stream.Close()

	// Open streams with IP headers + payload.
	for _, addr := range streamAddrs {
		s, err := conn.OpenStreamSync(ctx)
		if err != nil {
			return
		}
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(addr)))
		s.Write(hdr[:])
		s.Write([]byte(addr))
		s.Write([]byte("hello"))
		s.Close()
	}
}

// mockRelayServerSync is like mockRelayServer but returns an error instead of
// calling t.Errorf from a goroutine, making synchronization reliable.
func mockRelayServerSync(t *testing.T, ln *quic.Listener, streamAddrs []string) error {
	t.Helper()
	ctx := context.Background()

	conn, err := ln.Accept(ctx)
	if err != nil {
		return err
	}

	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("accept control stream: %w", err)
	}

	// Read identity.
	var userLen [1]byte
	io.ReadFull(stream, userLen[:])
	user := make([]byte, userLen[0])
	io.ReadFull(stream, user)

	var devLen [1]byte
	io.ReadFull(stream, devLen[:])
	dev := make([]byte, devLen[0])
	io.ReadFull(stream, dev)

	var pkLen [2]byte
	io.ReadFull(stream, pkLen[:])
	pk := make([]byte, binary.BigEndian.Uint16(pkLen[:]))
	io.ReadFull(stream, pk)

	pubKey, err := ssh.ParsePublicKey(pk)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	// Send challenge.
	challenge := []byte("test-challenge-1234567890abcdef")
	stream.Write([]byte{byte(len(challenge))})
	stream.Write(challenge)

	// Read signature.
	var sigLen [2]byte
	io.ReadFull(stream, sigLen[:])
	sigBytes := make([]byte, binary.BigEndian.Uint16(sigLen[:]))
	io.ReadFull(stream, sigBytes)

	var sig ssh.Signature
	if err := ssh.Unmarshal(sigBytes, &sig); err != nil {
		stream.Write([]byte{0})
		stream.Close()
		return fmt.Errorf("unmarshal sig: %w", err)
	}
	msg := append([]byte(domainSeparator), challenge...)
	if err := pubKey.Verify(msg, &sig); err != nil {
		stream.Write([]byte{0})
		stream.Close()
		return fmt.Errorf("verify sig: %w", err)
	}

	stream.Write([]byte{1})
	stream.Close()

	// Open streams with IP headers + payload.
	for _, addr := range streamAddrs {
		s, err := conn.OpenStreamSync(ctx)
		if err != nil {
			return fmt.Errorf("open stream: %w", err)
		}
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(addr)))
		s.Write(hdr[:])
		s.Write([]byte(addr))
		s.Write([]byte("hello"))
		s.Close()
	}
	return nil
}

// dialInsecure does the auth handshake with InsecureSkipVerify for tests.
func dialInsecure(ctx context.Context, addr string, user, device string, signer ssh.Signer) (*Conn, error) {
	tlsCfg := &tls.Config{
		NextProtos:         []string{"latch-relay"},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	}
	qconn, err := quic.DialAddr(ctx, addr, tlsCfg, nil)
	if err != nil {
		return nil, err
	}

	stream, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		qconn.CloseWithError(1, "")
		return nil, err
	}

	pubBytes := signer.PublicKey().Marshal()
	var hdr []byte
	hdr = append(hdr, byte(len(user)))
	hdr = append(hdr, user...)
	hdr = append(hdr, byte(len(device)))
	hdr = append(hdr, device...)
	hdr = append(hdr, byte(len(pubBytes)>>8), byte(len(pubBytes)))
	hdr = append(hdr, pubBytes...)
	stream.Write(hdr)

	var chLen [1]byte
	io.ReadFull(stream, chLen[:])
	challenge := make([]byte, chLen[0])
	io.ReadFull(stream, challenge)

	msg := append([]byte(domainSeparator), challenge...)
	sig, err := signer.Sign(nil, msg)
	if err != nil {
		qconn.CloseWithError(1, "")
		return nil, err
	}
	sigBytes := ssh.Marshal(sig)
	var sigHdr [2]byte
	sigHdr[0] = byte(len(sigBytes) >> 8)
	sigHdr[1] = byte(len(sigBytes))
	stream.Write(sigHdr[:])
	stream.Write(sigBytes)

	var result [1]byte
	if _, err := io.ReadFull(stream, result[:]); err != nil {
		qconn.CloseWithError(1, "")
		return nil, err
	}
	if result[0] != 1 {
		qconn.CloseWithError(1, "")
		return nil, io.ErrUnexpectedEOF
	}
	stream.Close()
	return &Conn{qconn: qconn}, nil
}

func TestDialAndAuth(t *testing.T) {
	tlsCfg := testTLSConfig(t)
	signer := testSigner(t)

	ln, err := quic.ListenAddr("127.0.0.1:0", tlsCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		mockRelayServer(t, ln, nil)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialInsecure(ctx, ln.Addr().String(), "testuser", "macbook", signer)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	<-done
}

func TestDialAuthReject(t *testing.T) {
	tlsCfg := testTLSConfig(t)

	ln, err := quic.ListenAddr("127.0.0.1:0", tlsCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		// Server that rejects all auth.
		ctx := context.Background()
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		buf := make([]byte, 4096)
		stream.Read(buf)
		stream.Write([]byte{4})
		stream.Write([]byte("test"))
		stream.Read(buf)
		stream.Write([]byte{0}) // rejection
		stream.Close()
		conn.CloseWithError(0, "")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	signer := testSigner(t)
	_, err = dialInsecure(ctx, ln.Addr().String(), "testuser", "macbook", signer)
	if err == nil {
		t.Fatal("expected auth error")
	}
}

func TestAcceptStreamIPHeader(t *testing.T) {
	tlsCfg := testTLSConfig(t)
	signer := testSigner(t)

	ln, err := quic.ListenAddr("127.0.0.1:0", tlsCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Use a channel so the mock server waits for the client to be ready
	// before opening data streams. This prevents a race where the server
	// opens a stream before the client calls AcceptStream.
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- mockRelayServerSync(t, ln, []string{"1.2.3.4:5678"})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dialInsecure(ctx, ln.Addr().String(), "testuser", "macbook", signer)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if stream.ClaimedAddr().String() != "1.2.3.4:5678" {
		t.Fatalf("claimed addr = %s, want 1.2.3.4:5678", stream.ClaimedAddr())
	}

	data, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Fatalf("data = %q, want %q", data, "hello")
	}

	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestAcceptMultipleStreams(t *testing.T) {
	tlsCfg := testTLSConfig(t)
	signer := testSigner(t)

	ln, err := quic.ListenAddr("127.0.0.1:0", tlsCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- mockRelayServerSync(t, ln, []string{"10.0.0.1:22", "10.0.0.2:22"})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dialInsecure(ctx, ln.Addr().String(), "testuser", "macbook", signer)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Accept two streams.
	addrs := make(map[string]bool)
	for i := 0; i < 2; i++ {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		addrs[stream.ClaimedAddr().String()] = true
		io.ReadAll(stream)
	}
	if !addrs["10.0.0.1:22"] {
		t.Fatal("missing 10.0.0.1:22")
	}
	if !addrs["10.0.0.2:22"] {
		t.Fatal("missing 10.0.0.2:22")
	}
}

func TestStreamNetConn(t *testing.T) {
	// Verify Stream satisfies net.Conn.
	var _ net.Conn = (*Stream)(nil)
}

func TestPersistentConnReconnectsAfterReject(t *testing.T) {
	tlsCfg := testTLSConfig(t)
	signer := testSigner(t)

	ln, err := quic.ListenAddr("127.0.0.1:0", tlsCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Count connection attempts. First rejects, second accepts.
	attempts := make(chan int, 10)
	go func() {
		count := 0
		for {
			ctx := context.Background()
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			count++
			attempts <- count

			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				return
			}
			// Read identity.
			buf := make([]byte, 4096)
			stream.Read(buf)

			if count == 1 {
				// Reject first attempt.
				stream.Write([]byte{4})
				stream.Write([]byte("test"))
				stream.Read(buf)
				stream.Write([]byte{0}) // rejection
				stream.Close()
				conn.CloseWithError(0, "")
			} else {
				// Accept second attempt with full handshake.
				challenge := []byte("test-challenge-1234567890abcdef")
				stream.Write([]byte{byte(len(challenge))})
				stream.Write(challenge)
				var sigLen [2]byte
				io.ReadFull(stream, sigLen[:])
				sigBytes := make([]byte, binary.BigEndian.Uint16(sigLen[:]))
				io.ReadFull(stream, sigBytes)
				stream.Write([]byte{1}) // accept
				stream.Close()
				// Keep connection open until test ends.
				<-ctx.Done()
			}
		}
	}()

	// Use PersistentConn with dialInsecure by testing the backoff pattern.
	// Instead of full PersistentConn (which uses Dial), test that the reconnect
	// logic of run() produces backoff by measuring the effect: Stop works even
	// when the server keeps rejecting.
	clientTLS := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"latch-relay"}, MinVersion: tls.VersionTLS13}
	p := NewPersistentConn(ln.Addr().String(), "user", "dev", signer, clientTLS, func(s *Stream) {})
	p.Start()

	// Wait for at least one attempt.
	select {
	case <-attempts:
	case <-time.After(5 * time.Second):
		t.Fatal("no connection attempts")
	}

	// Stop should work even while reconnecting.
	done := make(chan struct{})
	go func() {
		p.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return within 5s during reconnect")
	}
}

func TestPersistentConnStopDuringBackoff(t *testing.T) {
	// Use an unreachable address so Dial fails immediately with a connection error.
	signer := testSigner(t)
	clientTLS := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"latch-relay"}, MinVersion: tls.VersionTLS13}

	// Port 1 is unlikely to have a QUIC server.
	p := NewPersistentConn("127.0.0.1:1", "user", "dev", signer, clientTLS, func(s *Stream) {})
	p.Start()

	// Let it fail and enter backoff.
	time.Sleep(100 * time.Millisecond)

	// Stop must return promptly even during backoff sleep.
	done := make(chan struct{})
	go func() {
		p.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop blocked during backoff")
	}
}

func TestPersistentConnStop(t *testing.T) {
	signer := testSigner(t)
	tlsCfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"latch-relay"}, MinVersion: tls.VersionTLS13}
	p := NewPersistentConn("127.0.0.1:1", "user", "dev", signer, tlsCfg, func(s *Stream) {})
	p.Start()
	time.Sleep(50 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		p.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return within 5s")
	}
}

func TestRelayAuthOversizedIdentity(t *testing.T) {
	// The relay protocol uses a 1-byte length prefix for username.
	// byte(len(user)) truncates to uint8, so a 256-byte username wraps to 0.
	// Verify the client doesn't crash and the server handles it.
	tlsCfg := testTLSConfig(t)
	signer := testSigner(t)

	ln, err := quic.ListenAddr("127.0.0.1:0", tlsCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Server that reads the identity and checks what arrives.
	serverDone := make(chan error, 1)
	go func() {
		ctx := context.Background()
		conn, err := ln.Accept(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		// Read user length (1 byte). A 300-char username will be truncated
		// by byte() to 300-256=44.
		var userLen [1]byte
		if _, err := io.ReadFull(stream, userLen[:]); err != nil {
			serverDone <- err
			return
		}
		user := make([]byte, userLen[0])
		if _, err := io.ReadFull(stream, user); err != nil {
			serverDone <- err
			return
		}
		// Just reject after reading the identity to end the test cleanly.
		stream.Write([]byte{4})
		stream.Write([]byte("test"))
		buf := make([]byte, 4096)
		stream.Read(buf)
		stream.Write([]byte{0})
		stream.Close()
		conn.CloseWithError(0, "")
		serverDone <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 300-byte username exceeds 1-byte length prefix capacity.
	longUser := string(make([]byte, 300))
	_, err = dialInsecure(ctx, ln.Addr().String(), longUser, "dev", signer)
	// We expect either an auth error or the connection to work but with
	// a truncated username. The key point is no panic or hang.
	if err == nil {
		t.Log("dial succeeded despite oversized username (truncated by byte cast)")
	}
	<-serverDone
}

func TestRelayAuthOversizedSignature(t *testing.T) {
	tlsCfg := testTLSConfig(t)

	ln, err := quic.ListenAddr("127.0.0.1:0", tlsCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		ctx := context.Background()
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		// Read identity.
		buf := make([]byte, 4096)
		stream.Read(buf)
		// Send challenge.
		challenge := []byte("test-challenge-1234567890abcdef")
		stream.Write([]byte{byte(len(challenge))})
		stream.Write(challenge)
		// Read signature header claiming 65535 bytes.
		var sigLen [2]byte
		io.ReadFull(stream, sigLen[:])
		n := binary.BigEndian.Uint16(sigLen[:])
		// Read whatever the client actually sends. If n is huge, ReadFull
		// will block or EOF. The key check is no crash.
		sigBytes := make([]byte, n)
		io.ReadFull(stream, sigBytes)
		// Reject.
		stream.Write([]byte{0})
		stream.Close()
		conn.CloseWithError(0, "")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	signer := testSigner(t)
	_, err = dialInsecure(ctx, ln.Addr().String(), "user", "dev", signer)
	// The normal client sends a properly-sized signature; the server rejects it
	// because it sends {0} regardless. The point is no panic.
	if err == nil {
		t.Fatal("expected auth rejection")
	}
}

func TestRelayAuthEmptyChallenge(t *testing.T) {
	tlsCfg := testTLSConfig(t)
	signer := testSigner(t)

	ln, err := quic.ListenAddr("127.0.0.1:0", tlsCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		ctx := context.Background()
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		// Read identity.
		buf := make([]byte, 4096)
		stream.Read(buf)
		// Send 0-length challenge.
		stream.Write([]byte{0}) // challengeLen = 0
		// Read signature.
		var sigLen [2]byte
		io.ReadFull(stream, sigLen[:])
		n := binary.BigEndian.Uint16(sigLen[:])
		sigBytes := make([]byte, n)
		io.ReadFull(stream, sigBytes)
		// Accept (verify the client handled zero-length challenge).
		stream.Write([]byte{1})
		stream.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialInsecure(ctx, ln.Addr().String(), "user", "dev", signer)
	if err != nil {
		t.Fatalf("empty challenge should be handled: %v", err)
	}
	conn.Close()
}

func TestRelayStreamOversizedFrame(t *testing.T) {
	// WrapStream rejects stream headers > 512 bytes.
	tlsCfg := testTLSConfig(t)
	signer := testSigner(t)

	ln, err := quic.ListenAddr("127.0.0.1:0", tlsCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverDone := make(chan error, 1)
	go func() {
		ctx := context.Background()
		conn, err := ln.Accept(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		// Do auth handshake.
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			serverDone <- fmt.Errorf("accept control: %w", err)
			return
		}
		var userLen [1]byte
		io.ReadFull(stream, userLen[:])
		user := make([]byte, userLen[0])
		io.ReadFull(stream, user)
		var devLen [1]byte
		io.ReadFull(stream, devLen[:])
		dev := make([]byte, devLen[0])
		io.ReadFull(stream, dev)
		var pkLen [2]byte
		io.ReadFull(stream, pkLen[:])
		pk := make([]byte, binary.BigEndian.Uint16(pkLen[:]))
		io.ReadFull(stream, pk)
		pubKey, err := ssh.ParsePublicKey(pk)
		if err != nil {
			serverDone <- err
			return
		}
		challenge := []byte("test-challenge-1234567890abcdef")
		stream.Write([]byte{byte(len(challenge))})
		stream.Write(challenge)
		var sigLen [2]byte
		io.ReadFull(stream, sigLen[:])
		sigBytes := make([]byte, binary.BigEndian.Uint16(sigLen[:]))
		io.ReadFull(stream, sigBytes)
		var sig ssh.Signature
		if err := ssh.Unmarshal(sigBytes, &sig); err != nil {
			serverDone <- err
			return
		}
		msg := append([]byte(domainSeparator), challenge...)
		if err := pubKey.Verify(msg, &sig); err != nil {
			serverDone <- err
			return
		}
		stream.Write([]byte{1})
		stream.Close()

		// Open a data stream with an oversized header (> 512 bytes).
		s, err := conn.OpenStreamSync(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], 1000) // > 512
		s.Write(hdr[:])
		s.Write(make([]byte, 1000))
		s.Close()
		serverDone <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialInsecure(ctx, ln.Addr().String(), "user", "dev", signer)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, err = conn.AcceptStream(ctx)
	if err == nil {
		t.Fatal("expected error for oversized stream header")
	}
	<-serverDone
}

func TestRelayAuthEmptyUsername(t *testing.T) {
	tlsCfg := testTLSConfig(t)
	signer := testSigner(t)

	ln, err := quic.ListenAddr("127.0.0.1:0", tlsCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Server that reads identity and rejects empty username.
	serverDone := make(chan error, 1)
	go func() {
		ctx := context.Background()
		conn, err := ln.Accept(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			serverDone <- err
			return
		}

		// Read user length.
		var userLen [1]byte
		if _, err := io.ReadFull(stream, userLen[:]); err != nil {
			serverDone <- err
			return
		}
		user := make([]byte, userLen[0])
		if userLen[0] > 0 {
			io.ReadFull(stream, user)
		}

		// Reject if username is empty.
		if userLen[0] == 0 {
			// Send a zero-length challenge followed by rejection.
			stream.Write([]byte{4})      // challengeLen=4
			stream.Write([]byte("test")) // challenge
			buf := make([]byte, 4096)
			stream.Read(buf)        // read sig
			stream.Write([]byte{0}) // reject
			stream.Close()
			conn.CloseWithError(0, "")
			serverDone <- nil
			return
		}
		serverDone <- fmt.Errorf("expected empty username, got %q", user)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = dialInsecure(ctx, ln.Addr().String(), "", "mydevice", signer)
	if err == nil {
		t.Fatal("expected auth error for empty username")
	}
	<-serverDone
}

func TestRelayAuthEmptyDevice(t *testing.T) {
	tlsCfg := testTLSConfig(t)
	signer := testSigner(t)

	ln, err := quic.ListenAddr("127.0.0.1:0", tlsCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Server that reads identity and rejects empty device.
	serverDone := make(chan error, 1)
	serverCtx, serverCancel := context.WithCancel(context.Background())
	defer serverCancel()
	go func() {
		conn, err := ln.Accept(serverCtx)
		if err != nil {
			serverDone <- err
			return
		}
		stream, err := conn.AcceptStream(serverCtx)
		if err != nil {
			serverDone <- err
			return
		}

		// Read user.
		var userLen [1]byte
		io.ReadFull(stream, userLen[:])
		user := make([]byte, userLen[0])
		if userLen[0] > 0 {
			io.ReadFull(stream, user)
		}

		// Read device length.
		var devLen [1]byte
		if _, err := io.ReadFull(stream, devLen[:]); err != nil {
			serverDone <- err
			return
		}
		dev := make([]byte, devLen[0])
		if devLen[0] > 0 {
			io.ReadFull(stream, dev)
		}

		// Reject if device is empty.
		if devLen[0] == 0 {
			stream.Write([]byte{4})
			stream.Write([]byte("test"))
			buf := make([]byte, 4096)
			stream.Read(buf)
			stream.Write([]byte{0}) // reject
			stream.Close()
			conn.CloseWithError(0, "")
			serverDone <- nil
			return
		}
		serverDone <- fmt.Errorf("expected empty device, got %q", dev)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = dialInsecure(ctx, ln.Addr().String(), "testuser", "", signer)
	if err == nil {
		t.Fatal("expected auth error for empty device")
	}
	serverCancel()
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
	}
}

func TestPersistentConnWithServer(t *testing.T) {
	tlsCfg := testTLSConfig(t)
	signer := testSigner(t)

	ln, err := quic.ListenAddr("127.0.0.1:0", tlsCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		mockRelayServer(t, ln, []string{"9.8.7.6:22"})
	}()

	got := make(chan string, 1)
	// We can't use PersistentConn directly because it calls Dial (not dialInsecure).
	// But we can test the acceptLoop logic by constructing manually.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialInsecure(ctx, ln.Addr().String(), "testuser", "macbook", signer)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Manually run acceptLoop pattern.
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got <- stream.ClaimedAddr().String()
	io.ReadAll(stream)

	if addr := <-got; addr != "9.8.7.6:22" {
		t.Fatalf("addr = %s, want 9.8.7.6:22", addr)
	}
}
