package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unixshells/latch/internal/config"
	"github.com/unixshells/latch/pkg/proto"
	"github.com/unixshells/latch/pkg/transport"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/websocket"
)

func TestWebBridgeEncodeProto(t *testing.T) {
	msg, err := proto.MarshalMsg(0x01, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	if len(msg) != 7 {
		t.Fatalf("len = %d, want 7", len(msg))
	}
	if msg[0] != 0x01 {
		t.Fatalf("type = %x", msg[0])
	}
	if msg[1] != 0 || msg[2] != 4 {
		t.Fatalf("length = %x %x", msg[1], msg[2])
	}
	if string(msg[3:]) != "test" {
		t.Fatalf("payload = %q", msg[3:])
	}
}

func TestWebBridgeEncodeEmpty(t *testing.T) {
	msg, err := proto.MarshalMsg(proto.MsgDetach, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg) != 3 {
		t.Fatalf("len = %d, want 3", len(msg))
	}
	if msg[0] != proto.MsgDetach {
		t.Fatalf("type = %x, want %x", msg[0], proto.MsgDetach)
	}
	if binary.BigEndian.Uint16(msg[1:3]) != 0 {
		t.Fatal("expected zero length")
	}
}

func TestWebBridgeEncodeLargePayload(t *testing.T) {
	payload := make([]byte, 1000)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	msg, err := proto.MarshalMsg(proto.MsgOutput, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg) != 3+1000 {
		t.Fatalf("len = %d, want 1003", len(msg))
	}
	if msg[0] != proto.MsgOutput {
		t.Fatalf("type = %x", msg[0])
	}
	n := binary.BigEndian.Uint16(msg[1:3])
	if n != 1000 {
		t.Fatalf("length = %d, want 1000", n)
	}
	for i := 0; i < 1000; i++ {
		if msg[3+i] != byte(i%256) {
			t.Fatalf("payload[%d] = %d, want %d", i, msg[3+i], i%256)
			break
		}
	}
}

func TestSSHBridgeWriteOutput(t *testing.T) {
	r, w := newTestPipe()
	bridge := &sshBridge{ch: &fakeChannel{w: w}}

	payload := []byte("hello terminal")
	msg, err := proto.MarshalMsg(proto.MsgOutput, payload)
	if err != nil {
		t.Fatal(err)
	}
	n, err := bridge.Write(msg)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(msg) {
		t.Fatalf("n = %d, want %d", n, len(msg))
	}

	buf := make([]byte, 100)
	nn, _ := r.Read(buf)
	if string(buf[:nn]) != "hello terminal" {
		t.Fatalf("got %q, want %q", buf[:nn], "hello terminal")
	}
}

func TestSSHBridgeWriteNonOutput(t *testing.T) {
	bridge := &sshBridge{ch: &fakeChannel{w: discardWriter{}}}

	msg, err := proto.MarshalMsg(proto.MsgDetached, nil)
	if err != nil {
		t.Fatal(err)
	}
	n, err := bridge.Write(msg)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(msg) {
		t.Fatalf("n = %d, want %d", n, len(msg))
	}
}

func TestEncodeProtoMsgRoundTrip(t *testing.T) {
	msg, err := proto.MarshalMsg(proto.MsgOutput, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	if msg[0] != proto.MsgOutput {
		t.Fatal("wrong type")
	}
	n := binary.BigEndian.Uint16(msg[1:3])
	if string(msg[3:3+n]) != "data" {
		t.Fatalf("payload = %q", msg[3:3+n])
	}
}

func TestMarshalMsgTooLarge(t *testing.T) {
	payload := make([]byte, 65*1024)
	_, err := proto.MarshalMsg(proto.MsgOutput, payload)
	if err == nil {
		t.Fatal("expected error for oversized payload")
	}
}

func TestSSHBridgeReadFromBuf(t *testing.T) {
	// Pre-buffer a new-session message; Read should return it.
	buf, _ := proto.MarshalMsg(proto.MsgNewSession, []byte("test"))
	bridge := &sshBridge{
		ch:      &fakeChannel{w: discardWriter{}},
		readBuf: buf,
	}

	p := make([]byte, 256)
	n, err := bridge.Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(buf) {
		t.Fatalf("read %d bytes, want %d", n, len(buf))
	}

	// Decode what we read
	typ, payload, err := proto.Decode(bytes.NewReader(p[:n]))
	if err != nil {
		t.Fatal(err)
	}
	if typ != proto.MsgNewSession {
		t.Fatalf("type = %x, want MsgNewSession", typ)
	}
	if string(payload) != "test" {
		t.Fatalf("payload = %q, want %q", payload, "test")
	}
}

func TestSSHBridgeHandlePTYReq(t *testing.T) {
	bridge := &sshBridge{}

	// Build a valid pty-req payload: string term, uint32 cols, uint32 rows
	payload := make([]byte, 0, 50)
	payload = append(payload, 0, 0, 0, 5)             // string length
	payload = append(payload, "xterm"...)             // terminal type
	payload = append(payload, 0, 0, 0, 132, 0, 0, 0, 43, 0, 0, 0, 0, 0, 0, 0, 0) // cols, rows, pixel w/h

	// WantReply=false to avoid calling into the SSH mux.
	bridge.handlePTYReq(&ssh.Request{
		Type:    "pty-req",
		Payload: payload,
	})

	if bridge.cols != 132 {
		t.Fatalf("cols = %d, want 132", bridge.cols)
	}
	if bridge.rows != 43 {
		t.Fatalf("rows = %d, want 43", bridge.rows)
	}
}

func TestSSHBridgeHandlePTYReqZero(t *testing.T) {
	bridge := &sshBridge{}

	payload := make([]byte, 0, 50)
	payload = append(payload, 0, 0, 0, 2) // "sh"
	payload = append(payload, "sh"...)
	payload = append(payload, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) // cols=0, rows=0, pixel w/h

	bridge.handlePTYReq(&ssh.Request{
		Type:    "pty-req",
		Payload: payload,
	})

	if bridge.cols != 80 {
		t.Fatalf("cols = %d, want 80 (default)", bridge.cols)
	}
	if bridge.rows != 24 {
		t.Fatalf("rows = %d, want 24 (default)", bridge.rows)
	}
}

func TestSSHBridgeHandlePTYReqInvalid(t *testing.T) {
	bridge := &sshBridge{}

	// Too-short payload; WantReply=false to avoid mux panic
	bridge.handlePTYReq(&ssh.Request{
		Type:    "pty-req",
		Payload: []byte{0, 0},
	})

	if bridge.cols != 0 {
		t.Fatalf("cols = %d, want 0 (no change)", bridge.cols)
	}
}

func TestCheckOriginEmpty(t *testing.T) {
	req := &http.Request{Host: "example.com:7680", Header: http.Header{}}
	if err := checkOrigin(nil, req); err == nil {
		t.Fatal("empty origin should be rejected")
	}
}

func TestCheckOriginLocalhost(t *testing.T) {
	tests := []string{
		"https://localhost:8080",
		"https://127.0.0.1:9999",
		"https://[::1]:7680",
	}
	for _, origin := range tests {
		req := &http.Request{
			Host:   "example.com:7680",
			Header: http.Header{"Origin": {origin}},
		}
		if err := checkOrigin(nil, req); err != nil {
			t.Fatalf("localhost origin %q should be allowed: %v", origin, err)
		}
	}
}

func TestCheckOriginSameHost(t *testing.T) {
	req := &http.Request{
		Host:   "example.com:7680",
		Header: http.Header{"Origin": {"https://example.com:7680"}},
	}
	if err := checkOrigin(nil, req); err != nil {
		t.Fatalf("same host:port should be allowed: %v", err)
	}
}

func TestCheckOriginDifferentPort(t *testing.T) {
	req := &http.Request{
		Host:   "example.com:7680",
		Header: http.Header{"Origin": {"https://example.com:8080"}},
	}
	if err := checkOrigin(nil, req); err == nil {
		t.Fatal("different port should be rejected")
	}
}

func TestCheckOriginDifferentHost(t *testing.T) {
	req := &http.Request{
		Host:   "example.com:7680",
		Header: http.Header{"Origin": {"https://evil.com:7680"}},
	}
	if err := checkOrigin(nil, req); err == nil {
		t.Fatal("different host should be rejected")
	}
}

// Test helpers

type fakeChannel struct {
	w interface{ Write([]byte) (int, error) }
}

func (f *fakeChannel) Read(data []byte) (int, error)  { return 0, nil }
func (f *fakeChannel) Write(data []byte) (int, error) { return f.w.Write(data) }
func (f *fakeChannel) Close() error                   { return nil }
func (f *fakeChannel) CloseWrite() error              { return nil }
func (f *fakeChannel) SendRequest(string, bool, []byte) (bool, error) {
	return false, nil
}
func (f *fakeChannel) Stderr() io.ReadWriter {
	return &nopReadWriter{f.w}
}

type nopReadWriter struct {
	w interface{ Write([]byte) (int, error) }
}

func (n *nopReadWriter) Read(p []byte) (int, error)  { return 0, io.EOF }
func (n *nopReadWriter) Write(p []byte) (int, error) { return n.w.Write(p) }

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func newTestPipe() (*pipeReader, *pipeWriter) {
	ch := make(chan []byte, 10)
	return &pipeReader{ch: ch}, &pipeWriter{ch: ch}
}

type pipeReader struct{ ch chan []byte }
type pipeWriter struct{ ch chan []byte }

func (r *pipeReader) Read(p []byte) (int, error) {
	data := <-r.ch
	n := copy(p, data)
	return n, nil
}

func (w *pipeWriter) Write(p []byte) (int, error) {
	buf := make([]byte, len(p))
	copy(buf, p)
	w.ch <- buf
	return len(p), nil
}

// testWebServer sets up a server with web enabled and an authorized_keys file
// containing the given public key. Returns the server and the wss:// address.
func testWebServer(t *testing.T, pubKey ssh.PublicKey) (*Server, string) {
	t.Helper()

	dir, err := os.MkdirTemp("", "latch-web-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	// Set HOME so transport.AuthorizedKeysPath() resolves to our temp dir.
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", dir)
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })

	// Write authorized_keys with the test public key.
	latchDir := filepath.Join(dir, ".latch")
	if err := os.MkdirAll(latchDir, 0700); err != nil {
		t.Fatal(err)
	}
	akPath := filepath.Join(latchDir, "authorized_keys")
	akLine := string(ssh.MarshalAuthorizedKey(pubKey))
	if err := os.WriteFile(akPath, []byte(akLine), 0600); err != nil {
		t.Fatal(err)
	}

	// Generate TLS cert in temp dir.
	certPath := filepath.Join(latchDir, "tls.crt")
	keyPath := filepath.Join(latchDir, "tls.key")
	if _, err := transport.LoadOrGenerateTLS(certPath, keyPath); err != nil {
		t.Fatal(err)
	}

	sock := filepath.Join(dir, "sock")
	s := &Server{
		sockPath: sock,
		cfg:      config.Default(),
		limiter:  newConnLimiter(10),
		tracker:  newConnTracker(),
		access:   newAccessState(),
		connMeta: make(map[net.Conn]*ConnInfo),
	}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve() }()

	if err := s.ListenWeb(":0", certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	s.mu.Lock()
	addr := s.webAddr
	s.mu.Unlock()

	return s, addr
}

// wsConnect dials a WebSocket to the given address with TLS verification disabled.
func wsConnect(t *testing.T, addr, path string) *websocket.Conn {
	t.Helper()
	origin := "https://localhost"
	wsURL := fmt.Sprintf("wss://%s%s", addr, path)
	wsCfg, err := websocket.NewConfig(wsURL, origin)
	if err != nil {
		t.Fatal(err)
	}
	wsCfg.TlsConfig = &tls.Config{InsecureSkipVerify: true}

	conn, err := websocket.DialConfig(wsCfg)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// doWebAuth performs the Ed25519 challenge-response handshake.
// Returns the single-byte auth result.
func doWebAuth(t *testing.T, ws *websocket.Conn, signer ssh.Signer) byte {
	t.Helper()

	// Read the challenge: [0x01][32-byte challenge]
	var challengeMsg []byte
	if err := websocket.Message.Receive(ws, &challengeMsg); err != nil {
		t.Fatalf("receive challenge: %v", err)
	}
	if len(challengeMsg) != 33 || challengeMsg[0] != 0x01 {
		t.Fatalf("bad challenge message: len=%d first=%x", len(challengeMsg), challengeMsg[0])
	}
	challenge := challengeMsg[1:]

	// Sign with domain separator.
	signData := append([]byte("latch-web-auth-v1:"), challenge...)
	sig, err := signer.Sign(rand.Reader, signData)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Build response: [pubkey-len:4][pubkey][sig-len:4][sig]
	pubBytes := signer.PublicKey().Marshal()
	resp := make([]byte, 4+len(pubBytes)+4+len(sig.Blob))
	binary.BigEndian.PutUint32(resp[0:4], uint32(len(pubBytes)))
	copy(resp[4:], pubBytes)
	off := 4 + len(pubBytes)
	binary.BigEndian.PutUint32(resp[off:off+4], uint32(len(sig.Blob)))
	copy(resp[off+4:], sig.Blob)

	if _, err := ws.Write(resp); err != nil {
		t.Fatalf("send auth response: %v", err)
	}

	// Read auth result.
	var result []byte
	if err := websocket.Message.Receive(ws, &result); err != nil {
		t.Fatalf("receive auth result: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("auth result len=%d, want 1", len(result))
	}
	return result[0]
}

func TestWebSocketAuthSuccess(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	_, addr := testWebServer(t, sshPub)
	ws := wsConnect(t, addr, "/ws")
	defer ws.Close()

	result := doWebAuth(t, ws, sshSigner)
	if result != 0x00 {
		t.Fatalf("auth result = %x, want 0x00 (success)", result)
	}
}

func TestWebSocketAuthWrongKey(t *testing.T) {
	// Authorized key.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	// Wrong key (not in authorized_keys).
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongSigner, err := ssh.NewSignerFromKey(wrongPriv)
	if err != nil {
		t.Fatal(err)
	}

	_, addr := testWebServer(t, sshPub)
	ws := wsConnect(t, addr, "/ws")
	defer ws.Close()

	result := doWebAuth(t, ws, wrongSigner)
	if result != 0x02 {
		t.Fatalf("auth result = %x, want 0x02 (failure)", result)
	}
}

func TestWebSocketAuthNoKeys(t *testing.T) {
	dir := t.TempDir()

	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", dir)
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })

	// Create .latch dir but no authorized_keys file.
	latchDir := filepath.Join(dir, ".latch")
	if err := os.MkdirAll(latchDir, 0700); err != nil {
		t.Fatal(err)
	}

	certPath := filepath.Join(latchDir, "tls.crt")
	keyPath := filepath.Join(latchDir, "tls.key")
	if _, err := transport.LoadOrGenerateTLS(certPath, keyPath); err != nil {
		t.Fatal(err)
	}

	sock := filepath.Join(dir, "sock")
	s := &Server{
		sockPath: sock,
		cfg:      config.Default(),
		limiter:  newConnLimiter(10),
		tracker:  newConnTracker(),
		access:   newAccessState(),
		connMeta: make(map[net.Conn]*ConnInfo),
	}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	go s.Serve()
	if err := s.ListenWeb(":0", certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	s.mu.Lock()
	addr := s.webAddr
	s.mu.Unlock()

	ws := wsConnect(t, addr, "/ws")
	defer ws.Close()

	// Server should send 0x03 (no keys configured) and close.
	var msg []byte
	if err := websocket.Message.Receive(ws, &msg); err != nil {
		t.Fatalf("receive: %v", err)
	}
	if len(msg) != 1 || msg[0] != 0x03 {
		t.Fatalf("expected 0x03 (no keys), got %x", msg)
	}
}

func TestWebSocketAuthReplayChallenge(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	_, addr := testWebServer(t, sshPub)

	// First connection: capture the challenge.
	ws1 := wsConnect(t, addr, "/ws")
	defer ws1.Close()

	var challengeMsg1 []byte
	if err := websocket.Message.Receive(ws1, &challengeMsg1); err != nil {
		t.Fatalf("receive challenge1: %v", err)
	}
	if len(challengeMsg1) != 33 || challengeMsg1[0] != 0x01 {
		t.Fatalf("bad challenge1: len=%d", len(challengeMsg1))
	}
	challenge1 := challengeMsg1[1:]

	// Second connection: get its own challenge, but try to sign challenge1 instead.
	ws2 := wsConnect(t, addr, "/ws")
	defer ws2.Close()

	var challengeMsg2 []byte
	if err := websocket.Message.Receive(ws2, &challengeMsg2); err != nil {
		t.Fatalf("receive challenge2: %v", err)
	}
	if len(challengeMsg2) != 33 || challengeMsg2[0] != 0x01 {
		t.Fatalf("bad challenge2: len=%d", len(challengeMsg2))
	}
	challenge2 := challengeMsg2[1:]

	// Challenges must be unique (with overwhelming probability for 32 random bytes).
	if bytes.Equal(challenge1, challenge2) {
		t.Fatal("challenges should be unique per connection")
	}

	// Sign challenge1 (from first connection) and send it on ws2.
	signData := append([]byte("latch-web-auth-v1:"), challenge1...)
	sig, err := sshSigner.Sign(rand.Reader, signData)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes := sshSigner.PublicKey().Marshal()
	resp := make([]byte, 4+len(pubBytes)+4+len(sig.Blob))
	binary.BigEndian.PutUint32(resp[0:4], uint32(len(pubBytes)))
	copy(resp[4:], pubBytes)
	off := 4 + len(pubBytes)
	binary.BigEndian.PutUint32(resp[off:off+4], uint32(len(sig.Blob)))
	copy(resp[off+4:], sig.Blob)

	if _, err := ws2.Write(resp); err != nil {
		t.Fatalf("send replayed auth: %v", err)
	}

	var result []byte
	if err := websocket.Message.Receive(ws2, &result); err != nil {
		t.Fatalf("receive result: %v", err)
	}
	if len(result) != 1 || result[0] != 0x02 {
		t.Fatalf("replayed challenge should be rejected, got %x", result)
	}
}

func TestWebSocketAuthEmptySignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	_, addr := testWebServer(t, sshPub)
	ws := wsConnect(t, addr, "/ws")
	defer ws.Close()

	var challengeMsg []byte
	if err := websocket.Message.Receive(ws, &challengeMsg); err != nil {
		t.Fatalf("receive challenge: %v", err)
	}

	// Send response with valid pubkey but 0-length signature.
	pubBytes := sshPub.Marshal()
	resp := make([]byte, 4+len(pubBytes)+4) // sigLen=0
	binary.BigEndian.PutUint32(resp[0:4], uint32(len(pubBytes)))
	copy(resp[4:], pubBytes)
	binary.BigEndian.PutUint32(resp[4+len(pubBytes):], 0) // sig length = 0

	if _, err := ws.Write(resp); err != nil {
		t.Fatalf("send: %v", err)
	}

	var result []byte
	if err := websocket.Message.Receive(ws, &result); err != nil {
		t.Fatalf("receive: %v", err)
	}
	if len(result) != 1 || result[0] != 0x02 {
		t.Fatalf("empty signature should be rejected, got %x", result)
	}
}

func TestWebSocketAuthOversizedPayload(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	_, addr := testWebServer(t, sshPub)
	ws := wsConnect(t, addr, "/ws")
	defer ws.Close()

	var challengeMsg []byte
	if err := websocket.Message.Receive(ws, &challengeMsg); err != nil {
		t.Fatalf("receive challenge: %v", err)
	}

	// Send response with pubkey-len claiming 1MB. The WebSocket MaxPayloadBytes
	// is 2048, so the server should reject this before allocating 1MB.
	resp := make([]byte, 8)
	binary.BigEndian.PutUint32(resp[0:4], 1024*1024) // 1MB pubkey length
	// rest is zeros

	if _, err := ws.Write(resp); err != nil {
		t.Fatalf("send: %v", err)
	}

	// The server should reject (pubkey length exceeds message size).
	var result []byte
	if err := websocket.Message.Receive(ws, &result); err != nil {
		// Connection closed is also acceptable - no OOM.
		return
	}
	if len(result) == 1 && result[0] == 0x02 {
		return // rejection, correct
	}
	t.Fatalf("expected rejection or close, got %x", result)
}

func TestWebSocketAuthWrongDomain(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	_, addr := testWebServer(t, sshPub)
	ws := wsConnect(t, addr, "/ws")
	defer ws.Close()

	var challengeMsg []byte
	if err := websocket.Message.Receive(ws, &challengeMsg); err != nil {
		t.Fatalf("receive challenge: %v", err)
	}
	challenge := challengeMsg[1:]

	// Sign WITHOUT the domain separator (just the raw challenge).
	sig, err := sshSigner.Sign(rand.Reader, challenge)
	if err != nil {
		t.Fatal(err)
	}

	pubBytes := sshSigner.PublicKey().Marshal()
	resp := make([]byte, 4+len(pubBytes)+4+len(sig.Blob))
	binary.BigEndian.PutUint32(resp[0:4], uint32(len(pubBytes)))
	copy(resp[4:], pubBytes)
	off := 4 + len(pubBytes)
	binary.BigEndian.PutUint32(resp[off:off+4], uint32(len(sig.Blob)))
	copy(resp[off+4:], sig.Blob)

	if _, err := ws.Write(resp); err != nil {
		t.Fatalf("send: %v", err)
	}

	var result []byte
	if err := websocket.Message.Receive(ws, &result); err != nil {
		t.Fatalf("receive: %v", err)
	}
	if len(result) != 1 || result[0] != 0x02 {
		t.Fatalf("wrong domain separator should be rejected, got %x", result)
	}
}

func TestWebSocketInputOutput(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	_, addr := testWebServer(t, sshPub)
	ws := wsConnect(t, addr, "/ws")
	defer ws.Close()

	result := doWebAuth(t, ws, sshSigner)
	if result != 0x00 {
		t.Fatalf("auth result = %x, want 0x00", result)
	}

	// After auth, server creates a session and starts sending terminal output.
	// Send a resize so the server knows our terminal size.
	resizeMsg := make([]byte, 5)
	resizeMsg[0] = proto.MsgResize
	binary.BigEndian.PutUint16(resizeMsg[1:3], 80)
	binary.BigEndian.PutUint16(resizeMsg[3:5], 24)
	if _, err := ws.Write(resizeMsg); err != nil {
		t.Fatalf("send resize: %v", err)
	}

	// Send a command that produces known output. The wsBridge wraps raw bytes
	// as MsgInput, which the server writes to the PTY. We send "echo hi\n".
	if _, err := ws.Write([]byte("echo hi\n")); err != nil {
		t.Fatalf("send input: %v", err)
	}

	// Read output until we see "hi" echoed back. The server sends raw terminal
	// output (wsBridge.Write strips the proto header for MsgOutput).
	deadline := time.Now().Add(5 * time.Second)
	var collected []byte
	for time.Now().Before(deadline) {
		_ = ws.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		var data []byte
		if err := websocket.Message.Receive(ws, &data); err != nil {
			continue
		}
		collected = append(collected, data...)
		if strings.Contains(string(collected), "hi") {
			return // success
		}
	}
	t.Fatalf("did not receive expected output containing 'hi'; got %d bytes: %q",
		len(collected), collected)
}

func TestWebSocketAuthModifiedChallenge(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	_, addr := testWebServer(t, sshPub)
	ws := wsConnect(t, addr, "/ws")
	defer ws.Close()

	// Read the challenge.
	var challengeMsg []byte
	if err := websocket.Message.Receive(ws, &challengeMsg); err != nil {
		t.Fatalf("receive challenge: %v", err)
	}
	if len(challengeMsg) != 33 || challengeMsg[0] != 0x01 {
		t.Fatalf("bad challenge message: len=%d first=%x", len(challengeMsg), challengeMsg[0])
	}
	challenge := challengeMsg[1:]

	// Sign the original challenge correctly (with domain separator).
	signData := append([]byte("latch-web-auth-v1:"), challenge...)
	sig, err := sshSigner.Sign(rand.Reader, signData)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Flip one bit in the challenge AFTER signing.
	challenge[0] ^= 0x01

	// Build response using the modified challenge's public key but the
	// signature from the original challenge. The server will reconstruct
	// signData using its stored (original) challenge, but since we modified
	// the challenge byte in our local copy, the server still has the original.
	// Actually, the server uses its own stored challenge - so the signature
	// was made over the original challenge. But we need the server to fail.
	// The trick: sign the MODIFIED challenge, so the signature won't match
	// the server's original challenge.
	modifiedSignData := append([]byte("latch-web-auth-v1:"), challenge...)
	modifiedSig, err := sshSigner.Sign(rand.Reader, modifiedSignData)
	if err != nil {
		t.Fatalf("sign modified: %v", err)
	}
	_ = sig // unused, we use modifiedSig

	pubBytes := sshSigner.PublicKey().Marshal()
	resp := make([]byte, 4+len(pubBytes)+4+len(modifiedSig.Blob))
	binary.BigEndian.PutUint32(resp[0:4], uint32(len(pubBytes)))
	copy(resp[4:], pubBytes)
	off := 4 + len(pubBytes)
	binary.BigEndian.PutUint32(resp[off:off+4], uint32(len(modifiedSig.Blob)))
	copy(resp[off+4:], modifiedSig.Blob)

	if _, err := ws.Write(resp); err != nil {
		t.Fatalf("send auth response: %v", err)
	}

	// Read auth result - should be failure (0x02) because the signature
	// was computed over a different challenge than what the server sent.
	var result []byte
	if err := websocket.Message.Receive(ws, &result); err != nil {
		t.Fatalf("receive auth result: %v", err)
	}
	if len(result) != 1 || result[0] != 0x02 {
		t.Fatalf("modified challenge should be rejected, got %x", result)
	}
}
