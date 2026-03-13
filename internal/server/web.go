package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/unixshells/latch/internal/mux"
	"github.com/unixshells/latch/internal/web"
	"github.com/unixshells/latch/pkg/proto"
	"github.com/unixshells/latch/pkg/transport"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/websocket"
)

// ListenWeb starts an HTTPS+WSS server for browser access.
// Auto-generates a self-signed TLS certificate if none exists.
// Set certPath/keyPath to empty strings to use defaults (~/.latch/tls.{crt,key}).
func (s *Server) ListenWeb(addr, certPath, keyPath string) error {
	if certPath == "" || keyPath == "" {
		certPath, keyPath = transport.TLSPaths()
	}

	cert, err := transport.LoadOrGenerateTLS(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}

	static, err := fs.Sub(web.Static, "static")
	if err != nil {
		return fmt.Errorf("static fs: %w", err)
	}

	wsMux := http.NewServeMux()
	fileServer := http.FileServer(http.FS(static))
	wsMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' wss:")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		fileServer.ServeHTTP(w, r)
	})
	wsMux.Handle("/ws", &websocket.Server{
		Handler:   s.handleWS,
		Handshake: checkOrigin,
	})

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	ln, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("web listen: %w", err)
	}
	s.webLn = ln
	s.mu.Lock()
	s.webAddr = ln.Addr().String()
	s.mu.Unlock()

	fp := ""
	if len(cert.Certificate) > 0 {
		sum := sha256.Sum256(cert.Certificate[0])
		fp = " (cert: SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]) + ")"
	}
	fmt.Fprintf(os.Stderr, "latch web listening on https://%s%s\n", addr, fp)
	go func() {
		if err := http.Serve(ln, wsMux); err != nil && !errors.Is(err, net.ErrClosed) {
			fmt.Fprintf(os.Stderr, "web server: %v\n", err)
		}
	}()
	return nil
}

func (s *Server) handleWS(ws *websocket.Conn) {
	ws.PayloadType = websocket.BinaryFrame
	ws.MaxPayloadBytes = 2048
	defer ws.Close()

	if !s.access.Web() {
		return
	}

	addr, _ := net.ResolveTCPAddr("tcp", ws.Request().RemoteAddr)
	if addr == nil {
		addr = &net.TCPAddr{}
	}
	ip := extractIP(addr)
	if !s.limiter.acquire(ip) {
		return
	}
	defer s.limiter.release(ip)

	if err := s.webAuth(ws); err != nil {
		return
	}

	session := ws.Request().URL.Query().Get("session")
	if session == "" || mux.ValidateSessionName(session) != nil {
		session = "default"
	}

	bridge := &wsBridge{ws: ws}
	buf, err := proto.MarshalMsg(proto.MsgNewSession, []byte(session))
	if err != nil {
		return
	}
	bridge.readBuf = buf

	s.setConnMeta(bridge, &ConnInfo{
		Source:     "web",
		RemoteAddr: ws.Request().RemoteAddr,
	})
	s.handle(bridge)
}

// webAuth performs Ed25519 challenge-response authentication over WebSocket.
// Rejects all connections if no authorized_keys file exists (sends 0x03 so
// the browser shows the key setup UI).
// Protocol: server sends [0x01][32-byte challenge], client responds
// [pubkey-len:4][pubkey][sig-len:4][sig]. Server verifies signature against
// each authorized key (no key-check oracle — failure is indistinguishable).
func (s *Server) webAuth(ws *websocket.Conn) error {
	authKeys, err := transport.LoadAuthorizedKeys(transport.AuthorizedKeysPath())
	if err != nil {
		return err
	}
	if len(authKeys) == 0 {
		if _, err := ws.Write([]byte{0x03}); err != nil {
			return err
		}
		return fmt.Errorf("auth: no authorized_keys — add a key to connect")
	}

	// Generate 32-byte challenge.
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}

	// Send: [0x01][32-byte challenge]
	msg := make([]byte, 33)
	msg[0] = 0x01
	copy(msg[1:], challenge)
	if _, err := ws.Write(msg); err != nil {
		return err
	}

	// Receive response with a 30-second deadline.
	// MaxPayloadBytes on the connection enforces the size limit.
	ws.SetReadDeadline(time.Now().Add(30 * time.Second))
	var resp []byte
	if err := websocket.Message.Receive(ws, &resp); err != nil {
		return err
	}
	ws.SetReadDeadline(time.Time{}) // clear deadline
	if len(resp) < 8 {
		ws.Write([]byte{0x02}) // best-effort
		return fmt.Errorf("auth: response too short")
	}

	pkLen := int(binary.BigEndian.Uint32(resp[0:4]))
	if 4+pkLen+4 > len(resp) {
		ws.Write([]byte{0x02}) // best-effort
		return fmt.Errorf("auth: bad pubkey length")
	}
	pkBytes := resp[4 : 4+pkLen]

	sigOff := 4 + pkLen
	sigLen := int(binary.BigEndian.Uint32(resp[sigOff : sigOff+4]))
	if sigOff+4+sigLen > len(resp) {
		ws.Write([]byte{0x02}) // best-effort
		return fmt.Errorf("auth: bad sig length")
	}
	sigBytes := resp[sigOff+4 : sigOff+4+sigLen]

	// Parse the client's public key — must be Ed25519.
	clientKey, err := ssh.ParsePublicKey(pkBytes)
	if err != nil {
		ws.Write([]byte{0x02}) // best-effort
		return fmt.Errorf("auth: failed")
	}
	if clientKey.Type() != "ssh-ed25519" {
		ws.Write([]byte{0x02}) // best-effort
		return fmt.Errorf("auth: failed")
	}

	// Verify signature against each authorized key. No separate "is key
	// authorized" check — prevents key-enumeration oracle. Constant-time
	// comparison of key bytes prevents timing side-channel.
	// Domain separator prevents cross-protocol signature reuse.
	sig := &ssh.Signature{
		Format: "ssh-ed25519",
		Blob:   sigBytes,
	}
	signData := append([]byte("latch-web-auth-v1:"), challenge...)
	clientKeyBytes := clientKey.Marshal()
	for _, ak := range authKeys {
		if subtle.ConstantTimeCompare(ak.Key.Marshal(), clientKeyBytes) == 1 {
			if err := ak.Key.Verify(signData, sig); err == nil {
				if _, err := ws.Write([]byte{0x00}); err != nil {
					return err
				}
				return nil
			}
		}
	}

	ws.Write([]byte{0x02}) // best-effort
	return fmt.Errorf("auth: failed")
}

// wsBridge adapts a WebSocket to a net.Conn-like interface.
type wsBridge struct {
	ws      *websocket.Conn
	readBuf []byte
	mu      sync.Mutex
}

func (b *wsBridge) Read(p []byte) (int, error) {
	for len(b.readBuf) == 0 {
		var data []byte
		if err := websocket.Message.Receive(b.ws, &data); err != nil {
			return 0, err
		}
		if len(data) == 0 {
			continue
		}

		var buf []byte
		var err error

		if len(data) >= 1 {
			switch data[0] {
			case proto.MsgResize:
				if len(data) == 5 {
					cols := binary.BigEndian.Uint16(data[1:3])
					rows := binary.BigEndian.Uint16(data[3:5])
					buf, err = proto.MarshalMsg(proto.MsgResize, proto.EncodeResize(cols, rows))
					if err == nil {
						b.readBuf = buf
						continue
					}
				}
			case proto.MsgPaste:
				if len(data) > 1 {
					buf, err = proto.MarshalMsg(proto.MsgPaste, data[1:])
					if err == nil {
						b.readBuf = buf
						continue
					}
				}
			}
		}

		buf, err = proto.MarshalMsg(proto.MsgInput, data)
		if err != nil {
			return 0, err
		}
		b.readBuf = buf
	}

	n := copy(p, b.readBuf)
	b.readBuf = b.readBuf[n:]
	return n, nil
}

func (b *wsBridge) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	total := len(p)
	if len(p) >= 3 {
		typ := p[0]
		msgLen := int(binary.BigEndian.Uint16(p[1:3]))
		if 3+msgLen <= len(p) && typ == proto.MsgOutput {
			payload := p[3 : 3+msgLen]
			if _, err := b.ws.Write(payload); err != nil {
				return 0, err
			}
		}
	}
	return total, nil
}

func (b *wsBridge) Close() error {
	return b.ws.Close()
}

func (b *wsBridge) RemoteAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", b.ws.Request().RemoteAddr)
	if addr == nil {
		return &net.TCPAddr{}
	}
	return addr
}

func (b *wsBridge) LocalAddr() net.Addr                { return nil }
func (b *wsBridge) SetDeadline(t time.Time) error      { return nil }
func (b *wsBridge) SetReadDeadline(t time.Time) error  { return nil }
func (b *wsBridge) SetWriteDeadline(t time.Time) error { return nil }

var _ net.Conn = (*wsBridge)(nil)

// checkOrigin validates the WebSocket Origin header.
// Browsers always send Origin for WebSocket — require it to prevent
// non-browser CSRF bypass.
func checkOrigin(config *websocket.Config, req *http.Request) error {
	origin := req.Header.Get("Origin")
	if origin == "" {
		return fmt.Errorf("missing origin header")
	}
	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("invalid origin")
	}
	originHost := u.Host
	originHostname := u.Hostname()

	switch originHostname {
	case "localhost", "127.0.0.1", "::1":
		return nil
	}

	if originHost == req.Host {
		return nil
	}
	return fmt.Errorf("origin not allowed: %s", origin)
}
