package server

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"github.com/unixshells/latch/internal/input"
	"github.com/unixshells/latch/internal/mux"
	"github.com/unixshells/latch/pkg/proto"
	"github.com/unixshells/latch/pkg/transport"
	"github.com/unixshells/mosh-go"
	"golang.org/x/crypto/ssh"
)

// ListenRemote starts an SSH server for remote clients.
func (s *Server) ListenRemote(addr string) error {
	hostKey, err := transport.LoadHostKey(transport.KeyPath())
	if err != nil {
		return fmt.Errorf("host key: %w", err)
	}

	config := &ssh.ServerConfig{}
	config.AddHostKey(hostKey)

	// Load authorized keys — reject all connections if none configured.
	authKeys, err := transport.LoadAuthorizedKeys(transport.AuthorizedKeysPath())
	if err != nil {
		return fmt.Errorf("authorized keys: %w", err)
	}
	if len(authKeys) == 0 {
		fmt.Fprintf(os.Stderr, "WARNING: no authorized_keys — ssh will reject all connections\n")
		fmt.Fprintf(os.Stderr, "  add a key: ssh-keygen -t ed25519 && cat ~/.ssh/id_ed25519.pub >> %s\n", transport.AuthorizedKeysPath())
	}
	config.PublicKeyCallback = makePublicKeyCallback(authKeys)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("ssh listen: %w", err)
	}
	s.remoteLn = ln
	s.mu.Lock()
	s.sshAddr = ln.Addr().String()
	s.mu.Unlock()

	fp := ssh.FingerprintSHA256(hostKey.PublicKey())
	fmt.Fprintf(os.Stderr, "latch ssh listening on %s (key: %s)\n", addr, fp)

	go s.serveSSH(ln, config)
	return nil
}

func (s *Server) serveSSH(ln net.Listener, config *ssh.ServerConfig) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				fmt.Fprintf(os.Stderr, "ssh accept: %v\n", err)
			}
			return
		}
		go s.handleSSHConn(conn, config)
	}
}

func (s *Server) setSSHMeta(conn net.Conn, remoteAddr net.Addr, perms *ssh.Permissions) {
	info := &ConnInfo{
		Source:     "ssh",
		RemoteAddr: remoteAddr.String(),
	}
	if perms != nil && perms.Extensions != nil {
		info.KeyFP = perms.Extensions["fp"]
		info.KeyComment = perms.Extensions["comment"]
	}
	s.setConnMeta(conn, info)
}

func (s *Server) handleSSHConn(conn net.Conn, config *ssh.ServerConfig) {
	s.handleSSHConnRelay(conn, config, false)
}

func (s *Server) handleSSHConnRelay(conn net.Conn, config *ssh.ServerConfig, viaRelay bool) {
	defer conn.Close()

	if !s.access.SSH() {
		return
	}

	ip := extractIP(conn.RemoteAddr())
	if !s.limiter.acquire(ip) {
		return
	}
	defer s.limiter.release(ip)

	sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			return
		}
		go s.handleSSHSession(ch, requests, sconn.User(), conn.RemoteAddr(), sconn.Permissions, viaRelay)
	}
}

func (s *Server) handleSSHSession(ch ssh.Channel, reqs <-chan *ssh.Request, user string, remoteAddr net.Addr, perms *ssh.Permissions, viaRelay bool) {
	defer ch.Close()

	bridge := &sshBridge{
		ch:         ch,
		reqs:       reqs,
		remoteAddr: remoteAddr,
		input:      &input.Processor{PrefixKey: s.cfg.PrefixKey},
		viaRelay:   viaRelay,
	}

	// Wait for a pty-req or shell/exec request before starting.
	// Timeout prevents idle SSH connections from leaking goroutines.
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()

	session := "default"
	if user != "" && user != "latch" && mux.ValidateSessionName(user) == nil {
		session = user
	}
	for {
		select {
		case <-timeout.C:
			return
		case req, ok := <-reqs:
			if !ok {
				return
			}
			switch req.Type {
			case "pty-req":
				bridge.handlePTYReq(req)
			case "shell":
				if req.WantReply {
					req.Reply(true, nil)
				}
				bridge.readBuf = s.marshalSession(bridge, session)
				go bridge.watchRequests()
				s.setSSHMeta(bridge, remoteAddr, perms)
				s.handle(bridge)
				return
			case "exec":
				if len(req.Payload) >= 4 {
					cmdLen := binary.BigEndian.Uint32(req.Payload[:4])
					if cmdLen <= uint32(len(req.Payload)-4) {
						cmd := string(req.Payload[4 : 4+cmdLen])
						if strings.HasPrefix(cmd, "mosh-server") {
							if req.WantReply {
								req.Reply(true, nil)
							}
							s.handleMoshExec(ch, cmd, remoteAddr, perms, bridge.viaRelay)
							return
						}
						session = cmd
					}
				}
				if mux.ValidateSessionName(session) != nil {
					session = "default"
				}
				if req.WantReply {
					req.Reply(true, nil)
				}
				bridge.readBuf = s.marshalSession(bridge, session)
				go bridge.watchRequests()
				s.setSSHMeta(bridge, remoteAddr, perms)
				s.handle(bridge)
				return
			case "subsystem":
				if len(req.Payload) >= 4 {
					nameLen := binary.BigEndian.Uint32(req.Payload[:4])
					if nameLen <= uint32(len(req.Payload)-4) {
						name := string(req.Payload[4 : 4+nameLen])
						if name == "sftp" {
							if req.WantReply {
								req.Reply(true, nil)
							}
							s.handleSFTP(ch)
							return
						}
					}
				}
				if req.WantReply {
					req.Reply(false, nil)
				}
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}
}

// marshalSession builds the initial read buffer for an SSH bridge:
// a new-session message followed by an optional resize.
func (s *Server) marshalSession(bridge *sshBridge, session string) []byte {
	buf, _ := proto.MarshalMsg(proto.MsgNewSession, []byte(session))
	if bridge.cols > 0 {
		resize, _ := proto.MarshalMsg(proto.MsgResize,
			proto.EncodeResize(bridge.cols, bridge.rows))
		buf = append(buf, resize...)
	}
	return buf
}

// sshBridge adapts an SSH channel to a net.Conn-like interface.
// Read: translates SSH data into proto-formatted bytes with prefix key processing.
// Write: extracts MsgOutput payloads and sends raw ANSI to the channel.
type sshBridge struct {
	ch         ssh.Channel
	reqs       <-chan *ssh.Request
	remoteAddr net.Addr
	cols       uint16
	rows       uint16
	readBuf    []byte
	chBuf      [4096]byte // reusable read buffer for SSH channel
	mu         sync.Mutex
	input      *input.Processor
	viaRelay   bool // true if this SSH session came through the relay
}

func (b *sshBridge) handlePTYReq(req *ssh.Request) {
	// pty-req payload: string term, uint32 cols, uint32 rows, ...
	if len(req.Payload) < 4 {
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}
	termLen := binary.BigEndian.Uint32(req.Payload[:4])
	if termLen > uint32(len(req.Payload)-4) {
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}
	off := 4 + int(termLen)
	if off+8 > len(req.Payload) {
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}
	b.cols = uint16(binary.BigEndian.Uint32(req.Payload[off:]))
	b.rows = uint16(binary.BigEndian.Uint32(req.Payload[off+4:]))
	if b.cols == 0 {
		b.cols = 80
	}
	if b.rows == 0 {
		b.rows = 24
	}
	if req.WantReply {
		req.Reply(true, nil)
	}
}

func (b *sshBridge) watchRequests() {
	for req := range b.reqs {
		switch req.Type {
		case "window-change":
			// payload: uint32 cols, uint32 rows, ...
			if len(req.Payload) >= 8 {
				cols := uint16(binary.BigEndian.Uint32(req.Payload[0:4]))
				rows := uint16(binary.BigEndian.Uint32(req.Payload[4:8]))
				resize, err := proto.MarshalMsg(proto.MsgResize,
					proto.EncodeResize(cols, rows))
				if err != nil {
					continue
				}
				b.mu.Lock()
				// Keep only the latest resize to avoid unbounded growth,
				// but preserve any non-resize data already buffered.
				if len(b.readBuf)+len(resize) > 64*1024 {
					b.readBuf = resize
				} else {
					b.readBuf = append(b.readBuf, resize...)
				}
				b.mu.Unlock()
			}
			if req.WantReply {
				req.Reply(true, nil)
			}
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func (b *sshBridge) Read(p []byte) (int, error) {
	b.mu.Lock()
	if len(b.readBuf) > 0 {
		n := copy(p, b.readBuf)
		b.readBuf = b.readBuf[n:]
		b.mu.Unlock()
		return n, nil
	}
	b.mu.Unlock()

	n, err := b.ch.Read(b.chBuf[:])
	if err != nil {
		return 0, err
	}

	// Process input through prefix key handler if configured,
	// otherwise wrap as raw MsgInput.
	var buf bytes.Buffer
	if b.input != nil {
		if err := b.input.Process(&buf, b.chBuf[:n], n); err != nil {
			return 0, err
		}
	} else {
		msg, err := proto.MarshalMsg(proto.MsgInput, b.chBuf[:n])
		if err != nil {
			return 0, err
		}
		buf.Write(msg)
	}

	b.mu.Lock()
	b.readBuf = append(b.readBuf, buf.Bytes()...)
	n = copy(p, b.readBuf)
	b.readBuf = b.readBuf[n:]
	b.mu.Unlock()
	return n, nil
}

func (b *sshBridge) Write(p []byte) (int, error) {
	// proto.Encode writes exactly one message per Write call:
	// [1 byte type][2 byte len][payload]
	// Extract MsgOutput payloads and send raw ANSI to the SSH channel.
	total := len(p)
	if len(p) >= 3 {
		typ := p[0]
		msgLen := int(binary.BigEndian.Uint16(p[1:3]))
		if 3+msgLen <= len(p) && typ == proto.MsgOutput {
			payload := p[3 : 3+msgLen]
			if _, err := b.ch.Write(payload); err != nil {
				return 0, err
			}
		}
	}
	return total, nil
}

func (b *sshBridge) Close() error {
	return b.ch.Close()
}

func (b *sshBridge) RemoteAddr() net.Addr {
	return b.remoteAddr
}

func (b *sshBridge) LocalAddr() net.Addr                { return nil }
func (b *sshBridge) SetDeadline(t time.Time) error      { return nil }
func (b *sshBridge) SetReadDeadline(t time.Time) error  { return nil }
func (b *sshBridge) SetWriteDeadline(t time.Time) error { return nil }

var _ net.Conn = (*sshBridge)(nil)

// handleSFTP serves the SFTP subsystem over an SSH channel.
func (s *Server) handleSFTP(ch ssh.Channel) {
	server, err := sftp.NewServer(ch)
	if err != nil {
		return
	}
	server.Serve()
	server.Close()
}

// moshBridge adapts a mosh server connection to a net.Conn-like interface,
// allowing mosh clients to attach to latch sessions like SSH and WebSocket clients.
type moshBridge struct {
	toMosh     io.WriteCloser  // latch writes ANSI output here -> mosh reads
	fromMosh   io.ReadCloser   // latch reads keystrokes here <- mosh writes
	remoteAddr net.Addr
	readBuf    []byte
	resizeCh   chan [2]uint16
	mu         sync.Mutex
	closed     bool
	done       chan struct{}
}

func (b *moshBridge) Read(p []byte) (int, error) {
	b.mu.Lock()
	if len(b.readBuf) > 0 {
		n := copy(p, b.readBuf)
		b.readBuf = b.readBuf[n:]
		b.mu.Unlock()
		return n, nil
	}
	b.mu.Unlock()

	var buf [4096]byte
	n, err := b.fromMosh.Read(buf[:])
	if err != nil {
		return 0, err
	}

	msg, err := proto.MarshalMsg(proto.MsgInput, buf[:n])
	if err != nil {
		return 0, err
	}

	b.mu.Lock()
	b.readBuf = append(b.readBuf, msg...)
	n = copy(p, b.readBuf)
	b.readBuf = b.readBuf[n:]
	b.mu.Unlock()
	return n, nil
}

func (b *moshBridge) Write(p []byte) (int, error) {
	total := len(p)
	if len(p) >= 3 {
		typ := p[0]
		msgLen := int(binary.BigEndian.Uint16(p[1:3]))
		if 3+msgLen <= len(p) && typ == proto.MsgOutput {
			payload := p[3 : 3+msgLen]
			if _, err := b.toMosh.Write(payload); err != nil {
				return 0, err
			}
		}
	}
	return total, nil
}

func (b *moshBridge) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	close(b.done)
	b.toMosh.Close()
	return b.fromMosh.Close()
}

func (b *moshBridge) RemoteAddr() net.Addr                  { return b.remoteAddr }
func (b *moshBridge) LocalAddr() net.Addr                   { return nil }
func (b *moshBridge) SetDeadline(t time.Time) error         { return nil }
func (b *moshBridge) SetReadDeadline(t time.Time) error     { return nil }
func (b *moshBridge) SetWriteDeadline(t time.Time) error    { return nil }

func (b *moshBridge) watchResize() {
	for {
		select {
		case <-b.done:
			return
		case sz := <-b.resizeCh:
			resize, err := proto.MarshalMsg(proto.MsgResize,
				proto.EncodeResize(sz[0], sz[1]))
			if err != nil {
				continue
			}
			b.mu.Lock()
			b.readBuf = append(b.readBuf, resize...)
			b.mu.Unlock()
		}
	}
}

var _ net.Conn = (*moshBridge)(nil)

// pipeRW combines a read and write pipe into an io.ReadWriteCloser.
type pipeRW struct {
	r io.ReadCloser
	w io.WriteCloser
}

func (p *pipeRW) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeRW) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p *pipeRW) Close() error {
	p.r.Close()
	return p.w.Close()
}

// handleMoshExec handles mosh-server exec requests from SSH clients.
// It bridges the mosh server to a latch session so mosh clients get
// the same multiplexed experience as SSH and WebSocket clients.
//
// When connected to a relay, it requests a UDP bridge so the standard
// mosh client can connect through the relay's public UDP port.
func (s *Server) handleMoshExec(ch ssh.Channel, cmd string, remoteAddr net.Addr, perms *ssh.Permissions, viaRelay bool) {
	defer ch.Close()

	portLow, portHigh := parseMoshPorts(cmd)
	if portLow == 0 && portHigh == 0 {
		portLow, portHigh = 60000, 61000
	}

	srv, err := mosh.NewServer("", portLow, portHigh)
	if err != nil {
		fmt.Fprintf(ch.Stderr(), "mosh-server: %v\r\n", err)
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
		return
	}

	// If relay is active, request a UDP bridge so the mosh client
	// connects to the relay's public port instead of the local one.
	var bridgeStream interface{ Close() error }
	if viaRelay && s.relayCon != nil {
		relayPort, relayAddr, stream, err := s.RequestUDPBridge(uint16(srv.Port()))
		if err == nil {
			bridgeStream = stream
			fmt.Fprintf(ch, "\nMOSH CONNECT %d %s\n", relayPort, srv.KeyBase64())
			if relayAddr != "" {
				fmt.Fprintf(ch, "MOSH IP %s\n", relayAddr)
			}

			// Bridge UDP↔QUIC: relay sends framed datagrams [len:2][data]
			// on the QUIC stream, forward them to the local mosh UDP port.
			localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: srv.Port()}
			bridgeUDP, err := net.DialUDP("udp4", nil, localAddr)
			if err == nil {
				// QUIC stream → local UDP
				go func() {
					defer bridgeUDP.Close()
					var hdr [2]byte
					for {
						if _, err := io.ReadFull(stream, hdr[:]); err != nil {
							return
						}
						n := binary.BigEndian.Uint16(hdr[:])
						if n > 2048 {
							return
						}
						buf := make([]byte, n)
						if _, err := io.ReadFull(stream, buf); err != nil {
							return
						}
						bridgeUDP.Write(buf)
					}
				}()
				// Local UDP → QUIC stream
				go func() {
					buf := make([]byte, 2048)
					for {
						n, err := bridgeUDP.Read(buf)
						if err != nil {
							return
						}
						var hdr [2]byte
						binary.BigEndian.PutUint16(hdr[:], uint16(n))
						stream.Write(hdr[:])
						stream.Write(buf[:n])
					}
				}()
			}
		} else {
			// Bridge failed — fall back to original CONNECT line.
			fmt.Fprintf(ch.Stderr(), "relay bridge: %v (falling back to direct)\r\n", err)
			srv.WriteTo(ch)
		}
	} else {
		srv.WriteTo(ch)
	}

	ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
	ch.Close()

	// Create pipe pairs for bridging.
	moshR, latchW := io.Pipe() // latch writes ANSI -> mosh reads
	latchR, moshW := io.Pipe() // mosh writes keystrokes -> latch reads

	bridge := &moshBridge{
		toMosh:     latchW,
		fromMosh:   latchR,
		remoteAddr: remoteAddr,
		resizeCh:   make(chan [2]uint16, 4),
		done:       make(chan struct{}),
	}

	// Initial readBuf: new-session message.
	bridge.readBuf, _ = proto.MarshalMsg(proto.MsgNewSession, []byte("default"))

	// Start mosh server with the pipe pair.
	moshRW := &pipeRW{r: moshR, w: moshW}
	go func() {
		srv.ServeRW(moshRW, func(cols, rows uint16) {
			select {
			case bridge.resizeCh <- [2]uint16{cols, rows}:
			default:
			}
		})
		bridge.Close()
	}()

	go bridge.watchResize()

	info := &ConnInfo{
		Source:     "mosh",
		RemoteAddr: remoteAddr.String(),
	}
	if perms != nil && perms.Extensions != nil {
		info.KeyFP = perms.Extensions["fp"]
		info.KeyComment = perms.Extensions["comment"]
	}
	s.setConnMeta(bridge, info)
	s.handle(bridge)

	// Close the relay bridge stream after the mosh session ends.
	// This triggers teardown of the relay's UDP port binding.
	if bridgeStream != nil {
		bridgeStream.Close()
	}
}

// parseMoshPorts extracts -p PORT[:PORT2] from a mosh-server command.
func parseMoshPorts(cmd string) (low, high int) {
	fields := strings.Fields(cmd)
	for i, f := range fields {
		if f == "-p" && i+1 < len(fields) {
			portRange := fields[i+1]
			parts := strings.SplitN(portRange, ":", 2)
			low, _ = strconv.Atoi(parts[0])
			if len(parts) == 2 {
				high, _ = strconv.Atoi(parts[1])
			} else {
				high = low
			}
			return
		}
	}
	return 0, 0
}

func makePublicKeyCallback(authorized []transport.AuthorizedKey) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	return func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		// Reload authorized keys from disk on each attempt so new keys
		// take effect without restarting the daemon.
		keys, err := transport.LoadAuthorizedKeys(transport.AuthorizedKeysPath())
		if err != nil || len(keys) == 0 {
			keys = authorized // fall back to startup snapshot
		}
		keyBytes := key.Marshal()
		for _, ak := range keys {
			if subtle.ConstantTimeCompare(ak.Key.Marshal(), keyBytes) == 1 {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"fp":      ssh.FingerprintSHA256(key),
						"comment": ak.Comment,
					},
				}, nil
			}
		}
		return nil, fmt.Errorf("unknown public key")
	}
}
