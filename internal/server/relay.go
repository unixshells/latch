package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/unixshells/latch/pkg/relay"
	"github.com/unixshells/latch/pkg/transport"
	"golang.org/x/crypto/ssh"
)

// StartRelay starts the persistent relay connection.
// Incoming relay streams are SSH ciphertext — they go through the same
// SSH server handshake as direct SSH connections.
func (s *Server) StartRelay(addr, user, device, caFile string) error {
	signer, _, err := transport.LoadOrGenerateRelayKey(transport.RelayKeyPath())
	if err != nil {
		return fmt.Errorf("relay key: %w", err)
	}

	tlsCfg, err := relay.TLSConfig(caFile)
	if err != nil {
		return fmt.Errorf("relay tls: %w", err)
	}

	// SSH server config for relay connections (same auth as direct SSH).
	sshCfg, err := s.makeSSHConfig()
	if err != nil {
		return err
	}

	p := relay.NewPersistentConn(addr, user, device, signer, tlsCfg, func(stream *relay.Stream) {
		if !s.access.Relay() {
			stream.Close()
			return
		}
		s.handleRelayStream(stream, sshCfg)
	})
	p.UDPFunc = func(raw *quic.Stream) {
		s.handleUDPForwardStream(raw)
	}
	p.WebFunc = func(raw *quic.Stream) {
		s.handleWebTerminalStream(raw)
	}
	s.relayCon = p
	p.Start()
	fmt.Fprintf(os.Stderr, "latch relay connecting to %s as %s/%s\n", addr, user, device)
	return nil
}

// StopRelay stops the relay connection.
func (s *Server) StopRelay() {
	if s.relayCon != nil {
		s.relayCon.Stop()
		s.relayCon = nil
	}
}

// makeSSHConfig builds the SSH server config for relay or direct connections.
func (s *Server) makeSSHConfig() (*ssh.ServerConfig, error) {
	hostKey, err := transport.LoadHostKey(transport.KeyPath())
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}

	config := &ssh.ServerConfig{}
	config.AddHostKey(hostKey)

	authKeys, err := transport.LoadAuthorizedKeys(transport.AuthorizedKeysPath())
	if err != nil {
		return nil, fmt.Errorf("authorized keys: %w", err)
	}
	config.PublicKeyCallback = makePublicKeyCallback(authKeys)
	return config, nil
}

// RequestUDPBridge asks the relay to bridge a public UDP port to a local mosh port.
// Returns the relay's public port, public address, and the QUIC stream (kept open for the bridge lifetime).
func (s *Server) RequestUDPBridge(targetPort uint16) (relayPort int, relayAddr string, stream *quic.Stream, err error) {
	if s.relayCon == nil {
		return 0, "", nil, fmt.Errorf("no relay connection")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err = s.relayCon.OpenStream(ctx)
	if err != nil {
		return 0, "", nil, fmt.Errorf("open stream: %w", err)
	}

	// Write request: [0x03][targetPort:2]
	var req [3]byte
	req[0] = 0x03
	binary.BigEndian.PutUint16(req[1:3], targetPort)
	if _, err := stream.Write(req[:]); err != nil {
		stream.Close()
		return 0, "", nil, fmt.Errorf("write request: %w", err)
	}

	// Read response: [status:1][relayPort:2][addrLen:2][relayAddr]
	var resp [5]byte
	if _, err := io.ReadFull(stream, resp[:]); err != nil {
		stream.Close()
		return 0, "", nil, fmt.Errorf("read response: %w", err)
	}
	if resp[0] != 0x01 {
		stream.Close()
		return 0, "", nil, fmt.Errorf("bridge request rejected")
	}

	relayPort = int(binary.BigEndian.Uint16(resp[1:3]))
	addrLen := binary.BigEndian.Uint16(resp[3:5])
	if addrLen > 512 {
		stream.Close()
		return 0, "", nil, fmt.Errorf("address too large")
	}
	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(stream, addrBuf); err != nil {
		stream.Close()
		return 0, "", nil, fmt.Errorf("read address: %w", err)
	}
	relayAddr = string(addrBuf)

	return relayPort, relayAddr, stream, nil
}

// handleRelayStream runs the SSH server handshake on a relay stream.
// The stream carries SSH ciphertext from the relay's ProxyJump client.
func (s *Server) handleRelayStream(stream *relay.Stream, sshCfg *ssh.ServerConfig) {
	// Set metadata before handle.
	// RemoteAddr is the verified QUIC peer; ClaimedAddr is the relay-provided client IP.
	info := &ConnInfo{
		Source:     "relay",
		RemoteAddr: stream.RemoteAddr().String(),
	}
	s.setConnMeta(stream, info)
	s.handleSSHConn(stream, sshCfg)
}

// handleUDPForwardStream handles a UDP forward stream from the relay.
// Stream format after type byte (0x01): [targetPort:2][ipLen:2][ipString]
// Then framed datagrams: [len:2][data]...
func (s *Server) handleUDPForwardStream(raw *quic.Stream) {
	defer raw.Close()

	if !s.access.Relay() {
		return
	}

	// Read target port.
	var portBuf [2]byte
	if _, err := io.ReadFull(raw, portBuf[:]); err != nil {
		return
	}
	targetPort := binary.BigEndian.Uint16(portBuf[:])

	// Only allow mosh's dynamic port range (60000-61000).
	if targetPort < 60000 || targetPort > 61000 {
		return
	}

	// Read and discard client IP header.
	var ipLenBuf [2]byte
	if _, err := io.ReadFull(raw, ipLenBuf[:]); err != nil {
		return
	}
	ipLen := binary.BigEndian.Uint16(ipLenBuf[:])
	if ipLen > 512 {
		return
	}
	ipBuf := make([]byte, ipLen)
	if _, err := io.ReadFull(raw, ipBuf); err != nil {
		return
	}

	// Connect to local mosh-server UDP port.
	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("127.0.0.1:%d", targetPort))
	if err != nil {
		return
	}
	udpConn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return
	}
	defer udpConn.Close()

	// Forward: QUIC stream → local UDP.
	go func() {
		var hdr [2]byte
		for {
			if _, err := io.ReadFull(raw, hdr[:]); err != nil {
				udpConn.Close()
				return
			}
			n := binary.BigEndian.Uint16(hdr[:])
			if n > 1500 {
				udpConn.Close()
				return
			}
			buf := make([]byte, n)
			if _, err := io.ReadFull(raw, buf); err != nil {
				udpConn.Close()
				return
			}
			udpConn.Write(buf)
		}
	}()

	// Forward: local UDP → QUIC stream.
	buf := make([]byte, 1500)
	for {
		udpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := udpConn.Read(buf)
		if err != nil {
			return
		}
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(n))
		if _, err := raw.Write(hdr[:]); err != nil {
			return
		}
		if _, err := raw.Write(buf[:n]); err != nil {
			return
		}
	}
}

// handleWebTerminalStream handles a web terminal stream from the relay.
// The stream carries raw proto messages [type:1][len:2][payload].
// Stream header (after type byte 0x02): [ipLen:2][ipString]
func (s *Server) handleWebTerminalStream(raw *quic.Stream) {
	defer raw.Close()

	if !s.access.Relay() {
		return
	}

	// Read client IP header.
	var ipLenBuf [2]byte
	if _, err := io.ReadFull(raw, ipLenBuf[:]); err != nil {
		return
	}
	ipLen := binary.BigEndian.Uint16(ipLenBuf[:])
	if ipLen > 512 {
		return
	}
	ipBuf := make([]byte, ipLen)
	if _, err := io.ReadFull(raw, ipBuf); err != nil {
		return
	}

	bridge := &streamBridge{
		stream:     raw,
		remoteAddr: string(ipBuf),
	}

	info := &ConnInfo{
		Source:     "web-relay",
		RemoteAddr: string(ipBuf),
	}
	s.setConnMeta(bridge, info)
	s.handle(bridge)
}

// streamBridge wraps a QUIC stream as a net.Conn for proto message I/O.
// The stream carries raw proto frames [type:1][len:2][payload].
type streamBridge struct {
	stream     *quic.Stream
	remoteAddr string
}

func (b *streamBridge) Read(p []byte) (int, error)  { return b.stream.Read(p) }
func (b *streamBridge) Write(p []byte) (int, error) { return b.stream.Write(p) }
func (b *streamBridge) Close() error                { return b.stream.Close() }

func (b *streamBridge) RemoteAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", b.remoteAddr)
	if addr == nil {
		return &net.TCPAddr{}
	}
	return addr
}

func (b *streamBridge) LocalAddr() net.Addr                { return nil }
func (b *streamBridge) SetDeadline(t time.Time) error      { return nil }
func (b *streamBridge) SetReadDeadline(t time.Time) error  { return nil }
func (b *streamBridge) SetWriteDeadline(t time.Time) error { return nil }

var _ net.Conn = (*streamBridge)(nil)
