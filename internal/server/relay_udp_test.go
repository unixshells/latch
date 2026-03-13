package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/unixshells/mosh-go"
)

// pipeReadWriter joins two pipe ends into an io.ReadWriter.
type pipeReadWriter struct {
	r io.Reader
	w io.Writer
}

func (p *pipeReadWriter) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeReadWriter) Write(b []byte) (int, error) { return p.w.Write(b) }

// writeStreamHeader writes the initial device-side header:
// [targetPort:2][ipLen:2][ipString]
func writeStreamHeader(w io.Writer, port int, ip string) {
	var hdr [4]byte
	binary.BigEndian.PutUint16(hdr[0:], uint16(port))
	binary.BigEndian.PutUint16(hdr[2:], uint16(len(ip)))
	w.Write(hdr[:])
	w.Write([]byte(ip))
}

// startDeviceHandler simulates handleUDPForwardStream: reads the header
// from the stream, connects to the mosh server's UDP port, and
// bidirectionally forwards framed datagrams.
func startDeviceHandler(t *testing.T, stream io.ReadWriter, moshPort int) {
	t.Helper()

	// Read header: [targetPort:2][ipLen:2][ipString].
	var portBuf [2]byte
	if _, err := io.ReadFull(stream, portBuf[:]); err != nil {
		t.Fatalf("device: read port: %v", err)
	}
	targetPort := binary.BigEndian.Uint16(portBuf[:])

	var ipLenBuf [2]byte
	if _, err := io.ReadFull(stream, ipLenBuf[:]); err != nil {
		t.Fatalf("device: read iplen: %v", err)
	}
	ipLen := binary.BigEndian.Uint16(ipLenBuf[:])
	ipBuf := make([]byte, ipLen)
	if _, err := io.ReadFull(stream, ipBuf); err != nil {
		t.Fatalf("device: read ip: %v", err)
	}

	if int(targetPort) != moshPort {
		t.Fatalf("device: expected port %d, got %d", moshPort, targetPort)
	}

	udpConn, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: moshPort,
	})
	if err != nil {
		t.Fatalf("device: dial mosh: %v", err)
	}

	// Stream → mosh-server UDP.
	go func() {
		var hdr [2]byte
		for {
			if _, err := io.ReadFull(stream, hdr[:]); err != nil {
				udpConn.Close()
				return
			}
			n := binary.BigEndian.Uint16(hdr[:])
			buf := make([]byte, n)
			if _, err := io.ReadFull(stream, buf); err != nil {
				udpConn.Close()
				return
			}
			udpConn.Write(buf)
		}
	}()

	// Mosh-server UDP → stream.
	go func() {
		buf := make([]byte, 65536)
		for {
			udpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := udpConn.Read(buf)
			if err != nil {
				return
			}
			var hdr [2]byte
			binary.BigEndian.PutUint16(hdr[:], uint16(n))
			if _, err := stream.Write(hdr[:]); err != nil {
				return
			}
			if _, err := stream.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	t.Cleanup(func() { udpConn.Close() })
}

// startRelaySide simulates the relay's public-facing UDP socket.
// It listens on a local UDP port and bidirectionally frames datagrams
// to/from the stream, remembering the mosh-client's address.
func startRelaySide(t *testing.T, stream io.ReadWriter) *net.UDPAddr {
	t.Helper()

	relayConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	relayAddr := relayConn.LocalAddr().(*net.UDPAddr)

	var mu sync.Mutex
	var clientAddr *net.UDPAddr

	// Client UDP → framed stream.
	go func() {
		buf := make([]byte, 65536)
		for {
			relayConn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, addr, err := relayConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			clientAddr = addr
			mu.Unlock()

			var hdr [2]byte
			binary.BigEndian.PutUint16(hdr[:], uint16(n))
			stream.Write(hdr[:])
			stream.Write(buf[:n])
		}
	}()

	// Framed stream → client UDP.
	go func() {
		var hdr [2]byte
		for {
			if _, err := io.ReadFull(stream, hdr[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint16(hdr[:])
			buf := make([]byte, n)
			if _, err := io.ReadFull(stream, buf); err != nil {
				return
			}
			mu.Lock()
			addr := clientAddr
			mu.Unlock()
			if addr != nil {
				relayConn.WriteToUDP(buf, addr)
			}
		}
	}()

	t.Cleanup(func() { relayConn.Close() })

	return relayAddr
}

// TestRelayUDPFraming tests the relay's [len:2][data] framing with our
// Go SSP transport. No real mosh-client binary needed.
//
// Path: SSP client → UDP → relaySide → [len:2][data] pipe → deviceHandler → UDP → mosh.Server
func TestRelayUDPFraming(t *testing.T) {
	// Start native mosh server.
	srv, err := mosh.NewServer("", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })

	moshPort := srv.Port()
	keyStr := srv.KeyBase64()

	padded := keyStr
	for len(padded)%4 != 0 {
		padded += "="
	}

	// Pipe pair simulates the QUIC stream.
	// relay writes → device reads, device writes → relay reads.
	deviceR, relayW := io.Pipe()
	relayR, deviceW := io.Pipe()

	deviceStream := &pipeReadWriter{r: deviceR, w: deviceW}
	relayStream := &pipeReadWriter{r: relayR, w: relayW}

	// Write header into device-side of the stream.
	go writeStreamHeader(relayW, moshPort, "127.0.0.1")

	// Start device handler (reads header, then forwards).
	startDeviceHandler(t, deviceStream, moshPort)

	// Start relay-side UDP listener.
	relayAddr := startRelaySide(t, relayStream)

	// Build SSP client transport.
	ocb, err := mosh.NewOCBFromBase64(padded)
	if err != nil {
		t.Fatal(err)
	}
	tp := mosh.NewTransport(ocb, false)

	conn, err := net.DialUDP("udp4", nil, relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	send := func(diff []byte) {
		tp.SetPending(diff)
		for _, dg := range tp.Tick() {
			conn.Write(dg)
		}
	}

	recv := func(timeout time.Duration) []byte {
		buf := make([]byte, 16384+64)
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(buf)
		if err != nil {
			return nil
		}
		return tp.Recv(buf[:n])
	}

	// Associate with server.
	send(nil)

	// Wait for server output through the relay proxy.
	var gotOutput bool
	for i := 0; i < 40; i++ {
		diff := recv(500 * time.Millisecond)
		if len(diff) > 0 {
			gotOutput = true
			t.Logf("received %d bytes from mosh server via relay framing", len(diff))
			break
		}
		send(nil)
	}
	if !gotOutput {
		t.Fatal("no output from mosh server through relay proxy")
	}

	// Send a keystroke command and verify echo.
	marker := "RELAYUDP_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	keys := []byte("echo " + marker + "\n")
	diff := mosh.MarshalUserMessage([]mosh.UserInstruction{{Keys: keys}})
	send(diff)

	var allOutput string
	deadline := time.After(10 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("marker not echoed. Got: %q", allOutput)
		default:
		}
		d := recv(500 * time.Millisecond)
		if d != nil {
			instrs, err := mosh.UnmarshalHostMessage(d)
			if err == nil {
				for _, hi := range instrs {
					allOutput += string(hi.Hoststring)
				}
			}
		}
		send(nil)
		if strings.Contains(allOutput, marker) {
			t.Log("relay UDP framing: command echoed over SSP through framed proxy")
			return
		}
	}
}

// TestRelayUDPWithRealClient runs a real mosh-client binary through the
// relay's framing proxy to the native mosh server.
func TestRelayUDPWithRealClient(t *testing.T) {
	if _, err := exec.LookPath("mosh-client"); err != nil {
		t.Skip("mosh-client not installed")
	}

	srv, err := mosh.NewServer("", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })

	moshPort := srv.Port()
	keyStr := srv.KeyBase64()

	deviceR, relayW := io.Pipe()
	relayR, deviceW := io.Pipe()

	deviceStream := &pipeReadWriter{r: deviceR, w: deviceW}
	relayStream := &pipeReadWriter{r: relayR, w: relayW}

	go writeStreamHeader(relayW, moshPort, "127.0.0.1")
	startDeviceHandler(t, deviceStream, moshPort)

	relayAddr := startRelaySide(t, relayStream)

	cmd := exec.Command("mosh-client", "127.0.0.1", strconv.Itoa(relayAddr.Port))
	cmd.Env = append(cmd.Environ(),
		"MOSH_KEY="+keyStr,
		"TERM=xterm-256color",
	)

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ptmx.Close()
		cmd.Process.Kill()
		cmd.Wait()
	}()

	outputCh := make(chan string, 256)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				outputCh <- string(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	// Wait for shell.
	var allOutput string
	ready := false
	readyDeadline := time.After(15 * time.Second)
	for !ready {
		select {
		case chunk := <-outputCh:
			allOutput += chunk
			if len(allOutput) > 50 {
				ready = true
			}
		case <-readyDeadline:
			t.Fatalf("mosh-client did not produce enough output. Got %d bytes:\n%q",
				len(allOutput), truncate(allOutput, 500))
		}
	}
	t.Logf("mosh-client connected through relay proxy, got %d bytes", len(allOutput))

	// Let shell settle.
	time.Sleep(2 * time.Second)
	for {
		select {
		case chunk := <-outputCh:
			allOutput += chunk
		default:
			goto settled
		}
	}
settled:

	marker := "RELAYREAL_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	fmt.Fprintf(ptmx, "echo %s\n", marker)

	found := false
	markerDeadline := time.After(15 * time.Second)
	for !found {
		select {
		case chunk := <-outputCh:
			allOutput += chunk
			if strings.Contains(allOutput, marker) {
				found = true
			}
		case <-markerDeadline:
			t.Fatalf("marker not echoed. Output (%d bytes):\n%q",
				len(allOutput), truncate(allOutput, 1000))
		}
	}

	t.Log("real mosh-client through relay UDP framing: E2E passed")
}
