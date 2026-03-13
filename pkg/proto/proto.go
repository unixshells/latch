package proto

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// Message types: client → server
const (
	MsgNewSession  byte = 0x01
	MsgAttach      byte = 0x02
	MsgDetach      byte = 0x03
	MsgInput       byte = 0x04
	MsgResize      byte = 0x05
	MsgNewWindow   byte = 0x06
	MsgCloseWindow byte = 0x09
	MsgSelectWin   byte = 0x0A
	MsgList        byte = 0x0B
	MsgKillSession byte = 0x0C
	MsgPaste       byte = 0x13
	MsgHUD         byte = 0x14
	MsgAdminPanel  byte = 0x15 // client → server: open/close admin panel
	MsgAdminAction byte = 0x16 // client → server: toggle/kick action
	MsgEnableSSH    byte = 0x17 // client → server: start SSH listener (payload: addr)
	MsgEnableWeb    byte = 0x18 // client → server: start web listener (payload: addr)
	MsgScrollMode   byte = 0x19 // client → server: enter/exit scroll mode (payload: [0/1])
	MsgScrollAction byte = 0x1A // client → server: scroll action (payload: [action])
)

// Message types: server → client
const (
	MsgOutput      byte = 0x80
	MsgSessionList byte = 0x81
	MsgError       byte = 0x82
	MsgDetached    byte = 0x83
	MsgSessionDead byte = 0x84
	MsgAdminState  byte = 0x85 // server → client: admin panel state
)

// Window select special values
const (
	WindowNext byte = 0xFF
	WindowPrev byte = 0xFE
)

const maxPayload = 64 * 1024

var encodePool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 4096)
		return &b
	},
}

// Encode writes a message: [type][2-byte big-endian length][payload].
// Each call makes exactly one Write call containing the complete message.
// Bridge adapters (sshBridge, wsBridge) depend on this invariant.
func Encode(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > maxPayload {
		return fmt.Errorf("payload too large: %d", len(payload))
	}
	n := 3 + len(payload)
	bp := encodePool.Get().(*[]byte)
	buf := *bp
	if cap(buf) < n {
		buf = make([]byte, n)
	} else {
		buf = buf[:n]
	}
	buf[0] = typ
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(payload)))
	copy(buf[3:], payload)
	_, err := w.Write(buf)
	*bp = buf
	encodePool.Put(bp)
	return err
}

// Decode reads one message. Returns type and payload.
func Decode(r io.Reader) (byte, []byte, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	typ := hdr[0]
	n := binary.BigEndian.Uint16(hdr[1:])
	if int(n) > maxPayload {
		return 0, nil, fmt.Errorf("payload too large: %d", n)
	}
	if n == 0 {
		return typ, nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return typ, buf, nil
}

// EncodeResize encodes cols and rows as 4 bytes.
func EncodeResize(cols, rows uint16) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint16(buf[0:], cols)
	binary.BigEndian.PutUint16(buf[2:], rows)
	return buf[:]
}

// DecodeResize decodes cols and rows from 4 bytes.
func DecodeResize(b []byte) (cols, rows uint16, err error) {
	if len(b) < 4 {
		return 0, 0, fmt.Errorf("resize payload too short: %d", len(b))
	}
	cols = binary.BigEndian.Uint16(b[0:])
	rows = binary.BigEndian.Uint16(b[2:])
	return cols, rows, nil
}

// MarshalMsg returns a raw proto message as bytes without writing to a stream.
// Used by bridge adapters that need to buffer messages before delivery.
func MarshalMsg(typ byte, payload []byte) ([]byte, error) {
	if len(payload) > maxPayload {
		return nil, fmt.Errorf("payload too large: %d", len(payload))
	}
	buf := make([]byte, 3+len(payload))
	buf[0] = typ
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(payload)))
	copy(buf[3:], payload)
	return buf, nil
}
