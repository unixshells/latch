package client

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unixshells/latch/internal/mux"
	"github.com/unixshells/latch/pkg/proto"
)

// mockConn captures proto messages written to it.
type mockConn struct {
	msgs []mockMsg
}

type mockMsg struct {
	typ     byte
	payload []byte
}

func (m *mockConn) Write(p []byte) (int, error) {
	if len(p) >= 3 {
		typ := p[0]
		n := binary.BigEndian.Uint16(p[1:3])
		var payload []byte
		if n > 0 && 3+int(n) <= len(p) {
			payload = make([]byte, n)
			copy(payload, p[3:3+n])
		}
		m.msgs = append(m.msgs, mockMsg{typ: typ, payload: payload})
	}
	return len(p), nil
}

func (m *mockConn) Read([]byte) (int, error)         { return 0, nil }
func (m *mockConn) Close() error                     { return nil }
func (m *mockConn) LocalAddr() net.Addr              { return nil }
func (m *mockConn) RemoteAddr() net.Addr             { return nil }
func (m *mockConn) SetDeadline(time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.Conn = (*mockConn)(nil)

func (m *mockConn) lastMsg() mockMsg {
	if len(m.msgs) == 0 {
		return mockMsg{}
	}
	return m.msgs[len(m.msgs)-1]
}

func (m *mockConn) clear() {
	m.msgs = nil
}

func TestHandlePrefixDetach(t *testing.T) {
	var m mockConn
	consumed, err := handlePrefixW(&m, 'd')
	if err != nil {
		t.Fatal(err)
	}
	if !consumed {
		t.Fatal("expected consumed")
	}
	if m.lastMsg().typ != proto.MsgDetach {
		t.Fatalf("type = %x, want MsgDetach", m.lastMsg().typ)
	}
}

func TestHandlePrefixNewWindow(t *testing.T) {
	var m mockConn
	consumed, err := handlePrefixW(&m, 'c')
	if err != nil {
		t.Fatal(err)
	}
	if !consumed {
		t.Fatal("expected consumed")
	}
	if m.lastMsg().typ != proto.MsgNewWindow {
		t.Fatalf("type = %x, want MsgNewWindow", m.lastMsg().typ)
	}
}

func TestHandlePrefixNextPrevWindow(t *testing.T) {
	var m mockConn
	consumed, err := handlePrefixW(&m, 'n')
	if err != nil {
		t.Fatal(err)
	}
	if !consumed {
		t.Fatal("expected consumed")
	}
	if m.lastMsg().typ != proto.MsgSelectWin || m.lastMsg().payload[0] != proto.WindowNext {
		t.Fatalf("next: type=%x payload=%v", m.lastMsg().typ, m.lastMsg().payload)
	}

	m.clear()
	consumed, err = handlePrefixW(&m, 'p')
	if err != nil {
		t.Fatal(err)
	}
	if !consumed {
		t.Fatal("expected consumed")
	}
	if m.lastMsg().typ != proto.MsgSelectWin || m.lastMsg().payload[0] != proto.WindowPrev {
		t.Fatalf("prev: type=%x payload=%v", m.lastMsg().typ, m.lastMsg().payload)
	}
}

func TestHandlePrefixWindowSelect(t *testing.T) {
	for i := 0; i <= 9; i++ {
		var m mockConn
		b := byte('0' + i)
		consumed, err := handlePrefixW(&m, b)
		if err != nil {
			t.Fatal(err)
		}
		if !consumed {
			t.Fatalf("digit %d: expected consumed", i)
		}
		if m.lastMsg().typ != proto.MsgSelectWin {
			t.Fatalf("digit %d: type = %x", i, m.lastMsg().typ)
		}
		if m.lastMsg().payload[0] != byte(i) {
			t.Fatalf("digit %d: payload = %d", i, m.lastMsg().payload[0])
		}
	}
}

func TestHandlePrefixClose(t *testing.T) {
	var m mockConn
	consumed, err := handlePrefixW(&m, 'x')
	if err != nil {
		t.Fatal(err)
	}
	if !consumed {
		t.Fatal("expected consumed")
	}
	if m.lastMsg().typ != proto.MsgCloseWindow {
		t.Fatalf("type = %x, want MsgCloseWindow", m.lastMsg().typ)
	}
}

func TestHandlePrefixGotoNotConsumed(t *testing.T) {
	// 'g' is handled inline by readInput (goto mode), not handlePrefix
	var m mockConn
	consumed, err := handlePrefixW(&m, 'g')
	if err != nil {
		t.Fatal(err)
	}
	if consumed {
		t.Fatal("'g' should not be consumed by handlePrefix (handled by goto logic)")
	}
}

func TestHandlePrefixLiteralNotConsumed(t *testing.T) {
	var m mockConn
	consumed, err := handlePrefixW(&m, 0x1d)
	if err != nil {
		t.Fatal(err)
	}
	if consumed {
		t.Fatal("prefixKey should not be consumed by handlePrefix (handled by double-tap logic)")
	}
}

func TestHandlePrefixUnknown(t *testing.T) {
	var m mockConn
	consumed, err := handlePrefixW(&m, 'Q')
	if err != nil {
		t.Fatal(err)
	}
	if consumed {
		t.Fatal("should not consume unknown key")
	}
	if len(m.msgs) != 0 {
		t.Fatalf("expected no messages, got %d", len(m.msgs))
	}
}

// newProcessor creates an inputProcessor with defaults for testing.
func newProcessor(pfx byte) *inputProcessor {
	var ap atomic.Pointer[mux.AdminState]
	return &inputProcessor{
		prefixKey: pfx,
		adminPtr:  &ap,
	}
}

// feed sends bytes through the processor and returns captured messages.
func feed(p *inputProcessor, input ...byte) []mockMsg {
	var m mockConn
	p.processInput(&m, input, len(input))
	return m.msgs
}

func TestProcessInputPlainText(t *testing.T) {
	p := newProcessor(0x1d)
	msgs := feed(p, 'h', 'e', 'l', 'l', 'o')
	// Should batch into a single MsgInput.
	if len(msgs) != 1 {
		t.Fatalf("got %d msgs, want 1", len(msgs))
	}
	if msgs[0].typ != proto.MsgInput {
		t.Fatalf("type = %x, want MsgInput", msgs[0].typ)
	}
	if string(msgs[0].payload) != "hello" {
		t.Fatalf("payload = %q, want %q", msgs[0].payload, "hello")
	}
}

func TestProcessInputPrefixDetach(t *testing.T) {
	p := newProcessor(0x1d)
	msgs := feed(p, 0x1d, 'd')
	// Expect: MsgHUD(1), MsgDetach, MsgHUD(0)
	types := make([]byte, len(msgs))
	for i, m := range msgs {
		types[i] = m.typ
	}
	if len(msgs) != 3 {
		t.Fatalf("got %d msgs %v, want 3", len(msgs), types)
	}
	if msgs[0].typ != proto.MsgHUD || msgs[0].payload[0] != 1 {
		t.Fatal("expected MsgHUD(1) first")
	}
	if msgs[1].typ != proto.MsgDetach {
		t.Fatalf("expected MsgDetach, got %x", msgs[1].typ)
	}
	if msgs[2].typ != proto.MsgHUD || msgs[2].payload[0] != 0 {
		t.Fatal("expected MsgHUD(0) last")
	}
}

func TestProcessInputGotoWindow(t *testing.T) {
	p := newProcessor(0x1d)
	// prefix → g → 1 → 2 → Enter
	msgs := feed(p, 0x1d, 'g', '1', '2', '\r')
	// Expect: MsgHUD(1), MsgSelectWin(12), MsgHUD(0)
	found := false
	for _, m := range msgs {
		if m.typ == proto.MsgSelectWin && len(m.payload) == 1 && m.payload[0] == 12 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected MsgSelectWin with window index 12")
	}
}

func TestProcessInputGotoCancel(t *testing.T) {
	p := newProcessor(0x1d)
	// prefix → g → 5 → Esc (cancel)
	msgs := feed(p, 0x1d, 'g', '5', 0x1b)
	// Should NOT produce MsgSelectWin
	for _, m := range msgs {
		if m.typ == proto.MsgSelectWin {
			t.Fatal("did not expect MsgSelectWin on Esc cancel")
		}
	}
}

func TestProcessInputGotoOverflow(t *testing.T) {
	p := newProcessor(0x1d)
	// prefix → g → 9 → 9 → 9 → Enter (999 > 253, should be ignored)
	msgs := feed(p, 0x1d, 'g', '9', '9', '9', '\r')
	for _, m := range msgs {
		if m.typ == proto.MsgSelectWin {
			t.Fatal("did not expect MsgSelectWin for index > 253")
		}
	}
}

func TestProcessInputAdminPanel(t *testing.T) {
	p := newProcessor(0x1d)

	// Open admin panel: prefix → s
	msgs := feed(p, 0x1d, 's')
	found := false
	for _, m := range msgs {
		if m.typ == proto.MsgAdminPanel && len(m.payload) == 1 && m.payload[0] == 1 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected MsgAdminPanel(1) to open panel")
	}
	if !p.adminOpen {
		t.Fatal("expected adminOpen = true")
	}

	// Navigate: j=down, k=up
	msgs = feed(p, 'j')
	if len(msgs) != 1 || msgs[0].typ != proto.MsgAdminAction {
		t.Fatal("expected MsgAdminAction for 'j'")
	}
	msgs = feed(p, 'k')
	if len(msgs) != 1 || msgs[0].typ != proto.MsgAdminAction {
		t.Fatal("expected MsgAdminAction for 'k'")
	}

	// Toggle SSH (1)
	msgs = feed(p, '1')
	if len(msgs) != 1 || msgs[0].typ != proto.MsgAdminAction {
		t.Fatal("expected MsgAdminAction for '1'")
	}

	// Close with 'q'
	msgs = feed(p, 'q')
	found = false
	for _, m := range msgs {
		if m.typ == proto.MsgAdminPanel && len(m.payload) == 1 && m.payload[0] == 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected MsgAdminPanel(0) to close panel")
	}
	if p.adminOpen {
		t.Fatal("expected adminOpen = false after 'q'")
	}
}

func TestProcessInputAdminKick(t *testing.T) {
	p := newProcessor(0x1d)

	// Set admin state with a connection
	state := &mux.AdminState{
		Conns:    []mux.AdminConn{{ID: 42}},
		Selected: 0,
	}
	p.adminPtr.Store(state)
	p.adminOpen = true

	msgs := feed(p, 'x')
	if len(msgs) != 1 || msgs[0].typ != proto.MsgAdminAction {
		t.Fatal("expected MsgAdminAction for kick")
	}
	// Decode the action
	action, connID := mux.DecodeAdminAction(msgs[0].payload)
	if action != mux.AdminKick {
		t.Fatalf("action = %x, want AdminKick", action)
	}
	if connID != 42 {
		t.Fatalf("connID = %d, want 42", connID)
	}
}

func TestProcessInputMousePassthrough(t *testing.T) {
	p := newProcessor(0x1d)
	// SGR mouse: ESC[<0;10;20M
	mouse := []byte("\x1b[<0;10;20M")
	msgs := feed(p, mouse...)
	if len(msgs) != 1 {
		t.Fatalf("got %d msgs, want 1", len(msgs))
	}
	if msgs[0].typ != proto.MsgInput {
		t.Fatalf("type = %x, want MsgInput", msgs[0].typ)
	}
	if string(msgs[0].payload) != string(mouse) {
		t.Fatalf("payload = %q, want %q", msgs[0].payload, mouse)
	}
}

func TestProcessInputMouseRelease(t *testing.T) {
	p := newProcessor(0x1d)
	// SGR mouse release: ESC[<0;10;20m (lowercase m)
	mouse := []byte("\x1b[<0;10;20m")
	msgs := feed(p, mouse...)
	if len(msgs) != 1 || string(msgs[0].payload) != string(mouse) {
		t.Fatalf("expected mouse release passthrough, got %d msgs", len(msgs))
	}
}

func TestProcessInputBatchingStopsAtPrefix(t *testing.T) {
	p := newProcessor(0x1d)
	// "ab" + prefix + "d" → should produce MsgInput("ab"), MsgHUD(1), MsgDetach, MsgHUD(0)
	msgs := feed(p, 'a', 'b', 0x1d, 'd')
	if len(msgs) < 2 {
		t.Fatalf("got %d msgs, want >= 2", len(msgs))
	}
	if msgs[0].typ != proto.MsgInput || string(msgs[0].payload) != "ab" {
		t.Fatalf("first msg: type=%x payload=%q", msgs[0].typ, msgs[0].payload)
	}
	// Should contain a detach
	hasDetach := false
	for _, m := range msgs {
		if m.typ == proto.MsgDetach {
			hasDetach = true
		}
	}
	if !hasDetach {
		t.Fatal("expected MsgDetach")
	}
}

func TestProcessInputUnknownPrefixSendsBoth(t *testing.T) {
	p := newProcessor(0x1d)
	// prefix + 'z' (unknown) → should send both bytes as MsgInput
	msgs := feed(p, 0x1d, 'z')
	hasInput := false
	for _, m := range msgs {
		if m.typ == proto.MsgInput && len(m.payload) == 2 && m.payload[0] == 0x1d && m.payload[1] == 'z' {
			hasInput = true
		}
	}
	if !hasInput {
		t.Fatal("expected MsgInput with prefix+z bytes")
	}
}

func TestProcessInputLiteralPrefix(t *testing.T) {
	p := newProcessor(0x1d)
	// Two prefix keys with >300ms gap: first shows HUD, second sends literal prefix.
	// Simulate by calling processInput twice (first establishes prefix state,
	// second with same key sends literal since lastPrefixTime is old).
	feed(p, 0x1d) // sets prefix=true
	// Wait is implicit since lastPrefixTime was just set
	p.lastPrefixTime = time.Now().Add(-time.Second) // force >300ms gap
	msgs := feed(p, 0x1d)
	hasLiteral := false
	for _, m := range msgs {
		if m.typ == proto.MsgInput && len(m.payload) == 1 && m.payload[0] == 0x1d {
			hasLiteral = true
		}
	}
	if !hasLiteral {
		t.Fatal("expected literal prefix key input")
	}
}

func TestProcessInputHUDLock(t *testing.T) {
	p := newProcessor(0x1d)

	// Double-tap to lock HUD: prefix, prefix (within 300ms)
	feed(p, 0x1d) // prefix=true, shows HUD
	// Second prefix within 300ms → toggle hudLocked
	_ = feed(p, 0x1d)
	if !p.hudLocked {
		t.Fatal("expected hudLocked = true after double-tap")
	}

	// Now prefix + d should NOT hide HUD (locked)
	msgs := feed(p, 0x1d, 'd')
	for _, m := range msgs {
		if m.typ == proto.MsgHUD && len(m.payload) == 1 && m.payload[0] == 0 {
			t.Fatal("HUD should not be hidden when locked")
		}
	}
	_ = msgs
}

func TestProcessInputScrollMode(t *testing.T) {
	p := newProcessor(0x1d)

	// Enter scroll mode: prefix → [
	msgs := feed(p, 0x1d, '[')
	if !p.scrollMode {
		t.Fatal("expected scrollMode = true")
	}
	found := false
	for _, m := range msgs {
		if m.typ == proto.MsgScrollMode && len(m.payload) == 1 && m.payload[0] == 1 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected MsgScrollMode(1)")
	}

	// Scroll up with 'k'
	msgs = feed(p, 'k')
	if len(msgs) != 1 || msgs[0].typ != proto.MsgScrollAction || msgs[0].payload[0] != mux.ScrollUp {
		t.Fatal("expected ScrollUp action for 'k'")
	}

	// Scroll down with 'j'
	msgs = feed(p, 'j')
	if len(msgs) != 1 || msgs[0].typ != proto.MsgScrollAction || msgs[0].payload[0] != mux.ScrollDown {
		t.Fatal("expected ScrollDown action for 'j'")
	}

	// Half page up with Ctrl-u
	msgs = feed(p, 0x15)
	if len(msgs) != 1 || msgs[0].typ != proto.MsgScrollAction || msgs[0].payload[0] != mux.ScrollHalfUp {
		t.Fatal("expected ScrollHalfUp action for Ctrl-u")
	}

	// Half page down with Ctrl-d
	msgs = feed(p, 0x04)
	if len(msgs) != 1 || msgs[0].typ != proto.MsgScrollAction || msgs[0].payload[0] != mux.ScrollHalfDown {
		t.Fatal("expected ScrollHalfDown action for Ctrl-d")
	}

	// Top with 'g'
	msgs = feed(p, 'g')
	if len(msgs) != 1 || msgs[0].typ != proto.MsgScrollAction || msgs[0].payload[0] != mux.ScrollTop {
		t.Fatal("expected ScrollTop action for 'g'")
	}

	// Exit with 'q'
	msgs = feed(p, 'q')
	if p.scrollMode {
		t.Fatal("expected scrollMode = false after 'q'")
	}
	found = false
	for _, m := range msgs {
		if m.typ == proto.MsgScrollMode && len(m.payload) == 1 && m.payload[0] == 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected MsgScrollMode(0)")
	}
}

func TestProcessInputScrollModeExitG(t *testing.T) {
	p := newProcessor(0x1d)

	// Enter scroll mode
	feed(p, 0x1d, '[')
	if !p.scrollMode {
		t.Fatal("expected scrollMode = true")
	}

	// Exit with 'G' (go to bottom)
	msgs := feed(p, 'G')
	if p.scrollMode {
		t.Fatal("expected scrollMode = false after 'G'")
	}
	found := false
	for _, m := range msgs {
		if m.typ == proto.MsgScrollMode && len(m.payload) == 1 && m.payload[0] == 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected MsgScrollMode(0)")
	}
}

func TestProcessInputScrollModeExitEsc(t *testing.T) {
	p := newProcessor(0x1d)

	// Enter scroll mode
	feed(p, 0x1d, '[')

	// Exit with Esc
	msgs := feed(p, 0x1b)
	if p.scrollMode {
		t.Fatal("expected scrollMode = false after Esc")
	}
	found := false
	for _, m := range msgs {
		if m.typ == proto.MsgScrollMode && len(m.payload) == 1 && m.payload[0] == 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected MsgScrollMode(0)")
	}
}

func TestProcessInputScrollModeArrowKeys(t *testing.T) {
	p := newProcessor(0x1d)

	// Enter scroll mode
	feed(p, 0x1d, '[')

	// Up arrow: ESC[A
	msgs := feed(p, 0x1b, '[', 'A')
	found := false
	for _, m := range msgs {
		if m.typ == proto.MsgScrollAction && len(m.payload) == 1 && m.payload[0] == mux.ScrollUp {
			found = true
		}
	}
	if !found {
		t.Fatal("expected ScrollUp for up arrow")
	}

	// Down arrow: ESC[B
	msgs = feed(p, 0x1b, '[', 'B')
	found = false
	for _, m := range msgs {
		if m.typ == proto.MsgScrollAction && len(m.payload) == 1 && m.payload[0] == mux.ScrollDown {
			found = true
		}
	}
	if !found {
		t.Fatal("expected ScrollDown for down arrow")
	}
}

func TestProcessInputScrollModePageKeys(t *testing.T) {
	p := newProcessor(0x1d)

	// Enter scroll mode
	feed(p, 0x1d, '[')

	// Page Up: ESC[5~
	msgs := feed(p, 0x1b, '[', '5', '~')
	found := false
	for _, m := range msgs {
		if m.typ == proto.MsgScrollAction && len(m.payload) == 1 && m.payload[0] == mux.ScrollHalfUp {
			found = true
		}
	}
	if !found {
		t.Fatal("expected ScrollHalfUp for Page Up")
	}

	// Page Down: ESC[6~
	msgs = feed(p, 0x1b, '[', '6', '~')
	found = false
	for _, m := range msgs {
		if m.typ == proto.MsgScrollAction && len(m.payload) == 1 && m.payload[0] == mux.ScrollHalfDown {
			found = true
		}
	}
	if !found {
		t.Fatal("expected ScrollHalfDown for Page Down")
	}
}

func TestProcessInputScrollModeIgnoresOtherKeys(t *testing.T) {
	p := newProcessor(0x1d)

	// Enter scroll mode
	feed(p, 0x1d, '[')

	// Regular keys should be consumed silently (not forwarded as input)
	msgs := feed(p, 'a', 'b', 'c')
	for _, m := range msgs {
		if m.typ == proto.MsgInput {
			t.Fatal("scroll mode should not forward regular keys as input")
		}
	}
}

func TestValidateUsername(t *testing.T) {
	valid := []string{"rasengan", "ab", "a-b", "user123"}
	for _, s := range valid {
		if err := validateUsername(s); err != nil {
			t.Errorf("validateUsername(%q) = %v, want nil", s, err)
		}
	}
	invalid := []string{"", "a", "-ab", "ab-", "AB", "a b", "a_b",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} // 34 chars
	for _, s := range invalid {
		if err := validateUsername(s); err == nil {
			t.Errorf("validateUsername(%q) = nil, want error", s)
		}
	}
}

func TestValidateDevice(t *testing.T) {
	valid := []string{"macbook", "server-1", "Host.local", "a"}
	for _, s := range valid {
		if err := validateDevice(s); err != nil {
			t.Errorf("validateDevice(%q) = %v, want nil", s, err)
		}
	}
	invalid := []string{"", "a b", "foo/bar"}
	for _, s := range invalid {
		if err := validateDevice(s); err == nil {
			t.Errorf("validateDevice(%q) = nil, want error", s)
		}
	}
}
