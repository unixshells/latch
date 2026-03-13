package mux

import "testing"

func TestAdminStateRoundtrip(t *testing.T) {
	state := &AdminState{
		SSHEnabled:   true,
		RelayEnabled: false,
		Selected:     1,
		Conns: []AdminConn{
			{ID: 42, Source: "ssh", RemoteAddr: "1.2.3.4:22", KeyComment: "friend@laptop", Session: "default", Duration: "5m"},
			{ID: 99, Source: "relay", RemoteAddr: "5.6.7.8:0", KeyComment: "", Session: "work", Duration: "12s"},
		},
	}

	data := EncodeAdminState(state)
	got := DecodeAdminState(data)

	if got == nil {
		t.Fatal("decode returned nil")
	}
	if got.SSHEnabled != true {
		t.Fatal("ssh should be enabled")
	}
	if got.RelayEnabled != false {
		t.Fatal("relay should be disabled")
	}
	if got.Selected != 1 {
		t.Fatalf("selected = %d, want 1", got.Selected)
	}
	if len(got.Conns) != 2 {
		t.Fatalf("got %d conns, want 2", len(got.Conns))
	}
	if got.Conns[0].ID != 42 {
		t.Fatalf("conn 0 ID = %d, want 42", got.Conns[0].ID)
	}
	if got.Conns[0].KeyComment != "friend@laptop" {
		t.Fatalf("conn 0 comment = %q", got.Conns[0].KeyComment)
	}
	if got.Conns[1].Source != "relay" {
		t.Fatalf("conn 1 source = %q", got.Conns[1].Source)
	}
}

func TestAdminActionRoundtrip(t *testing.T) {
	data := EncodeAdminAction(AdminKick, 12345)
	action, id := DecodeAdminAction(data)
	if action != AdminKick {
		t.Fatalf("action = %d, want %d", action, AdminKick)
	}
	if id != 12345 {
		t.Fatalf("id = %d, want 12345", id)
	}
}

func TestRenderAdminSmallTerminal(t *testing.T) {
	state := &AdminState{SSHEnabled: true, RelayEnabled: true}
	buf := RenderAdmin(state, 10, 5)
	if buf != nil {
		t.Fatal("should return nil for small terminal")
	}
}

func TestRenderAdminNormal(t *testing.T) {
	state := &AdminState{
		SSHEnabled:   true,
		RelayEnabled: false,
		Conns: []AdminConn{
			{ID: 1, Source: "ssh", RemoteAddr: "1.2.3.4", Duration: "2m"},
		},
	}
	buf := RenderAdmin(state, 80, 24)
	if len(buf) == 0 {
		t.Fatal("expected non-empty output")
	}
}

func TestRenderAdminSelectedOutOfBounds(t *testing.T) {
	state := &AdminState{
		SSHEnabled: true,
		Selected:   999,
		Conns: []AdminConn{
			{ID: 1, Source: "ssh", RemoteAddr: "1.2.3.4", Duration: "1m"},
			{ID: 2, Source: "web", RemoteAddr: "5.6.7.8", Duration: "2m"},
		},
	}
	// Must not panic even though Selected=999 exceeds len(Conns)=2.
	buf := RenderAdmin(state, 80, 24)
	if len(buf) == 0 {
		t.Fatal("expected non-empty output")
	}
}

func TestRenderAdminEmptyConns(t *testing.T) {
	state := &AdminState{
		SSHEnabled: false,
		Conns:      nil,
	}
	// Must not panic with zero connections.
	buf := RenderAdmin(state, 80, 24)
	if len(buf) == 0 {
		t.Fatal("expected non-empty output for empty conns (shows 'none')")
	}
}

func TestVisLen(t *testing.T) {
	if n := visLen([]byte("hello")); n != 5 {
		t.Fatalf("visLen plain = %d, want 5", n)
	}
	if n := visLen([]byte("\x1b[38;5;75mhello\x1b[0m")); n != 5 {
		t.Fatalf("visLen with escapes = %d, want 5", n)
	}
}
