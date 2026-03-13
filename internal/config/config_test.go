package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg.PrefixKey != 0x1d {
		t.Fatalf("prefix: got 0x%02x, want 0x1d", cfg.PrefixKey)
	}
	if cfg.MaxSessions != 64 {
		t.Fatalf("max-sessions: got %d, want 64", cfg.MaxSessions)
	}
	if !cfg.Mouse {
		t.Fatal("mouse: expected true")
	}
}

func TestLoadMissing(t *testing.T) {
	cfg, err := Load("/nonexistent/config")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PrefixKey != 0x1d {
		t.Fatalf("expected defaults on missing file")
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	data := `# latch config
prefix = C-b
scrollback = 5000
max-sessions = 32
mouse = false
shell = /bin/zsh
render-coalesce-ms = 5
ssh-addr = :3333
web-addr = :8080
`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PrefixKey != 0x02 { // Ctrl-b
		t.Fatalf("prefix: got 0x%02x, want 0x02", cfg.PrefixKey)
	}
	if cfg.ScrollbackLines != 5000 {
		t.Fatalf("scrollback: got %d, want 5000", cfg.ScrollbackLines)
	}
	if cfg.MaxSessions != 32 {
		t.Fatalf("max-sessions: got %d, want 32", cfg.MaxSessions)
	}
	if cfg.Mouse {
		t.Fatal("mouse: expected false")
	}
	if cfg.Shell != "/bin/zsh" {
		t.Fatalf("shell: got %s, want /bin/zsh", cfg.Shell)
	}
	if cfg.RenderCoalesceMs != 5 {
		t.Fatalf("render-coalesce-ms: got %d, want 5", cfg.RenderCoalesceMs)
	}
	if cfg.SSHAddr != ":3333" {
		t.Fatalf("ssh-addr: got %s, want :3333", cfg.SSHAddr)
	}
}

func TestParsePrefix(t *testing.T) {
	tests := []struct {
		input string
		want  byte
	}{
		{"C-a", 0x01},
		{"C-b", 0x02},
		{"C-]", 0x1d},
		{"C-[", 0x1b},
		{"0x1d", 0x1d},
		{"0x02", 0x02},
	}
	for _, tt := range tests {
		b, err := parsePrefix(tt.input)
		if err != nil {
			t.Errorf("parsePrefix(%q): %v", tt.input, err)
			continue
		}
		if b != tt.want {
			t.Errorf("parsePrefix(%q): got 0x%02x, want 0x%02x", tt.input, b, tt.want)
		}
	}
}

func TestLoadBadKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	os.WriteFile(path, []byte("badkey = 1\n"), 0644)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestScrollbackBounds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")

	// Over max
	os.WriteFile(path, []byte("scrollback = 2000000\n"), 0644)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for scrollback > 1000000")
	}

	// Valid max
	os.WriteFile(path, []byte("scrollback = 1000000\n"), 0644)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ScrollbackLines != 1000000 {
		t.Fatalf("scrollback: got %d, want 1000000", cfg.ScrollbackLines)
	}
}

func TestMaxSessionsBounds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")

	os.WriteFile(path, []byte("max-sessions = 1001\n"), 0644)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for max-sessions > 1000")
	}

	os.WriteFile(path, []byte("max-sessions = 0\n"), 0644)
	_, err = Load(path)
	if err == nil {
		t.Fatal("expected error for max-sessions < 1")
	}
}

func TestRenderCoalesceBounds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")

	os.WriteFile(path, []byte("render-coalesce-ms = 20000\n"), 0644)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for render-coalesce-ms > 10000")
	}
}

func TestLoadWorldWritable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	os.WriteFile(path, []byte("mouse = true\n"), 0600)
	os.Chmod(path, 0666)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for world-writable config")
	}
}

func TestMouseInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	os.WriteFile(path, []byte("mouse = banana\n"), 0600)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid mouse value")
	}
}

func TestRelayConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	data := `relay-host = unixshells.com
relay-node = us.unixshells.com
relay-user = rasengan
relay-device = macbook
relay-enabled = true
relay-ca = /etc/latch/relay-ca.pem
`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RelayHost != "unixshells.com" {
		t.Fatalf("relay-host: got %s, want unixshells.com", cfg.RelayHost)
	}
	if cfg.RelayNode != "us.unixshells.com" {
		t.Fatalf("relay-node: got %s, want us.unixshells.com", cfg.RelayNode)
	}
	if cfg.RelayUser != "rasengan" {
		t.Fatalf("relay-user: got %s, want rasengan", cfg.RelayUser)
	}
	if cfg.RelayDevice != "macbook" {
		t.Fatalf("relay-device: got %s, want macbook", cfg.RelayDevice)
	}
	if !cfg.RelayEnabled {
		t.Fatal("relay-enabled: expected true")
	}
	if cfg.RelayCAFile != "/etc/latch/relay-ca.pem" {
		t.Fatalf("relay-ca: got %s, want /etc/latch/relay-ca.pem", cfg.RelayCAFile)
	}
}

func TestSetKeyNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")

	if err := SetKey(path, "relay-enabled", "true"); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RelayEnabled {
		t.Fatal("expected relay-enabled = true")
	}
}

func TestSetKeyReplace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	os.WriteFile(path, []byte("relay-enabled = false\nmouse = true\n"), 0600)

	if err := SetKey(path, "relay-enabled", "true"); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RelayEnabled {
		t.Fatal("expected relay-enabled = true after replace")
	}
	if !cfg.Mouse {
		t.Fatal("expected mouse = true preserved")
	}
}

func TestSetKeyAppend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	os.WriteFile(path, []byte("mouse = false\n"), 0600)

	if err := SetKey(path, "relay-enabled", "true"); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RelayEnabled {
		t.Fatal("expected relay-enabled appended")
	}
	if cfg.Mouse {
		t.Fatal("expected mouse = false preserved")
	}
}

func TestParsePrefixSpecialChars(t *testing.T) {
	tests := []struct {
		input string
		want  byte
	}{
		{"C-^", 0x1e},
		{"C-_", 0x1f},
		{"C-\\", 0x1c},
	}
	for _, tt := range tests {
		b, err := parsePrefix(tt.input)
		if err != nil {
			t.Errorf("parsePrefix(%q): %v", tt.input, err)
			continue
		}
		if b != tt.want {
			t.Errorf("parsePrefix(%q): got 0x%02x, want 0x%02x", tt.input, b, tt.want)
		}
	}
}
