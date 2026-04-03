package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config holds all configurable latch settings.
type Config struct {
	PrefixKey       byte   // prefix key byte (default: 0x1d = Ctrl-])
	Shell           string // shell to spawn (default: $SHELL or /bin/sh)
	ScrollbackLines int    // VT scrollback lines (default: 10000)
	MaxSessions     int    // max concurrent sessions (default: 64)
	Mouse           bool   // enable mouse support (default: true)

	// Rendering
	RenderCoalesceMs int // render coalesce delay in ms (default: 2)

	// Network defaults
	SSHAddr string // default SSH listen address (default: :2222)
	WebAddr string // default web listen address (default: :7680)

	// Server mode
	Persistent bool // keep running even when all sessions/clients disconnect

	// Relay
	RelayHost    string // API server host (default: unixshells.com)
	RelayNode    string // QUIC relay hostname (regional, e.g. us.unixshells.com)
	RelayUser    string // relay account username
	RelayDevice  string // device name (default: OS hostname)
	RelayEnabled bool   // whether relay is enabled
	RelayCAFile  string // CA certificate file for relay TLS verification

	APIEnabled bool // whether API access (send/screen) is enabled
}

// Default returns a Config with default values.
func Default() *Config {
	return &Config{
		PrefixKey:        0x1d, // Ctrl-]
		ScrollbackLines:  10000,
		MaxSessions:      64,
		Mouse:            false,
		RenderCoalesceMs: 2,
		SSHAddr:          ":2222",
		WebAddr:          ":7680",
		APIEnabled:       false,
	}
}

// Path returns the default config file path.
func Path() string {
	dir := os.Getenv("HOME")
	if dir == "" {
		panic("latch: HOME not set")
	}
	return filepath.Join(dir, ".latch", "config")
}

// Load reads config from the given path. Missing file returns defaults.
func Load(path string) (*Config, error) {
	cfg := Default()
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat config: %w", err)
	}
	if info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("config %s is group/world writable (mode %04o)", path, info.Mode().Perm())
	}

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: missing '='", path, lineNum)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if err := cfg.set(key, val); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNum, err)
		}
	}
	return cfg, scanner.Err()
}

func (c *Config) set(key, val string) error {
	switch key {
	case "prefix":
		b, err := parsePrefix(val)
		if err != nil {
			return err
		}
		c.PrefixKey = b
	case "shell":
		if !filepath.IsAbs(val) {
			return fmt.Errorf("shell must be an absolute path: %s", val)
		}
		c.Shell = val
	case "scrollback":
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 || n > 1000000 {
			return fmt.Errorf("invalid scrollback: %s (0-1000000)", val)
		}
		c.ScrollbackLines = n
	case "max-sessions":
		n, err := strconv.Atoi(val)
		if err != nil || n < 1 || n > 1000 {
			return fmt.Errorf("invalid max-sessions: %s (1-1000)", val)
		}
		c.MaxSessions = n
	case "mouse":
		switch val {
		case "true", "yes", "on", "1":
			c.Mouse = true
		case "false", "no", "off", "0":
			c.Mouse = false
		default:
			return fmt.Errorf("invalid mouse value: %s (true/false/yes/no/on/off/1/0)", val)
		}
	case "render-coalesce-ms":
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 || n > 10000 {
			return fmt.Errorf("invalid render-coalesce-ms: %s (0-10000)", val)
		}
		c.RenderCoalesceMs = n
	case "ssh-addr":
		c.SSHAddr = val
	case "web-addr":
		c.WebAddr = val
	case "relay-host":
		c.RelayHost = val
	case "relay-node":
		c.RelayNode = val
	case "relay-user":
		c.RelayUser = val
	case "relay-device":
		c.RelayDevice = val
	case "relay-ca":
		if !filepath.IsAbs(val) {
			return fmt.Errorf("relay-ca must be an absolute path: %s", val)
		}
		c.RelayCAFile = val
	case "relay-enabled":
		switch val {
		case "true", "yes", "on", "1":
			c.RelayEnabled = true
		case "false", "no", "off", "0":
			c.RelayEnabled = false
		default:
			return fmt.Errorf("invalid relay-enabled value: %s (true/false/yes/no/on/off/1/0)", val)
		}
	case "api-enabled":
		switch val {
		case "true", "yes", "on", "1":
			c.APIEnabled = true
		case "false", "no", "off", "0":
			c.APIEnabled = false
		default:
			return fmt.Errorf("invalid api-enabled value: %s (true/false/yes/no/on/off/1/0)", val)
		}
	default:
		return fmt.Errorf("unknown key: %s", key)
	}
	return nil
}

// SetKey updates or appends a key=value pair in the config file.
// Creates the file if it doesn't exist.
func SetKey(path, key, val string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Read existing lines.
	var lines []string
	data, err := os.ReadFile(path)
	if err == nil {
		lines = strings.Split(string(data), "\n")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read config: %w", err)
	}

	// Find and replace existing key.
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed[0] == '#' {
			continue
		}
		k, _, ok := strings.Cut(trimmed, "=")
		if ok && strings.TrimSpace(k) == key {
			lines[i] = key + " = " + val
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, key+" = "+val)
	}

	// Ensure file ends with a newline.
	content := strings.Join(lines, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	return os.WriteFile(path, []byte(content), 0600)
}

// RemoveKeys removes all lines matching the given keys from the config file.
func RemoveKeys(path string, keys ...string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read config: %w", err)
	}

	remove := make(map[string]bool, len(keys))
	for _, k := range keys {
		remove[k] = true
	}

	lines := strings.Split(string(data), "\n")
	var out []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && trimmed[0] != '#' {
			k, _, ok := strings.Cut(trimmed, "=")
			if ok && remove[strings.TrimSpace(k)] {
				continue
			}
		}
		out = append(out, line)
	}

	content := strings.Join(out, "\n")
	return os.WriteFile(path, []byte(content), 0600)
}

// parsePrefix parses a prefix key specification.
// Accepts: "C-]", "C-a", "C-b", or a raw byte like "0x1d".
func parsePrefix(s string) (byte, error) {
	if strings.HasPrefix(s, "C-") && len(s) == 3 {
		ch := s[2]
		if ch >= 'a' && ch <= 'z' {
			return ch - 'a' + 1, nil
		}
		if ch >= 'A' && ch <= 'Z' {
			return ch - 'A' + 1, nil
		}
		if ch >= '[' && ch <= '_' {
			return ch - '@', nil
		}
		return 0, fmt.Errorf("invalid prefix: %s", s)
	}
	if strings.HasPrefix(s, "0x") {
		n, err := strconv.ParseUint(s, 0, 8)
		if err != nil {
			return 0, fmt.Errorf("invalid prefix hex: %s", s)
		}
		return byte(n), nil
	}
	return 0, fmt.Errorf("invalid prefix: %s (use C-] or 0x1d format)", s)
}
