package client

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/unixshells/latch/pkg/transport"
	"golang.org/x/crypto/ssh"
)

// AuthAdd adds a public key to ~/.latch/authorized_keys.
// key can be a path to a file or an inline key string.
func AuthAdd(key string) error {
	// Try reading as a file first.
	data, err := os.ReadFile(key)
	if err != nil {
		// Not a file, treat as inline key.
		data = []byte(key)
	}

	// Validate it parses as a public key.
	pub, comment, _, _, err := ssh.ParseAuthorizedKey(bytes.TrimSpace(data))
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	path := transport.AuthorizedKeysPath()
	if err := os.MkdirAll(dirOf(path), 0700); err != nil {
		return err
	}

	// Check for duplicates.
	existing, _ := transport.LoadAuthorizedKeys(path)
	pubBytes := pub.Marshal()
	for _, k := range existing {
		if bytes.Equal(k.Key.Marshal(), pubBytes) {
			return fmt.Errorf("key already exists (%s)", k.Comment)
		}
	}

	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if comment != "" {
		line = line + " " + comment
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = fmt.Fprintln(f, line)
	if err != nil {
		return err
	}
	fmt.Printf("key added (%s %s)\n", pub.Type(), comment)
	return nil
}

// AuthList prints the keys in ~/.latch/authorized_keys.
func AuthList() error {
	keys, err := transport.LoadAuthorizedKeys(transport.AuthorizedKeysPath())
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		fmt.Println("no authorized keys")
		return nil
	}
	for _, k := range keys {
		fp := ssh.FingerprintSHA256(k.Key)
		name := k.Comment
		if name == "" {
			name = "(no comment)"
		}
		fmt.Printf("  %s  %s  %s\n", k.Key.Type(), fp, name)
	}
	return nil
}

// AuthRemove removes a key from ~/.latch/authorized_keys by fingerprint or comment.
func AuthRemove(match string) error {
	path := transport.AuthorizedKeysPath()
	keys, err := transport.LoadAuthorizedKeys(path)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Find which key matches.
	var target ssh.PublicKey
	for _, k := range keys {
		fp := ssh.FingerprintSHA256(k.Key)
		if fp == match || k.Comment == match {
			target = k.Key
			break
		}
	}
	if target == nil {
		return fmt.Errorf("no key matching %q", match)
	}

	targetBytes := target.Marshal()

	// Rewrite the file without the matching key.
	var out []byte
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed[0] == '#' {
			out = append(out, []byte(line+"\n")...)
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(trimmed))
		if err != nil {
			out = append(out, []byte(line+"\n")...)
			continue
		}
		if bytes.Equal(pub.Marshal(), targetBytes) {
			continue // skip this key
		}
		out = append(out, []byte(line+"\n")...)
	}

	if err := os.WriteFile(path, out, 0600); err != nil {
		return err
	}
	fmt.Println("key removed")
	return nil
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
