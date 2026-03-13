package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// homeDir returns $HOME or panics. Latch requires HOME to resolve paths
// for keys, config, and sockets. Every caller up the stack catches panics
// from user-facing entry points, so this is recoverable in tests.
func homeDir() string {
	dir := os.Getenv("HOME")
	if dir == "" {
		panic("latch: HOME not set")
	}
	return dir
}

// KeyPath returns the default host key path.
func KeyPath() string {
	return filepath.Join(homeDir(), ".latch", "host_key")
}

// GenerateHostKey creates a new ed25519 key pair and saves the private key
// in OpenSSH format.
func GenerateHostKey(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	data := pem.EncodeToMemory(block)
	defer func() {
		for i := range data {
			data[i] = 0
		}
		for i := range block.Bytes {
			block.Bytes[i] = 0
		}
	}()
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}

// LoadHostKey reads an ed25519 private key from file.
// If the file doesn't exist, generates a new key first.
func LoadHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		if err := GenerateHostKey(path); err != nil {
			return nil, err
		}
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		return nil, fmt.Errorf("stat key: %w", statErr)
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("host key %s has unsafe permissions %04o (must be 0600 or stricter)", path, info.Mode().Perm())
	}
	defer func() {
		for i := range data {
			data[i] = 0
		}
	}()
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	return signer, nil
}

// AuthorizedKeysPath returns the default authorized_keys path.
func AuthorizedKeysPath() string {
	return filepath.Join(homeDir(), ".latch", "authorized_keys")
}

// AuthorizedKey holds a parsed public key and its comment.
type AuthorizedKey struct {
	Key     ssh.PublicKey
	Comment string
}

// LoadAuthorizedKeys reads public keys from an authorized_keys file.
// Returns nil (no keys) if the file doesn't exist.
// Rejects the file if permissions are too open (must be 0600 or stricter).
func LoadAuthorizedKeys(path string) ([]AuthorizedKey, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stat authorized_keys: %w", err)
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("authorized_keys %s has unsafe permissions %04o (must be 0600 or stricter)", path, info.Mode().Perm())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read authorized_keys: %w", err)
	}

	var keys []AuthorizedKey
	for len(data) > 0 {
		// Skip blank lines and comments.
		if line, rest, ok := cutLine(data); ok {
			trimmed := bytes.TrimSpace(line)
			if len(trimmed) == 0 || trimmed[0] == '#' {
				data = rest
				continue
			}
		}
		key, comment, _, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			// Skip unparseable line and continue.
			if _, rest, ok := cutLine(data); ok {
				data = rest
				continue
			}
			break
		}
		keys = append(keys, AuthorizedKey{Key: key, Comment: comment})
		data = rest
	}
	return keys, nil
}

// RelayKeyPath returns the default relay key path.
func RelayKeyPath() string {
	return filepath.Join(homeDir(), ".latch", "relay.key")
}

// LoadOrGenerateRelayKey loads or creates the relay Ed25519 keypair.
// Returns the signer and the SSH public key.
func LoadOrGenerateRelayKey(path string) (ssh.Signer, ssh.PublicKey, error) {
	signer, err := LoadHostKey(path)
	if err != nil {
		return nil, nil, err
	}
	return signer, signer.PublicKey(), nil
}

// GenerateRelayKey always generates a new relay Ed25519 keypair at path.
// Returns the signer and the SSH public key.
func GenerateRelayKey(path string) (ssh.Signer, ssh.PublicKey, error) {
	if err := GenerateHostKey(path); err != nil {
		return nil, nil, err
	}
	signer, err := LoadHostKey(path)
	if err != nil {
		return nil, nil, err
	}
	return signer, signer.PublicKey(), nil
}

// cutLine splits data at the first newline, returning the line and the rest.
func cutLine(data []byte) (line, rest []byte, ok bool) {
	i := bytes.IndexByte(data, '\n')
	if i < 0 {
		return data, nil, len(data) > 0
	}
	return data[:i], data[i+1:], true
}
