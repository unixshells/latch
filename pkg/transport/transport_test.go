package transport

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestKeyGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host_key")

	if err := GenerateHostKey(path); err != nil {
		t.Fatal(err)
	}

	signer, err := LoadHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if signer.PublicKey().Type() != "ssh-ed25519" {
		t.Fatalf("key type = %s, want ssh-ed25519", signer.PublicKey().Type())
	}
}

func TestAutoGenerateKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "host_key")

	// Should auto-generate
	signer, err := LoadHostKey(path)
	if err != nil {
		t.Fatal(err)
	}

	// Should load the same key
	signer2, err := LoadHostKey(path)
	if err != nil {
		t.Fatal(err)
	}

	fp1 := ssh.FingerprintSHA256(signer.PublicKey())
	fp2 := ssh.FingerprintSHA256(signer2.PublicKey())
	if fp1 != fp2 {
		t.Fatal("loaded key differs")
	}
}

func TestAuthorizedKeysEmpty(t *testing.T) {
	keys, err := LoadAuthorizedKeys("/nonexistent/authorized_keys")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected nil, got %d keys", len(keys))
	}
}

func TestAuthorizedKeysRoundtrip(t *testing.T) {
	dir := t.TempDir()

	// Generate a host key to use as an authorized key
	keyPath := filepath.Join(dir, "test_key")
	if err := GenerateHostKey(keyPath); err != nil {
		t.Fatal(err)
	}
	signer, err := LoadHostKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Write it as an authorized key
	authPath := filepath.Join(dir, "authorized_keys")
	pubBytes := ssh.MarshalAuthorizedKey(signer.PublicKey())
	if err := writeFile(authPath, pubBytes, 0600); err != nil {
		t.Fatal(err)
	}

	keys, err := LoadAuthorizedKeys(authPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}

	if string(keys[0].Key.Marshal()) != string(signer.PublicKey().Marshal()) {
		t.Fatal("key mismatch")
	}
}

func TestAuthorizedKeysWithComments(t *testing.T) {
	dir := t.TempDir()

	// Generate two keys
	key1Path := filepath.Join(dir, "key1")
	key2Path := filepath.Join(dir, "key2")
	if err := GenerateHostKey(key1Path); err != nil {
		t.Fatal(err)
	}
	if err := GenerateHostKey(key2Path); err != nil {
		t.Fatal(err)
	}
	signer1, err := LoadHostKey(key1Path)
	if err != nil {
		t.Fatal(err)
	}
	signer2, err := LoadHostKey(key2Path)
	if err != nil {
		t.Fatal(err)
	}

	// Write authorized_keys with blank lines and comments
	pub1 := ssh.MarshalAuthorizedKey(signer1.PublicKey())
	pub2 := ssh.MarshalAuthorizedKey(signer2.PublicKey())
	var content []byte
	content = append(content, "# This is a comment\n"...)
	content = append(content, '\n') // blank line
	content = append(content, pub1...)
	content = append(content, "# Another comment\n"...)
	content = append(content, '\n')
	content = append(content, pub2...)

	authPath := filepath.Join(dir, "authorized_keys")
	if err := writeFile(authPath, content, 0600); err != nil {
		t.Fatal(err)
	}

	keys, err := LoadAuthorizedKeys(authPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
	if string(keys[0].Key.Marshal()) != string(signer1.PublicKey().Marshal()) {
		t.Fatal("key 1 mismatch")
	}
	if string(keys[1].Key.Marshal()) != string(signer2.PublicKey().Marshal()) {
		t.Fatal("key 2 mismatch")
	}
}

func TestAuthorizedKeysComment(t *testing.T) {
	dir := t.TempDir()

	keyPath := filepath.Join(dir, "key")
	if err := GenerateHostKey(keyPath); err != nil {
		t.Fatal(err)
	}
	signer, err := LoadHostKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Write authorized_keys with a comment field
	pub := ssh.MarshalAuthorizedKey(signer.PublicKey())
	// MarshalAuthorizedKey appends \n; insert comment before it
	line := make([]byte, 0, len(pub)+len(" friend@laptop\n"))
	line = append(line, pub[:len(pub)-1]...)
	line = append(line, []byte(" friend@laptop\n")...)

	authPath := filepath.Join(dir, "authorized_keys")
	if err := writeFile(authPath, line, 0600); err != nil {
		t.Fatal(err)
	}

	keys, err := LoadAuthorizedKeys(authPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	if keys[0].Comment != "friend@laptop" {
		t.Fatalf("comment = %q, want %q", keys[0].Comment, "friend@laptop")
	}
}

func TestTLSGenerate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")

	cert, err := LoadOrGenerateTLS(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("no certificate")
	}

	// Should load the same cert
	cert2, err := LoadOrGenerateTLS(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert2.Certificate) == 0 {
		t.Fatal("no certificate on reload")
	}
}

func TestTLSCertFields(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")

	cert, err := LoadOrGenerateTLS(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if x509Cert.Subject.CommonName != "latch" {
		t.Fatalf("CN = %q, want 'latch'", x509Cert.Subject.CommonName)
	}
}

func TestRelayKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.key")

	signer, pub, err := LoadOrGenerateRelayKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if signer == nil {
		t.Fatal("signer is nil")
	}
	if pub.Type() != "ssh-ed25519" {
		t.Fatalf("key type = %s, want ssh-ed25519", pub.Type())
	}

	// Reload should return same key.
	_, pub2, err := LoadOrGenerateRelayKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if ssh.FingerprintSHA256(pub) != ssh.FingerprintSHA256(pub2) {
		t.Fatal("relay key changed on reload")
	}
}

func TestHostKeyRejectsWorldWritable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host_key")

	// Generate a valid key first.
	if err := GenerateHostKey(path); err != nil {
		t.Fatal(err)
	}
	// Make it world-writable.
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	_, err := LoadHostKey(path)
	if err == nil {
		t.Fatal("expected error for world-writable key file")
	}
}

func TestAuthorizedKeysRejectsWorldWritable(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := GenerateHostKey(keyPath); err != nil {
		t.Fatal(err)
	}
	signer, err := LoadHostKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	authPath := filepath.Join(dir, "authorized_keys")
	pub := ssh.MarshalAuthorizedKey(signer.PublicKey())
	os.WriteFile(authPath, pub, 0644)
	os.Chmod(authPath, 0666)
	_, err = LoadAuthorizedKeys(authPath)
	if err == nil {
		t.Fatal("expected error for world-writable authorized_keys")
	}
}

func writeFile(path string, data []byte, perm uint32) error {
	return os.WriteFile(path, data, os.FileMode(perm))
}
