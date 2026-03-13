package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func genTestKey(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshPub, string(ssh.MarshalAuthorizedKey(sshPub))
}

func writePubFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func setupAuthDir(t *testing.T) (string, func()) {
	t.Helper()
	orig := os.Getenv("HOME")
	dir := t.TempDir()
	os.Setenv("HOME", dir)
	os.MkdirAll(filepath.Join(dir, ".latch"), 0700)
	return dir, func() { os.Setenv("HOME", orig) }
}

func TestAuthAddInline(t *testing.T) {
	_, cleanup := setupAuthDir(t)
	defer cleanup()

	_, keyStr := genTestKey(t)
	if err := AuthAdd(strings.TrimSpace(keyStr)); err != nil {
		t.Fatal(err)
	}

	if err := AuthList(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthAddFile(t *testing.T) {
	dir, cleanup := setupAuthDir(t)
	defer cleanup()

	_, keyStr := genTestKey(t)
	pubFile := writePubFile(t, dir, "test.pub", keyStr)

	if err := AuthAdd(pubFile); err != nil {
		t.Fatal(err)
	}
}

func TestAuthAddDuplicate(t *testing.T) {
	_, cleanup := setupAuthDir(t)
	defer cleanup()

	_, keyStr := genTestKey(t)
	key := strings.TrimSpace(keyStr)

	if err := AuthAdd(key); err != nil {
		t.Fatal(err)
	}
	if err := AuthAdd(key); err == nil {
		t.Fatal("expected error for duplicate key")
	}
}

func TestAuthAddInvalid(t *testing.T) {
	_, cleanup := setupAuthDir(t)
	defer cleanup()

	if err := AuthAdd("not-a-key"); err == nil {
		t.Fatal("expected error for invalid key")
	}
}

func TestAuthListEmpty(t *testing.T) {
	_, cleanup := setupAuthDir(t)
	defer cleanup()

	if err := AuthList(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthRemoveByComment(t *testing.T) {
	_, cleanup := setupAuthDir(t)
	defer cleanup()

	pub, _ := genTestKey(t)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " testuser@laptop"
	if err := AuthAdd(line); err != nil {
		t.Fatal(err)
	}

	if err := AuthRemove("testuser@laptop"); err != nil {
		t.Fatal(err)
	}

	// Should be empty now.
	home := os.Getenv("HOME")
	data, _ := os.ReadFile(filepath.Join(home, ".latch", "authorized_keys"))
	if strings.TrimSpace(string(data)) != "" {
		t.Fatalf("expected empty file, got %q", data)
	}
}

func TestAuthRemoveByFingerprint(t *testing.T) {
	_, cleanup := setupAuthDir(t)
	defer cleanup()

	pub, keyStr := genTestKey(t)
	if err := AuthAdd(strings.TrimSpace(keyStr)); err != nil {
		t.Fatal(err)
	}

	fp := ssh.FingerprintSHA256(pub)
	if err := AuthRemove(fp); err != nil {
		t.Fatal(err)
	}
}

func TestAuthRemoveNotFound(t *testing.T) {
	_, cleanup := setupAuthDir(t)
	defer cleanup()

	_, keyStr := genTestKey(t)
	if err := AuthAdd(strings.TrimSpace(keyStr)); err != nil {
		t.Fatal(err)
	}

	if err := AuthRemove("nonexistent"); err == nil {
		t.Fatal("expected error for non-matching key")
	}
}

func TestAuthMultipleKeys(t *testing.T) {
	_, cleanup := setupAuthDir(t)
	defer cleanup()

	_, k1 := genTestKey(t)
	_, k2 := genTestKey(t)
	_, k3 := genTestKey(t)

	for _, k := range []string{k1, k2, k3} {
		if err := AuthAdd(strings.TrimSpace(k)); err != nil {
			t.Fatal(err)
		}
	}

	// Remove the middle one by fingerprint.
	pub2, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(k2))
	fp2 := ssh.FingerprintSHA256(pub2)
	if err := AuthRemove(fp2); err != nil {
		t.Fatal(err)
	}

	// Should have 2 keys left.
	home := os.Getenv("HOME")
	data, _ := os.ReadFile(filepath.Join(home, ".latch", "authorized_keys"))
	lines := 0
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) != "" {
			lines++
		}
	}
	if lines != 2 {
		t.Fatalf("expected 2 keys, got %d", lines)
	}
}
