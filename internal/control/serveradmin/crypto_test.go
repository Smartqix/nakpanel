package serveradmin

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey(seed byte) []byte {
	return bytes.Repeat([]byte{seed}, envelopeKeyBytes)
}

func TestKeyringRoundTripUsesEnvelopeEncryption(t *testing.T) {
	keyring, err := NewKeyring(1, map[int][]byte{1: testKey(0x11)})
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("relay-password")
	aad := []byte("mail:smarthost")

	envelope, err := keyring.Seal(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Algorithm != EnvelopeAlgorithm || envelope.KeyVersion != 1 {
		t.Fatalf("envelope metadata = %+v", envelope)
	}
	if bytes.Contains(envelope.Ciphertext, plaintext) || bytes.Contains(envelope.WrappedDataKey, plaintext) {
		t.Fatal("encrypted envelope contains plaintext")
	}

	opened, err := keyring.Open(envelope, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened = %q, want %q", opened, plaintext)
	}
}

func TestKeyringBindsCiphertextToSecretIdentity(t *testing.T) {
	keyring, err := NewKeyring(1, map[int][]byte{1: testKey(0x22)})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := keyring.Seal([]byte("database-password"), []byte("database:primary"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := keyring.Open(envelope, []byte("database:secondary")); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Open wrong identity error = %v, want ErrInvalidEnvelope", err)
	}

	tampered := envelope
	tampered.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	tampered.Ciphertext[len(tampered.Ciphertext)-1] ^= 0xff
	if _, err := keyring.Open(tampered, []byte("database:primary")); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Open tampered error = %v, want ErrInvalidEnvelope", err)
	}
}

func TestKeyringRotatesFromRetainedOldKey(t *testing.T) {
	oldRing, err := NewKeyring(1, map[int][]byte{1: testKey(0x31)})
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("registry:docker")
	oldEnvelope, err := oldRing.Seal([]byte("registry-token"), aad)
	if err != nil {
		t.Fatal(err)
	}

	rotatingRing, err := NewKeyring(2, map[int][]byte{
		1: testKey(0x31),
		2: testKey(0x32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rotatingRing.NeedsRotation(oldEnvelope) {
		t.Fatal("old envelope was not marked for rotation")
	}
	rotated, err := rotatingRing.Rotate(oldEnvelope, aad)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.KeyVersion != 2 || rotatingRing.NeedsRotation(rotated) {
		t.Fatalf("rotated key version = %d", rotated.KeyVersion)
	}
	opened, err := rotatingRing.Open(rotated, aad)
	if err != nil || string(opened) != "registry-token" {
		t.Fatalf("Open rotated = %q, %v", opened, err)
	}

	newOnlyRing, err := NewKeyring(2, map[int][]byte{2: testKey(0x32)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newOnlyRing.Open(oldEnvelope, aad); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("Open without retained old key error = %v", err)
	}
}

func TestLoadKeyringReadsStrictProtectedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret-keys.json")
	document := `{"active_version":2,"keys":{"1":"` +
		base64.StdEncoding.EncodeToString(testKey(0x41)) + `","2":"` +
		base64.StdEncoding.EncodeToString(testKey(0x42)) + `"}}`
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}

	keyring, err := LoadKeyring(path)
	if err != nil {
		t.Fatal(err)
	}
	if keyring.ActiveVersion() != 2 {
		t.Fatalf("ActiveVersion = %d, want 2", keyring.ActiveVersion())
	}
}

func TestLoadKeyringRejectsUnsafeOrMalformedFiles(t *testing.T) {
	validKey := base64.StdEncoding.EncodeToString(testKey(0x51))
	tests := []struct {
		name     string
		document string
		mode     os.FileMode
		want     string
	}{
		{"group readable", `{"active_version":1,"keys":{"1":"` + validKey + `"}}`, 0o640, "group or other"},
		{"unknown field", `{"active_version":1,"keys":{"1":"` + validKey + `"},"extra":true}`, 0o600, "unknown field"},
		{"trailing document", `{"active_version":1,"keys":{"1":"` + validKey + `"}} {}`, 0o600, "exactly one"},
		{"missing active version", `{"active_version":2,"keys":{"1":"` + validKey + `"}}`, 0o600, "is not present"},
		{"short key", `{"active_version":1,"keys":{"1":"` + base64.StdEncoding.EncodeToString([]byte("short")) + `"}}`, 0o600, "exactly 32 bytes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "keys.json")
			if err := os.WriteFile(path, []byte(test.document), test.mode); err != nil {
				t.Fatal(err)
			}
			_, err := LoadKeyring(path)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("LoadKeyring error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestLoadKeyringRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.json")
	link := filepath.Join(root, "keys.json")
	document := `{"active_version":1,"keys":{"1":"` + base64.StdEncoding.EncodeToString(testKey(0x61)) + `"}}`
	if err := os.WriteFile(target, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyring(link); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("LoadKeyring symlink error = %v", err)
	}
}
