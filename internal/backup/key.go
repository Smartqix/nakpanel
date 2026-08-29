package backup

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"strings"
)

// keyPrefix identifies an encoded archive key. The trailing digit is the
// encoding version, independent of the stream version.
const keyPrefix = "nkbk1-"

var keyEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateKey returns a fresh random 32-byte archive master key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// EncodeKey renders a key for operator custody, e.g.
// "nkbk1-XXXXXXXX...". The encoding is case-insensitive on decode.
func EncodeKey(key []byte) (string, error) {
	if len(key) != KeySize {
		return "", ErrBadKey
	}
	return keyPrefix + keyEncoding.EncodeToString(key), nil
}

// DecodeKey parses an operator-supplied key string.
func DecodeKey(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if !strings.HasPrefix(strings.ToLower(encoded), keyPrefix) {
		return nil, errors.New("backup: key must start with nkbk1-")
	}
	raw := strings.ToUpper(encoded[len(keyPrefix):])
	key, err := keyEncoding.DecodeString(raw)
	if err != nil {
		return nil, errors.New("backup: key is not valid base32")
	}
	if len(key) != KeySize {
		return nil, ErrBadKey
	}
	return key, nil
}

// Fingerprint returns a short stable identifier for a key so a restore can
// fail fast on the wrong key without attempting decryption.
func Fingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:8])
}
