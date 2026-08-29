package serveradmin

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	EnvelopeAlgorithm = "AES-256-GCM"
	envelopeKeyBytes  = 32
	maxKeyFileBytes   = 64 << 10
)

var (
	ErrKeyUnavailable  = errors.New("secret encryption key is unavailable")
	ErrInvalidEnvelope = errors.New("invalid encrypted secret envelope")
)

// Envelope contains a per-secret data key wrapped by a versioned master key.
// It is safe to persist, but callers must still avoid logging it unnecessarily.
type Envelope struct {
	Algorithm       string
	KeyVersion      int
	WrappedKeyNonce []byte
	WrappedDataKey  []byte
	ValueNonce      []byte
	Ciphertext      []byte
}

// Keyring holds versioned master keys. The active version is used for writes;
// older versions remain available only to decrypt and rotate existing values.
type Keyring struct {
	activeVersion int
	keys          map[int][envelopeKeyBytes]byte
}

type keyFileDocument struct {
	ActiveVersion int               `json:"active_version"`
	Keys          map[string]string `json:"keys"`
}

func NewKeyring(activeVersion int, keys map[int][]byte) (*Keyring, error) {
	if activeVersion < 1 {
		return nil, errors.New("active secret key version must be positive")
	}
	if len(keys) == 0 {
		return nil, errors.New("at least one secret key is required")
	}

	loaded := make(map[int][envelopeKeyBytes]byte, len(keys))
	for version, material := range keys {
		if version < 1 {
			return nil, fmt.Errorf("secret key version %d must be positive", version)
		}
		if len(material) != envelopeKeyBytes {
			return nil, fmt.Errorf("secret key version %d must contain exactly %d bytes", version, envelopeKeyBytes)
		}
		var key [envelopeKeyBytes]byte
		copy(key[:], material)
		loaded[version] = key
	}
	if _, ok := loaded[activeVersion]; !ok {
		return nil, fmt.Errorf("active secret key version %d is not present", activeVersion)
	}
	return &Keyring{activeVersion: activeVersion, keys: loaded}, nil
}

// LoadKeyring reads a strict JSON key document:
//
//	{"active_version":2,"keys":{"1":"<base64>","2":"<base64>"}}
//
// The file must be an absolute, regular, non-symlink file inaccessible to
// group and other users. This also works with systemd credential files.
func LoadKeyring(path string) (*Keyring, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("secret key file path is required")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("secret key file path must be absolute and clean")
	}

	linkInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect secret key file: %w", err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 || !linkInfo.Mode().IsRegular() {
		return nil, errors.New("secret key file must be a regular non-symlink file")
	}
	if linkInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("secret key file must not be accessible by group or other users")
	}
	if linkInfo.Size() > maxKeyFileBytes {
		return nil, errors.New("secret key file is too large")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open secret key file: %w", err)
	}
	defer file.Close()

	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat opened secret key file: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(linkInfo, openedInfo) {
		return nil, errors.New("secret key file changed while it was being opened")
	}
	if openedInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("secret key file must not be accessible by group or other users")
	}
	if openedInfo.Size() > maxKeyFileBytes {
		return nil, errors.New("secret key file is too large")
	}

	decoder := json.NewDecoder(io.LimitReader(file, maxKeyFileBytes+1))
	decoder.DisallowUnknownFields()
	var document keyFileDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode secret key file: %w", err)
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return nil, err
	}

	keys := make(map[int][]byte, len(document.Keys))
	for rawVersion, encoded := range document.Keys {
		version, err := strconv.Atoi(rawVersion)
		if err != nil || version < 1 || strconv.Itoa(version) != rawVersion {
			return nil, fmt.Errorf("invalid secret key version %q", rawVersion)
		}
		material, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode secret key version %d: %w", version, err)
		}
		keys[version] = material
	}
	return NewKeyring(document.ActiveVersion, keys)
}

func rejectTrailingJSON(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("decode trailing secret key data: %w", err)
	}
	return errors.New("secret key file must contain exactly one JSON document")
}

func (k *Keyring) ActiveVersion() int {
	if k == nil {
		return 0
	}
	return k.activeVersion
}

func (k *Keyring) NeedsRotation(envelope Envelope) bool {
	return k == nil || envelope.KeyVersion != k.activeVersion
}

func (k *Keyring) Seal(plaintext, associatedData []byte) (Envelope, error) {
	if k == nil {
		return Envelope{}, ErrKeyUnavailable
	}
	if len(plaintext) == 0 {
		return Envelope{}, errors.New("secret value must not be empty")
	}
	master, ok := k.keys[k.activeVersion]
	if !ok {
		return Envelope{}, ErrKeyUnavailable
	}

	dataKey := make([]byte, envelopeKeyBytes)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		return Envelope{}, fmt.Errorf("generate data encryption key: %w", err)
	}
	defer clear(dataKey)

	wrappedNonce, wrapped, err := sealAESGCM(master[:], dataKey, envelopeAAD("wrap", associatedData))
	if err != nil {
		return Envelope{}, fmt.Errorf("wrap data encryption key: %w", err)
	}
	valueNonce, ciphertext, err := sealAESGCM(dataKey, plaintext, envelopeAAD("value", associatedData))
	if err != nil {
		return Envelope{}, fmt.Errorf("encrypt secret value: %w", err)
	}
	return Envelope{
		Algorithm:       EnvelopeAlgorithm,
		KeyVersion:      k.activeVersion,
		WrappedKeyNonce: wrappedNonce,
		WrappedDataKey:  wrapped,
		ValueNonce:      valueNonce,
		Ciphertext:      ciphertext,
	}, nil
}

func (k *Keyring) Open(envelope Envelope, associatedData []byte) ([]byte, error) {
	if k == nil {
		return nil, ErrKeyUnavailable
	}
	if err := validateEnvelope(envelope); err != nil {
		return nil, err
	}
	master, ok := k.keys[envelope.KeyVersion]
	if !ok {
		return nil, fmt.Errorf("%w: version %d", ErrKeyUnavailable, envelope.KeyVersion)
	}

	dataKey, err := openAESGCM(master[:], envelope.WrappedKeyNonce, envelope.WrappedDataKey, envelopeAAD("wrap", associatedData))
	if err != nil {
		return nil, fmt.Errorf("%w: unwrap data encryption key", ErrInvalidEnvelope)
	}
	defer clear(dataKey)
	if len(dataKey) != envelopeKeyBytes {
		return nil, ErrInvalidEnvelope
	}

	plaintext, err := openAESGCM(dataKey, envelope.ValueNonce, envelope.Ciphertext, envelopeAAD("value", associatedData))
	if err != nil {
		return nil, fmt.Errorf("%w: decrypt secret value", ErrInvalidEnvelope)
	}
	return plaintext, nil
}

func (k *Keyring) Rotate(envelope Envelope, associatedData []byte) (Envelope, error) {
	plaintext, err := k.Open(envelope, associatedData)
	if err != nil {
		return Envelope{}, err
	}
	defer clear(plaintext)
	return k.Seal(plaintext, associatedData)
}

func validateEnvelope(envelope Envelope) error {
	if envelope.Algorithm != EnvelopeAlgorithm ||
		envelope.KeyVersion < 1 ||
		len(envelope.WrappedKeyNonce) != 12 ||
		len(envelope.WrappedDataKey) != envelopeKeyBytes+16 ||
		len(envelope.ValueNonce) != 12 ||
		len(envelope.Ciphertext) < 16 {
		return ErrInvalidEnvelope
	}
	return nil
}

func sealAESGCM(key, plaintext, associatedData []byte) ([]byte, []byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, associatedData), nil
}

func openAESGCM(key, nonce, ciphertext, associatedData []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, ErrInvalidEnvelope
	}
	return gcm.Open(nil, nonce, ciphertext, associatedData)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func envelopeAAD(purpose string, associatedData []byte) []byte {
	prefix := []byte("nakpanel:service-secret:v1:" + purpose + "\x00")
	return bytes.Join([][]byte{prefix, associatedData}, nil)
}
