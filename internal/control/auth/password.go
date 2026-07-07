package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const argon2Version = 19

type PasswordParams struct {
	Memory     uint32
	Time       uint32
	Threads    uint8
	SaltLength uint32
	KeyLength  uint32
}

var DefaultPasswordParams = PasswordParams{
	Memory:     64 * 1024,
	Time:       3,
	Threads:    1,
	SaltLength: 16,
	KeyLength:  32,
}

var TestPasswordParams = PasswordParams{
	Memory:     1024,
	Time:       1,
	Threads:    1,
	SaltLength: 16,
	KeyLength:  32,
}

func HashPassword(password string, params PasswordParams) (string, error) {
	if params.Memory == 0 || params.Time == 0 || params.Threads == 0 || params.SaltLength == 0 || params.KeyLength == 0 {
		return "", errors.New("argon2id parameters must be non-zero")
	}

	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read password salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, params.Time, params.Memory, params.Threads, params.KeyLength)
	return encodePHC(params, salt, key), nil
}

func VerifyPassword(password, encodedHash string) (bool, error) {
	params, salt, key, err := decodePHC(encodedHash)
	if err != nil {
		return false, err
	}

	candidate := argon2.IDKey([]byte(password), salt, params.Time, params.Memory, params.Threads, uint32(len(key)))
	if subtle.ConstantTimeCompare(candidate, key) == 1 {
		return true, nil
	}
	return false, nil
}

func encodePHC(params PasswordParams, salt, key []byte) string {
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2Version,
		params.Memory,
		params.Time,
		params.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

func decodePHC(encodedHash string) (PasswordParams, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return PasswordParams{}, nil, nil, errors.New("invalid argon2id hash format")
	}

	version, err := parseVersion(parts[2])
	if err != nil {
		return PasswordParams{}, nil, nil, err
	}
	if version != argon2Version {
		return PasswordParams{}, nil, nil, fmt.Errorf("unsupported argon2id version %d", version)
	}

	params, err := parseParams(parts[3])
	if err != nil {
		return PasswordParams{}, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return PasswordParams{}, nil, nil, fmt.Errorf("decode argon2id salt: %w", err)
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return PasswordParams{}, nil, nil, fmt.Errorf("decode argon2id key: %w", err)
	}
	if len(salt) == 0 || len(key) == 0 {
		return PasswordParams{}, nil, nil, errors.New("argon2id salt and key must be non-empty")
	}

	return params, salt, key, nil
}

func parseVersion(field string) (int, error) {
	value, ok := strings.CutPrefix(field, "v=")
	if !ok {
		return 0, errors.New("invalid argon2id version field")
	}
	version, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("parse argon2id version: %w", err)
	}
	return version, nil
}

func parseParams(field string) (PasswordParams, error) {
	var params PasswordParams
	for _, part := range strings.Split(field, ",") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return PasswordParams{}, errors.New("invalid argon2id parameter field")
		}

		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return PasswordParams{}, fmt.Errorf("parse argon2id parameter %s: %w", key, err)
		}

		switch key {
		case "m":
			params.Memory = uint32(parsed)
		case "t":
			params.Time = uint32(parsed)
		case "p":
			if parsed > 255 {
				return PasswordParams{}, errors.New("argon2id parallelism exceeds uint8")
			}
			params.Threads = uint8(parsed)
		default:
			return PasswordParams{}, fmt.Errorf("unknown argon2id parameter %q", key)
		}
	}

	if params.Memory == 0 || params.Time == 0 || params.Threads == 0 {
		return PasswordParams{}, errors.New("argon2id parameters must be non-zero")
	}

	return params, nil
}
