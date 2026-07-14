package provisioningapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const ScopeProvisioning = "provisioning"

var (
	ErrAPIKeyMalformed = errors.New("malformed API key")
	ErrAPIKeyRevoked   = errors.New("API key is revoked")
	ErrAPIKeyExpired   = errors.New("API key is expired")
	ErrAPIKeyScope     = errors.New("API key scope is not permitted")
	ErrAPIKeyIP        = errors.New("remote address is not permitted")
)

type GeneratedAPIKey struct {
	Raw    string
	Prefix string
	Salt   []byte
	Hash   []byte
}

type APIKey struct {
	ID                    int64
	Name                  string
	Prefix                string
	Scope                 string
	IPAllowlist           []string
	RateLimitPerMinute    int
	ExpiresAt, RevokedAt  time.Time
	LastUsedAt, CreatedAt time.Time
	Salt, Hash            []byte
}

type APIKeyCreate struct {
	Name               string
	Scope              string
	IPAllowlist        []string
	RateLimitPerMinute int
	ExpiresAt          time.Time
}

func GenerateAPIKey() (GeneratedAPIKey, error) {
	prefixBytes := make([]byte, 9)
	secretBytes := make([]byte, 32)
	salt := make([]byte, 16)
	if _, err := rand.Read(prefixBytes); err != nil {
		return GeneratedAPIKey{}, err
	}
	if _, err := rand.Read(secretBytes); err != nil {
		return GeneratedAPIKey{}, err
	}
	if _, err := rand.Read(salt); err != nil {
		return GeneratedAPIKey{}, err
	}
	prefix := hex.EncodeToString(prefixBytes)[:16]
	raw := "npk_" + prefix + "_" + base64.RawURLEncoding.EncodeToString(secretBytes)
	return GeneratedAPIKey{Raw: raw, Prefix: prefix, Salt: salt, Hash: HashAPIKey(raw, salt)}, nil
}

func APIKeyPrefix(raw string) (string, error) {
	if !strings.HasPrefix(raw, "npk_") {
		return "", ErrAPIKeyMalformed
	}
	remainder := strings.TrimPrefix(raw, "npk_")
	separator := strings.IndexByte(remainder, '_')
	if separator < 10 || separator > 24 || len(remainder)-separator-1 < 40 {
		return "", ErrAPIKeyMalformed
	}
	prefix, secret := remainder[:separator], remainder[separator+1:]
	if _, err := hex.DecodeString(prefix); err != nil {
		return "", ErrAPIKeyMalformed
	}
	if _, err := base64.RawURLEncoding.DecodeString(secret); err != nil {
		return "", ErrAPIKeyMalformed
	}
	return prefix, nil
}

func HashAPIKey(raw string, salt []byte) []byte {
	h := sha256.New()
	_, _ = h.Write(salt)
	_, _ = h.Write([]byte(raw))
	return h.Sum(nil)
}

func (k APIKey) ValidateAt(now time.Time) error {
	if !k.RevokedAt.IsZero() {
		return ErrAPIKeyRevoked
	}
	if !k.ExpiresAt.IsZero() && !k.ExpiresAt.After(now) {
		return ErrAPIKeyExpired
	}
	if k.Scope != ScopeProvisioning {
		return ErrAPIKeyScope
	}
	return nil
}

func (k APIKey) AllowsIP(ip net.IP) bool {
	if len(k.IPAllowlist) == 0 {
		return true
	}
	for _, raw := range k.IPAllowlist {
		_, network, err := net.ParseCIDR(raw)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

type KeyStore struct{ db *sql.DB }

func NewKeyStore(db *sql.DB) *KeyStore { return &KeyStore{db: db} }

func (s *KeyStore) Create(ctx context.Context, req APIKeyCreate) (APIKey, string, error) {
	if s == nil || s.db == nil {
		return APIKey{}, "", errors.New("API key database is unavailable")
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 120 {
		return APIKey{}, "", errors.New("API key name must contain 1 to 120 characters")
	}
	if req.Scope == "" {
		req.Scope = ScopeProvisioning
	}
	if req.Scope != ScopeProvisioning {
		return APIKey{}, "", ErrAPIKeyScope
	}
	if req.RateLimitPerMinute == 0 {
		req.RateLimitPerMinute = 120
	}
	if req.RateLimitPerMinute < 1 || req.RateLimitPerMinute > 100000 {
		return APIKey{}, "", errors.New("rate limit must be between 1 and 100000 requests per minute")
	}
	for _, cidr := range req.IPAllowlist {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return APIKey{}, "", fmt.Errorf("invalid CIDR %q", cidr)
		}
	}
	generated, err := GenerateAPIKey()
	if err != nil {
		return APIKey{}, "", err
	}
	var expires any
	if !req.ExpiresAt.IsZero() {
		expires = req.ExpiresAt
	}
	var result APIKey
	var expiresAt, lastUsed sql.NullTime
	var allowlistJSON []byte
	err = s.db.QueryRowContext(ctx, `INSERT INTO api_keys
(name,key_prefix,key_salt,key_hash,scope,ip_allowlist,rate_limit_per_minute,expires_at)
VALUES($1,$2,$3,$4,$5,$6::cidr[],$7,$8)
RETURNING id,name,key_prefix,scope,array_to_json(ip_allowlist),rate_limit_per_minute,expires_at,last_used_at,created_at`,
		req.Name, generated.Prefix, generated.Salt, generated.Hash, req.Scope, req.IPAllowlist,
		req.RateLimitPerMinute, expires).Scan(&result.ID, &result.Name, &result.Prefix, &result.Scope,
		&allowlistJSON, &result.RateLimitPerMinute, &expiresAt, &lastUsed, &result.CreatedAt)
	if err != nil {
		return APIKey{}, "", err
	}
	if err = json.Unmarshal(allowlistJSON, &result.IPAllowlist); err != nil {
		return APIKey{}, "", err
	}
	result.ExpiresAt = expiresAt.Time
	result.LastUsedAt = lastUsed.Time
	return result, generated.Raw, nil
}

func (s *KeyStore) Authenticate(ctx context.Context, raw string) (APIKey, error) {
	prefix, err := APIKeyPrefix(raw)
	if err != nil || s == nil || s.db == nil {
		return APIKey{}, ErrAPIKeyMalformed
	}
	var key APIKey
	var expiresAt, revokedAt, lastUsed sql.NullTime
	var allowlistJSON []byte
	err = s.db.QueryRowContext(ctx, `SELECT id,name,key_prefix,key_salt,key_hash,scope,array_to_json(ip_allowlist),
rate_limit_per_minute,expires_at,revoked_at,last_used_at,created_at FROM api_keys WHERE key_prefix=$1`, prefix).Scan(
		&key.ID, &key.Name, &key.Prefix, &key.Salt, &key.Hash, &key.Scope, &allowlistJSON,
		&key.RateLimitPerMinute, &expiresAt, &revokedAt, &lastUsed, &key.CreatedAt)
	if err != nil {
		return APIKey{}, ErrAPIKeyMalformed
	}
	if subtle.ConstantTimeCompare(HashAPIKey(raw, key.Salt), key.Hash) != 1 {
		return APIKey{}, ErrAPIKeyMalformed
	}
	if err = json.Unmarshal(allowlistJSON, &key.IPAllowlist); err != nil {
		return APIKey{}, ErrAPIKeyMalformed
	}
	key.ExpiresAt, key.RevokedAt, key.LastUsedAt = expiresAt.Time, revokedAt.Time, lastUsed.Time
	if err = key.ValidateAt(time.Now()); err != nil {
		return APIKey{}, err
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE api_keys SET last_used_at=now(),updated_at=now() WHERE id=$1`, key.ID)
	return key, nil
}

func (s *KeyStore) List(ctx context.Context) ([]APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,key_prefix,scope,array_to_json(ip_allowlist),rate_limit_per_minute,
expires_at,revoked_at,last_used_at,created_at FROM api_keys ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []APIKey
	for rows.Next() {
		var key APIKey
		var expiresAt, revokedAt, lastUsed sql.NullTime
		var allowlistJSON []byte
		if err = rows.Scan(&key.ID, &key.Name, &key.Prefix, &key.Scope, &allowlistJSON, &key.RateLimitPerMinute, &expiresAt, &revokedAt, &lastUsed, &key.CreatedAt); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(allowlistJSON, &key.IPAllowlist); err != nil {
			return nil, err
		}
		key.ExpiresAt, key.RevokedAt, key.LastUsedAt = expiresAt.Time, revokedAt.Time, lastUsed.Time
		result = append(result, key)
	}
	return result, rows.Err()
}

func (s *KeyStore) Revoke(ctx context.Context, prefix string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE api_keys SET revoked_at=COALESCE(revoked_at,now()),updated_at=now() WHERE key_prefix=$1`, strings.TrimSpace(prefix))
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return sql.ErrNoRows
	}
	return nil
}
