package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"
)

var ErrSessionNotFound = errors.New("session not found")
var ErrSessionSecurityUnavailable = errors.New("session security operations are unavailable")

type SessionStore interface {
	CreateSession(ctx context.Context, tokenHash string, userID int64, expiresAt time.Time, meta SessionMeta) error
	GetSession(ctx context.Context, tokenHash string, now time.Time) (SessionUser, error)
	DeleteSession(ctx context.Context, tokenHash string) error
}

// SessionMeta records where a session was minted from, for login alerting and
// operator forensics.
type SessionMeta struct {
	IPAddress string
	UserAgent string
}

type SessionOptions struct {
	TTL        time.Duration
	TokenBytes int
	Now        func() time.Time
}

type SessionSecurityStore interface {
	MarkSessionReauthenticated(ctx context.Context, tokenHash string) (int64, error)
}

type SessionManager struct {
	store      SessionStore
	ttl        time.Duration
	tokenBytes int
	now        func() time.Time
}

func NewSessionManager(store SessionStore, opts SessionOptions) *SessionManager {
	ttl := opts.TTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}

	tokenBytes := opts.TokenBytes
	if tokenBytes == 0 {
		tokenBytes = 32
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}

	return &SessionManager{
		store:      store,
		ttl:        ttl,
		tokenBytes: tokenBytes,
		now:        now,
	}
}

func (m *SessionManager) Create(ctx context.Context, userID int64, meta SessionMeta) (string, time.Time, error) {
	token, err := randomToken(m.tokenBytes)
	if err != nil {
		return "", time.Time{}, err
	}

	if len(meta.UserAgent) > 256 {
		meta.UserAgent = meta.UserAgent[:256]
	}
	expiresAt := m.now().Add(m.ttl)
	if err := m.store.CreateSession(ctx, TokenHash(token), userID, expiresAt, meta); err != nil {
		return "", time.Time{}, err
	}

	return token, expiresAt, nil
}

func (m *SessionManager) Authenticate(ctx context.Context, token string) (SessionUser, error) {
	if token == "" {
		return SessionUser{}, ErrSessionNotFound
	}
	return m.store.GetSession(ctx, TokenHash(token), m.now())
}

func (m *SessionManager) Delete(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	return m.store.DeleteSession(ctx, TokenHash(token))
}

func (m *SessionManager) MarkReauthenticated(ctx context.Context, token string) error {
	if token == "" {
		return ErrSessionNotFound
	}
	store, ok := m.store.(SessionSecurityStore)
	if !ok {
		return ErrSessionSecurityUnavailable
	}
	updated, err := store.MarkSessionReauthenticated(ctx, TokenHash(token))
	if err != nil {
		return err
	}
	if updated != 1 {
		return ErrSessionNotFound
	}
	return nil
}

func (m *SessionManager) RecentlyAuthenticated(user SessionUser, within time.Duration) bool {
	if within <= 0 || user.AuthenticatedAt.IsZero() {
		return false
	}
	now := m.now()
	return !user.AuthenticatedAt.After(now) && now.Sub(user.AuthenticatedAt) <= within
}

func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomToken(size int) (string, error) {
	token := make([]byte, size)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(token), nil
}
