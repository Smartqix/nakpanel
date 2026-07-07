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

type SessionStore interface {
	CreateSession(ctx context.Context, tokenHash string, userID int64, expiresAt time.Time) error
	GetSession(ctx context.Context, tokenHash string, now time.Time) (SessionUser, error)
	DeleteSession(ctx context.Context, tokenHash string) error
}

type SessionOptions struct {
	TTL        time.Duration
	TokenBytes int
	Now        func() time.Time
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

func (m *SessionManager) Create(ctx context.Context, userID int64) (string, time.Time, error) {
	token, err := randomToken(m.tokenBytes)
	if err != nil {
		return "", time.Time{}, err
	}

	expiresAt := m.now().Add(m.ttl)
	if err := m.store.CreateSession(ctx, TokenHash(token), userID, expiresAt); err != nil {
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
