package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

type memorySessionStore struct {
	tokenHash string
	userID    int64
	expiresAt time.Time
	deleted   bool
}

func (s *memorySessionStore) CreateSession(ctx context.Context, tokenHash string, userID int64, expiresAt time.Time) error {
	s.tokenHash = tokenHash
	s.userID = userID
	s.expiresAt = expiresAt
	s.deleted = false
	return nil
}

func (s *memorySessionStore) GetSession(ctx context.Context, tokenHash string, now time.Time) (SessionUser, error) {
	if s.deleted || tokenHash != s.tokenHash || !now.Before(s.expiresAt) {
		return SessionUser{}, ErrSessionNotFound
	}
	return SessionUser{
		ID:    s.userID,
		Email: "client@nakpanel.test",
		Role:  RoleClient,
	}, nil
}

func (s *memorySessionStore) DeleteSession(ctx context.Context, tokenHash string) error {
	if tokenHash == s.tokenHash {
		s.deleted = true
	}
	return nil
}

func TestSessionManagerCreatesOpaqueTokenAndAuthenticates(t *testing.T) {
	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	store := &memorySessionStore{}
	manager := NewSessionManager(store, SessionOptions{
		TTL:        time.Hour,
		TokenBytes: 32,
		Now:        func() time.Time { return now },
	})

	token, expiresAt, err := manager.Create(context.Background(), 42)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	if token == "" {
		t.Fatal("Create returned an empty token")
	}
	if expiresAt != now.Add(time.Hour) {
		t.Fatalf("expiresAt = %s, want %s", expiresAt, now.Add(time.Hour))
	}
	if store.tokenHash == token {
		t.Fatal("stored token hash matched the raw session token")
	}
	if len(store.tokenHash) != 64 {
		t.Fatalf("stored token hash length = %d, want 64 hex chars", len(store.tokenHash))
	}

	user, err := manager.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if user.ID != 42 || user.Role != RoleClient {
		t.Fatalf("Authenticate returned %#v, want client user 42", user)
	}
}

func TestSessionManagerRejectsExpiredSessions(t *testing.T) {
	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	store := &memorySessionStore{}
	manager := NewSessionManager(store, SessionOptions{
		TTL:        time.Minute,
		TokenBytes: 32,
		Now:        func() time.Time { return now },
	})

	token, _, err := manager.Create(context.Background(), 42)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	manager.now = func() time.Time { return now.Add(2 * time.Minute) }
	_, err = manager.Authenticate(context.Background(), token)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Authenticate error = %v, want ErrSessionNotFound", err)
	}
}

func TestSessionManagerDeleteRemovesSession(t *testing.T) {
	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	store := &memorySessionStore{}
	manager := NewSessionManager(store, SessionOptions{
		TTL:        time.Hour,
		TokenBytes: 32,
		Now:        func() time.Time { return now },
	})

	token, _, err := manager.Create(context.Background(), 42)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	if err := manager.Delete(context.Background(), token); err != nil {
		t.Fatalf("Delete returned error: %v", err)
	}

	_, err = manager.Authenticate(context.Background(), token)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Authenticate error after delete = %v, want ErrSessionNotFound", err)
	}
}
