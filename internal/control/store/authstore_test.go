package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
)

type fakeAuthQuerier struct {
	user       User
	userErr    error
	session    GetSessionUserRow
	sessionErr error

	createdSession CreateSessionParams
	deletedHash    string
}

func (q *fakeAuthQuerier) FindUserByEmail(ctx context.Context, email string) (User, error) {
	return q.user, q.userErr
}

func (q *fakeAuthQuerier) CreateSession(ctx context.Context, arg CreateSessionParams) error {
	q.createdSession = arg
	return nil
}

func (q *fakeAuthQuerier) GetSessionUser(ctx context.Context, arg GetSessionUserParams) (GetSessionUserRow, error) {
	return q.session, q.sessionErr
}

func (q *fakeAuthQuerier) DeleteSession(ctx context.Context, tokenHash string) error {
	q.deletedHash = tokenHash
	return nil
}

func TestAuthStoreFindUserByEmailMapsUser(t *testing.T) {
	store := NewAuthStore(&fakeAuthQuerier{
		user: User{
			ID:           7,
			Email:        "admin@nakpanel.test",
			PasswordHash: "$argon2id$hash",
			Role:         "admin",
		},
	})

	user, err := store.FindUserByEmail(context.Background(), "admin@nakpanel.test")
	if err != nil {
		t.Fatalf("FindUserByEmail returned error: %v", err)
	}
	if user.ID != 7 || user.Email != "admin@nakpanel.test" || user.Role != auth.RoleAdmin {
		t.Fatalf("FindUserByEmail returned %#v", user)
	}
}

func TestAuthStoreFindUserByEmailMapsMissingUser(t *testing.T) {
	store := NewAuthStore(&fakeAuthQuerier{userErr: sql.ErrNoRows})

	_, err := store.FindUserByEmail(context.Background(), "missing@nakpanel.test")
	if !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("FindUserByEmail error = %v, want ErrUserNotFound", err)
	}
}

func TestAuthStoreCreatesAndDeletesSession(t *testing.T) {
	q := &fakeAuthQuerier{}
	store := NewAuthStore(q)
	expiresAt := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)

	if err := store.CreateSession(context.Background(), "hash", 42, expiresAt); err != nil {
		t.Fatalf("CreateSession returned error: %v", err)
	}
	if q.createdSession.TokenHash != "hash" || q.createdSession.UserID != 42 || !q.createdSession.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("created session = %#v", q.createdSession)
	}

	if err := store.DeleteSession(context.Background(), "hash"); err != nil {
		t.Fatalf("DeleteSession returned error: %v", err)
	}
	if q.deletedHash != "hash" {
		t.Fatalf("deletedHash = %q, want hash", q.deletedHash)
	}
}

func TestAuthStoreGetsSessionUser(t *testing.T) {
	q := &fakeAuthQuerier{
		session: GetSessionUserRow{
			ID:    42,
			Email: "client@nakpanel.test",
			Role:  "client",
		},
	}
	store := NewAuthStore(q)
	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)

	user, err := store.GetSession(context.Background(), "hash", now)
	if err != nil {
		t.Fatalf("GetSession returned error: %v", err)
	}
	if user.ID != 42 || user.Email != "client@nakpanel.test" || user.Role != auth.RoleClient {
		t.Fatalf("GetSession returned %#v", user)
	}
}

func TestAuthStoreMapsMissingSession(t *testing.T) {
	store := NewAuthStore(&fakeAuthQuerier{sessionErr: sql.ErrNoRows})

	_, err := store.GetSession(context.Background(), "missing", time.Now())
	if !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("GetSession error = %v, want ErrSessionNotFound", err)
	}
}
