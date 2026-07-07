package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
)

type AuthQuerier interface {
	FindUserByEmail(ctx context.Context, email string) (User, error)
	CreateSession(ctx context.Context, arg CreateSessionParams) error
	GetSessionUser(ctx context.Context, arg GetSessionUserParams) (GetSessionUserRow, error)
	DeleteSession(ctx context.Context, tokenHash string) error
}

type AuthStore struct {
	queries AuthQuerier
}

func NewAuthStore(queries AuthQuerier) *AuthStore {
	return &AuthStore{queries: queries}
}

func (s *AuthStore) FindUserByEmail(ctx context.Context, email string) (auth.User, error) {
	user, err := s.queries.FindUserByEmail(ctx, email)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.User{}, auth.ErrUserNotFound
	}
	if err != nil {
		return auth.User{}, fmt.Errorf("find user by email: %w", err)
	}

	role := auth.Role(user.Role)
	if !role.Valid() {
		return auth.User{}, fmt.Errorf("invalid user role %q", user.Role)
	}

	return auth.User{
		ID:           user.ID,
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
		Role:         role,
	}, nil
}

func (s *AuthStore) CreateSession(ctx context.Context, tokenHash string, userID int64, expiresAt time.Time) error {
	return s.queries.CreateSession(ctx, CreateSessionParams{
		TokenHash: tokenHash,
		UserID:    userID,
		ExpiresAt: expiresAt,
	})
}

func (s *AuthStore) GetSession(ctx context.Context, tokenHash string, now time.Time) (auth.SessionUser, error) {
	user, err := s.queries.GetSessionUser(ctx, GetSessionUserParams{
		TokenHash: tokenHash,
		ExpiresAt: now,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return auth.SessionUser{}, auth.ErrSessionNotFound
	}
	if err != nil {
		return auth.SessionUser{}, fmt.Errorf("get session user: %w", err)
	}

	role := auth.Role(user.Role)
	if !role.Valid() {
		return auth.SessionUser{}, fmt.Errorf("invalid session user role %q", user.Role)
	}

	return auth.SessionUser{
		ID:    user.ID,
		Email: user.Email,
		Role:  role,
	}, nil
}

func (s *AuthStore) DeleteSession(ctx context.Context, tokenHash string) error {
	return s.queries.DeleteSession(ctx, tokenHash)
}
