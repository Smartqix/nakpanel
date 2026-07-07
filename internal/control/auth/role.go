package auth

import "errors"

var ErrUserNotFound = errors.New("user not found")

type Role string

const (
	RoleAdmin    Role = "admin"
	RoleReseller Role = "reseller"
	RoleClient   Role = "client"
)

func (r Role) Valid() bool {
	switch r {
	case RoleAdmin, RoleReseller, RoleClient:
		return true
	default:
		return false
	}
}

type User struct {
	ID           int64
	Email        string
	PasswordHash string
	Role         Role
}

type SessionUser struct {
	ID    int64
	Email string
	Role  Role
}
