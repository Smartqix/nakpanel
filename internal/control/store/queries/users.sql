-- name: CreateUser :one
INSERT INTO users (
    email,
    password_hash,
    role
) VALUES (
    $1,
    $2,
    $3
)
RETURNING id, email, password_hash, role, created_at, updated_at;

-- name: GetUser :one
SELECT id, email, password_hash, role, created_at, updated_at
FROM users
WHERE id = $1;

-- name: ListUsers :many
SELECT id, email, password_hash, role, created_at, updated_at
FROM users
ORDER BY id;

-- name: FindUserByEmail :one
SELECT id, email, password_hash, role, created_at, updated_at
FROM users
WHERE email = $1;

-- name: CreateSession :exec
INSERT INTO sessions (
    token_hash,
    user_id,
    expires_at
) VALUES (
    $1,
    $2,
    $3
)
ON CONFLICT (token_hash) DO UPDATE
SET
    user_id = EXCLUDED.user_id,
    expires_at = EXCLUDED.expires_at,
    created_at = now();

-- name: GetSessionUser :one
SELECT users.id, users.email, users.role
FROM sessions
INNER JOIN users ON users.id = sessions.user_id
WHERE sessions.token_hash = $1
  AND sessions.expires_at > $2;

-- name: DeleteSession :exec
DELETE FROM sessions
WHERE token_hash = $1;
