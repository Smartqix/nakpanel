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
RETURNING id, email, password_hash, role, created_at, updated_at, login_disabled;

-- name: GetUser :one
SELECT id, email, password_hash, role, created_at, updated_at, login_disabled
FROM users
WHERE id = $1;

-- name: ListUsers :many
SELECT id, email, password_hash, role, created_at, updated_at, login_disabled
FROM users
ORDER BY id;

-- name: FindUserByEmail :one
SELECT users.id, users.email, users.password_hash, users.role, users.created_at, users.updated_at, users.login_disabled
FROM users
WHERE lower(users.email) = lower($1)
  AND users.login_disabled = false
  AND (
    role = 'admin'
    OR (role = 'client' AND EXISTS (SELECT 1 FROM customers WHERE customers.login_user_id = users.id AND customers.status = 'active'))
    OR (role = 'reseller' AND EXISTS (
      SELECT 1 FROM reseller_accounts r JOIN reseller_subscriptions rs ON rs.reseller_id=r.id
      WHERE r.login_user_id=users.id AND r.status='active' AND rs.status='active'
    ))
  );

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
  AND sessions.expires_at > $2
  AND users.login_disabled = false
  AND (
    users.role = 'admin'
    OR (users.role = 'client' AND EXISTS (SELECT 1 FROM customers WHERE customers.login_user_id = users.id AND customers.status = 'active'))
    OR (users.role = 'reseller' AND EXISTS (
      SELECT 1 FROM reseller_accounts r JOIN reseller_subscriptions rs ON rs.reseller_id=r.id
      WHERE r.login_user_id=users.id AND r.status='active' AND rs.status='active'
    ))
  );

-- name: DeleteSession :exec
DELETE FROM sessions
WHERE token_hash = $1;
