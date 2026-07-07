-- name: UpsertDatabaseIntent :one
INSERT INTO databases (
    owner_user_id,
    subscription_id,
    engine,
    db_name,
    db_user,
    status,
    last_error
) VALUES (
    $1,
    (SELECT id FROM subscriptions WHERE customer_user_id = $1 AND status = 'active' LIMIT 1),
    $2,
    $3,
    $4,
    'pending',
    ''
)
ON CONFLICT (db_name) DO UPDATE
SET
    owner_user_id = EXCLUDED.owner_user_id,
    subscription_id = EXCLUDED.subscription_id,
    engine = EXCLUDED.engine,
    db_user = EXCLUDED.db_user,
    status = 'pending',
    last_error = '',
    updated_at = now()
RETURNING id, owner_user_id, engine, db_name, db_user, status, last_error, created_at, updated_at, subscription_id;

-- name: GetDatabase :one
SELECT id, owner_user_id, engine, db_name, db_user, status, last_error, created_at, updated_at, subscription_id
FROM databases
WHERE id = $1;

-- name: ListDatabases :many
SELECT id, owner_user_id, engine, db_name, db_user, status, last_error, created_at, updated_at, subscription_id
FROM databases
ORDER BY id;

-- name: MarkDatabaseActive :exec
UPDATE databases
SET
    status = 'active',
    last_error = '',
    updated_at = now()
WHERE id = $1;

-- name: MarkDatabaseFailed :exec
UPDATE databases
SET
    status = 'failed',
    last_error = $2,
    updated_at = now()
WHERE id = $1;
