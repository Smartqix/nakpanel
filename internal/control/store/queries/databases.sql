-- name: UpsertDatabaseIntent :one
INSERT INTO databases (
    owner_user_id,
    customer_id,
    subscription_id,
    site_id,
    engine,
    db_name,
    db_user,
    status,
    last_error
) SELECT
    sqlc.arg(owner_user_id),
    s.customer_id,
    s.id,
    NULLIF(sqlc.arg(site_id), 0),
    sqlc.arg(engine),
    sqlc.arg(db_name),
    sqlc.arg(db_user),
    'pending',
    ''
FROM subscriptions s
WHERE s.id = sqlc.arg(subscription_id)
  AND s.status = 'active'
  AND (sqlc.arg(site_id)::bigint = 0 OR EXISTS (
      SELECT 1 FROM sites site WHERE site.id = sqlc.arg(site_id)::bigint AND site.subscription_id = s.id
  ))
ON CONFLICT (db_name) DO UPDATE
SET
    owner_user_id = EXCLUDED.owner_user_id,
    customer_id = EXCLUDED.customer_id,
    subscription_id = EXCLUDED.subscription_id,
    site_id = EXCLUDED.site_id,
    engine = EXCLUDED.engine,
    db_user = EXCLUDED.db_user,
    status = 'pending',
    last_error = '',
    updated_at = now()
WHERE databases.subscription_id = EXCLUDED.subscription_id
RETURNING id, owner_user_id, engine, db_name, db_user, status, last_error, created_at, updated_at, subscription_id, customer_id, site_id;

-- name: GetDatabase :one
SELECT id, owner_user_id, engine, db_name, db_user, status, last_error, created_at, updated_at, subscription_id, customer_id, site_id
FROM databases
WHERE id = $1;

-- name: ListDatabases :many
SELECT id, owner_user_id, engine, db_name, db_user, status, last_error, created_at, updated_at, subscription_id, customer_id, site_id
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
