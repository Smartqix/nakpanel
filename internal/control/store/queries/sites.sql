-- name: UpsertSiteIntent :one
INSERT INTO sites (
    owner_user_id,
    customer_id,
    subscription_id,
    username,
    domain,
    php_version,
    status,
    last_error
) SELECT
    sqlc.arg(owner_user_id),
    s.customer_id,
    s.id,
    sqlc.arg(username),
    sqlc.arg(domain),
    sqlc.arg(php_version),
    'pending',
    ''
FROM subscriptions s
WHERE s.id = sqlc.arg(subscription_id)
  AND s.status = 'active'
ON CONFLICT (domain) DO UPDATE
SET
    owner_user_id = EXCLUDED.owner_user_id,
    customer_id = EXCLUDED.customer_id,
    subscription_id = EXCLUDED.subscription_id,
    username = EXCLUDED.username,
    php_version = EXCLUDED.php_version,
    status = 'pending',
    last_error = '',
    updated_at = now()
WHERE sites.subscription_id = EXCLUDED.subscription_id
RETURNING id, owner_user_id, username, domain, php_version, status, last_error, created_at, updated_at, tls_status, tls_issuer, tls_cert_path, tls_key_path, tls_expires_at, tls_last_error, subscription_id, customer_id, desired_status, desired_php_version, https_redirect, desired_https_redirect, settings_status, settings_error, tls_auto_renew;

-- name: GetSite :one
SELECT id, owner_user_id, username, domain, php_version, status, last_error, created_at, updated_at, tls_status, tls_issuer, tls_cert_path, tls_key_path, tls_expires_at, tls_last_error, subscription_id, customer_id, desired_status, desired_php_version, https_redirect, desired_https_redirect, settings_status, settings_error, tls_auto_renew
FROM sites
WHERE id = $1;

-- name: GetSiteByDomain :one
SELECT id, owner_user_id, username, domain, php_version, status, last_error, created_at, updated_at, tls_status, tls_issuer, tls_cert_path, tls_key_path, tls_expires_at, tls_last_error, subscription_id, customer_id, desired_status, desired_php_version, https_redirect, desired_https_redirect, settings_status, settings_error, tls_auto_renew
FROM sites
WHERE domain = $1;

-- name: ListSites :many
SELECT id, owner_user_id, username, domain, php_version, status, last_error, created_at, updated_at, tls_status, tls_issuer, tls_cert_path, tls_key_path, tls_expires_at, tls_last_error, subscription_id, customer_id, desired_status, desired_php_version, https_redirect, desired_https_redirect, settings_status, settings_error, tls_auto_renew
FROM sites
ORDER BY id;

-- name: MarkSiteActive :exec
UPDATE sites
SET
    status = 'active',
    last_error = '',
    updated_at = now()
WHERE id = $1;

-- name: MarkSiteTLSPending :exec
UPDATE sites
SET
    tls_status = 'pending',
    tls_issuer = $2,
    tls_last_error = '',
    updated_at = now()
WHERE id = $1;

-- name: MarkSiteTLSActive :exec
UPDATE sites
SET
    tls_status = 'active',
    tls_issuer = $2,
    tls_cert_path = $3,
    tls_key_path = $4,
    tls_expires_at = $5,
    tls_last_error = '',
    updated_at = now()
WHERE id = $1;

-- name: MarkSiteTLSFailed :exec
UPDATE sites
SET
    tls_status = 'failed',
    tls_last_error = $2,
    updated_at = now()
WHERE id = $1;

-- name: MarkSiteFailed :exec
UPDATE sites
SET
    status = 'failed',
    last_error = $2,
    updated_at = now()
WHERE id = $1;
