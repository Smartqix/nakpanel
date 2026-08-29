-- +goose Up
ALTER TABLE sessions ADD COLUMN ip_address TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN user_agent TEXT NOT NULL DEFAULT '';

CREATE TABLE user_totp (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_envelope JSONB NOT NULL,
    confirmed_at TIMESTAMPTZ,
    last_used_step BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_recovery_codes (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX user_recovery_codes_user_idx ON user_recovery_codes(user_id) WHERE used_at IS NULL;

CREATE TABLE login_challenges (
    token_hash TEXT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    ip_address TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX login_challenges_expires_idx ON login_challenges(expires_at);

CREATE TABLE login_attempts (
    id BIGSERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    stage TEXT NOT NULL CHECK (stage IN ('password','totp','recovery')),
    succeeded BOOLEAN NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX login_attempts_email_idx ON login_attempts(email, attempted_at DESC);
CREATE INDEX login_attempts_ip_idx ON login_attempts(ip_address, attempted_at DESC);

CREATE TABLE security_settings (
    id BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    require_totp_admin BOOLEAN NOT NULL DEFAULT false,
    alert_email TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO security_settings (id) VALUES (true);

ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('threshold', 'over_limit', 'collection_failed', 'suspended', 'sync_failed',
                    'maintenance_failed', 'certificate_expiring', 'mail_outbound_spike',
                    'scheduled_task_failed', 'server_backup_failed',
                    'login_new_device', 'login_failed_burst'));

-- +goose Down
DELETE FROM notifications WHERE kind IN ('login_new_device', 'login_failed_burst');
ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('threshold', 'over_limit', 'collection_failed', 'suspended', 'sync_failed',
                    'maintenance_failed', 'certificate_expiring', 'mail_outbound_spike',
                    'scheduled_task_failed', 'server_backup_failed'));
DROP TABLE IF EXISTS security_settings;
DROP INDEX IF EXISTS login_attempts_ip_idx;
DROP INDEX IF EXISTS login_attempts_email_idx;
DROP TABLE IF EXISTS login_attempts;
DROP INDEX IF EXISTS login_challenges_expires_idx;
DROP TABLE IF EXISTS login_challenges;
DROP INDEX IF EXISTS user_recovery_codes_user_idx;
DROP TABLE IF EXISTS user_recovery_codes;
DROP TABLE IF EXISTS user_totp;
ALTER TABLE sessions DROP COLUMN IF EXISTS user_agent;
ALTER TABLE sessions DROP COLUMN IF EXISTS ip_address;
