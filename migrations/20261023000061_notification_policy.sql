-- +goose Up
-- Development schema: replace address-only delivery records with scoped user batches.
DROP TABLE IF EXISTS notification_deliveries;
ALTER TABLE security_settings DROP COLUMN alert_email;
CREATE TABLE notification_preferences(
 user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 email_mode TEXT NOT NULL DEFAULT 'off' CHECK(email_mode IN ('off','immediate','digest')),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE notification_delivery_policy(
 singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK(singleton),
 enabled BOOLEAN NOT NULL DEFAULT false,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO notification_delivery_policy(singleton) VALUES(true);
CREATE TABLE notification_email_batches(
 id BIGSERIAL PRIMARY KEY,
 batch_key TEXT NOT NULL UNIQUE,
 recipient_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 mode TEXT NOT NULL CHECK(mode IN ('immediate','digest')),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','failed','skipped')),
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 8),
 next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 accepted_at TIMESTAMPTZ,
 last_error TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 CHECK((status='accepted')=(accepted_at IS NOT NULL))
);
CREATE INDEX notification_email_due_idx ON notification_email_batches(next_attempt_at,id) WHERE status IN ('pending','failed') AND attempts<8;
CREATE TABLE notification_email_items(
 batch_id BIGINT NOT NULL REFERENCES notification_email_batches(id) ON DELETE CASCADE,
 notification_id BIGINT NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
 user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 PRIMARY KEY(notification_id,user_id)
);

-- +goose Down
ALTER TABLE security_settings ADD COLUMN alert_email TEXT NOT NULL DEFAULT '';
DROP TABLE notification_email_items;
DROP TABLE notification_email_batches;
DROP TABLE notification_delivery_policy;
DROP TABLE notification_preferences;
CREATE TABLE notification_deliveries(
 id BIGSERIAL PRIMARY KEY,notification_id BIGINT NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
 channel TEXT NOT NULL CHECK(channel IN ('smtp')),recipient TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','sent','failed')),
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),last_error TEXT NOT NULL DEFAULT '',sent_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),UNIQUE(notification_id,channel,recipient)
);
