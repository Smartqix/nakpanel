-- +goose Up
-- Mailbox credentials are verified by Stalwart directly against the directory
-- views below, so the panel stores argon2id PHC hashes, never recoverable
-- ciphertext and never plaintext.
ALTER TABLE mailboxes DROP COLUMN password_ciphertext;
ALTER TABLE mailboxes ADD COLUMN password_hash TEXT NOT NULL DEFAULT '';

-- Node-wide mail delivery settings (single row): outbound smarthost relay,
-- per-tenant outbound rate limit, and the queue-backlog alert threshold.
CREATE TABLE mail_settings (
    id BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    mail_hostname TEXT NOT NULL DEFAULT '',
    smarthost_host TEXT NOT NULL DEFAULT '',
    smarthost_port INTEGER NOT NULL DEFAULT 587 CHECK (smarthost_port BETWEEN 1 AND 65535),
    smarthost_username TEXT NOT NULL DEFAULT '',
    smarthost_password TEXT NOT NULL DEFAULT '',
    outbound_rate_limit TEXT NOT NULL DEFAULT '200/1h',
    queue_alert_threshold INTEGER NOT NULL DEFAULT 50 CHECK (queue_alert_threshold >= 1),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO mail_settings (id) VALUES (true);

-- Read-only projections consumed by Stalwart's SQL directory. Stalwart never
-- reads the base tables; the install script grants SELECT on these views to a
-- dedicated read-only role.
CREATE VIEW stalwart_accounts AS
SELECT lower(mb.local_part) || '@' || md.domain AS name,
       'individual' AS type,
       mb.password_hash AS secret,
       '' AS description,
       CASE WHEN mb.quota_mb <= 0 THEN 0 ELSE mb.quota_mb::bigint * 1048576 END AS quota
FROM mailboxes mb
JOIN mail_domains md ON md.id = mb.mail_domain_id
WHERE mb.enabled AND md.enabled AND NOT md.delete_requested;

CREATE VIEW stalwart_emails AS
SELECT account.name AS name, account.name AS address, 'primary' AS type
FROM stalwart_accounts account
UNION ALL
SELECT lower(dest.addr) AS name,
       lower(al.local_part) || '@' || md.domain AS address,
       'alias' AS type
FROM mail_aliases al
JOIN mail_domains md ON md.id = al.mail_domain_id AND md.enabled AND NOT md.delete_requested
CROSS JOIN LATERAL unnest(al.destinations) AS dest(addr)
WHERE EXISTS (SELECT 1 FROM stalwart_accounts account WHERE account.name = lower(dest.addr));

CREATE VIEW stalwart_domains AS
SELECT domain AS name FROM mail_domains WHERE enabled AND NOT delete_requested;

ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('threshold', 'over_limit', 'collection_failed', 'suspended', 'sync_failed', 'maintenance_failed', 'certificate_expiring', 'mail_outbound_spike'));

-- +goose Down
UPDATE notifications SET kind = 'maintenance_failed' WHERE kind = 'mail_outbound_spike';
ALTER TABLE notifications DROP CONSTRAINT notifications_kind_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check
    CHECK (kind IN ('threshold', 'over_limit', 'collection_failed', 'suspended', 'sync_failed', 'maintenance_failed', 'certificate_expiring'));

DROP VIEW IF EXISTS stalwart_domains;
DROP VIEW IF EXISTS stalwart_emails;
DROP VIEW IF EXISTS stalwart_accounts;
DROP TABLE IF EXISTS mail_settings;

ALTER TABLE mailboxes DROP COLUMN password_hash;
ALTER TABLE mailboxes ADD COLUMN password_ciphertext BYTEA NOT NULL DEFAULT '\x';
