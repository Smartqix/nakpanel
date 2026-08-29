-- +goose Up
-- Stalwart authenticates and routes directly through these views. Keep raw
-- operator intent in enabled, while effective_enabled is the fail-closed
-- convergence result after lifecycle and entitlement policy are applied.
ALTER TABLE mail_domains
    ADD COLUMN effective_enabled BOOLEAN NOT NULL DEFAULT false;

-- Preserve existing service during migration. The startup mail convergence
-- job immediately recalculates this value from current policy and lifecycle.
UPDATE mail_domains
SET effective_enabled = enabled AND NOT delete_requested;

CREATE OR REPLACE VIEW stalwart_accounts AS
SELECT lower(mb.local_part) || '@' || md.domain AS name,
       'individual' AS type,
       mb.password_hash AS secret,
       '' AS description,
       CASE WHEN mb.quota_mb <= 0 THEN 0 ELSE mb.quota_mb::bigint * 1048576 END AS quota
FROM mailboxes mb
JOIN mail_domains md ON md.id = mb.mail_domain_id
WHERE mb.enabled AND md.effective_enabled AND NOT md.delete_requested;

CREATE OR REPLACE VIEW stalwart_emails AS
SELECT account.name AS name, account.name AS address, 'primary' AS type
FROM stalwart_accounts account
UNION ALL
SELECT lower(dest.addr) AS name,
       lower(al.local_part) || '@' || md.domain AS address,
       'alias' AS type
FROM mail_aliases al
JOIN mail_domains md ON md.id = al.mail_domain_id
    AND md.effective_enabled AND NOT md.delete_requested
CROSS JOIN LATERAL unnest(al.destinations) AS dest(addr)
WHERE EXISTS (SELECT 1 FROM stalwart_accounts account WHERE account.name = lower(dest.addr));

CREATE OR REPLACE VIEW stalwart_domains AS
SELECT domain AS name
FROM mail_domains
WHERE effective_enabled AND NOT delete_requested;

-- +goose Down
CREATE OR REPLACE VIEW stalwart_accounts AS
SELECT lower(mb.local_part) || '@' || md.domain AS name,
       'individual' AS type,
       mb.password_hash AS secret,
       '' AS description,
       CASE WHEN mb.quota_mb <= 0 THEN 0 ELSE mb.quota_mb::bigint * 1048576 END AS quota
FROM mailboxes mb
JOIN mail_domains md ON md.id = mb.mail_domain_id
WHERE mb.enabled AND md.enabled AND NOT md.delete_requested;

CREATE OR REPLACE VIEW stalwart_emails AS
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

CREATE OR REPLACE VIEW stalwart_domains AS
SELECT domain AS name FROM mail_domains WHERE enabled AND NOT delete_requested;

ALTER TABLE mail_domains DROP COLUMN effective_enabled;
