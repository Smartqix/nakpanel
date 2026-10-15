-- +goose Up
CREATE TABLE mail_imports (
 id TEXT PRIMARY KEY,
 mailbox_id BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
 subscription_id BIGINT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
 actor_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 source_kind TEXT NOT NULL CHECK(source_kind IN ('imap','maildir')),
 source_host TEXT NOT NULL DEFAULT '', source_port INTEGER NOT NULL DEFAULT 993 CHECK(source_port=993),
 source_user TEXT NOT NULL DEFAULT '', staging_id TEXT NOT NULL DEFAULT '', manifest_sha256 TEXT NOT NULL DEFAULT '', prepared BOOLEAN NOT NULL DEFAULT FALSE,
 source_secret_id TEXT NOT NULL DEFAULT '', target_secret_id TEXT NOT NULL,
 state TEXT NOT NULL DEFAULT 'preview' CHECK(state IN ('preview','queued','discovering','copying','verifying','paused','cancelled','attention_required','failed','complete')),
 desired_revision BIGINT NOT NULL DEFAULT 1 CHECK(desired_revision>0), applied_revision BIGINT NOT NULL DEFAULT 0,
 discovered BIGINT NOT NULL DEFAULT 0 CHECK(discovered>=0), copied BIGINT NOT NULL DEFAULT 0 CHECK(copied>=0),
 verified BIGINT NOT NULL DEFAULT 0 CHECK(verified>=0 AND verified<=copied), failed BIGINT NOT NULL DEFAULT 0 CHECK(failed>=0), uncertain BIGINT NOT NULL DEFAULT 0 CHECK(uncertain>=0),
 last_error TEXT NOT NULL DEFAULT '', expires_at TIMESTAMPTZ NOT NULL DEFAULT now()+interval '30 minutes',
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX mail_import_one_active_mailbox ON mail_imports(mailbox_id) WHERE state IN ('queued','discovering','copying','verifying','paused','attention_required');
CREATE TABLE mail_import_folders (
 id BIGSERIAL PRIMARY KEY, import_id TEXT NOT NULL REFERENCES mail_imports(id) ON DELETE CASCADE,
 source_name TEXT NOT NULL, target_name TEXT NOT NULL, uid_validity BIGINT NOT NULL DEFAULT 0,
 special_use TEXT NOT NULL DEFAULT '', approved BOOLEAN NOT NULL DEFAULT TRUE,
 UNIQUE(import_id,source_name)
);
CREATE TABLE mail_import_messages (
 id BIGSERIAL PRIMARY KEY, folder_id BIGINT NOT NULL REFERENCES mail_import_folders(id) ON DELETE CASCADE,
 source_identity TEXT NOT NULL, source_key TEXT NOT NULL DEFAULT '', source_uid BIGINT NOT NULL DEFAULT 0,
 sha256 TEXT NOT NULL, byte_size BIGINT NOT NULL CHECK(byte_size>=0), internal_date TIMESTAMPTZ NOT NULL,
 flags JSONB NOT NULL DEFAULT '[]'::jsonb CHECK(jsonb_typeof(flags)='array'),
 receipt_token TEXT NOT NULL UNIQUE, target_uid BIGINT NOT NULL DEFAULT 0, target_uid_validity BIGINT NOT NULL DEFAULT 0,
 state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','appending','copied','verified','uncertain','failed','excluded')),
 last_error TEXT NOT NULL DEFAULT '', UNIQUE(folder_id,source_identity),
 CHECK(state NOT IN ('copied','verified') OR (target_uid>0 AND target_uid_validity>0))
);
CREATE UNIQUE INDEX mail_import_target_receipt ON mail_import_messages(folder_id,target_uid_validity,target_uid) WHERE target_uid>0;
-- +goose Down
DROP TABLE mail_import_messages;
DROP TABLE mail_import_folders;
DROP TABLE mail_imports;
