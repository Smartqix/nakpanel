-- +goose Up
ALTER TABLE notifications DROP COLUMN read_at;
CREATE TABLE notification_receipts (
 notification_id BIGINT NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
 user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 read_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 archived_at TIMESTAMPTZ,
 PRIMARY KEY(notification_id,user_id)
);
CREATE INDEX notification_receipts_user_idx ON notification_receipts(user_id,notification_id);

CREATE TABLE operations (
 id BIGSERIAL PRIMARY KEY,
 operation_key TEXT NOT NULL UNIQUE,
 kind TEXT NOT NULL,
 resource_kind TEXT NOT NULL CHECK(resource_kind IN ('server','site','subscription','customer','user')),
 resource_id BIGINT NOT NULL CHECK((resource_kind='server' AND resource_id=0) OR (resource_kind<>'server' AND resource_id>0)),
 title TEXT NOT NULL,
 trigger TEXT NOT NULL CHECK(trigger IN ('manual','scheduled','reconciliation','recovery','system')),
 state TEXT NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','running','waiting_retry','succeeded','failed','cancelled')),
 stage TEXT NOT NULL DEFAULT '',
 intent_revision BIGINT NOT NULL DEFAULT 0 CHECK(intent_revision>=0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX operations_scope_idx ON operations(resource_kind,resource_id,id DESC);
CREATE INDEX operations_active_idx ON operations(id) WHERE state IN ('queued','running','waiting_retry');

CREATE TABLE operation_attempts (
 id BIGSERIAL PRIMARY KEY,
 operation_id BIGINT NOT NULL REFERENCES operations(id),
 number INTEGER NOT NULL CHECK(number>0),
 river_job_id BIGINT NOT NULL UNIQUE,
 state TEXT NOT NULL DEFAULT 'running' CHECK(state IN ('queued','running','waiting_retry','succeeded','failed','cancelled')),
 error_code TEXT NOT NULL DEFAULT '',
 started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 finished_at TIMESTAMPTZ,
 verification JSONB,
 UNIQUE(operation_id,number),
 CHECK((finished_at IS NOT NULL) = (state IN ('succeeded','failed','cancelled')))
);
CREATE UNIQUE INDEX operation_attempts_active_idx ON operation_attempts(operation_id) WHERE finished_at IS NULL;

CREATE TABLE issues (
 id BIGSERIAL PRIMARY KEY,
 resource_kind TEXT NOT NULL CHECK(resource_kind IN ('server','site','subscription','customer','user')),
 resource_id BIGINT NOT NULL CHECK((resource_kind='server' AND resource_id=0) OR (resource_kind<>'server' AND resource_id>0)),
 kind TEXT NOT NULL,
 condition TEXT NOT NULL,
 severity TEXT NOT NULL CHECK(severity IN ('info','warning','critical')),
 title TEXT NOT NULL,
 summary TEXT NOT NULL,
 state TEXT NOT NULL DEFAULT 'open' CHECK(state IN ('open','acknowledged','checking','resolved')),
 generation BIGINT NOT NULL DEFAULT 1 CHECK(generation>0),
 occurrences INTEGER NOT NULL DEFAULT 1 CHECK(occurrences>0),
 latest_event_id BIGINT NOT NULL,
 intent_revision BIGINT NOT NULL DEFAULT 0 CHECK(intent_revision>=0),
 operation_id BIGINT REFERENCES operations(id),
 previous_issue_id BIGINT REFERENCES issues(id),
 acknowledged_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
 acknowledged_at TIMESTAMPTZ,
 observed_at TIMESTAMPTZ NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 resolved_at TIMESTAMPTZ,
 verification JSONB,
 CHECK((resolved_at IS NOT NULL) = (state='resolved'))
);
CREATE UNIQUE INDEX issues_open_condition_idx ON issues(resource_kind,resource_id,kind,condition) WHERE resolved_at IS NULL;
CREATE INDEX issues_scope_idx ON issues(resource_kind,resource_id,id DESC);

-- Source events and their outbox are one durable record. Publication is added
-- by the dispatcher; source sequence IDs are not browser feed cursors.
CREATE TABLE operation_events (
 id BIGSERIAL PRIMARY KEY,
 event_key TEXT NOT NULL UNIQUE,
 resource_kind TEXT NOT NULL CHECK(resource_kind IN ('server','site','subscription','customer','user')),
 resource_id BIGINT NOT NULL CHECK((resource_kind='server' AND resource_id=0) OR (resource_kind<>'server' AND resource_id>0)),
 kind TEXT NOT NULL,
 operation_id BIGINT REFERENCES operations(id),
 issue_id BIGINT REFERENCES issues(id),
 notification_id BIGINT REFERENCES notifications(id) ON DELETE SET NULL,
 recipient_user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
 summary TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 dispatched_at TIMESTAMPTZ
);
ALTER TABLE issues ADD CONSTRAINT issues_latest_event_fk FOREIGN KEY(latest_event_id) REFERENCES operation_events(id) DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX operation_events_undispatched_idx ON operation_events(id) WHERE dispatched_at IS NULL;

-- +goose Down
ALTER TABLE issues DROP CONSTRAINT issues_latest_event_fk;
DROP TABLE operation_events;
DROP TABLE issues;
DROP TABLE operation_attempts;
DROP TABLE operations;
DROP TABLE notification_receipts;
ALTER TABLE notifications ADD COLUMN read_at TIMESTAMPTZ;
