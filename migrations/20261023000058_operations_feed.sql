-- +goose Up
ALTER TABLE notifications ADD COLUMN issue_id BIGINT REFERENCES issues(id);
ALTER TABLE notifications ADD COLUMN operation_id BIGINT REFERENCES operations(id);
CREATE INDEX notifications_issue_idx ON notifications(issue_id);
ALTER TABLE operation_events ADD COLUMN feed_cursor BIGINT UNIQUE;
CREATE TABLE operation_feed_clock(singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK(singleton),cursor BIGINT NOT NULL DEFAULT 0);
INSERT INTO operation_feed_clock(singleton) VALUES(true);

-- +goose Down
DROP TABLE operation_feed_clock;
ALTER TABLE operation_events DROP COLUMN feed_cursor;
ALTER TABLE notifications DROP COLUMN operation_id;
ALTER TABLE notifications DROP COLUMN issue_id;
