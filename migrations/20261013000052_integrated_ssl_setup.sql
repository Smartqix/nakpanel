-- +goose Up
ALTER TABLE sites ADD COLUMN ssl_setup_requested BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE sites DROP COLUMN ssl_setup_requested;
