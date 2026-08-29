-- +goose Up
-- Host power and package management are singleton host activities. Managed
-- service actions are unique by service and action while an earlier request is
-- still active. These database constraints backstop browser retries and races.
CREATE UNIQUE INDEX server_operations_active_host_action_idx
    ON server_operations (target_type, target_key)
    WHERE target_type IN ('server_host', 'server_updates')
      AND status IN ('pending', 'running', 'awaiting_confirmation');

CREATE UNIQUE INDEX server_operations_active_service_action_idx
    ON server_operations (target_type, target_key, action)
    WHERE target_type = 'server_service'
      AND status IN ('pending', 'running', 'awaiting_confirmation');

-- +goose Down
DROP INDEX IF EXISTS server_operations_active_service_action_idx;
DROP INDEX IF EXISTS server_operations_active_host_action_idx;
