-- +goose Up
-- Keep 8.2 valid for migrated rows, but runtime capability and entitlement
-- checks prevent new assignments to an unavailable legacy interpreter.
ALTER TABLE sites DROP CONSTRAINT IF EXISTS sites_php_version_check;
ALTER TABLE sites ADD CONSTRAINT sites_php_version_check
    CHECK (php_version IN ('8.2','8.3','8.4','8.5'));

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM sites WHERE php_version NOT IN ('8.2','8.3')) THEN
        RAISE EXCEPTION 'cannot restore the pre-Phase 30 PHP version constraint while PHP 8.4 or 8.5 sites exist';
    END IF;
END;
$$;
-- +goose StatementEnd

ALTER TABLE sites DROP CONSTRAINT IF EXISTS sites_php_version_check;
ALTER TABLE sites ADD CONSTRAINT sites_php_version_check
    CHECK (php_version IN ('8.2','8.3'));
