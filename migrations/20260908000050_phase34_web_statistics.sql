-- +goose Up
-- Preserve the purchased statistics value from each immutable subscription snapshot.
UPDATE subscription_entitlements SET hosting_policy=jsonb_set(hosting_policy,'{logs}',
 COALESCE(hosting_policy->'logs',service_presets->'logs','{}'::jsonb) || jsonb_build_object(
 'statistics_engine',CASE WHEN COALESCE(hosting_policy#>>'{logs,statistics_enabled}',service_presets#>>'{logs,statistics_enabled}','false')='true' THEN 'goaccess' ELSE 'disabled' END))
WHERE hosting_policy#>>'{logs,statistics_engine}' IS NULL
AND NOT EXISTS(SELECT 1 FROM billing_accounts account WHERE account.subscription_id=subscription_entitlements.subscription_id AND account.provisioning_state IN ('terminating','terminated'));

CREATE TABLE web_statistics_settings (
 id integer PRIMARY KEY CHECK(id=1), enabled boolean NOT NULL DEFAULT true,
 retention_days integer NOT NULL DEFAULT 30 CHECK(retention_days BETWEEN 1 AND 90),
 schedule_hour integer NOT NULL DEFAULT 3 CHECK(schedule_hour BETWEEN 0 AND 23),
 anonymize_ip boolean NOT NULL DEFAULT true,
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0)
);
INSERT INTO web_statistics_settings(id) VALUES(1);
CREATE TABLE site_web_statistics (
 site_id bigint PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
 generation bigint NOT NULL DEFAULT 0, report_generation bigint NOT NULL DEFAULT 0,
 settings_revision bigint NOT NULL DEFAULT 0,
 status text NOT NULL DEFAULT 'idle' CHECK(status IN('idle','pending','ready','failed')),
 requested_at timestamptz, generated_at timestamptz,
 summary jsonb NOT NULL DEFAULT '{}'::jsonb, last_error text NOT NULL DEFAULT ''
);

-- +goose StatementBegin
CREATE FUNCTION nakpanel_guard_web_statistics() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE subscription_id_value bigint;
BEGIN
 IF current_setting('nakpanel.account_teardown',true) IS DISTINCT FROM 'on' THEN
  SELECT subscription_id INTO subscription_id_value FROM sites WHERE id=NEW.site_id;
  PERFORM nakpanel_assert_account_mutable(subscription_id_value);
 END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER site_web_statistics_account_teardown_guard BEFORE INSERT OR UPDATE ON site_web_statistics FOR EACH ROW EXECUTE FUNCTION nakpanel_guard_web_statistics();

-- +goose Down
DROP TABLE site_web_statistics;
DROP FUNCTION nakpanel_guard_web_statistics();
DROP TABLE web_statistics_settings;
