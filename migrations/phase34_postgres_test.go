package migrations

import "testing"

func TestPhase34BackfillRespectsTeardownPostgreSQL(t *testing.T) {
	db := phase30Postgres(t)
	_, err := db.Exec(`
CREATE TABLE billing_accounts(subscription_id bigint PRIMARY KEY,provisioning_state text NOT NULL);
CREATE TABLE sites(id bigint PRIMARY KEY,subscription_id bigint NOT NULL);
CREATE TABLE subscription_entitlements(subscription_id bigint PRIMARY KEY,hosting_policy jsonb NOT NULL,service_presets jsonb NOT NULL);
INSERT INTO billing_accounts VALUES(1,'active'),(2,'terminating'),(3,'terminated');
INSERT INTO sites VALUES(10,1),(20,2),(30,3);
INSERT INTO subscription_entitlements SELECT subscription_id,'{"schema_version":4}'::jsonb,'{"logs":{"statistics_enabled":true}}'::jsonb FROM billing_accounts;
CREATE FUNCTION nakpanel_assert_account_mutable(id bigint) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM billing_accounts WHERE subscription_id=id AND provisioning_state IN ('terminating','terminated')) THEN RAISE EXCEPTION 'billing account teardown has started'; END IF;
END; $$;
CREATE FUNCTION fixture_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM nakpanel_assert_account_mutable(NEW.subscription_id); RETURN NEW; END; $$;
CREATE TRIGGER subscription_entitlements_account_teardown_guard BEFORE UPDATE ON subscription_entitlements FOR EACH ROW EXECUTE FUNCTION fixture_guard();
`)
	if err != nil {
		t.Fatal(err)
	}
	up, down := migrationSections(t, "20260908000050_phase34_web_statistics.sql")
	if _, err = db.Exec(up); err != nil {
		t.Fatalf("upgrade with terminating accounts: %v", err)
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM subscription_entitlements WHERE hosting_policy#>>'{logs,statistics_engine}'='goaccess'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("active-only legacy backfill count=%d err=%v", count, err)
	}
	if _, err = db.Exec(`INSERT INTO site_web_statistics(site_id) VALUES(10)`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO site_web_statistics(site_id) VALUES(20)`); err == nil {
		t.Fatal("terminating account accepted statistics mutation")
	}
	if _, err = db.Exec(`UPDATE subscription_entitlements SET hosting_policy='{}' WHERE subscription_id=2`); err == nil {
		t.Fatal("existing teardown guard disabled")
	}
	if _, err = db.Exec(down); err != nil {
		t.Fatalf("down migration: %v", err)
	}
}
