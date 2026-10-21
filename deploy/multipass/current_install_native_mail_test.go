package multipass

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type bootstrapMailProfile struct{ name, image, baseline, defaultPHP, versions, jsonVersions string }

var bootstrapMailProfiles = []bootstrapMailProfile{
	{"ubuntu-26.04-sury", "26.04", "8.3", "8.4", "8.3,8.4,8.5", `["8.3","8.4","8.5"]`},
	{"ubuntu-26.04-native", "26.04", "8.5", "8.5", "8.5", `["8.5"]`},
}

// Validate profile selection without a database so ordinary local tests also
// catch a fixture table that requests an unsupported server OS.
func TestBootstrapMailProfileSelection(t *testing.T) {
	data, err := os.ReadFile("current-install-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	function := shellFixtureFunction(t, string(data), "configure_bootstrap_mail_profile", true)
	for _, profile := range bootstrapMailProfiles {
		t.Run(profile.name, func(t *testing.T) {
			program := "set -euo pipefail\n" + function + `configure_bootstrap_mail_profile
printf '%s|%s|%s' "$bootstrap_default_php" "$bootstrap_php_versions" "$bootstrap_php_json"
`
			cmd := exec.Command("bash", "-c", program)
			cmd.Env = append(os.Environ(), "NAKPANEL_RUN_TOKEN=fixture-mail-test", "IMAGE="+profile.image, "NAKPANEL_QUALIFICATION_PROFILE="+profile.name, "NAKPANEL_BASELINE_PHP="+profile.baseline)
			out, err := cmd.CombinedOutput()
			want := profile.defaultPHP + "|" + profile.versions + "|" + profile.jsonVersions
			if err != nil || string(out) != want {
				t.Fatalf("mail fixture profile selection: %v output=%q want=%q", err, out, want)
			}
		})
	}
	t.Run("unsupported-os-rejected-before-database", func(t *testing.T) {
		cmd := exec.Command("bash", "-c", "set -euo pipefail\ndb(){ echo database-was-reached; return 86; }\n"+function+"configure_bootstrap_mail_profile\n")
		cmd.Env = append(os.Environ(), "NAKPANEL_RUN_TOKEN=fixture-mail-test", "IMAGE=24.04", "NAKPANEL_QUALIFICATION_PROFILE=ubuntu-24.04", "NAKPANEL_BASELINE_PHP=8.3")
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "unsupported mail fixture profile") || strings.Contains(string(out), "database-was-reached") {
			t.Fatalf("unsupported OS reached mail fixture setup: %v %s", err, out)
		}
	})
}

// Small API/policy-boundary model; production compatibility is independently
// exercised by TestBootstrapMailActualProductionSchema55And56 below.
func bootstrapMailSQL(t *testing.T) (*sql.DB, string, string) {
	t.Helper()
	dsn := os.Getenv("NAKPANEL_NATIVE_FIXTURE_TEST_DSN")
	if dsn == "" {
		t.Skip("requires explicitly isolated PostgreSQL fixture DSN")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	schema := fmt.Sprintf("bootstrap_mail_%d_%d", os.Getpid(), time.Now().UnixNano())
	if _, err = db.Exec("CREATE SCHEMA " + schema + "; SET search_path TO " + schema); err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec("SET search_path TO public; DROP SCHEMA " + schema + " CASCADE"); db.Close() })
	_, err = db.Exec(`CREATE TABLE plans(id bigserial PRIMARY KEY,reseller_id bigint,lifecycle_status text,is_active boolean,hosting_enabled boolean,default_php_version text,php_allowlist text,max_mailboxes int,hosting_policy jsonb,name text,revision int DEFAULT 1,last_validated_at timestamptz,readiness_error text DEFAULT '');
CREATE TABLE plan_revisions(plan_id bigint,revision int,snapshot jsonb);
CREATE TABLE customers(id bigint,email text,status text,reseller_id bigint);
CREATE TABLE subscriptions(id bigint,customer_id bigint,plan_id bigint,status text,sync_status text,name text,sync_mode text DEFAULT 'synced');
CREATE TABLE subscription_entitlements(subscription_id bigint,hosting_enabled boolean,default_php_version text,php_allowlist text,max_mailboxes int,hosting_policy jsonb,source_revision int DEFAULT 1,plan_name text);
CREATE TABLE subscription_policy_overrides(subscription_id bigint,policy_patch jsonb);
CREATE TABLE sites(id bigint,subscription_id bigint,domain text,status text,desired_status text,php_version text,desired_php_version text,settings_status text DEFAULT 'in_sync',removal_state text DEFAULT 'none');
CREATE TABLE site_policy_overrides(site_id bigint,policy_patch jsonb);
INSERT INTO customers VALUES(11,'admin@nakpanel.test','active',NULL);
INSERT INTO plans VALUES(1,NULL,'retired',true,true,'8.4','8.3,8.4,8.5',-1,'{"resources":{"max_mailboxes":-1},"permissions":{"hosting":true,"mail":true},"mail":{"enabled":true,"webmail":false,"mailbox_quota_mb":64},"php":{"default_version":"8.4","allowed_versions":["8.3","8.4","8.5"]}}','Legacy Unlimited',1,'2020-01-01','');
INSERT INTO plan_revisions SELECT id,revision,to_jsonb(p) FROM plans p;
INSERT INTO subscriptions VALUES(88,11,1,'active','in_sync','Legacy seeded subscription','synced');
INSERT INTO subscription_entitlements SELECT 88,hosting_enabled,default_php_version,php_allowlist,max_mailboxes,hosting_policy,1,name FROM plans WHERE id=1;
SELECT setval('plans_id_seq',10);`)
	if err != nil {
		t.Fatal(err)
	}
	return db, dsn, schema
}

func bootstrapMailBlock(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("current-install-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	a := strings.Index(s, "# Fresh bootstrap mail fixtures")
	if a < 0 {
		a = strings.Index(s, "# The modern native gates need")
	}
	if a < 0 {
		t.Fatal("bootstrap fixture boundary missing")
	}
	bidx := strings.Index(s[a:], `if [[ "$(db "SELECT count(*) FROM dns_zones`)
	if bidx < 0 {
		t.Fatal("bootstrap fixture end missing")
	}
	return s[a : a+bidx]
}

func runBootstrapMail(t *testing.T, profile bootstrapMailProfile, mode string, db *sql.DB, dsn, schema string) (string, string, error) {
	t.Helper()
	state := t.TempDir()
	trace := filepath.Join(state, "calls")
	policy := fmt.Sprintf(`{"resources":{"max_mailboxes":4},"permissions":{"hosting":true,"mail":true},"mail":{"enabled":true,"webmail":true,"mailbox_quota_mb":64},"php":{"default_version":"%s","allowed_versions":%s}}`, profile.defaultPHP, profile.jsonVersions)
	program := `set -euo pipefail
store(){ psql -X -qAt "$TEST_DSN" -v ON_ERROR_STOP=1 -c "$1"; }
db(){ [[ "$1" == SELECT* ]] || { echo 'fixture emitted SQL mutation' >&2;return 86; };store "$1"; }
wait_for(){ [[ "$MODE" != sync-failed ]] || return 72;[[ "$(db "$1")" == "$2" ]]; }
post(){
 local route="$1";shift;printf '%s\n' "$route $*" >>"$TRACE"
 local -a values=("$@")
 form(){ local field="$1" part;for part in "${values[@]}";do case "$part" in "$field="*) printf '%s' "${part#*=}";return;;esac;done;return 1; }
 forms(){ local field="$1" part;for part in "${values[@]}";do case "$part" in "$field="*) printf '%s\n' "${part#*=}";;esac;done; }
 case "$route" in
 plans)
  [[ "$MODE" != plan-api-failed ]] || return 71
  [[ "$(form plan_id)" == 0 && "$(form name)" == "Qualification Mail $NAKPANEL_RUN_TOKEN" && "$(form lifecycle_status)" == active ]] || return 73
  [[ "$(form allow_mail)" == true && "$(form mail_webmail_enabled)" == true && "$(form mailbox_quota_mb)" == 64 && "$(form max_mailboxes)" == 4 ]] || return 74
  [[ "$(form php_allowlist)" == "$EXPECTED_VERSIONS" && "$(forms php_versions | paste -sd, -)" == "$EXPECTED_VERSIONS" && "$(form default_php_version)" == "$EXPECTED_DEFAULT" ]] || return 75
  [[ "$(form disk_mb)" -gt 0 && "$(form max_sites)" -gt 0 && "$(form max_databases)" -gt 0 && "$(form max_backups)" -gt 0 ]] || return 76
  local policy="$MAIL_POLICY";[[ "$MODE" != invalid-plan ]] || policy='{}'
  store "INSERT INTO plans(reseller_id,lifecycle_status,is_active,hosting_enabled,default_php_version,php_allowlist,max_mailboxes,hosting_policy,name,last_validated_at) VALUES(NULL,'active',true,true,'$EXPECTED_DEFAULT','$EXPECTED_VERSIONS',4,'$policy','$(form name)',now()); INSERT INTO plan_revisions SELECT id,revision,to_jsonb(p) FROM plans p WHERE id>1" >/dev/null;;
 subscriptions)
  [[ "$MODE" != subscription-api-failed ]] || return 77
  [[ "$(form customer_id)" == 11 && "$(form subscription_name)" == "Qualification Bootstrap $NAKPANEL_RUN_TOKEN" ]] || return 78
  local id="$(form plan_id)"
  store "INSERT INTO subscriptions VALUES(188,11,$id,'active','in_sync','$(form subscription_name)','synced'); INSERT INTO subscription_entitlements SELECT 188,hosting_enabled,default_php_version,php_allowlist,max_mailboxes,hosting_policy,revision,name FROM plans WHERE id=$id" >/dev/null
  case "$MODE" in
   subscription-override) store "INSERT INTO subscription_policy_overrides VALUES(188,'{\"mail\":{\"webmail\":false}}')" >/dev/null;;
   invalid-entitlement) store "UPDATE subscription_entitlements SET hosting_policy=jsonb_set(hosting_policy,'{mail,webmail}','false') WHERE subscription_id=188" >/dev/null;;
  esac;;
 sites)
  [[ "$MODE" != site-api-failed ]] || return 79
  [[ "$(form subscription_id)" == 188 && "$(form domain)" == current-bootstrap.test && "$(form php_version)" == "$NAKPANEL_BASELINE_PHP" ]] || return 80
  store "INSERT INTO sites VALUES(201,188,'current-bootstrap.test','active','active','$NAKPANEL_BASELINE_PHP','$NAKPANEL_BASELINE_PHP','in_sync','none')" >/dev/null
  [[ "$MODE" != site-override ]] || store "INSERT INTO site_policy_overrides VALUES(201,'{\"mail\":{\"webmail\":false}}')" >/dev/null;;
 *) return 81;;
 esac
}
` + bootstrapMailBlock(t) + "\nprintf '%s:%s' \"$subscription_id\" \"$site_id\"\n"
	cmd := exec.Command("bash", "-c", program)
	token := "fixture-mail-test"
	if mode == "bad-token" {
		token = "bad'token"
	}
	cmd.Env = append(os.Environ(), "TEST_DSN="+dsn, "PGOPTIONS=-c search_path="+schema, "TRACE="+trace, "MODE="+mode, "MAIL_POLICY="+policy, "IMAGE="+profile.image, "NAKPANEL_QUALIFICATION_PROFILE="+profile.name, "NAKPANEL_BASELINE_PHP="+profile.baseline, "NAKPANEL_RUN_TOKEN="+token, "EXPECTED_DEFAULT="+profile.defaultPHP, "EXPECTED_VERSIONS="+profile.versions)
	output, err := cmd.CombinedOutput()
	calls, _ := os.ReadFile(trace)
	return string(output), string(calls), err
}

func preservedBootstrapRows(t *testing.T, db *sql.DB) string {
	t.Helper()
	var value string
	if err := db.QueryRow(`SELECT jsonb_build_array((SELECT to_jsonb(p) FROM plans p WHERE id=1),(SELECT to_jsonb(s) FROM subscriptions s WHERE id=88),(SELECT to_jsonb(e) FROM subscription_entitlements e WHERE subscription_id=88),(SELECT to_jsonb(h) FROM plan_revisions h WHERE plan_id=1))::text`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestBootstrapMailOwnedAPICreationAllProfilesWithRealPostgres(t *testing.T) {
	for _, profile := range bootstrapMailProfiles {
		t.Run(profile.name, func(t *testing.T) {
			db, dsn, schema := bootstrapMailSQL(t)
			before := preservedBootstrapRows(t, db)
			output, calls, err := runBootstrapMail(t, profile, "create", db, dsn, schema)
			if err != nil {
				t.Fatalf("dedicated mail fixture not created: %v %s; calls=%s", err, output, calls)
			}
			if strings.TrimSpace(output) != "188:201" {
				t.Fatalf("reused unrelated legacy fixture: %s", output)
			}
			for _, route := range []string{"plans ", "subscriptions ", "sites "} {
				if strings.Count(calls, route) != 1 {
					t.Fatalf("route missing/replayed %q: %s", route, calls)
				}
			}
			if before != preservedBootstrapRows(t, db) {
				t.Fatal("unrelated default/history/snapshot changed")
			}
			var def, versions string
			var webmail bool
			if err := db.QueryRow(`SELECT e.default_php_version,e.php_allowlist,(e.hosting_policy#>>'{mail,webmail}')::boolean FROM subscription_entitlements e WHERE subscription_id=188`).Scan(&def, &versions, &webmail); err != nil {
				t.Fatal(err)
			}
			if def != profile.defaultPHP || versions != profile.versions || !webmail {
				t.Fatalf("requested PHP/mail contract lost: %s %s %v", def, versions, webmail)
			}
		})
	}
}

func TestBootstrapMailRejectsExistingOwnedRowsBeforeAnyCreation(t *testing.T) {
	for _, mode := range []string{"owned-plan", "owned-subscription", "existing-site", "inactive-customer", "bad-token", "unsupported-profile"} {
		t.Run(mode, func(t *testing.T) {
			db, dsn, schema := bootstrapMailSQL(t)
			switch mode {
			case "owned-plan":
				_, _ = db.Exec(`INSERT INTO plans(name) VALUES('Qualification Mail fixture-mail-test')`)
			case "owned-subscription":
				_, _ = db.Exec(`INSERT INTO subscriptions(id,customer_id,name) VALUES(188,11,'Qualification Bootstrap fixture-mail-test')`)
			case "existing-site":
				_, _ = db.Exec(`INSERT INTO sites(id,subscription_id,domain) VALUES(201,88,'current-bootstrap.test'); INSERT INTO site_policy_overrides VALUES(201,'{"mail":{"webmail":false}}')`)
			case "inactive-customer":
				_, _ = db.Exec(`UPDATE customers SET status='suspended'`)
			}
			profile := bootstrapMailProfiles[0]
			if mode == "unsupported-profile" {
				profile.name = "unsupported-profile"
			}
			output, calls, err := runBootstrapMail(t, profile, mode, db, dsn, schema)
			if err == nil || calls != "" {
				t.Fatalf("unsafe existing fixture reached creation: %v %s %s", err, output, calls)
			}
		})
	}
}

func TestBootstrapMailAPISyncAndPolicyFailuresStopDownstreamCreation(t *testing.T) {
	for _, mode := range []string{"plan-api-failed", "invalid-plan", "subscription-api-failed", "sync-failed", "invalid-entitlement", "subscription-override", "site-api-failed", "site-override"} {
		t.Run(mode, func(t *testing.T) {
			db, dsn, schema := bootstrapMailSQL(t)
			before := preservedBootstrapRows(t, db)
			output, calls, err := runBootstrapMail(t, bootstrapMailProfiles[1], mode, db, dsn, schema)
			if err == nil {
				t.Fatalf("failed fixture accepted: %s %s", output, calls)
			}
			if before != preservedBootstrapRows(t, db) {
				t.Fatal("failure rewrote unrelated legacy rows")
			}
			if (mode == "invalid-plan" || mode == "plan-api-failed") && strings.Contains(calls, "subscriptions ") {
				t.Fatalf("invalid plan reached subscription creation: %s", calls)
			}
			if mode != "site-api-failed" && mode != "site-override" && strings.Contains(calls, "sites ") {
				t.Fatalf("invalid policy/sync reached site creation: %s", calls)
			}
		})
	}
}

func assertBootstrapMail(t *testing.T, profile bootstrapMailProfile, dsn, schema string) (string, error) {
	t.Helper()
	return assertBootstrapMailIDs(t, profile, dsn, schema, 11, 11, 188, 201)
}

func assertBootstrapMailIDs(t *testing.T, profile bootstrapMailProfile, dsn, schema string, customer, plan, subscription, site int64) (string, error) {
	t.Helper()
	data, err := os.ReadFile("current-install-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	program := `set -euo pipefail
db(){ [[ "$1" == SELECT* ]] || return 86;psql -X -qAt "$TEST_DSN" -v ON_ERROR_STOP=1 -c "$1"; }
post(){ echo 'assertion attempted product mutation' >&2;return 87; }
` + shellFixtureFunction(t, string(data), "configure_bootstrap_mail_profile", true) + shellFixtureFunction(t, string(data), "find_bootstrap_mail_plan", true) + shellFixtureFunction(t, string(data), "assert_bootstrap_mail_fixture", true) + `
configure_bootstrap_mail_profile
customer_id="$TEST_CUSTOMER";plan_id="$TEST_PLAN";subscription_id="$TEST_SUBSCRIPTION";site_id="$TEST_SITE"
selected="$(find_bootstrap_mail_plan)"
[[ "$selected" == "$plan_id" ]] || exit 88
assert_bootstrap_mail_fixture
`
	siteID := ""
	if site > 0 {
		siteID = fmt.Sprintf("%d", site)
	}
	cmd := exec.Command("bash", "-c", program)
	cmd.Env = append(os.Environ(), "TEST_DSN="+dsn, "PGOPTIONS=-c search_path="+schema, "IMAGE="+profile.image, "NAKPANEL_QUALIFICATION_PROFILE="+profile.name, "NAKPANEL_BASELINE_PHP="+profile.baseline, "NAKPANEL_RUN_TOKEN=fixture-mail-test", fmt.Sprintf("TEST_CUSTOMER=%d", customer), fmt.Sprintf("TEST_PLAN=%d", plan), fmt.Sprintf("TEST_SUBSCRIPTION=%d", subscription), "TEST_SITE="+siteID)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestBootstrapMailEffectiveEligibilityWithRealPostgres(t *testing.T) {
	cases := []struct{ name, query string }{
		{"ready", ""},
		{"webmail-disabled", `UPDATE subscription_entitlements SET hosting_policy=jsonb_set(hosting_policy,'{mail,webmail}','false')`},
		{"mail-disabled", `UPDATE subscription_entitlements SET hosting_policy=jsonb_set(hosting_policy,'{mail,enabled}','false')`},
		{"permission-denied", `UPDATE subscription_entitlements SET hosting_policy=jsonb_set(hosting_policy,'{permissions,mail}','false')`},
		{"string-not-boolean", `UPDATE subscription_entitlements SET hosting_policy=jsonb_set(hosting_policy,'{mail,webmail}','"true"')`},
		{"missing-policy", `UPDATE subscription_entitlements SET hosting_policy='{}'`},
		{"zero-mailboxes", `UPDATE subscription_entitlements SET max_mailboxes=0`},
		{"invalid-unlimited", `UPDATE subscription_entitlements SET max_mailboxes=-2`},
		{"zero-policy-mailboxes", `UPDATE subscription_entitlements SET hosting_policy=jsonb_set(hosting_policy,'{resources,max_mailboxes}','0')`},
		{"zero-mailbox-bytes", `UPDATE subscription_entitlements SET hosting_policy=jsonb_set(hosting_policy,'{mail,mailbox_quota_mb}','0')`},
		{"invalid-mailbox-bytes", `UPDATE subscription_entitlements SET hosting_policy=jsonb_set(hosting_policy,'{mail,mailbox_quota_mb}','-2')`},
		{"string-mailbox-bytes", `UPDATE subscription_entitlements SET hosting_policy=jsonb_set(hosting_policy,'{mail,mailbox_quota_mb}','"64"')`},
		{"subscription-override", `INSERT INTO subscription_policy_overrides VALUES(188,'{}')`},
		{"site-override", `INSERT INTO site_policy_overrides VALUES(201,'{}')`},
		{"wrong-customer", `UPDATE subscriptions SET customer_id=12 WHERE id=188`},
		{"wrong-plan-owner", `UPDATE plans SET reseller_id=12 WHERE id=11`},
		{"wrong-run-name", `UPDATE subscriptions SET name='unrelated' WHERE id=188`},
		{"pending-subscription", `UPDATE subscriptions SET sync_status='pending' WHERE id=188`},
		{"inactive-subscription", `UPDATE subscriptions SET status='suspended' WHERE id=188`},
		{"locked-snapshot", `UPDATE subscriptions SET sync_mode='locked' WHERE id=188`},
		{"stale-source-revision", `UPDATE subscription_entitlements SET source_revision=0 WHERE subscription_id=188`},
		{"unvalidated-plan", `UPDATE plans SET last_validated_at=NULL WHERE id=11`},
		{"plan-readiness-error", `UPDATE plans SET readiness_error='not ready' WHERE id=11`},
		{"wrong-selected-php", `UPDATE sites SET php_version='8.4' WHERE id=201`},
		{"wrong-desired-php", `UPDATE sites SET desired_php_version='8.4' WHERE id=201`},
		{"site-not-synced", `UPDATE sites SET settings_status='pending' WHERE id=201`},
		{"inactive-site", `UPDATE sites SET status='suspended' WHERE id=201`},
		{"desired-stopped-site", `UPDATE sites SET desired_status='suspended' WHERE id=201`},
		{"removing-site", `UPDATE sites SET removal_state='pending' WHERE id=201`},
		{"wrong-default-php", `UPDATE subscription_entitlements SET default_php_version='8.3' WHERE subscription_id=188`},
		{"wrong-scalar-offers", `UPDATE subscription_entitlements SET php_allowlist='8.3,8.4,8.5' WHERE subscription_id=188`},
		{"wrong-policy-offers", `UPDATE subscription_entitlements SET hosting_policy=jsonb_set(hosting_policy,'{php,allowed_versions}','["8.3","8.4","8.5"]') WHERE subscription_id=188`},
	}
	// Every predicate is exercised against real PostgreSQL. Both current 26.04
	// profiles also cover ready and disabled-webmail behavior.
	for _, profile := range bootstrapMailProfiles {
		for _, tc := range cases {
			if profile.name != "ubuntu-26.04-native" && tc.name != "ready" && tc.name != "webmail-disabled" {
				continue
			}
			t.Run(profile.name+"/"+tc.name, func(t *testing.T) {
				db, dsn, schema := bootstrapMailSQL(t)
				if out, _, err := runBootstrapMail(t, profile, "create", db, dsn, schema); err != nil {
					t.Fatalf("setup: %v %s", err, out)
				}
				if tc.query != "" {
					if _, err := db.Exec(tc.query); err != nil {
						t.Fatal(err)
					}
				}
				before := preservedBootstrapRows(t, db)
				out, err := assertBootstrapMail(t, profile, dsn, schema)
				if tc.name == "ready" && err != nil {
					t.Fatalf("ready fixture rejected: %v %s", err, out)
				}
				if tc.name != "ready" && err == nil {
					t.Fatalf("ineligible fixture accepted: %s", out)
				}
				if before != preservedBootstrapRows(t, db) {
					t.Fatal("read-only assertion changed unrelated fixture")
				}
			})
		}
	}
}

// Apply the production migration bytes, rather than modeling their columns.
// Every file is read by this Go test so migration changes invalidate its cache.
func bootstrapMailProductionSchema(t *testing.T, version string) (*sql.DB, string, string) {
	t.Helper()
	dsn := os.Getenv("NAKPANEL_NATIVE_FIXTURE_TEST_DSN")
	if dsn == "" {
		t.Skip("requires explicitly isolated PostgreSQL fixture DSN")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	schema := fmt.Sprintf("bootstrap_production_%d_%d", os.Getpid(), time.Now().UnixNano())
	if _, err = db.Exec("CREATE SCHEMA " + schema + ";SET search_path TO " + schema); err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec("SET search_path TO public;DROP SCHEMA " + schema + " CASCADE"); db.Close() })
	files, err := filepath.Glob("../../migrations/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	applied := 0
	for _, file := range files {
		if strings.SplitN(filepath.Base(file), "_", 2)[0] > version {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		up := strings.SplitN(string(data), "-- +goose Down", 2)[0]
		if _, err = db.Exec(up); err != nil {
			t.Fatalf("actual production migration %s: %v", filepath.Base(file), err)
		}
		applied++
	}
	if applied == 0 {
		t.Fatal("no production migrations applied")
	}
	var syncColumn, inventedColumn int
	if err := db.QueryRow(`SELECT count(*) FILTER(WHERE column_name='sync_mode'),count(*) FILTER(WHERE column_name='plan_mode') FROM information_schema.columns WHERE table_schema=$1 AND table_name='subscriptions'`, schema).Scan(&syncColumn, &inventedColumn); err != nil {
		t.Fatal(err)
	}
	if syncColumn != 1 || inventedColumn != 0 {
		t.Fatalf("production subscription columns: sync_mode=%d plan_mode=%d", syncColumn, inventedColumn)
	}
	t.Logf("actual production migration schema %s: %d files; sync_mode exists, plan_mode absent", version, applied)
	return db, dsn, schema
}

func TestBootstrapMailActualProductionSchema55And56(t *testing.T) {
	for _, version := range []string{"20261015000055", "20261018000056"} {
		for _, profile := range bootstrapMailProfiles {
			t.Run(version+"/"+profile.name, func(t *testing.T) {
				db, dsn, schema := bootstrapMailProductionSchema(t, version)
				var customer, owner, plan, subscription, account, site int64
				if err := db.QueryRow(`SELECT id,login_user_id FROM customers WHERE email='admin@nakpanel.test'`).Scan(&customer, &owner); err != nil {
					t.Fatal(err)
				}
				policy := fmt.Sprintf(`{"resources":{"max_mailboxes":4},"permissions":{"hosting":true,"mail":true},"mail":{"enabled":true,"webmail":true,"mailbox_quota_mb":64},"php":{"default_version":"%s","allowed_versions":%s}}`, profile.defaultPHP, profile.jsonVersions)
				if err := db.QueryRow(`INSERT INTO plans(name,lifecycle_status,hosting_enabled,default_php_version,php_allowlist,max_mailboxes,hosting_policy,last_validated_at) VALUES('Qualification Mail fixture-mail-test','active',true,$1,$2,4,$3,now()) RETURNING id`, profile.defaultPHP, profile.versions, policy).Scan(&plan); err != nil {
					t.Fatal(err)
				}
				if err := db.QueryRow(`INSERT INTO subscriptions(customer_id,plan_id,name,status,sync_status,sync_mode) VALUES($1,$2,'Qualification Bootstrap fixture-mail-test','active','in_sync','synced') RETURNING id`, customer, plan).Scan(&subscription); err != nil {
					t.Fatal(err)
				}
				if out, err := assertBootstrapMailIDs(t, profile, dsn, schema, customer, plan, subscription, 0); err != nil {
					t.Fatalf("actual schema%s initial subscription/plan check rejected: %v %s", version, err, out)
				}
				if err := db.QueryRow(`INSERT INTO subscription_system_accounts(subscription_id,username,home_path,applied_state,convergence_status) VALUES($1,'fixturemail','/home/fixturemail','active','in_sync') RETURNING id`, subscription).Scan(&account); err != nil {
					t.Fatal(err)
				}
				if err := db.QueryRow(`INSERT INTO sites(owner_user_id,username,domain,php_version,desired_php_version,status,desired_status,subscription_id,customer_id,system_account_id,document_root,settings_status,removal_state) VALUES($1,'fixturemail','current-bootstrap.test',$2,$2,'active','active',$3,$4,$5,'/home/fixturemail/domains/current-bootstrap.test/public_html','in_sync','none') RETURNING id`, owner, profile.baseline, subscription, customer, account).Scan(&site); err != nil {
					t.Fatal(err)
				}
				snapshot := func() string {
					var value string
					if err := db.QueryRow(`SELECT jsonb_build_object('plans',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM plans p),'revisions',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM plan_revisions r),'subscriptions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM subscriptions s),'entitlements',(SELECT jsonb_agg(to_jsonb(e) ORDER BY subscription_id) FROM subscription_entitlements e),'sites',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM sites s))::text`).Scan(&value); err != nil {
						t.Fatal(err)
					}
					return value
				}
				before := snapshot()
				out, err := assertBootstrapMailIDs(t, profile, dsn, schema, customer, plan, subscription, site)
				if err != nil {
					t.Fatalf("actual schema%s ready fixture rejected: %v %s", version, err, out)
				}
				if snapshot() != before {
					t.Fatal("eligibility check changed actual production rows/history")
				}
				if _, err := db.Exec(`UPDATE subscriptions SET sync_mode='locked' WHERE id=$1`, subscription); err != nil {
					t.Fatal(err)
				}
				before = snapshot()
				if out, err = assertBootstrapMailIDs(t, profile, dsn, schema, customer, plan, subscription, site); err == nil {
					t.Fatalf("actual schema%s locked snapshot accepted: %s", version, out)
				}
				if !strings.Contains(out, "owned fixture effective PHP/mail/webmail entitlement is unavailable") {
					t.Fatalf("locked snapshot refused for unrelated SQL failure: %s", out)
				}
				if snapshot() != before {
					t.Fatal("locked rejection changed actual production rows/history")
				}
			})
		}
	}
}
