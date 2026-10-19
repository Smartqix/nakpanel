package multipass

import (
	"database/sql"
	"fmt"
	_ "github.com/jackc/pgx/v5/stdlib"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const nativeMailPolicy = `{"resources":{"max_mailboxes":4},"permissions":{"hosting":true,"mail":true},"mail":{"enabled":true,"mailbox_quota_mb":64},"php":{"default_version":"8.5","allowed_versions":["8.5"]}}`

func nativeMailFixtureSQL(t *testing.T) (*sql.DB, string, string) {
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
	schema := fmt.Sprintf("native_mail_%d", time.Now().UnixNano())
	if _, err = db.Exec("CREATE SCHEMA " + schema + "; SET search_path TO " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec("SET search_path TO public; DROP SCHEMA " + schema + " CASCADE"); db.Close() })
	_, err = db.Exec(`CREATE TABLE plans(id bigserial PRIMARY KEY,reseller_id bigint,lifecycle_status text,is_active boolean,hosting_enabled boolean,default_php_version text,php_allowlist text,max_mailboxes int,hosting_policy jsonb,name text);
CREATE TABLE customers(id bigint,email text,status text,reseller_id bigint);
CREATE TABLE subscriptions(id bigint,customer_id bigint,plan_id bigint,status text,sync_status text,name text);
CREATE TABLE subscription_entitlements(subscription_id bigint,hosting_enabled boolean,default_php_version text,php_allowlist text,max_mailboxes int,hosting_policy jsonb);
CREATE TABLE subscription_policy_overrides(subscription_id bigint,policy_patch jsonb);
CREATE TABLE sites(id bigint,subscription_id bigint,domain text,status text,desired_status text,php_version text,desired_php_version text);
CREATE TABLE site_policy_overrides(site_id bigint,policy_patch jsonb);
INSERT INTO customers VALUES(11,'admin@nakpanel.test','active',NULL);
INSERT INTO plans VALUES(1,NULL,'active',true,true,'8.5','8.5',0,'{"resources":{"max_mailboxes":0},"permissions":{"hosting":true,"mail":false},"mail":{"enabled":false,"mailbox_quota_mb":0},"php":{"default_version":"8.5","allowed_versions":["8.5"]}}','Starter');
INSERT INTO plans SELECT 2,NULL,'active',true,true,'8.5','8.5',0,hosting_policy,'Business' FROM plans WHERE id=1;
SELECT setval('plans_id_seq',10);`)
	if err != nil {
		t.Fatal(err)
	}
	return db, dsn, schema
}

func currentNativeFixtureBlock(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("current-install-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	a := strings.Index(s, "# The modern native gates need")
	b := strings.Index(s[a:], `site_id="$(db "SELECT id FROM sites WHERE domain='current-bootstrap.test'")"`)
	if a < 0 || b < 0 {
		t.Fatal("native fixture boundary missing")
	}
	return s[a : a+b]
}

func TestNativeBootstrapMailFixtureSelectionWithRealPostgres(t *testing.T) {
	for _, mode := range []string{"create", "reuse", "invalid-created-plan", "creation-failed", "invalid-entitlement"} {
		t.Run(mode, func(t *testing.T) {
			db, dsn, schema := nativeMailFixtureSQL(t)
			if mode == "reuse" {
				if _, err := db.Exec(`INSERT INTO plans VALUES(3,NULL,'active',true,true,'8.5','8.5',4,$1,'Existing eligible')`, nativeMailPolicy); err != nil {
					t.Fatal(err)
				}
			}
			var before string
			if err := db.QueryRow(`SELECT string_agg(md5(to_jsonb(p)::text),',' ORDER BY id) FROM plans p WHERE id IN(1,2)`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			trace := filepath.Join(t.TempDir(), "calls")
			program := `set -euo pipefail
IMAGE=26.04
NAKPANEL_QUALIFICATION_PROFILE=ubuntu-26.04-native
NAKPANEL_BASELINE_PHP=8.5
NAKPANEL_RUN_TOKEN=fixture-mail-test
site_id=''
db(){ psql -X -qAt "$TEST_DSN" -v ON_ERROR_STOP=1 -c "$1"; }
wait_for(){ [[ "$(db "$1")" == "$2" ]]; }
post(){
 local route="$1";shift
 printf '%s\n' "$route $*" >>"$TRACE"
 local key value plan_id='' plan_name=''
 local -a values=("$@")
 get_form(){ local field="$1" part;for part in "${values[@]}";do case "$part" in "$field="*) printf '%s' "${part#*=}";return;;esac;done;return 1; }
 case "$route" in
 plans)
  [[ "$MODE" != creation-failed ]] || return 71
  [[ "$(get_form plan_id)" == 0 && "$(get_form allow_mail)" == true && "$(get_form mailbox_quota_mb)" == 64 && "$(get_form max_mailboxes)" == 4 && "$(get_form php_versions)" == 8.5 && "$(get_form default_php_version)" == 8.5 ]]
  [[ "$(get_form disk_mb)" -gt 0 && "$(get_form max_sites)" -gt 0 && "$(get_form max_databases)" -gt 0 && "$(get_form max_backups)" -gt 0 ]]
  plan_name="$(get_form name)";[[ "$plan_name" == 'Qualification Native Mail fixture-mail-test' ]]
  policy="$MAIL_POLICY";[[ "$MODE" != invalid-created-plan ]] || policy='{}'
  db "INSERT INTO plans(reseller_id,lifecycle_status,is_active,hosting_enabled,default_php_version,php_allowlist,max_mailboxes,hosting_policy,name) VALUES(NULL,'active',true,true,'8.5','8.5',4,'$policy','$plan_name')" >/dev/null;;
 subscriptions)
  plan_id="$(get_form plan_id)";[[ "$plan_id" =~ ^[0-9]+$ ]]
  db "INSERT INTO subscriptions VALUES(88,11,$plan_id,'active','in_sync','NativeBootstrap'); INSERT INTO subscription_entitlements SELECT 88,hosting_enabled,default_php_version,php_allowlist,max_mailboxes,hosting_policy FROM plans WHERE id=$plan_id" >/dev/null
  if [[ "$MODE" == invalid-entitlement ]];then db "UPDATE subscription_entitlements SET hosting_policy=jsonb_set(hosting_policy,'{permissions,mail}','false')" >/dev/null;fi;;
 *) return 72;;
 esac
}
` + currentNativeFixtureBlock(t)
			cmd := exec.Command("bash", "-c", program)
			cmd.Env = append(os.Environ(), "TEST_DSN="+dsn, "PGOPTIONS=-c search_path="+schema, "TRACE="+trace, "MODE="+mode, "MAIL_POLICY="+nativeMailPolicy)
			out, err := cmd.CombinedOutput()
			positive := mode == "create" || mode == "reuse"
			if positive != (err == nil) {
				t.Fatalf("%s: unexpected fixture result: %v %s", mode, err, out)
			}
			calls, _ := os.ReadFile(trace)
			if mode == "reuse" && strings.Contains(string(calls), "plans ") {
				t.Fatal("eligible plan was unnecessarily modified/recreated")
			}
			if mode == "create" && !strings.Contains(string(calls), "plans ") {
				t.Fatal("mail-disabled seeded plans were selected without creating an owned eligible fixture")
			}
			var after string
			db.QueryRow(`SELECT string_agg(md5(to_jsonb(p)::text),',' ORDER BY id) FROM plans p WHERE id IN(1,2)`).Scan(&after)
			if before != after {
				t.Fatal("built-in plan quota/default/policy rows were changed")
			}
			if positive {
				var planID, mailboxes int
				var policyMail bool
				if err := db.QueryRow(`SELECT s.plan_id,e.max_mailboxes,(e.hosting_policy#>>'{permissions,mail}')::boolean FROM subscriptions s JOIN subscription_entitlements e ON e.subscription_id=s.id`).Scan(&planID, &mailboxes, &policyMail); err != nil {
					t.Fatal(err)
				}
				if mailboxes != 4 || !policyMail || mode == "reuse" && planID != 3 {
					t.Fatalf("created subscription cannot host required mail fixture: plan=%d quota=%d enabled=%v", planID, mailboxes, policyMail)
				}
			} else if mode != "invalid-entitlement" && strings.Contains(string(calls), "subscriptions ") {
				t.Fatalf("invalid/unavailable fixture plan reached subscription mutation: %s", calls)
			}
		})
	}
}

func TestNativeMailPlanCreationBoundaryFailsClosed(t *testing.T) {
	data, err := os.ReadFile("current-install-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	functions := shellFixtureFunction(t, string(data), "find_native_mail_plan", false) + "\n" + shellFixtureFunction(t, string(data), "select_or_create_native_mail_plan", false)
	for _, mode := range []string{"reuse", "create", "empty-result", "bad-id", "db-error", "post-error", "collision", "bad-token"} {
		t.Run(mode, func(t *testing.T) {
			state := t.TempDir()
			program := `set -euo pipefail
NAKPANEL_RUN_TOKEN=fixture-mail-test
[[ "$MODE" != bad-token ]] || NAKPANEL_RUN_TOKEN="bad'owner"
printf 0 >"$STATE/queries"
db(){
 local n;n=$(cat "$STATE/queries");n=$((n+1));printf '%s' "$n" >"$STATE/queries"
 [[ "$MODE" != db-error ]] || return 75
 if [[ "$n" == 1 ]];then
  case "$MODE" in reuse) echo 31;;bad-id) echo not-a-plan;;esac
 elif [[ "$n" == 2 ]];then
  if [[ "$MODE" == collision ]];then echo 1;else echo 0;fi
 elif [[ "$n" == 3 && "$MODE" != empty-result ]];then echo 41
 fi
}
post(){
 printf '%s\n' "$*" >>"$STATE/posts"
 [[ "$MODE" != post-error ]] || return 76
 [[ "$1" == plans && "$*" == *'plan_id=0'* && "$*" == *'max_mailboxes=4'* && "$*" == *'mailbox_quota_mb=64'* && "$*" == *'allow_mail=true'* && "$*" == *'php_versions=8.5'* ]]
}
` + functions + "\nselect_or_create_native_mail_plan\n"
			cmd := exec.Command("bash", "-c", program)
			cmd.Env = append(os.Environ(), "MODE="+mode, "STATE="+state)
			out, err := cmd.CombinedOutput()
			positive := mode == "reuse" || mode == "create"
			if (err == nil) != positive {
				t.Fatalf("%s: %v %s", mode, err, out)
			}
			posts, _ := os.ReadFile(filepath.Join(state, "posts"))
			if mode == "reuse" || mode == "bad-id" || mode == "db-error" || mode == "collision" || mode == "bad-token" {
				if len(posts) != 0 {
					t.Fatalf("unexpected fixture mutation: %s", posts)
				}
			} else if strings.Count(string(posts), "plans ") != 1 {
				t.Fatalf("fixture creation was skipped/repeated: %s", posts)
			}
		})
	}
}

func TestNativeMailFixtureEffectiveEligibilityWithRealPostgres(t *testing.T) {
	data, err := os.ReadFile("current-install-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	function := shellFixtureFunction(t, string(data), "assert_native_mail_fixture", false)
	for _, tc := range []struct {
		name, mutation string
		ready          bool
	}{
		{"ready", "", true},
		{"mail quota zero", `UPDATE subscription_entitlements SET max_mailboxes=0`, false},
		{"policy mail disabled", `UPDATE subscription_entitlements SET hosting_policy=jsonb_set(hosting_policy,'{mail,enabled}','false')`, false},
		{"permission disabled", `UPDATE subscription_entitlements SET hosting_policy=jsonb_set(hosting_policy,'{permissions,mail}','false')`, false},
		{"policy quota zero", `UPDATE subscription_entitlements SET hosting_policy=jsonb_set(hosting_policy,'{resources,max_mailboxes}','0')`, false},
		{"mailbox bytes zero", `UPDATE subscription_entitlements SET hosting_policy=jsonb_set(hosting_policy,'{mail,mailbox_quota_mb}','0')`, false},
		{"subscription override", `INSERT INTO subscription_policy_overrides VALUES(88,'{"mail":{"enabled":false}}')`, false},
		{"site override", `INSERT INTO site_policy_overrides VALUES(101,'{"php":{"default_version":"8.3"}}')`, false},
		{"wrong site owner", `UPDATE sites SET subscription_id=89`, false},
		{"wrong PHP intent", `UPDATE sites SET desired_php_version='8.3'`, false},
		{"inactive site", `UPDATE sites SET status='pending'`, false},
		{"unsynced subscription", `UPDATE subscriptions SET sync_status='pending'`, false},
		{"invalid negative quota", `UPDATE subscription_entitlements SET max_mailboxes=-2`, false},
		{"string permission", `UPDATE subscription_entitlements SET hosting_policy=jsonb_set(hosting_policy,'{permissions,mail}','"true"')`, false},
		{"string mailbox bytes", `UPDATE subscription_entitlements SET hosting_policy=jsonb_set(hosting_policy,'{mail,mailbox_quota_mb}','"64"')`, false},
		{"wrong PHP offer", `UPDATE subscription_entitlements SET php_allowlist='8.3,8.5'`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, dsn, schema := nativeMailFixtureSQL(t)
			if _, err := db.Exec(`INSERT INTO subscriptions VALUES(88,11,1,'active','in_sync','NativeBootstrap'); INSERT INTO sites VALUES(101,88,'current-bootstrap.test','active','active','8.5','8.5')`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO subscription_entitlements VALUES(88,true,'8.5','8.5',4,$1)`, nativeMailPolicy); err != nil {
				t.Fatal(err)
			}
			if tc.mutation != "" {
				if _, err := db.Exec(tc.mutation); err != nil {
					t.Fatal(err)
				}
			}
			program := `set -euo pipefail
NAKPANEL_QUALIFICATION_PROFILE=ubuntu-26.04-native
subscription_id=88;site_id=101
db(){ psql -X -qAt "$TEST_DSN" -v ON_ERROR_STOP=1 -c "$1"; }
` + function + "\nassert_native_mail_fixture\n"
			cmd := exec.Command("bash", "-c", program)
			cmd.Env = append(os.Environ(), "TEST_DSN="+dsn, "PGOPTIONS=-c search_path="+schema)
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.ready {
				t.Fatalf("effective eligibility %s: %v %s", tc.name, err, out)
			}
		})
	}
}
