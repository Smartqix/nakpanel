package multipass

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func phase31PHPPSQLEnv(t *testing.T) []string {
	t.Helper()
	dsn := os.Getenv("NAKPANEL_NATIVE_FIXTURE_TEST_DSN")
	if dsn == "" {
		if os.Getenv("NAKPANEL_REQUIRE_PLAN_PHP_POSTGRES") == "1" {
			t.Fatal("NAKPANEL_NATIVE_FIXTURE_TEST_DSN is required for the real Phase31 psql boundary")
		}
		t.Skip("optional PostgreSQL: explicit native fixture DSN is not set")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil || !filepath.IsAbs(config.Host) {
		t.Fatal("an explicitly owned Unix-socket PostgreSQL fixture is required")
	}
	info, err := os.Stat(config.Host)
	if err != nil || !info.IsDir() {
		t.Fatal("owned PostgreSQL socket directory is unavailable")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) {
		t.Fatal("PostgreSQL fixture socket directory must belong to the current user")
	}
	psql, err := exec.LookPath("psql")
	if err != nil {
		t.Fatal("explicit PostgreSQL coverage requires real psql in PATH")
	}
	psql, err = filepath.Abs(psql)
	if err != nil {
		t.Fatal("psql absolute path is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	version, err := exec.CommandContext(ctx, "bash", "-c", `printf '%s' "${BASH_VERSINFO[0]}"`).Output()
	major, parseErr := strconv.Atoi(string(version))
	if err != nil || parseErr != nil || major < 5 {
		t.Fatal("the Phase31 fixture requires Bash5 or newer in PATH")
	}
	var env []string
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "PG") {
			env = append(env, item)
		}
	}
	return append(env, "PGHOST="+config.Host, "PGPORT="+strconv.Itoa(int(config.Port)),
		"PGDATABASE="+config.Database, "PGUSER="+config.User, "PGPASSWORD="+config.Password,
		"PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=3000 -c lock_timeout=1000",
		"PGCONNECT_TIMEOUT=3", "PGAPPNAME=nakpanel-phase31-readonly-oracle", "PHASE31_PSQL="+psql)
}

func phase31PHPFunction(t *testing.T, source, name string) string {
	t.Helper()
	// Extract only function definitions; never source the VM-operating verifier.
	pattern := `(?ms)^` + regexp.QuoteMeta(name) + `\(\)\{\n.*?^\}`
	if name == "db" {
		pattern = `(?m)^db\(\)\{[^\n]*\}$`
	}
	matches := regexp.MustCompile(pattern).FindAllString(source, -1)
	if len(matches) != 1 {
		t.Fatalf("expected one exact %s function", name)
	}
	return matches[0]
}

func phase31PHPHistoryCTE(kind string) string {
	rows, actor, label, reason, marker, hash := "1", "1::bigint", "'owned@example.test'", "'Owned read-only regression'", "'php_versions_only'", "encode(sha256(convert_to(definition::text,'UTF8')),'hex')"
	definition := ""
	switch kind {
	case "valid two":
		rows = "2"
	case "mixed missing kind":
		rows = "2"
		definition = `CASE WHEN n=1 THEN '{"_operation":{"kind":"php_versions_only"}}'::jsonb ELSE '{"_operation":{}}'::jsonb END`
	case "mixed JSON-null kind":
		rows = "2"
		definition = `CASE WHEN n=1 THEN '{"_operation":{"kind":"php_versions_only"}}'::jsonb ELSE '{"_operation":{"kind":null}}'::jsonb END`
	case "mixed null hash":
		rows, hash = "2", "CASE WHEN n=1 THEN encode(sha256(convert_to(definition::text,'UTF8')),'hex') ELSE NULL::text END"
	case "mixed null actor label":
		rows, label = "2", "CASE WHEN n=1 THEN 'owned@example.test' ELSE NULL END"
	case "mixed null reason":
		rows, reason = "2", "CASE WHEN n=1 THEN 'Owned read-only regression' ELSE NULL END"
	case "wrong count":
		rows = "2"
	case "zero rows":
		rows = "0"
	case "wrong hash":
		hash = "repeat('0',64)"
	case "null predicate":
		hash = "NULL::text"
	case "wrong marker":
		marker = "'ordinary'"
	case "missing actor":
		actor = "NULL::bigint"
	case "blank actor":
		label = "'   '"
	case "blank reason":
		reason = "'   '"
	}
	if definition == "" {
		definition = fmt.Sprintf("jsonb_build_object('_operation',jsonb_build_object('kind',%s::text))", marker)
	}
	return fmt.Sprintf(`WITH definitions AS(SELECT n,%s definition FROM generate_series(1,%s)n),plan_revisions AS(SELECT 77::bigint plan_id,1+n revision,definition,%s definition_hash,%s actor_user_id,%s::text actor_label,%s::text change_reason FROM definitions)`, definition, rows, hash, actor, label, reason)
}

func phase31PHPConvergenceCTE(kind string) string {
	snapshot, base, desired, applied, state, syncError, service, lastError, present, addon := "2", "2", "2", "2", "'in_sync'", "''", "'in_sync'", "''", "true", "false"
	switch kind {
	case "pending snapshot":
		state = "'pending'"
	case "snapshot error":
		syncError = "'owned failure'"
	case "wrong base":
		base = "1"
	case "wrong composed revision":
		snapshot = "1"
	case "pending account":
		service = "'pending'"
	case "unapplied account":
		applied = "1"
	case "account error":
		lastError = "'owned failure'"
	case "null predicate":
		lastError = "NULL"
	case "zero rows":
		present = "false"
	case "valid higher addon":
		addon, snapshot = "true", "9"
	case "unapplied higher addon":
		addon = "true"
	}
	return fmt.Sprintf(`WITH subscriptions AS(SELECT 1::bigint id,%s::text sync_status,%s::text sync_error,%s plan_revision,77::bigint plan_id WHERE %s),plans AS(SELECT 77::bigint id,2 revision),subscription_entitlements AS(SELECT 1::bigint subscription_id,%s source_revision),subscription_system_accounts AS(SELECT 1::bigint subscription_id,%s::text convergence_status,%s desired_revision,%s applied_revision,%s::text last_error),subscription_addons AS(SELECT 1::bigint subscription_id,4::bigint addon_plan_id WHERE %s),addon_plans AS(SELECT 4::bigint id,9 revision)`, state, syncError, base, present, snapshot, service, desired, applied, lastError, addon)
}

func TestPhase31PHPRealPSQLBooleanOracles(t *testing.T) {
	env := phase31PHPPSQLEnv(t)
	helper, err := os.ReadFile("phase31-plan-php-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := os.ReadFile("phase31-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	_ = helper // ReadFile also makes this child source a Go test-cache dependency.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	control := exec.CommandContext(ctx, "bash", "-c", `"$PHASE31_PSQL" -X -Atq -v ON_ERROR_STOP=1 -c "SELECT current_setting('transaction_read_only');VALUES(true),(false),(NULL::boolean);SELECT true::text;SELECT false::text"`)
	control.Env = env
	output, err := control.Output()
	if err != nil || string(output) != "on\nt\nf\n\ntrue\nfalse\n" {
		t.Fatal("real psql read-only/native boolean serialization control failed")
	}
	t.Log("actual owned Unix psql: read_only=on, native bool=t/f, bool::text=true/false")
	program := `set -euo pipefail
source ./phase31-plan-php-verify.sh
VM_NAME=unit
fail(){ echo "phase31: $*" >&2; exit 1; }
# Keep the actual wait_for string comparison, with one bounded diagnostic poll.
seq(){ printf '1\n'; }
sleep(){ :; }
` + phase31PHPFunction(t, string(verifier), "db") + "\n" + phase31PHPFunction(t, string(verifier), "wait_for") + `
# Replace only the VM transport. The exact db() still consumes real psql output.
multipass_exec_short(){
 [[ "$#" == 10 && "$1" == unit && "$2" == -- && "$3" == sudo && "$4" == -u && "$5" == postgres && "$6" == psql && "$7" == -Atqd && "$8" == nakpanel && "$9" == -c ]] || fail 'unexpected guest transport'
 local query="${10}" prefix value
 case "$query" in
  *'FROM plan_revisions'*) prefix="$PHASE31_HISTORY_CTE";;
  *'FROM audit_events'*) prefix="$PHASE31_AUDIT_CTE";;
  *'FROM subscriptions s JOIN plans p'*) prefix="$PHASE31_CONVERGENCE_CTE";;
  *) fail 'unexpected read oracle';;
 esac
 value="$("$PHASE31_PSQL" -X -Atq -v ON_ERROR_STOP=1 -c "${prefix} ${query}")" || fail 'read-only psql execution failed'
 printf '%s\n' "$value" >>"$PHASE31_TRACE"
 printf '%s\n' "$value"
}
case "$1" in
 history) phase31_php_history 77 1 5 "$PHASE31_EXPECT_WRITES";;
 convergence) phase31_php_wait 1;;
 *) fail 'unexpected oracle mode';;
esac
`
	for _, mode := range []string{"history", "convergence"} {
		cases := []string{"valid", "valid two", "mixed missing kind", "mixed JSON-null kind", "mixed null hash", "mixed null actor label", "mixed null reason", "wrong count", "zero rows", "wrong hash", "null predicate", "wrong marker", "missing actor", "blank actor", "blank reason", "wrong audit count"}
		if mode == "convergence" {
			cases = []string{"valid", "valid higher addon", "zero rows", "null predicate", "pending snapshot", "snapshot error", "wrong base", "wrong composed revision", "pending account", "unapplied account", "account error", "unapplied higher addon"}
		}
		for _, kind := range cases {
			t.Run(mode+"/"+kind, func(t *testing.T) {
				dir := t.TempDir()
				trace := filepath.Join(dir, "actual-psql-values")
				writes := 1
				if strings.HasPrefix(kind, "mixed ") || kind == "valid two" {
					writes = 2
				}
				rows := 5 + writes
				if kind == "wrong audit count" {
					rows = 5
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "bash", "-c", program, "fixture", mode)
				historyCTE, convergenceCTE := phase31PHPHistoryCTE(kind), phase31PHPConvergenceCTE(kind)
				auditCTE := fmt.Sprintf("WITH audit_events AS(SELECT 'plan.saved'::text action,'plan'::text target_type,77::bigint target_id FROM generate_series(1,%d))", rows)
				fixtureHash := sha256.Sum256([]byte(fmt.Sprintf("%s\n%s\n%s\n%d", historyCTE, convergenceCTE, auditCTE, writes)))
				t.Logf("fixture: mode=%s case=%q writes=%d sha256=%x", mode, kind, writes, fixtureHash)
				cmd.Env = append(append([]string{}, env...), "PHASE31_TRACE="+trace,
					"PHASE31_HISTORY_CTE="+historyCTE, "PHASE31_CONVERGENCE_CTE="+convergenceCTE,
					"PHASE31_AUDIT_CTE="+auditCTE, fmt.Sprintf("PHASE31_EXPECT_WRITES=%d", writes))
				output, err := cmd.CombinedOutput()
				values, readErr := os.ReadFile(trace)
				if readErr != nil || ctx.Err() != nil {
					t.Fatal("actual psql oracle did not complete within its bound")
				}
				valid := kind == "valid" || kind == "valid two" || kind == "valid higher addon"
				if (err == nil) != valid {
					t.Fatalf("accepted=%t want=%t actual psql=%q outcome=%s", err == nil, valid, values, output)
				}
				if valid && !strings.HasPrefix(string(values), "true\n") {
					t.Fatalf("valid actual psql value was not literal true: %q", values)
				}
				if !valid && !strings.Contains(string(output), "phase31: PHP-only") {
					t.Fatalf("negative stopped outside the actual oracle: %s", output)
				}
				if kind == "wrong audit count" && (string(values) != "true\n5\n" || !strings.Contains(string(output), "exactly one atomic audit")) {
					t.Fatalf("negative did not reach the real audit counter: %q %s", values, output)
				}
				if !valid && kind != "wrong audit count" {
					want := "false\n"
					if mode == "convergence" && (kind == "null predicate" || kind == "zero rows") {
						want = "\n"
					}
					if string(values) != want {
						t.Fatalf("negative actual psql value=%q want%q", values, want)
					}
				}
			})
		}
	}
}
