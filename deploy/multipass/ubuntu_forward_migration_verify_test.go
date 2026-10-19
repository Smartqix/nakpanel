package multipass_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	panelhttp "github.com/nakroteck/nakpanel/internal/control/http"
	"github.com/nakroteck/nakpanel/internal/control/phpapp"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestForwardMigrationVerifierRejectsMissingFixturesWithoutVMWork(t *testing.T) {
	tmp := t.TempDir()
	log := filepath.Join(tmp, "multipass.log")
	if err := os.WriteFile(filepath.Join(tmp, "multipass"), []byte("#!/bin/sh\necho called >> \"$VM_CALL_LOG\"\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "ubuntu-forward-migration-verify.sh")
	cmd.Env = append(os.Environ(), "PATH="+tmp+":"+os.Getenv("PATH"), "VM_CALL_LOG="+log, "NAKPANEL_RUN_TOKEN=migrationtest", "NAKPANEL_MULTIPASS_ARCH=arm64", "NAKPANEL_FORWARD_ARCHIVE=", "NAKPANEL_FORWARD_KEY=", "NAKPANEL_FORWARD_FIXTURE_DRIVER=", "NAKPANEL_FORWARD_TARGET_BUNDLE=")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "NAKPANEL_FORWARD_ARCHIVE") {
		t.Fatalf("err=%v output=%s", err, out)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatal("called Multipass before validating fixtures")
	}
}
func TestForwardMigrationVerifierHasCompleteGates(t *testing.T) {
	data, err := os.ReadFile("ubuntu-forward-migration-verify.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{"assert_vm_identity", "destroy_owned_vm", "--check-only", "--mode forward-migration", "--experimental-forward-migration", "install-native-target", "assert-source-readonly", "assert-migration-data", "assert-trusted-tls", "assert-no-source-writes", "assert-reboot", "pg_restore --version", "SHOW server_version", "SELECT VERSION()", "nginx -t", "named-checkconf", "sshd -t", "proftpd -t", "quotaon -p", "multipass restart"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(s, "destroy_legacy_phase_vms") || strings.Contains(s, "do-release-upgrade") {
		t.Fatal("uses unrelated cleanup or OS upgrade")
	}
}

func TestBundledForwardFixtureBehavior(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	for _, file := range []string{"ubuntu-forward-migration-probe.py", "ubuntu-forward-migration-fixture.py", "ubuntu_forward_migration_fixture_test.py"} {
		if _, err := os.ReadFile(file); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(python, "-I", "-B", "ubuntu_forward_migration_fixture_test.py")
	if os.Getenv("NAKPANEL_FORWARD_PHP_TEST_DSN") == "" && os.Getenv("NAKPANEL_NATIVE_FIXTURE_TEST_DSN") != "" {
		cmd.Env = append(os.Environ(), "NAKPANEL_FORWARD_PHP_TEST_DSN="+os.Getenv("NAKPANEL_NATIVE_FIXTURE_TEST_DSN"))
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fixture behavior: %v\n%s", err, out)
	}
}

func signedForwardBundle(t *testing.T, root string) (string, string) {
	t.Helper()
	bundle := filepath.Join(root, "bundle")
	key := filepath.Join(root, "private.pem")
	public := filepath.Join(root, "public.pem")
	for _, args := range [][]string{{"genrsa", "-out", key, "2048"}, {"pkey", "-in", key, "-pubout", "-out", public}} {
		if out, err := exec.Command("openssl", args...).CombinedOutput(); err != nil {
			t.Fatalf("key fixture: %s %v", out, err)
		}
	}
	elf := make([]byte, 120)
	copy(elf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(elf[16:], 2)
	binary.LittleEndian.PutUint16(elf[18:], 183)
	binary.LittleEndian.PutUint32(elf[20:], 1)
	binary.LittleEndian.PutUint64(elf[32:], 64)
	binary.LittleEndian.PutUint16(elf[52:], 64)
	binary.LittleEndian.PutUint16(elf[54:], 56)
	binary.LittleEndian.PutUint16(elf[56:], 1)
	binary.LittleEndian.PutUint32(elf[64:], 1)
	binary.LittleEndian.PutUint64(elf[96:], 120)
	files := map[string][]byte{"VERSION": []byte("29.0.0\n"), "Makefile": []byte("build:\n"), "go.mod": []byte("module example\n"), "go.sum": []byte("checksums\n"), "deploy/install/install.sh": []byte("#!/bin/sh\n"), "migrations/00001.sql": []byte("-- fixture\n")}
	for _, name := range []string{"panel", "agent", "panelctl"} {
		files["bin/"+name] = elf
	}
	hashes := map[string]string{}
	for name, data := range files {
		path := filepath.Join(bundle, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		hashes[name] = hex.EncodeToString(sum[:])
	}
	manifest, _ := json.Marshal(map[string]any{"schema_version": 1, "version": "29.0.0", "commit": strings.Repeat("a", 40), "go_toolchain": "go1.26.9", "cgo_enabled": false, "os": "linux", "architecture": "arm64", "cpu_baseline": "v8.0", "files": hashes})
	os.WriteFile(filepath.Join(bundle, "manifest.json"), manifest, 0600)
	if out, err := exec.Command("openssl", "dgst", "-sha256", "-sign", key, "-out", filepath.Join(bundle, "manifest.sig"), filepath.Join(bundle, "manifest.json")).CombinedOutput(); err != nil {
		t.Fatalf("sign fixture: %s %v", out, err)
	}
	return bundle, public
}

func TestForwardVerifierRejectsUnsignedTargetBeforeAnyVMWork(t *testing.T) {
	tmp := t.TempDir()
	bundle, public := signedForwardBundle(t, tmp)
	os.WriteFile(filepath.Join(bundle, "bin/panel"), []byte("tampered"), 0600)
	log := filepath.Join(tmp, "multipass.log")
	os.WriteFile(filepath.Join(tmp, "multipass"), []byte("#!/bin/sh\necho called >> \"$VM_CALL_LOG\"\nexit 1\n"), 0700)
	archive, key := filepath.Join(tmp, "source.nkbk"), filepath.Join(tmp, "key")
	os.WriteFile(archive, []byte("archive"), 0600)
	os.WriteFile(key, []byte("key"), 0600)
	driver := filepath.Join(tmp, "driver")
	os.WriteFile(driver, []byte("#!/bin/sh\nprintf '%s\\n' fixture-v1 install-native-target assert-source-readonly assert-baseline assert-migration-data assert-services assert-trusted-tls assert-reboot assert-no-source-writes\n"), 0700)
	cmd := exec.Command("bash", "ubuntu-forward-migration-verify.sh")
	cmd.Env = append(os.Environ(), "PATH="+tmp+":"+os.Getenv("PATH"), "VM_CALL_LOG="+log, "NAKPANEL_RUN_TOKEN=migrationtest", "NAKPANEL_MULTIPASS_ARCH=arm64", "NAKPANEL_MULTIPASS_SOURCE_VM=nakpanel-source-test", "NAKPANEL_FORWARD_ARCHIVE="+archive, "NAKPANEL_FORWARD_KEY="+key, "NAKPANEL_FORWARD_TARGET_BUNDLE="+bundle, "NAKPANEL_FORWARD_TARGET_PUBLIC_KEY="+public, "NAKPANEL_FORWARD_TARGET_VERSION=29.0.0", "NAKPANEL_FORWARD_ALLOW_DEVELOPMENT=0", "NAKPANEL_FORWARD_FIXTURE_DRIVER="+driver)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "bundle verification") {
		t.Fatalf("err=%v out=%s", err, out)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		t.Fatal("called Multipass before signature validation")
	}
}

func TestForwardVerifierDoesNotReuseNobleCloudImageForResoluteTarget(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "alias", true: "explicit"}[explicit], func(t *testing.T) {
			tmp := t.TempDir()
			scriptdir := filepath.Join(tmp, "deploy/multipass")
			os.MkdirAll(scriptdir, 0700)
			for source, destination := range map[string]string{"ubuntu-forward-migration-verify.sh": "deploy/multipass/verify.sh", "ubuntu-forward-migration-fixture.py": "deploy/multipass/ubuntu-forward-migration-fixture.py", "../release/verify.py": "deploy/release/verify.py", "../install/stage_bundle.py": "deploy/install/stage_bundle.py"} {
				data, err := os.ReadFile(source)
				if err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(tmp, destination)
				os.MkdirAll(filepath.Dir(target), 0700)
				os.WriteFile(target, data, 0700)
			}
			os.WriteFile(filepath.Join(scriptdir, "common.sh"), []byte(`assert_distinct_vm_names(){ :; }
validate_run_identity(){ :; }
assert_disposable_name(){ :; }
require_multipass(){ printf '%s|%s|%s' "$NAKPANEL_MULTIPASS_IMAGE" "${NAKPANEL_MULTIPASS_IMAGE_SOURCE:-}" "${NAKPANEL_MULTIPASS_IMAGE_SHA256:-}" > "$FORWARD_OBSERVED"; return 1; }
`), 0600)
			driver := filepath.Join(tmp, "driver")
			os.WriteFile(driver, []byte("#!/bin/sh\nprintf '%s\\n' fixture-v1 install-native-target assert-source-readonly assert-baseline assert-migration-data assert-services assert-trusted-tls assert-reboot assert-no-source-writes\n"), 0700)
			bundle, public := signedForwardBundle(t, tmp)
			archive, key := filepath.Join(tmp, "archive"), filepath.Join(tmp, "key")
			os.WriteFile(archive, []byte("archive"), 0600)
			os.WriteFile(key, []byte("key"), 0600)
			observed := filepath.Join(tmp, "observed")
			cmd := exec.Command("bash", filepath.Join(scriptdir, "verify.sh"))
			cmd.Env = append(os.Environ(), "NAKPANEL_FORWARD_ARCHIVE="+archive, "NAKPANEL_FORWARD_KEY="+key, "NAKPANEL_FORWARD_TARGET_BUNDLE="+bundle, "NAKPANEL_FORWARD_TARGET_PUBLIC_KEY="+public, "NAKPANEL_FORWARD_TARGET_VERSION=29.0.0", "NAKPANEL_FORWARD_ALLOW_DEVELOPMENT=0", "NAKPANEL_FORWARD_FIXTURE_DRIVER="+driver, "NAKPANEL_MULTIPASS_SOURCE_VM=nakpanel-source-test", "NAKPANEL_RUN_TOKEN=migrationtest", "NAKPANEL_MULTIPASS_ARCH=arm64", "NAKPANEL_MULTIPASS_IMAGE=24.04", "NAKPANEL_MULTIPASS_IMAGE_SOURCE=/offline/noble.img", "NAKPANEL_MULTIPASS_IMAGE_SHA256=noble-digest", "FORWARD_OBSERVED="+observed, "NAKPANEL_FORWARD_TARGET_IMAGE_SOURCE=", "NAKPANEL_FORWARD_TARGET_IMAGE_SHA256=")
			want := "26.04||"
			if explicit {
				cmd.Env = append(cmd.Env, "NAKPANEL_FORWARD_TARGET_IMAGE_SOURCE=/offline/resolute.img", "NAKPANEL_FORWARD_TARGET_IMAGE_SHA256=resolute-digest")
				want = "26.04|/offline/resolute.img|resolute-digest"
			}
			if out, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("stub must stop before VM access: %s", out)
			}
			got, err := os.ReadFile(observed)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != want {
				t.Fatalf("target image=%q want %q", got, want)
			}
		})
	}
}

// Exercise actual migration revision shapes and the exact canonical serializer
// used by SavePlan. The qualifier compares a stable live-row shape, never a
// hand-written replica of a historical or canonical revision definition.
func TestForwardPlanProductionMigrationDefinitions(t *testing.T) {
	dsn := os.Getenv("NAKPANEL_NATIVE_FIXTURE_TEST_DSN")
	if dsn == "" {
		t.Skip("requires explicitly isolated PostgreSQL fixture DSN")
	}
	for _, file := range []string{"ubuntu-forward-migration-probe.py", "ubuntu_forward_migration_fixture_test.py"} {
		if _, err := os.ReadFile(file); err != nil {
			t.Fatal(err)
		}
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil || !filepath.IsAbs(config.Host) {
		t.Fatal("requires an explicitly owned Unix-socket PostgreSQL fixture DSN", err)
	}
	admin := stdlib.OpenDB(*config)
	defer admin.Close()
	schema := fmt.Sprintf("forward_plans_%d_%d", os.Getpid(), time.Now().UnixNano())
	if _, err = admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec("DROP SCHEMA " + schema + " CASCADE")
	config.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*config)
	defer db.Close()
	db.SetMaxOpenConns(4)
	files, err := filepath.Glob("../../migrations/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	cases := []map[string]any{}
	for _, file := range files {
		version := strings.SplitN(filepath.Base(file), "_", 2)[0]
		if version > "20261018000056" {
			break
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(strings.SplitN(string(raw), "-- +goose Down", 2)[0]); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if version != "20260830000047" && version != "20260927000051" {
			continue
		}
		var id int64
		if err = db.QueryRow("SELECT id FROM plans WHERE name='Starter' AND reseller_id IS NULL").Scan(&id); err != nil {
			t.Fatal(err)
		}
		var definition, live json.RawMessage
		if err = db.QueryRow(`SELECT r.definition,jsonb_build_object('plan',to_jsonb(p)-'created_at'-'updated_at'-'last_validated_at'-'readiness_error','presets',to_jsonb(ps)-'plan_id'-'updated_at') FROM plans p JOIN plan_revisions r ON r.plan_id=p.id AND r.revision=p.revision JOIN plan_service_presets ps ON ps.plan_id=p.id WHERE p.id=$1`, id).Scan(&definition, &live); err != nil {
			t.Fatal(err)
		}
		plan, err := controlquota.NewSQLStore(db).GetPlan(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		canonical, _, err := controlquota.CanonicalPlanDefinition(plan)
		if err != nil {
			t.Fatal(err)
		}
		candidate := plan
		candidate.PHPAllowlist = "8.5"
		candidate.DefaultPHPVersion = "8.5"
		candidate.Revision++
		// Deep-copy policy/presets because their PHP offer slices are reference types.
		candidate.HostingPolicy.PHP.AllowedVersions = []string{"8.5"}
		candidate.HostingPolicy.PHP.DefaultVersion = "8.5"
		candidate.Presets.Hosting.DefaultPHPVersion = "8.5"
		candidate.Presets.Hosting.AllowedPHPVersions = []string{"8.5"}
		after, _, err := controlquota.CanonicalPlanDefinition(candidate)
		if err != nil {
			t.Fatal(err)
		}
		preview, err := controlquota.NewSQLStore(db).PreviewPlan(context.Background(), candidate)
		if err != nil {
			t.Fatal(err)
		}
		if !preview.Allowed {
			t.Fatal("real product preview refused PHP-only candidate")
		}
		diff, err := controlquota.DiffPlanDefinitions(plan, candidate)
		if err != nil {
			t.Fatal(err)
		}
		for _, change := range diff {
			if change.Path != "php.default_version" && change.Path != "php.allowed_versions" {
				t.Fatalf("PHP-only Go candidate changed %s", change.Path)
			}
		}
		cases = append(cases, map[string]any{"migration": version, "historical": definition, "live": live, "canonical": canonical, "candidate": after, "changes": diff})
	}
	if len(cases) != 2 {
		t.Fatal("migration47/51 fixtures missing")
	}
	var activeAddon, inactiveAddon int64
	if err = db.QueryRow(`INSERT INTO addon_plans(name,is_active,php_allowlist) VALUES('Forward unassigned active',true,'8.2') RETURNING id`).Scan(&activeAddon); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`INSERT INTO addon_plans(name,is_active,php_allowlist) VALUES('Forward inactive historical',false,'8.1') RETURNING id`).Scan(&inactiveAddon); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	program := `import importlib.util,json,sys,copy,subprocess,os
from pathlib import Path
p=Path('ubuntu-forward-migration-probe.py');s=importlib.util.spec_from_file_location('probe',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
for c in json.load(sys.stdin):
 old=c['historical'];canonical=c['canonical']
 if 'plan' not in old or 'plan' in canonical:raise RuntimeError('actual revision serialization fixture missing')
 if old['plan']['id']!=canonical['id'] or old['plan']['name']!=canonical['name']:raise RuntimeError('Go canonical identity changed')
 m.assert_plan_only_php_changed(canonical,c['candidate'])
 before=c['live'];after=copy.deepcopy(before);after['plan'].update(revision=before['plan']['revision']+1,php_allowlist='8.5',default_php_version='8.5');after['plan']['hosting_policy']['php'].update(default_version='8.5',allowed_versions=['8.5']);after['presets']['php'].update(default_version='8.5',allowed_versions='8.5');after['presets']['hosting'].update(default_php_version='8.5',allowed_php_versions=['8.5'])
 m.assert_plan_only_php_changed(before,after)
 for mutate in ('scalar','unknown-policy','preset','sync-identity'):
  bad=copy.deepcopy(after)
  if mutate=='scalar':bad['plan']['max_mailboxes']+=1
  elif mutate=='unknown-policy':bad['plan']['hosting_policy']['unexpected_permission']=True
  elif mutate=='preset':bad['presets']['mail']['webmail_enabled']=not bad['presets']['mail'].get('webmail_enabled',False)
  else:bad['plan']['reseller_id']=99999
  try:m.assert_plan_only_php_changed(before,bad)
  except RuntimeError:pass
  else:raise RuntimeError('non-PHP '+mutate+' accepted')
 print('migration'+c['migration']+' actual historical + Go canonical PHP comparison PASS')
def query(sql):
 r=subprocess.run(['psql',os.environ['NAKPANEL_NATIVE_FIXTURE_TEST_DSN'],'-XAtq','-v','ON_ERROR_STOP=1','-c',sql],capture_output=True,text=True,check=True,env=dict(os.environ,PGOPTIONS='-c search_path='+sys.argv[1]))
 return r.stdout.strip()
m.pg=query
state=m.php_normalization_state()
if not isinstance(state,list):raise RuntimeError('invalid actual PHP normalization state query')
inventory=m.fixture_php_inventory();ids={x['id'] for x in inventory['addons']}
if int(sys.argv[2]) not in ids or int(sys.argv[3]) in ids:raise RuntimeError('actual addon inventory mismatches full active union')
try:m.assert_fixture_php_inventory({'target_profile':'ubuntu-26.04-sury','remediate_stale_php82':True},allow_preparation=True)
except RuntimeError as e:
 if 'add-on' not in str(e):raise
else:raise RuntimeError('unassigned active PHP82 addon accepted')
for table,projection in m.intent_projections().items():
 query("SELECT encode(sha256(convert_to(COALESCE(jsonb_agg(to_jsonb(q) ORDER BY id),'[]'::jsonb)::text,'UTF8')),'hex') FROM (SELECT "+projection+' FROM '+table+') q')
print('actual production addon union and every durable projection SQL PASS')
`
	for _, optimized := range []bool{false, true} {
		args := []string{"-I", "-B"}
		if optimized {
			args = append(args, "-O")
		}
		args = append(args, "-c", program, schema, fmt.Sprint(activeAddon), fmt.Sprint(inactiveAddon))
		cmd := exec.Command("python3", args...)
		cmd.Stdin = bytes.NewReader(payload)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("actual production definitions optimized=%t: %v\n%s", optimized, err, out)
		} else {
			t.Log(string(out))
		}
	}
	forwardManagedHTTPContract(t, db)
	forwardClassicStoreContract(t, db)
	forwardPHPDurableOracle(t, schema)
}

// Embed the service interface so unused operations cannot silently turn into
// fake implementations. The actual HTTP parser calls the real SQL store.
type forwardPHPService struct {
	panelhttp.PHPApplicationService
	store *phpapp.SQLStore
}

// The HTTP parser and SQL implementation are real; only server-owned runtime
// discovery is supplied by the test. No readiness field comes from the form.
type forwardPlanPHPService struct {
	panelhttp.QuotaManager
	store *controlquota.SQLStore
	ready []string
}

func (s *forwardPlanPHPService) command(actor auth.SessionUser, id int64, input controlquota.PlanPHPVersionsInput) controlquota.PlanPHPVersionsCommand {
	return controlquota.PlanPHPVersionsCommand{PlanID: id, Input: input, Actor: actor, Scope: types.ProviderScope{ActorUserID: actor.ID, Role: string(actor.Role)}, ReadyPHPVersions: s.ready}
}
func (s *forwardPlanPHPService) PreviewPlanPHPVersions(ctx context.Context, actor auth.SessionUser, id int64, input controlquota.PlanPHPVersionsInput) (controlquota.PlanPHPVersionsPreview, error) {
	return s.store.PreviewPlanPHPVersions(ctx, s.command(actor, id, input))
}
func (s *forwardPlanPHPService) UpdatePlanPHPVersions(ctx context.Context, actor auth.SessionUser, id int64, input controlquota.PlanPHPVersionsInput) (controlquota.PlanPHPVersionsResult, error) {
	return s.store.UpdatePlanPHPVersions(ctx, s.command(actor, id, input))
}

type forwardPlanSession struct {
	forwardPHPSession
	actor auth.SessionUser
}

func (s forwardPlanSession) GetSession(context.Context, string, time.Time) (auth.SessionUser, error) {
	return s.actor, nil
}

func TestForwardPHPOnlyPlanAPIProductionSeeds(t *testing.T) {
	dsn := os.Getenv("NAKPANEL_NATIVE_FIXTURE_TEST_DSN")
	if dsn == "" {
		t.Skip("requires explicitly isolated PostgreSQL fixture DSN")
	}
	if _, err := os.ReadFile("ubuntu-forward-migration-probe.py"); err != nil {
		t.Fatal(err)
	}
	for _, terminal := range []string{"20261015000055", "20261018000056"} {
		t.Run("schema"+terminal[len(terminal)-2:], func(t *testing.T) {
			config, err := pgx.ParseConfig(dsn)
			if err != nil || !filepath.IsAbs(config.Host) {
				t.Fatal("requires owned Unix-socket PostgreSQL", err)
			}
			admin := stdlib.OpenDB(*config)
			defer admin.Close()
			schema := fmt.Sprintf("forward_php_api_%d_%d", os.Getpid(), time.Now().UnixNano())
			if _, err = admin.Exec("CREATE SCHEMA " + schema); err != nil {
				t.Fatal(err)
			}
			defer admin.Exec("DROP SCHEMA " + schema + " CASCADE")
			config.RuntimeParams["search_path"] = schema
			db := stdlib.OpenDB(*config)
			defer db.Close()
			db.SetMaxOpenConns(4)
			files, err := filepath.Glob("../../migrations/*.sql")
			if err != nil || len(files) == 0 {
				t.Fatal("production migrations missing", err)
			}
			last := ""
			for _, file := range files {
				version := strings.SplitN(filepath.Base(file), "_", 2)[0]
				if version > terminal {
					break
				}
				raw, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = db.Exec(strings.SplitN(string(raw), "-- +goose Down", 2)[0]); err != nil {
					t.Fatalf("%s: %v", file, err)
				}
				last = version
			}
			if last != terminal {
				t.Fatalf("missing actual terminal schema %s", terminal)
			}
			var id int64
			var revision int
			if err = db.QueryRow("SELECT id,revision FROM plans WHERE name='Starter' AND reseller_id IS NULL").Scan(&id, &revision); err != nil {
				t.Fatal(err)
			}
			var sparse bool
			if err = db.QueryRow(`SELECT NOT(ps.php ? 'max_execution_seconds') AND p.hosting_policy#>>'{php,max_execution_seconds}'='30' AND NOT(ps.dns ? 'default_ttl') AND p.hosting_policy#>>'{dns,default_ttl}'='3600' FROM plans p JOIN plan_service_presets ps ON ps.plan_id=p.id WHERE p.id=$1`, id).Scan(&sparse); err != nil || !sparse {
				t.Fatalf("actual sparse seed no longer exercises absent/30 and absent/3600 representations: %t %v", sparse, err)
			}
			// Keep the actual sparse seed representations, and add unknown keys
			// that typed full-form serialization cannot safely reconstruct.
			for _, query := range []string{`UPDATE plans SET hosting_policy=hosting_policy||'{"future_policy":{"keep":[null,"opaque"]}}'::jsonb WHERE id=$1`, `UPDATE plan_service_presets SET mail=mail||'{"future_mail":{"keep":null}}'::jsonb,hosting=hosting||'{"future_hosting":[false,0]}'::jsonb,php=php||'{"future_php":{"keep":true}}'::jsonb WHERE plan_id=$1`} {
				if _, err = db.Exec(query, id); err != nil {
					t.Fatal(err)
				}
			}
			var actor auth.SessionUser
			if err = db.QueryRow("SELECT id,email,role FROM users WHERE role='admin' ORDER BY id LIMIT 1").Scan(&actor.ID, &actor.Email, &actor.Role); err != nil {
				t.Fatal(err)
			}
			service := &forwardPlanPHPService{store: controlquota.NewSQLStore(db), ready: []string{"8.5"}}
			server := panelhttp.NewServer(nil, auth.NewSessionManager(forwardPlanSession{actor: actor}, auth.SessionOptions{}), panelhttp.ServerOptions{QuotaManager: service})
			request := func(suffix string, form url.Values, status int) []byte {
				t.Helper()
				req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("https://panel.test/plans/%d/php-versions%s", id, suffix), strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Accept", "application/json")
				req.AddCookie(&http.Cookie{Name: panelhttp.SessionCookieName, Value: "owned-test"})
				csrf := sha256.Sum256([]byte("nakpanel-csrf-v1:owned-test"))
				req.Header.Set("X-Nakpanel-CSRF", hex.EncodeToString(csrf[:]))
				rec := httptest.NewRecorder()
				server.Handler().ServeHTTP(rec, req)
				if rec.Code != status {
					t.Fatalf("actual plan API suffix=%s status=%d expected=%d body=%s", suffix, rec.Code, status, rec.Body.String())
				}
				return rec.Body.Bytes()
			}
			query := func(sql string) []byte {
				t.Helper()
				var value []byte
				if err := db.QueryRow(sql, id).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			state := func() []byte {
				return query(`SELECT jsonb_build_object('plan',to_jsonb(p),'presets',to_jsonb(ps),'history',(SELECT jsonb_agg(to_jsonb(r) ORDER BY revision) FROM plan_revisions r WHERE plan_id=p.id),'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM audit_events a WHERE target_type='plan' AND target_id=p.id))::text FROM plans p LEFT JOIN plan_service_presets ps ON ps.plan_id=p.id WHERE p.id=$1`)
			}
			rawContract := func() []byte {
				return query(`SELECT jsonb_build_object('plan',to_jsonb(p)-'created_at'-'updated_at'-'last_validated_at'-'readiness_error','presets',to_jsonb(ps)-'plan_id'-'updated_at')::text FROM plans p JOIN plan_service_presets ps ON ps.plan_id=p.id WHERE p.id=$1`)
			}
			historySQL := fmt.Sprintf(`SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY revision),'[]'::jsonb)::text FROM plan_revisions r WHERE plan_id=$1 AND revision<=%d`, revision)
			oldHistory, before := query(historySQL), rawContract()
			program := `import importlib.util,json,sys
s=importlib.util.spec_from_file_location('p','ubuntu-forward-migration-probe.py');p=importlib.util.module_from_spec(s);s.loader.exec_module(p)
print(json.dumps(p.plan_php_form(int(sys.argv[1]),['8.5'],'8.5')))`
			cmd := exec.Command("python3", "-I", "-B", "-c", program, fmt.Sprint(revision))
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("qualifier form: %v %s", err, out)
			}
			var fields [][]string
			if err = json.Unmarshal(out, &fields); err != nil {
				t.Fatal(err)
			}
			form := url.Values{}
			for _, field := range fields {
				form.Add(field[0], field[1])
			}
			initial := state()
			preview := request("/preview", form, http.StatusOK)
			var previewPaths struct{ Preview types.PlanPreview }
			if err = json.Unmarshal(preview, &previewPaths); err != nil {
				t.Fatal(err)
			}
			for _, change := range previewPaths.Preview.Changes {
				t.Logf("actual preview field path: %s", change.Path)
			}
			if !bytes.Equal(initial, state()) {
				t.Fatal("actual preview mutated seed state/history/audit/timestamps")
			}
			cmd = exec.Command("python3", "-I", "-B", "-c", `import importlib.util,sys
s=importlib.util.spec_from_file_location('p','ubuntu-forward-migration-probe.py');p=importlib.util.module_from_spec(s);s.loader.exec_module(p)
p.assert_php_only_preview(sys.stdin.read(),int(sys.argv[1]),int(sys.argv[2]))`, fmt.Sprint(id), fmt.Sprint(revision))
			cmd.Stdin = bytes.NewReader(preview)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("qualifier refused real preview before commit: %v %s", err, out)
			}
			result := request("", form, http.StatusOK)
			after := rawContract()
			if !bytes.Equal(oldHistory, query(historySQL)) {
				t.Fatal("actual PHP API changed immutable prior history")
			}
			var valid bool
			if err = db.QueryRow(`SELECT r.actor_user_id=$3 AND r.change_reason=$4 AND r.definition_hash=encode(sha256(convert_to(r.definition::text,'UTF8')),'hex') AND r.definition#>>'{_operation,kind}'='php_versions_only' AND (r.definition#>>'{_operation,from_revision}')::int=$2-1 AND (SELECT count(*)=1 FROM audit_events a WHERE a.target_type='plan' AND a.target_id=$1 AND a.metadata->>'operation'='php_versions_only' AND (a.metadata->>'new_revision')::int=$2 AND a.actor_user_id=$3 AND a.metadata->>'change_reason'=$4 AND a.metadata->>'definition_hash'=r.definition_hash) FROM plan_revisions r WHERE r.plan_id=$1 AND r.revision=$2`, id, revision+1, actor.ID, form.Get("change_reason")).Scan(&valid); err != nil || !valid {
				t.Fatalf("actual revision+audit attribution/hash incomplete: %t %v", valid, err)
			}
			payload, _ := json.Marshal(map[string]any{"before": json.RawMessage(before), "after": json.RawMessage(after), "preview": json.RawMessage(preview), "result": json.RawMessage(result)})
			verify := `import importlib.util,json,sys
s=importlib.util.spec_from_file_location('p','ubuntu-forward-migration-probe.py');p=importlib.util.module_from_spec(s);s.loader.exec_module(p);x=json.load(sys.stdin)
p.assert_php_only_preview(json.dumps(x['preview']),int(sys.argv[1]),int(sys.argv[2]));p.assert_plan_php_result(json.dumps(x['result']),int(sys.argv[1]),int(sys.argv[2])+1)
p.assert_plan_only_php_changed(x['before'],x['after'])
for key in ('mail','dns','performance','logs','applications'):
 if x['before']['presets'][key]!=x['after']['presets'][key]:raise RuntimeError('raw seed preset changed: '+key)
for section,keys in (('hosting',('allowed_php_versions','default_php_version')),('php',('allowed_versions','default_version'))):
 for key in keys:
  if (key in x['before']['presets'][section])!=(key in x['after']['presets'][section]):raise RuntimeError('absent PHP mirror materialized: '+section+'.'+key)
if x['before']['plan']['hosting_policy']['future_policy']!=x['after']['plan']['hosting_policy']['future_policy']:raise RuntimeError('unknown policy changed')
print('actual sparse production seed + unknown JSON preserved by real PHP-only HTTP API')`
			for _, optimized := range []bool{false, true} {
				args := []string{"-I", "-B"}
				if optimized {
					args = append(args, "-O")
				}
				args = append(args, "-c", verify, fmt.Sprint(id), fmt.Sprint(revision))
				cmd := exec.Command("python3", args...)
				cmd.Stdin = bytes.NewReader(payload)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("actual API comparison optimized=%t: %v %s", optimized, err, out)
				} else {
					t.Log(string(out))
				}
			}
			committed := state()
			request("/preview", form, http.StatusConflict)
			request("", form, http.StatusConflict)
			form.Set("expected_revision", fmt.Sprint(revision+1))
			noopPreview := request("/preview", form, http.StatusOK)
			var noopView struct {
				NoChange bool `json:"no_change"`
			}
			if err = json.Unmarshal(noopPreview, &noopView); err != nil || !noopView.NoChange {
				t.Fatalf("same-revision no-op preview: %s %v", noopPreview, err)
			}
			noop := request("", form, http.StatusOK)
			var noChange struct{ Changed bool }
			if err = json.Unmarshal(noop, &noChange); err != nil || noChange.Changed {
				t.Fatalf("same-revision no-op response: %s %v", noop, err)
			}
			service.ready = []string{"8.3"}
			blocked := request("/preview", form, http.StatusOK)
			var view struct {
				Preview  struct{ Allowed bool }
				Blockers []any
			}
			if err = json.Unmarshal(blocked, &view); err != nil || view.Preview.Allowed || len(view.Blockers) == 0 {
				t.Fatalf("unready no-op preview did not refuse: %s %v", blocked, err)
			}
			request("", form, http.StatusBadRequest)
			service.ready = nil
			request("", form, http.StatusServiceUnavailable)
			if !bytes.Equal(committed, state()) {
				t.Fatal("stale/readiness refusal or no-op mutated raw state/history/audit/timestamps")
			}
			forwardLegacySnapshotMirrorContract(t, db)
		})
	}
}

func forwardLegacySnapshotMirrorContract(t *testing.T, db *sql.DB) {
	t.Helper()
	var id int64
	var revision int
	if err := db.QueryRow("SELECT id,revision FROM plans WHERE name='Legacy Unlimited' AND reseller_id IS NULL").Scan(&id, &revision); err != nil {
		t.Fatal(err)
	}
	capture := func() json.RawMessage {
		t.Helper()
		var raw []byte
		if err := db.QueryRow(`SELECT COALESCE(jsonb_agg(to_jsonb(e)||jsonb_build_object('plan_id',s.plan_id,'sync_mode',s.sync_mode) ORDER BY e.subscription_id),'[]'::jsonb) FROM subscription_entitlements e JOIN subscriptions s ON s.id=e.subscription_id WHERE s.plan_id=$1`, id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	readyAccounts := func() {
		t.Helper()
		if _, err := db.Exec(`UPDATE subscription_system_accounts SET applied_revision=desired_revision,convergence_status='in_sync',last_error='' WHERE subscription_id IN (SELECT id FROM subscriptions WHERE plan_id=$1)`, id); err != nil {
			t.Fatal(err)
		}
	}
	initial := capture()
	// Supply only observed test-owned service convergence. The entitlement rows
	// remain the untouched production migration output before the first API call.
	readyAccounts()
	if !bytes.Equal(initial, capture()) {
		t.Fatal("test setup changed untouched legacy entitlement snapshots")
	}
	var actor auth.SessionUser
	if err := db.QueryRow("SELECT id,email,role FROM users WHERE role='admin' ORDER BY id LIMIT 1").Scan(&actor.ID, &actor.Email, &actor.Role); err != nil {
		t.Fatal(err)
	}
	service := &forwardPlanPHPService{store: controlquota.NewSQLStore(db), ready: []string{"8.3", "8.5"}}
	server := panelhttp.NewServer(nil, auth.NewSessionManager(forwardPlanSession{actor: actor}, auth.SessionOptions{}), panelhttp.ServerOptions{QuotaManager: service})
	for _, target := range []string{"sury", "native"} {
		t.Run("legacy-mirrors-"+target, func(t *testing.T) {
			before := capture()
			version := "8.3"
			if target == "native" {
				version = "8.5"
			}
			form := url.Values{"expected_revision": {fmt.Sprint(revision)}, "php_versions": {version}, "default_php_version": {version}, "change_reason": {"Owned fixture PHP-only snapshot mirror test"}}
			request := func(suffix string) []byte {
				t.Helper()
				req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("https://panel.test/plans/%d/php-versions%s", id, suffix), strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.AddCookie(&http.Cookie{Name: panelhttp.SessionCookieName, Value: "owned-test"})
				csrf := sha256.Sum256([]byte("nakpanel-csrf-v1:owned-test"))
				req.Header.Set("X-Nakpanel-CSRF", hex.EncodeToString(csrf[:]))
				rec := httptest.NewRecorder()
				server.Handler().ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Fatalf("legacy PHP API suffix=%s status=%d body=%s", suffix, rec.Code, rec.Body.String())
				}
				return rec.Body.Bytes()
			}
			preview := request("/preview")
			var view struct{ Preview types.PlanPreview }
			if err := json.Unmarshal(preview, &view); err != nil || !view.Preview.Allowed {
				t.Fatalf("real legacy API preview refused: %s %v", preview, err)
			}
			result := request("")
			payload, _ := json.Marshal(map[string]any{"before": before, "after": capture(), "result": json.RawMessage(result)})
			revision++
			readyAccounts()
			program := `import copy,importlib.util,json,sys
s=importlib.util.spec_from_file_location('p','ubuntu-forward-migration-probe.py');p=importlib.util.module_from_spec(s);s.loader.exec_module(p);x=json.load(sys.stdin)
before=x['before'];after=x['after'];sury=sys.argv[1]=='sury'
if len(before)!=2 or len(after)!=2:raise RuntimeError('actual two legacy seed subscriptions missing')
if any(not isinstance(r['service_presets']['php']['allowed_versions'],str) for r in before):raise RuntimeError('production migration legacy CSV mirror missing')
if sury and any(r['service_presets']['php']['allowed_versions']!='8.3,8.2' for r in before):raise RuntimeError('untouched migration legacy mirrors changed before actual API')
p.assert_snapshot_only_php_changed(before,after,preserve_supported_php=sury)
for mutation in ('memory_limit_mb','unknown_non_php'):
 bad=copy.deepcopy(after);php=bad[0]['service_presets']['php']
 if mutation=='memory_limit_mb':php[mutation]+=1
 else:php[mutation]={'keep':False}
 try:p.assert_snapshot_only_php_changed(before,bad,preserve_supported_php=sury)
 except RuntimeError:pass
 else:raise RuntimeError('non-PHP legacy snapshot mutation accepted: '+mutation)
if sury:
 for key,value in (('allowed_versions','8.3,8.4'),('default_version','8.5')):
  bad=copy.deepcopy(after);bad[0]['service_presets']['php'][key]=value
  try:p.assert_snapshot_only_php_changed(before,bad,preserve_supported_php=True)
  except RuntimeError:pass
  else:raise RuntimeError('Surý mirror-only PHP drift accepted: '+key)
print('actual legacy snapshot API '+sys.argv[1]+' PHP mirror update accepted; non-PHP and Surý drift rejected')`
			for _, optimized := range []bool{false, true} {
				args := []string{"-I", "-B"}
				if optimized {
					args = append(args, "-O")
				}
				args = append(args, "-c", program, target)
				cmd := exec.Command("python3", args...)
				cmd.Stdin = bytes.NewReader(payload)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("actual legacy snapshot comparator optimized=%t: %v %s", optimized, err, out)
				} else {
					t.Log(string(out))
				}
			}
		})
	}
}

func (s forwardPHPService) ConfigureApplication(ctx context.Context, actor auth.SessionUser, site int64, input phpapp.ConfigureApplicationInput) (types.PHPApplicationSpec, error) {
	return s.store.ConfigureApplication(ctx, actor.ID, site, input, types.PHPRuntimeCapability{Version: "8.5", Ready: true})
}

type forwardPHPSession struct{}

func (forwardPHPSession) CreateSession(context.Context, string, int64, time.Time, auth.SessionMeta) error {
	return nil
}
func (forwardPHPSession) DeleteSession(context.Context, string) error { return nil }
func (forwardPHPSession) GetSession(context.Context, string, time.Time) (auth.SessionUser, error) {
	return auth.SessionUser{ID: 1, Role: auth.RoleAdmin, Email: "admin@nakpanel.test"}, nil
}

type forwardPHPQueue struct{ jobs []river.JobArgs }

func (q *forwardPHPQueue) InsertTx(_ context.Context, _ *sql.Tx, args river.JobArgs, _ *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	q.jobs = append(q.jobs, args)
	return nil, nil
}

func forwardManagedHTTPContract(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`UPDATE subscription_entitlements SET hosting_policy=jsonb_set(jsonb_set(jsonb_set(hosting_policy,'{permissions}',hosting_policy->'permissions'||'{"git":true,"managed_php_deployments":true,"composer":true,"composer_code_execution":true}'::jsonb),'{php,allowed_versions}','["8.3","8.4","8.5"]'::jsonb),'{resources,max_php_releases}','10') WHERE subscription_id=1`); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"8.3", "8.4"} {
		t.Run("managed-http-"+version, func(t *testing.T) {
			var site, app, repository int64
			if err := db.QueryRow(`INSERT INTO sites(owner_user_id,subscription_id,customer_id,system_account_id,username,document_root,domain,php_version,desired_php_version,status,desired_status,https_redirect,desired_https_redirect) SELECT s.customer_user_id,s.id,s.customer_id,a.id,a.username,a.home_path||'/domains/forward'||$1||'/public_html','forward'||$1||'.test',$1,$1,'active','active',true,true FROM subscriptions s JOIN subscription_system_accounts a ON a.subscription_id=s.id WHERE s.id=1 RETURNING id`, version).Scan(&site); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(`INSERT INTO git_repositories(site_id,mode,branch) VALUES($1,'hosted','stable') RETURNING id`, site).Scan(&repository); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(`UPDATE php_applications SET hosting_mode='managed',repository_id=$2,repository_ref='release/stable',framework_profile='custom',public_path='www',health_path='/ready',shared_paths='["storage","cache"]',composer_install=true,composer_allow_plugins=true,release_retention=7,observed_state='healthy' WHERE site_id=$1 RETURNING id`, site, repository).Scan(&app); err != nil {
				t.Fatal(err)
			}
			for _, statement := range []string{`INSERT INTO php_workers(subscription_id,application_id,name,script,arguments,processes,desired_state) VALUES(1,$1,'running-worker','worker.php','["--queue"]',2,'running'),(1,$1,'stopped-worker','idle.php','[]',1,'stopped')`, `INSERT INTO php_environment_bindings(subscription_id,application_id,name,plain_value) VALUES(1,$1,'PRESERVE_ME','opaque-value')`, `INSERT INTO php_deployments(subscription_id,application_id,requested_revision,resolved_revision,release_number,status) VALUES(1,$1,'stable',repeat('a',40),1,'healthy')`} {
				if _, err := db.Exec(statement, app); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.Exec(`UPDATE php_applications SET active_deployment_id=(SELECT id FROM php_deployments WHERE application_id=$1) WHERE id=$1`, app); err != nil {
				t.Fatal(err)
			}
			var raw json.RawMessage
			if err := db.QueryRow(`SELECT to_jsonb(a) FROM php_applications a WHERE id=$1`, app).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			program := `import sys,importlib.util,json
s=importlib.util.spec_from_file_location('p','ubuntu-forward-migration-probe.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
print(json.dumps(m.php_application_form(json.load(sys.stdin))))`
			cmd := exec.Command("python3", "-I", "-B", "-c", program)
			cmd.Stdin = bytes.NewReader(raw)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("generated full form: %v %s", err, out)
			}
			var fields map[string]json.RawMessage
			if err = json.Unmarshal(out, &fields); err != nil {
				t.Fatal(err)
			}
			form := url.Values{}
			for key, value := range fields {
				var list []string
				if len(value) > 0 && value[0] == '[' {
					if err = json.Unmarshal(value, &list); err != nil {
						t.Fatal(err)
					}
					for _, v := range list {
						form.Add(key, v)
					}
				} else {
					var str string
					if err = json.Unmarshal(value, &str); err != nil {
						str = string(value)
					}
					form.Set(key, str)
				}
			}
			hash := func() string {
				var value string
				if err := db.QueryRow(`SELECT encode(sha256(convert_to(jsonb_build_object('application',to_jsonb(a)-'php_version'-'desired_revision'-'convergence_status'-'last_error'-'updated_at','workers',(SELECT jsonb_agg(to_jsonb(w) ORDER BY id) FROM php_workers w WHERE application_id=a.id),'environment',(SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM php_environment_bindings e WHERE application_id=a.id),'deployments',(SELECT jsonb_agg(to_jsonb(d) ORDER BY id) FROM php_deployments d WHERE application_id=a.id),'site',(SELECT to_jsonb(s) FROM sites s WHERE s.id=a.site_id))::text,'UTF8')),'hex') FROM php_applications a WHERE a.id=$1`, app).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			before := hash()
			queue := &forwardPHPQueue{}
			service := forwardPHPService{store: phpapp.NewSQLStore(db, queue, nil)}
			server := panelhttp.NewServer(nil, auth.NewSessionManager(forwardPHPSession{}, auth.SessionOptions{}), panelhttp.ServerOptions{PHPApplications: service})
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("https://panel.test/sites/%d/php-application", site), strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Accept", "application/json")
			req.Header.Set("X-Nakpanel-SPA", "true")
			req.AddCookie(&http.Cookie{Name: panelhttp.SessionCookieName, Value: "owned-test"})
			csrf := sha256.Sum256([]byte("nakpanel-csrf-v1:owned-test"))
			req.Header.Set("X-Nakpanel-CSRF", hex.EncodeToString(csrf[:]))
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("actual parser/ConfigureApplication response=%d body=%s", rec.Code, rec.Body.String())
			}
			var actual string
			var revision int
			if err := db.QueryRow(`SELECT php_version,desired_revision FROM php_applications WHERE id=$1`, app).Scan(&actual, &revision); err != nil {
				t.Fatal(err)
			}
			if actual != "8.5" || revision != 2 || len(queue.jobs) != 1 || before != hash() {
				t.Fatalf("PHP-only HTTP configuration lost existing intent: php=%s revision=%d queued=%d preserved=%t", actual, revision, len(queue.jobs), before == hash())
			}
		})
	}
}

func forwardClassicStoreContract(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, name := range []string{"nil", "empty", "invalid"} {
		t.Run("classic-store-"+name, func(t *testing.T) {
			var site, app int64
			if err := db.QueryRow(`INSERT INTO sites(owner_user_id,subscription_id,customer_id,system_account_id,username,document_root,domain,php_version,desired_php_version,status,desired_status,https_redirect,desired_https_redirect) SELECT s.customer_user_id,s.id,s.customer_id,a.id,a.username,a.home_path||'/domains/classic-'||$1||'.test/public_html','classic-'||$1||'.test','8.3','8.3','active','active',true,true FROM subscriptions s JOIN subscription_system_accounts a ON a.subscription_id=s.id WHERE s.id=1 RETURNING id`, name).Scan(&site); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(`SELECT id FROM php_applications WHERE site_id=$1`, site).Scan(&app); err != nil {
				t.Fatal(err)
			}
			hash := func(mask bool) string {
				var raw string
				projection := "to_jsonb(a)"
				if mask {
					projection += "-'php_version'-'desired_revision'-'convergence_status'-'last_error'-'updated_at'"
				}
				if err := db.QueryRow(`SELECT jsonb_build_object('application',`+projection+`,'site',(SELECT to_jsonb(s) FROM sites s WHERE s.id=a.site_id))::text FROM php_applications a WHERE id=$1`, app).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				h := sha256.Sum256([]byte(raw))
				return hex.EncodeToString(h[:])
			}
			before, full := hash(true), hash(false)
			queue := &forwardPHPQueue{}
			input := phpapp.ConfigureApplicationInput{HostingMode: types.PHPHostingModeClassic, PHPVersion: "8.5"}
			if name == "empty" {
				input.SharedPaths = []string{}
			}
			if name == "invalid" {
				input.PHPVersion = "8.2"
			}
			_, err := phpapp.NewSQLStore(db, queue, nil).ConfigureApplication(context.Background(), 1, site, input, types.PHPRuntimeCapability{Version: "8.5", Ready: true})
			if name == "invalid" {
				if err == nil || !strings.Contains(err.Error(), "not allowed") || full != hash(false) || len(queue.jobs) != 0 {
					t.Fatalf("invalid classic request did not roll back: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("valid classic %s shared paths failed actual schema56: %v", name, err)
			}
			var version, kind, paths string
			var revision int
			if err = db.QueryRow(`SELECT php_version,desired_revision,jsonb_typeof(shared_paths),shared_paths::text FROM php_applications WHERE id=$1`, app).Scan(&version, &revision, &kind, &paths); err != nil {
				t.Fatal(err)
			}
			if version != "8.5" || revision != 2 || kind != "array" || paths != "[]" || before != hash(true) || len(queue.jobs) != 1 {
				t.Fatalf("classic PHP-only configure changed preserved state: version=%s revision=%d shared=%s/%s preserved=%t queued=%d", version, revision, kind, paths, before == hash(true), len(queue.jobs))
			}
		})
	}
}

func forwardPHPDurableOracle(t *testing.T, schema string) {
	t.Helper()
	program := `import sys,os,subprocess,importlib.util
s=importlib.util.spec_from_file_location('p','ubuntu-forward-migration-probe.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def query(sql):
 r=subprocess.run(['psql',os.environ['NAKPANEL_NATIVE_FIXTURE_TEST_DSN'],'-XAtq','-v','ON_ERROR_STOP=1','-c',sql],capture_output=True,text=True,check=True,env=dict(os.environ,PGOPTIONS='-c search_path='+sys.argv[1]))
 return r.stdout.strip()
projections=m.intent_projections()
cases=[('php_applications',"UPDATE php_applications SET repository_ref=repository_ref||'-changed' WHERE id=(SELECT min(id) FROM php_applications WHERE hosting_mode='managed')"),('php_workers',"UPDATE php_workers SET arguments='[\"--unexpected\"]' WHERE id=(SELECT min(id) FROM php_workers)"),('php_environment_bindings',"UPDATE php_environment_bindings SET plain_value='changed-opaque' WHERE id=(SELECT min(id) FROM php_environment_bindings)"),('php_deployments',"UPDATE php_deployments SET requested_revision='other-branch' WHERE id=(SELECT min(id) FROM php_deployments)")]
for table,mutation in cases:
 if table not in projections:raise RuntimeError('missing durable projection: '+table)
 sql="SELECT encode(sha256(convert_to(COALESCE(jsonb_agg(to_jsonb(q) ORDER BY id),'[]'::jsonb)::text,'UTF8')),'hex') FROM (SELECT "+projections[table]+' FROM '+table+') q'
 before=query(sql);changed=query('BEGIN;'+mutation+';'+sql+';ROLLBACK;')
 if before==changed:raise RuntimeError('durable non-PHP mutation escaped baseline: '+table)
 if query(sql)!=before:raise RuntimeError('owned test mutation was not rolled back')
 print(table+' durable mutation rejection PASS')
`
	cmd := exec.Command("python3", "-I", "-B", "-c", program, schema)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("durable PHP oracle: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}
