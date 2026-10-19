package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestCollectPlatformUsesObservedToolsAndIntent(t *testing.T) {
	p, err := collectPlatform(context.Background(), "test-dsn", platformProbe{
		readFile: func(path string) ([]byte, error) {
			switch path {
			case "/etc/os-release":
				return []byte("ID=ubuntu\nVERSION_ID=26.04\nVERSION_CODENAME=resolute\n"), nil
			case "/etc/nakpanel/platform.json":
				return []byte(fmt.Sprintf(`{"os_id":"ubuntu","version_id":"26.04","architecture":%q,"profile":"ubuntu-26.04-native","internal_php_version":"8.5","hosting_php_versions":["8.3"]}`, runtime.GOARCH)), nil
			}
			return nil, errors.New("missing")
		},
		command: func(_ context.Context, name string, args ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "SHOW server_version") {
				return []byte("18.0 (Ubuntu 18.0-1)"), nil
			}
			if strings.Contains(joined, requiredPHPIntentQuery) {
				return []byte(`{"required":["8.2","8.3","8.4"],"execution":["8.3","8.4"]}`), nil
			}
			switch name {
			case "php8.5":
				if args[0] == "-r" {
					return []byte("8.5"), nil
				}
				return []byte("PHP 8.5.1"), nil
			case "/usr/sbin/php-fpm8.5":
				return []byte("PHP 8.5.1 (fpm-fcgi)"), nil
			case "pg_dump", "pg_restore":
				return []byte(name + " (PostgreSQL) 18.0"), nil
			case "mariadb-dump":
				return []byte("mariadb-dump Ver 10.19 Distrib 11.8.3-MariaDB"), nil
			case "mariadb":
				if args[0] == "--version" {
					return []byte("mariadb from 11.8.3-MariaDB, client 15.2 for Linux"), nil
				}
				return []byte("11.8.3-MariaDB-0ubuntu1"), nil
			case "stalwart-mail":
				return []byte("Stalwart Mail Server v0.11.8"), nil
			}
			return nil, errors.New("no tool")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.MariaDBDumpVersion != "11.8.3" || p.MariaDBClientVersion != "11.8.3" || p.PostgresServerVersion != "18.0" || p.StalwartVersion != "0.11.8" {
		t.Fatalf("wrong observed versions %+v", p)
	}
	if len(p.HostingPHPVersions) != 0 || strings.Join(p.RequiredPHPVersions, ",") != "8.2,8.3,8.4" || !p.PHPInventoryComplete || !bool(p.ExecutionPHPInventoryComplete) || !reflect.DeepEqual(p.ExecutionPHPVersions, []string{"8.3", "8.4"}) {
		t.Fatalf("trusted configured inventory instead of tools/SQL: %+v", p)
	}
}

func TestImageProvenanceUsesActualRootlessImageDigest(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	ref := "registry.example.test/app@" + digest
	probe := platformProbe{command: func(_ context.Context, name string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "json_agg") {
			return []byte(fmt.Sprintf(`[{"username":"tenant","subscription_id":7,"image_ref":%q}]`, ref)), nil
		}
		if name != "runuser" || !strings.Contains(joined, "XDG_DATA_HOME=/var/lib/nakpanel/containers/sub-7/data") || !strings.Contains(joined, "podman image inspect") {
			t.Fatalf("wrong observation command %s %s", name, joined)
		}
		return []byte(digest), nil
	}}
	got := collectImageDigests(context.Background(), "test-dsn", probe)
	if got[ref] != digest {
		t.Fatalf("digests=%v", got)
	}
}

func TestRequiredPHPInventoryIncludesActivePlanOffersWithRealPostgres(t *testing.T) {
	dsn := os.Getenv("NAKPANEL_PLATFORM_TEST_DSN")
	if dsn == "" {
		t.Skip("requires explicitly isolated PostgreSQL test DSN")
	}
	fixtureSQL := `BEGIN;
 CREATE TEMP TABLE sites(php_version text,desired_php_version text);
 CREATE TEMP TABLE php_applications(php_version text);
 CREATE TEMP TABLE plans(lifecycle_status text,hosting_enabled boolean,default_php_version text,php_allowlist text,hosting_policy jsonb);
CREATE TEMP TABLE addon_plans(is_active boolean,php_allowlist text,hosting_policy jsonb);
 CREATE TEMP TABLE subscription_entitlements(subscription_id bigint,hosting_enabled boolean,default_php_version text,php_allowlist text,hosting_policy jsonb);
 CREATE TEMP TABLE subscription_policy_overrides(subscription_id bigint,policy_patch jsonb);
 CREATE TEMP TABLE site_policy_overrides(site_id bigint,policy_patch jsonb);
 INSERT INTO subscription_entitlements VALUES(1,true,'8.1','8.1,8.5','{"php":{"default_version":"8.1","allowed_versions":["8.1","8.5"]}}');
 INSERT INTO sites VALUES('8.3','8.4'); INSERT INTO php_applications VALUES('8.5');
 INSERT INTO plans VALUES('active',true,'8.3','8.3, 8.4','{"php":{"default_version":"8.3","allowed_versions":["8.3","8.4"]}}'),
 ('active',true,'8.5','8.5','{"php":{"default_version":"8.5","allowed_versions":["8.2","8.5"]}}'),
 ('draft',true,'7.4','7.4','{}'),('retired',true,'8.0','8.0','{}'),('active',false,'8.1','8.1','{}');
 `
	queries := 0
	platform, err := collectPlatform(context.Background(), dsn, platformProbe{
		readFile: func(path string) ([]byte, error) {
			if path == "/etc/os-release" {
				return []byte("ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n"), nil
			}
			return nil, os.ErrNotExist
		},
		command: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if name == "php8.3" {
				return []byte("8.3"), nil
			}
			if strings.Contains(strings.Join(args, " "), requiredPHPIntentQuery) {
				queries++
				return exec.CommandContext(ctx, "psql", "-X", "-qAt", dsn, "-v", "ON_ERROR_STOP=1", "-c", fixtureSQL+requiredPHPIntentQuery+`;ROLLBACK;`).CombinedOutput()
			}
			return nil, errors.New("observation unavailable")
		},
	})
	if err != nil {
		t.Fatalf("isolated complete PHP collector failed: %v", err)
	}
	if queries != 1 || !platform.PHPInventoryComplete || !bool(platform.ExecutionPHPInventoryComplete) {
		t.Fatalf("non-atomic/incomplete collector result: %d %+v", queries, platform)
	}
	if !reflect.DeepEqual(platform.RequiredPHPVersions, []string{"8.1", "8.2", "8.3", "8.4", "8.5"}) || !reflect.DeepEqual(platform.ExecutionPHPVersions, []string{"8.3", "8.4", "8.5"}) {
		t.Fatalf("offer and execution projections conflated: required=%v execution=%v", platform.RequiredPHPVersions, platform.ExecutionPHPVersions)
	}
}

func TestCollectPlatformRejectsFailedOrMalformedExecutionProjection(t *testing.T) {
	for _, payload := range []string{"query failure", `{}`, `{"required":["8.3"]}`, `{"required":["8.3"],"execution":null}`, `{"required":["8.3"],"execution":["8.2"]}`, `{"required":["8.3"],"execution":["8.3","8.3"]}`, `{"required":["8.3"],"execution":[null]}`} {
		t.Run(payload, func(t *testing.T) {
			platform, err := collectPlatform(context.Background(), "test", platformProbe{
				readFile: func(path string) ([]byte, error) {
					if path == "/etc/os-release" {
						return []byte("ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n"), nil
					}
					return nil, os.ErrNotExist
				},
				command: func(_ context.Context, _ string, args ...string) ([]byte, error) {
					if strings.Contains(strings.Join(args, " "), requiredPHPIntentQuery) && payload != "query failure" {
						return []byte(payload), nil
					}
					return nil, errors.New("sensitive query error must not leak")
				},
			})
			if err == nil || platform.PHPInventoryComplete || bool(platform.ExecutionPHPInventoryComplete) || platform.ExecutionPHPVersions != nil {
				t.Fatalf("partial or failed observation accepted: %+v %v", platform, err)
			}
			if strings.Contains(err.Error(), "sensitive") {
				t.Fatal("query details leaked")
			}
		})
	}
}

// Use one private transaction per counterexample so a version from another
// policy or execution path cannot accidentally satisfy the inventory assertion.
func TestRequiredPHPInventoryIncludesPolicyOverridesWithRealPostgres(t *testing.T) {
	dsn := os.Getenv("NAKPANEL_PLATFORM_TEST_DSN")
	if dsn == "" {
		t.Skip("requires explicitly isolated PostgreSQL test DSN")
	}
	for _, tc := range []struct {
		name        string
		extra       string
		required    []string
		execution   []string
		missing     string
		sameMissing string
		wantError   bool
	}{
		{name: "subscription default", extra: `INSERT INTO subscription_policy_overrides VALUES(1,'{"php":{"default_version":"8.2"}}');`, required: []string{"8.2", "8.3"}, missing: "8.2"},
		{name: "subscription allowlist", extra: `INSERT INTO subscription_policy_overrides VALUES(1,'{"php":{"allowed_versions":["8.3","8.2"]}}');`, required: []string{"8.2", "8.3"}, missing: "8.2"},
		{name: "site default", extra: `INSERT INTO site_policy_overrides VALUES(1,'{"php":{"default_version":"8.2"}}');`, required: []string{"8.2", "8.3"}, missing: "8.2"},
		{name: "site allowlist", extra: `INSERT INTO site_policy_overrides VALUES(1,'{"php":{"allowed_versions":["8.3","8.2"]}}');`, required: []string{"8.2", "8.3"}, missing: "8.2"},
		{name: "enable-only subscription inherits base offers", extra: `INSERT INTO subscription_entitlements VALUES(2,false,'8.4','8.4','{"php":{"default_version":"8.4","allowed_versions":["8.4"]}}'); INSERT INTO subscription_policy_overrides VALUES(2,'{"permissions":{"hosting":true}}');`, required: []string{"8.3", "8.4"}, missing: "8.4"},
		{name: "active addon CSV offer", extra: `INSERT INTO addon_plans VALUES(true,'8.2','{}');`, required: []string{"8.2", "8.3"}, missing: "8.2"},
		{name: "active addon policy default", extra: `INSERT INTO addon_plans VALUES(true,'','{"php":{"default_version":"8.2"}}');`, required: []string{"8.2", "8.3"}, missing: "8.2"},
		{name: "active addon policy allowlist", extra: `INSERT INTO addon_plans VALUES(true,'','{"php":{"allowed_versions":["8.2"]}}');`, required: []string{"8.2", "8.3"}, missing: "8.2"},
		{name: "inactive addon not assignable", extra: `INSERT INTO addon_plans VALUES(false,'8.2','{"php":{"allowed_versions":["8.2"]}}');`, required: []string{"8.3"}},
		{name: "JSON null inherits", extra: `INSERT INTO subscription_policy_overrides VALUES(1,'{"php":{"default_version":null,"allowed_versions":null}}'); INSERT INTO site_policy_overrides VALUES(1,'{"php":{"default_version":null,"allowed_versions":null}}');`, required: []string{"8.3"}},
		{name: "selected unavailable runtime", extra: `UPDATE sites SET php_version='8.2';`, required: []string{"8.2", "8.3"}, execution: []string{"8.2", "8.3"}, missing: "8.2", sameMissing: "8.2"},
		{name: "desired unavailable runtime", extra: `UPDATE sites SET desired_php_version='8.2';`, required: []string{"8.2", "8.3"}, execution: []string{"8.2", "8.3"}, missing: "8.2", sameMissing: "8.2"},
		{name: "non-array subscription allowlist fails closed", extra: `INSERT INTO subscription_policy_overrides VALUES(1,'{"php":{"allowed_versions":"8.2"}}');`, wantError: true},
		{name: "non-array site allowlist fails closed", extra: `INSERT INTO site_policy_overrides VALUES(1,'{"php":{"allowed_versions":{}}}');`, wantError: true},
		{name: "non-array addon allowlist fails closed", extra: `INSERT INTO addon_plans VALUES(true,'','{"php":{"allowed_versions":true}}');`, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixtureSQL := `BEGIN;
CREATE TEMP TABLE sites(php_version text,desired_php_version text);
CREATE TEMP TABLE php_applications(php_version text);
CREATE TEMP TABLE plans(lifecycle_status text,hosting_enabled boolean,default_php_version text,php_allowlist text,hosting_policy jsonb);
CREATE TEMP TABLE addon_plans(is_active boolean,php_allowlist text,hosting_policy jsonb);
CREATE TEMP TABLE subscription_entitlements(subscription_id bigint,hosting_enabled boolean,default_php_version text,php_allowlist text,hosting_policy jsonb);
CREATE TEMP TABLE subscription_policy_overrides(subscription_id bigint,policy_patch jsonb);
CREATE TEMP TABLE site_policy_overrides(site_id bigint,policy_patch jsonb);
INSERT INTO sites VALUES('8.3','8.3');
INSERT INTO php_applications VALUES('8.3');
INSERT INTO plans VALUES('active',true,'8.3','8.3','{"php":{"default_version":"8.3","allowed_versions":["8.3"]}}');
INSERT INTO subscription_entitlements VALUES(1,true,'8.3','8.3','{"php":{"default_version":"8.3","allowed_versions":["8.3"]}}');
` + tc.extra
			queries := 0
			source, err := collectPlatform(context.Background(), dsn, platformProbe{
				readFile: func(path string) ([]byte, error) {
					if path == "/etc/os-release" {
						return []byte("ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n"), nil
					}
					return nil, os.ErrNotExist
				},
				command: func(ctx context.Context, name string, args ...string) ([]byte, error) {
					if strings.Contains(strings.Join(args, " "), requiredPHPIntentQuery) {
						queries++
						return exec.CommandContext(ctx, "psql", "-X", "-qAt", dsn, "-v", "ON_ERROR_STOP=1", "-c", fixtureSQL+requiredPHPIntentQuery+`;ROLLBACK;`).CombinedOutput()
					}
					if name == "php8.3" {
						return []byte("8.3"), nil
					}
					return nil, errors.New("observation unavailable")
				},
			})
			if queries != 1 {
				t.Fatalf("queries=%d", queries)
			}
			if tc.wantError {
				if err == nil || source.PHPInventoryComplete || bool(source.ExecutionPHPInventoryComplete) || source.ExecutionPHPVersions != nil {
					t.Fatalf("malformed policy offer published complete inventory: %+v %v", source, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			wantExecution := tc.execution
			if wantExecution == nil {
				wantExecution = []string{"8.3"}
			}
			if !source.PHPInventoryComplete || !bool(source.ExecutionPHPInventoryComplete) || !reflect.DeepEqual(source.RequiredPHPVersions, tc.required) || !reflect.DeepEqual(source.ExecutionPHPVersions, wantExecution) {
				t.Fatalf("override offer omitted or conflated with execution: %+v", source)
			}
			// The target has precisely the source's ready runtime; the additional
			// override offer was never installed or selected on either side.
			source.HostingPHPVersions = []string{"8.3"}
			target := platformFixture("24.04")
			target.Architecture = source.Architecture
			target.HostingPHPVersions = []string{"8.3"}
			before, _ := json.Marshal(source)
			err = CheckRestoreCompatibility(Manifest{Platform: &source}, target, RestoreSamePlatform)
			if tc.sameMissing != "" {
				if err == nil || !strings.Contains(err.Error(), "PHP "+tc.sameMissing) {
					t.Fatalf("selected/desired missing runtime accepted: %v", err)
				}
			} else if err != nil {
				t.Fatalf("unselected override offer blocked same-profile recovery: %v", err)
			}
			after, _ := json.Marshal(source)
			if !bytes.Equal(before, after) {
				t.Fatal("same-profile recovery rewrote override intent")
			}
			if tc.missing != "" {
				forward := platformFixture("26.04")
				forward.Architecture = source.Architecture
				forward.HostingPHPVersions = []string{"8.3"}
				// Supply the unrelated observed database fields; the PHP provenance is
				// exactly the result of the real collector above.
				observed := platformFixture("24.04")
				source.PostgresServerVersion = observed.PostgresServerVersion
				source.PostgresDumpVersion = observed.PostgresDumpVersion
				source.PostgresRestoreVersion = observed.PostgresRestoreVersion
				source.MariaDBServerVersion = observed.MariaDBServerVersion
				source.MariaDBDumpVersion = observed.MariaDBDumpVersion
				source.MariaDBClientVersion = observed.MariaDBClientVersion
				if err = CheckRestoreCompatibility(Manifest{Platform: &source}, forward, RestoreForwardMigration); err == nil || !strings.Contains(err.Error(), "PHP "+tc.missing) {
					t.Fatalf("forward migration ignored collected override-only offer: %v", err)
				}
			}
		})
	}
}
