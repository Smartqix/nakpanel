package quota

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/riverqueue/river/rivermigrate"
)

func planPHPPostgres(t *testing.T, terminal string) *sql.DB {
	t.Helper()
	dsn := os.Getenv("NAKPANEL_PLAN_PHP_TEST_DSN")
	if dsn == "" {
		if os.Getenv("NAKPANEL_REQUIRE_PLAN_PHP_POSTGRES") == "1" {
			t.Fatal("NAKPANEL_PLAN_PHP_TEST_DSN is required")
		}
		t.Skip("optional PostgreSQL: NAKPANEL_PLAN_PHP_TEST_DSN is not set")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil || !filepath.IsAbs(config.Host) {
		t.Fatal("an explicitly owned Unix-socket PostgreSQL test cluster is required")
	}
	info, err := os.Stat(config.Host)
	if err != nil {
		t.Fatal("owned socket directory unavailable")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) {
		t.Fatal("test socket directory must belong to the current user")
	}
	admin := stdlib.OpenDB(*config)
	schema := fmt.Sprintf("plan_php_%d", time.Now().UnixNano())
	if _, err = admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	config.RuntimeParams["search_path"] = schema
	config.RuntimeParams["application_name"] = schema
	db := stdlib.OpenDB(*config)
	db.SetMaxOpenConns(6)
	t.Cleanup(func() {
		db.Close()
		if _, err := admin.Exec("DROP SCHEMA " + schema + " CASCADE"); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	files, err := filepath.Glob("../../../migrations/*.sql")
	if err != nil || len(files) == 0 {
		t.Fatal("migration files missing", err)
	}
	last := ""
	for _, file := range files {
		if filepath.Base(file) > terminal {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(strings.SplitN(string(raw), "-- +goose Down", 2)[0]); err != nil {
			t.Fatalf("migration %s: %v", filepath.Base(file), err)
		}
		last = filepath.Base(file)
	}
	if last != terminal {
		t.Fatalf("terminal migration %s != %s", last, terminal)
	}
	connections := make([]*sql.Conn, 0, 2)
	for range 2 {
		conn, err := db.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
		var actual string
		if err = conn.QueryRowContext(context.Background(), "SELECT current_schema()").Scan(&actual); err != nil || actual != schema {
			t.Fatalf("pooled schema mismatch %q: %v", actual, err)
		}
	}
	for _, conn := range connections {
		conn.Close()
	}
	t.Logf("real PostgreSQL terminal migration %s; independent pooled schema checks PASS", terminal)
	return db
}

func planPHPAddon(t *testing.T, db *sql.DB) types.AddonPlan {
	t.Helper()
	store := NewSQLStore(db)
	addon, err := store.UpsertAddonPlan(context.Background(), types.AddonPlan{Name: "PHP test addon", IsActive: true, Entitlements: types.SubscriptionEntitlements{PlanName: "PHP test addon", DiskMB: 16, PHPAllowlist: "8.4"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE addon_plans SET revision=9 WHERE id=$1`, addon.ID); err != nil {
		t.Fatal(err)
	}
	if err = store.SetSubscriptionAddons(context.Background(), 1, []int64{addon.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE subscription_system_accounts SET applied_revision=desired_revision,convergence_status='in_sync',last_error='' WHERE subscription_id=1`); err != nil {
		t.Fatal(err)
	}
	addon.Revision = 9
	return addon
}

func TestPlanPHPStatusComposedRevisionPostgreSQL(t *testing.T) {
	db := planPHPPostgres(t, "20261018000056_dns_managed_defaults.sql")
	cmd := planPHPCommand(t, db)
	planPHPAddon(t, db)
	view, err := NewSQLStore(db).PlanSynchronization(context.Background(), cmd.PlanID)
	if err != nil || view.State != "in_sync" || view.Synced != 1 {
		t.Fatalf("converged higher addon revision reported pending: %+v %v", view, err)
	}
}

func TestPlanPHPStaleWorkersAndFullMutationPostgreSQL(t *testing.T) {
	db := planPHPPostgres(t, "20261018000056_dns_managed_defaults.sql")
	cmd := planPHPCommand(t, db)
	addon := planPHPAddon(t, db)
	if _, err := db.Exec(`UPDATE subscription_entitlements SET disk_mb=3456,service_presets=service_presets||'{"future":{"keep":null}}' WHERE subscription_id=1`); err != nil {
		t.Fatal(err)
	}
	store := NewSQLStore(db)
	if _, err := store.UpdatePlanPHPVersions(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	before := planPHPNonPHPState(t, db, cmd.PlanID)
	if err := NewSyncPlanWorker(db).Work(context.Background(), &river.Job[SyncPlanArgs]{Args: NewSyncPlanArgs(cmd.PlanID, int64(cmd.Input.ExpectedRevision))}); err != nil {
		t.Fatal(err)
	}
	if err := NewSyncAddonWorker(db).Work(context.Background(), &river.Job[SyncAddonArgs]{Args: NewSyncAddonArgs(addon.ID, 1)}); err != nil {
		t.Fatal(err)
	}
	if before != planPHPNonPHPState(t, db, cmd.PlanID) {
		t.Fatal("stale queued worker erased preserved snapshot")
	}
	if _, err := db.Exec(`UPDATE subscriptions SET sync_mode='locked' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSubscriptionMode(context.Background(), 1, "synced", types.SubscriptionEntitlements{}); err != nil {
		t.Fatal(err)
	}
	var disk int
	if err := db.QueryRow(`SELECT disk_mb FROM subscription_entitlements WHERE subscription_id=1`).Scan(&disk); err != nil {
		t.Fatal(err)
	}
	if disk == 3456 {
		t.Fatal("explicit locked-to-synced conversion failed to apply ordinary full contract")
	}
}

func planPHPCommand(t *testing.T, db *sql.DB) PlanPHPVersionsCommand {
	t.Helper()
	ctx := context.Background()
	if _, err := db.Exec("UPDATE subscriptions SET sync_mode='locked' WHERE id<>1;DELETE FROM subscription_addons WHERE subscription_id=1"); err != nil {
		t.Fatal(err)
	}
	store := NewSQLStore(db)
	if err := store.SyncSubscription(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE subscription_system_accounts SET applied_revision=desired_revision,convergence_status='in_sync',last_error='' WHERE subscription_id=1"); err != nil {
		t.Fatal(err)
	}
	var actor auth.SessionUser
	if err := db.QueryRow("SELECT id,email,role FROM users WHERE role='admin' ORDER BY id LIMIT 1").Scan(&actor.ID, &actor.Email, &actor.Role); err != nil {
		t.Fatal(err)
	}
	var id int64
	var revision int
	if err := db.QueryRow("SELECT p.id,p.revision FROM plans p JOIN subscriptions s ON s.plan_id=p.id WHERE s.id=1").Scan(&id, &revision); err != nil {
		t.Fatal(err)
	}
	return PlanPHPVersionsCommand{PlanID: id, Input: PlanPHPVersionsInput{ExpectedRevision: revision, PHPVersions: []string{"8.3", "8.5"}, DefaultPHPVersion: "8.5", ChangeReason: "Explicit PHP-only test update"}, Actor: actor, Scope: types.ProviderScope{ActorUserID: actor.ID, Role: string(actor.Role)}, ReadyPHPVersions: []string{"8.2", "8.3", "8.4", "8.5"}}
}

func planPHPNonPHPState(t *testing.T, db *sql.DB, planID int64) string {
	t.Helper()
	var value string
	err := db.QueryRow(`SELECT jsonb_build_object('plan',to_jsonb(p)-'revision'-'updated_at'-'php_allowlist'-'default_php_version'-'hosting_policy',
'policy',p.hosting_policy #- '{php,allowed_versions}' #- '{php,default_version}',
'presets',(to_jsonb(ps)-'hosting'-'php') || jsonb_build_object('hosting',ps.hosting-'allowed_php_versions'-'default_php_version','php',ps.php-'allowed_versions'-'default_version'),
'snapshot',(to_jsonb(e)-'source_revision'-'updated_at'-'php_allowlist'-'default_php_version'-'hosting_policy'-'service_presets') || jsonb_build_object('policy',e.hosting_policy #- '{php,allowed_versions}' #- '{php,default_version}',
'presets',e.service_presets #- '{hosting,allowed_php_versions}' #- '{hosting,default_php_version}' #- '{php,allowed_versions}' #- '{php,default_version}'))::text
FROM plans p LEFT JOIN plan_service_presets ps ON ps.plan_id=p.id JOIN subscription_entitlements e ON e.subscription_id=1 WHERE p.id=$1`, planID).Scan(&value)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestPlanPHPVersionsPreservesRawPostgreSQL(t *testing.T) {
	for _, terminal := range []string{"20261015000055_dns_template_deletions.sql", "20261018000056_dns_managed_defaults.sql"} {
		t.Run(terminal, func(t *testing.T) {
			db := planPHPPostgres(t, terminal)
			cmd := planPHPCommand(t, db)
			for _, query := range []string{`UPDATE plans SET hosting_policy=hosting_policy || '{"future":{"keep":[null,"opaque"]}}'::jsonb WHERE id=$1`,
				`UPDATE plan_service_presets SET mail='{"webmail_enabled":true,"future_mail":null}',hosting=hosting||'{"future_web":{"keep":true}}',php=php||'{"future_php":[1,null]}' WHERE plan_id=$1`,
				`UPDATE subscription_entitlements SET disk_mb=3456,service_presets=service_presets||'{"future_snapshot":{"keep":null}}',hosting_policy=hosting_policy||'{"future_policy":[null,"kept"]}' WHERE subscription_id=1 AND $1>0`} {
				if _, err := db.Exec(query, cmd.PlanID); err != nil {
					t.Fatal(err)
				}
			}
			before := planPHPNonPHPState(t, db, cmd.PlanID)
			store := NewSQLStore(db)
			preview, err := store.PreviewPlanPHPVersions(context.Background(), cmd)
			if err != nil || !preview.Preview.Allowed || preview.NoChange {
				t.Fatalf("preview: %+v %v", preview, err)
			}
			for _, change := range preview.Preview.Changes {
				if change.Path != "php.allowed_versions" && change.Path != "php.default_version" {
					t.Fatalf("PHP-only preview advertises non-PHP change: %s", change.Path)
				}
			}
			if after := planPHPNonPHPState(t, db, cmd.PlanID); before != after {
				t.Fatal("preview changed persistent state")
			}
			result, err := store.UpdatePlanPHPVersions(context.Background(), cmd)
			if err != nil || !result.Changed || result.Revision != cmd.Input.ExpectedRevision+1 {
				t.Fatalf("update: %+v %v", result, err)
			}
			if after := planPHPNonPHPState(t, db, cmd.PlanID); before != after {
				t.Fatalf("non-PHP data changed\nbefore %s\nafter %s", before, after)
			}
			var php, marker string
			var hashOK bool
			if err := db.QueryRow(`SELECT e.php_allowlist||':'||e.default_php_version,r.definition#>>'{_operation,kind}',r.definition_hash=encode(sha256(convert_to(r.definition::text,'UTF8')),'hex') FROM subscription_entitlements e JOIN plan_revisions r ON r.plan_id=$1 AND r.revision=$2 WHERE e.subscription_id=1`, cmd.PlanID, result.Revision).Scan(&php, &marker, &hashOK); err != nil || php != "8.3,8.5:8.5" || marker != "php_versions_only" || !hashOK {
				t.Fatalf("PHP/history: %q %q %t %v", php, marker, hashOK, err)
			}
			if err = store.SyncSubscription(context.Background(), 1); err != nil {
				t.Fatal(err)
			}
			if after := planPHPNonPHPState(t, db, cmd.PlanID); before != after {
				t.Fatal("same-revision sync erased preservation")
			}
		})
	}
}

func TestPlanPHPVersionsStaleNoopAndReadinessPostgreSQL(t *testing.T) {
	db := planPHPPostgres(t, "20261018000056_dns_managed_defaults.sql")
	cmd := planPHPCommand(t, db)
	if _, err := db.Exec("UPDATE plans SET revision=revision+1 WHERE id=$1", cmd.PlanID); err != nil {
		t.Fatal(err)
	}
	cmd.Input.ExpectedRevision++
	plan, err := NewSQLStore(db).GetPlan(context.Background(), cmd.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Input.PHPVersions = strings.Split(plan.PHPAllowlist, ",")
	cmd.Input.DefaultPHPVersion = plan.DefaultPHPVersion
	store := NewSQLStore(db)
	beforeNoop := planPHPAllState(t, db)
	result, err := store.UpdatePlanPHPVersions(context.Background(), cmd)
	if err != nil || result.Changed {
		t.Fatalf("no-op %+v %v", result, err)
	}
	if result.SyncState != "pending" {
		t.Fatalf("no-op hid an unconverged base revision: %+v", result)
	}
	if beforeNoop != planPHPAllState(t, db) {
		t.Fatal("no-op wrote state")
	}
	cmd.Input.ExpectedRevision--
	_, err = store.UpdatePlanPHPVersions(context.Background(), cmd)
	var conflict *PlanPHPConflictError
	if !errors.As(err, &conflict) || conflict.Code != "stale_revision" {
		t.Fatalf("stale identical intent: %v", err)
	}
	cmd.Input.ExpectedRevision++
	cmd.ReadyPHPVersions = []string{"8.5"}
	_, err = store.UpdatePlanPHPVersions(context.Background(), cmd)
	var readiness *PlanPHPReadinessError
	if !errors.As(err, &readiness) {
		t.Fatalf("unready no-op accepted: %v", err)
	}
}

func planPHPAllState(t *testing.T, db *sql.DB) string {
	t.Helper()
	var result strings.Builder
	for _, table := range []string{"plans", "plan_service_presets", "subscriptions", "subscription_entitlements", "subscription_system_accounts", "plan_revisions", "audit_events", "subscription_policy_overrides", "site_policy_overrides", "sites"} {
		var raw string
		if err := db.QueryRow(`SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]'::jsonb)::text FROM ` + table + ` x`).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		result.WriteString(table + raw)
	}
	var queueExists bool
	if err := db.QueryRow(`SELECT to_regclass('river_job') IS NOT NULL`).Scan(&queueExists); err != nil {
		t.Fatal(err)
	}
	if queueExists {
		var raw string
		if err := db.QueryRow(`SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb)::text FROM river_job x`).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		result.WriteString("river_job" + raw)
	}
	return result.String()
}

func TestPlanPHPQueuedSyncAndFailureRollbackPostgreSQL(t *testing.T) {
	for _, failQueue := range []bool{false, true} {
		t.Run(map[bool]string{false: "queued snapshot", true: "queue refusal"}[failQueue], func(t *testing.T) {
			db := planPHPPostgres(t, "20261018000056_dns_managed_defaults.sql")
			cmd := planPHPCommand(t, db)
			if _, err := db.Exec(`UPDATE subscription_entitlements SET disk_mb=3456,service_presets=service_presets||'{"future":{"keep":null}}' WHERE subscription_id=1`); err != nil {
				t.Fatal(err)
			}
			driver := riverdatabasesql.New(db)
			migrator, err := rivermigrate.New(driver, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = migrator.Migrate(context.Background(), rivermigrate.DirectionUp, nil); err != nil {
				t.Fatal(err)
			}
			client, err := river.NewClient(driver, &river.Config{})
			if err != nil {
				t.Fatal(err)
			}
			if failQueue {
				if _, err = db.Exec(`CREATE FUNCTION refuse_php_queue() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.kind='sync_plan_subscriptions' THEN RAISE EXCEPTION 'injected queue refusal';END IF;RETURN NEW;END$$;CREATE TRIGGER refuse_php_queue BEFORE INSERT ON river_job FOR EACH ROW EXECUTE FUNCTION refuse_php_queue()`); err != nil {
					t.Fatal(err)
				}
			}
			before := planPHPAllState(t, db)
			preserved := planPHPNonPHPState(t, db, cmd.PlanID)
			result, err := NewSQLStore(db, client).UpdatePlanPHPVersions(context.Background(), cmd)
			if failQueue {
				if err == nil || !strings.Contains(err.Error(), "injected queue refusal") || before != planPHPAllState(t, db) {
					t.Fatalf("queue failure did not atomically roll back: %v", err)
				}
				return
			}
			if err != nil || !result.Changed || result.SyncState != "pending" {
				t.Fatalf("queue result %+v %v", result, err)
			}
			var queued bool
			if err = db.QueryRow(`SELECT count(*)=1 AND bool_and((args->>'plan_id')::bigint=$1 AND (args->>'revision')::int=$2) FROM river_job WHERE kind='sync_plan_subscriptions'`, cmd.PlanID, result.Revision).Scan(&queued); err != nil || !queued {
				t.Fatalf("exact committed plan job missing: %t %v", queued, err)
			}
			if err = NewSyncPlanWorker(db).Work(context.Background(), &river.Job[SyncPlanArgs]{Args: NewSyncPlanArgs(cmd.PlanID, int64(result.Revision))}); err != nil {
				t.Fatal(err)
			}
			if preserved != planPHPNonPHPState(t, db, cmd.PlanID) {
				t.Fatal("asynchronous worker rewrote non-PHP snapshot")
			}
		})
	}
}

func TestPlanPHPEffectiveOverrideConflictIsReadOnlyPostgreSQL(t *testing.T) {
	db := planPHPPostgres(t, "20261018000056_dns_managed_defaults.sql")
	cmd := planPHPCommand(t, db)
	cmd.Input.PHPVersions = []string{"8.5"}
	cmd.Input.DefaultPHPVersion = "8.5"
	if _, err := db.Exec(`INSERT INTO subscription_policy_overrides(subscription_id,policy_patch) VALUES(1,'{"php":{"default_version":"8.3"}}') ON CONFLICT(subscription_id) DO UPDATE SET policy_patch=EXCLUDED.policy_patch`); err != nil {
		t.Fatal(err)
	}
	before := planPHPAllState(t, db)
	store := NewSQLStore(db)
	preview, err := store.PreviewPlanPHPVersions(context.Background(), cmd)
	if err != nil || preview.Preview.Allowed || len(preview.Preview.BlockingReasons) == 0 {
		t.Fatalf("effective override conflict was not previewed: %+v %v", preview, err)
	}
	if _, err = store.UpdatePlanPHPVersions(context.Background(), cmd); err == nil {
		t.Fatal("invalid effective policy committed")
	}
	if before != planPHPAllState(t, db) {
		t.Fatal("effective policy refusal changed raw rows")
	}
}

func TestPlanPHPVersionsRawShapesPostgreSQL(t *testing.T) {
	for _, tt := range []struct {
		name, query string
		reject      bool
	}{
		{"sparse", `UPDATE plan_service_presets SET hosting='{}',php='{}',mail='{"future":{"keep":null}}' WHERE plan_id=$1`, false},
		{"missing presets", `DELETE FROM plan_service_presets WHERE plan_id=$1`, false},
		{"legacy mirrors", `UPDATE plan_service_presets SET php=jsonb_build_object('allowed_versions',(SELECT php_allowlist FROM plans WHERE id=$1),'default_version',(SELECT default_php_version FROM plans WHERE id=$1),'unknown',NULL) WHERE plan_id=$1`, false},
		{"malformed PHP container", `UPDATE plans SET hosting_policy=jsonb_set(hosting_policy,'{php}','null') WHERE id=$1`, true},
		{"contradictory hosting mirror", `UPDATE plan_service_presets SET hosting=hosting||'{"allowed_php_versions":["9.9"],"default_php_version":"9.9"}' WHERE plan_id=$1`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			db := planPHPPostgres(t, "20261018000056_dns_managed_defaults.sql")
			cmd := planPHPCommand(t, db)
			if _, err := db.Exec(tt.query, cmd.PlanID); err != nil {
				t.Fatal(err)
			}
			before := planPHPAllState(t, db)
			_, err := NewSQLStore(db).UpdatePlanPHPVersions(context.Background(), cmd)
			if tt.reject {
				if err == nil {
					t.Fatal("invalid raw intent accepted")
				}
				if before != planPHPAllState(t, db) {
					t.Fatal("rejection changed state")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if tt.name == "missing presets" {
				var count int
				if err := db.QueryRow("SELECT count(*) FROM plan_service_presets WHERE plan_id=$1", cmd.PlanID).Scan(&count); err != nil || count != 0 {
					t.Fatalf("missing presets materialized: %d %v", count, err)
				}
			}
		})
	}
}

func TestPlanPHPVersionsAtomicAuditRollbackPostgreSQL(t *testing.T) {
	db := planPHPPostgres(t, "20261018000056_dns_managed_defaults.sql")
	cmd := planPHPCommand(t, db)
	if _, err := db.Exec(`CREATE FUNCTION refuse_php_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.action='plan.saved' THEN RAISE EXCEPTION 'injected audit refusal';END IF;RETURN NEW;END$$;CREATE TRIGGER refuse_php_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION refuse_php_audit()`); err != nil {
		t.Fatal(err)
	}
	before := planPHPAllState(t, db)
	if _, err := NewSQLStore(db).UpdatePlanPHPVersions(context.Background(), cmd); err == nil || !strings.Contains(err.Error(), "injected audit refusal") {
		t.Fatalf("audit failure not propagated: %v", err)
	}
	if before != planPHPAllState(t, db) {
		t.Fatal("partial operation committed before audit failure")
	}
}

func TestPlanPHPVersionsPendingAndExcludedPostgreSQL(t *testing.T) {
	db := planPHPPostgres(t, "20261018000056_dns_managed_defaults.sql")
	cmd := planPHPCommand(t, db)
	for _, query := range []string{`UPDATE subscription_system_accounts SET convergence_status='pending' WHERE subscription_id=1`, `UPDATE subscriptions SET sync_status='pending' WHERE id=1`, `UPDATE subscription_entitlements SET source_revision=source_revision+1 WHERE subscription_id=1`} {
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(query); err != nil {
			t.Fatal(err)
		}
		tx.Commit()
		before := planPHPAllState(t, db)
		_, err = NewSQLStore(db).UpdatePlanPHPVersions(context.Background(), cmd)
		var conflict *PlanPHPConflictError
		if !errors.As(err, &conflict) || conflict.Code != "plan_sync_pending" {
			t.Fatalf("pending participant accepted: %v", err)
		}
		if before != planPHPAllState(t, db) {
			t.Fatal("pending refusal changed state")
		}
		if _, err = db.Exec(`UPDATE subscription_system_accounts SET convergence_status='in_sync',applied_revision=desired_revision WHERE subscription_id=1;UPDATE subscriptions SET sync_status='in_sync' WHERE id=1;UPDATE subscription_entitlements e SET source_revision=p.revision FROM subscriptions s JOIN plans p ON p.id=s.plan_id WHERE s.id=1 AND e.subscription_id=s.id`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`UPDATE subscriptions SET sync_mode='locked' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := db.QueryRow(`SELECT to_jsonb(e)::text FROM subscription_entitlements e WHERE subscription_id=1`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSQLStore(db).UpdatePlanPHPVersions(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	var after string
	if err := db.QueryRow(`SELECT to_jsonb(e)::text FROM subscription_entitlements e WHERE subscription_id=1`).Scan(&after); err != nil || before != after {
		t.Fatalf("locked snapshot changed: %v", err)
	}
}

func TestPlanPHPContiguousHistoryAndFullSavePostgreSQL(t *testing.T) {
	db := planPHPPostgres(t, "20261018000056_dns_managed_defaults.sql")
	cmd := planPHPCommand(t, db)
	store := NewSQLStore(db)
	if _, err := db.Exec(`UPDATE subscription_entitlements SET disk_mb=3456,service_presets=service_presets||'{"future":{"keep":null}}' WHERE subscription_id=1`); err != nil {
		t.Fatal(err)
	}
	before := planPHPNonPHPState(t, db, cmd.PlanID)
	first, err := store.UpdatePlanPHPVersions(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE subscription_system_accounts SET applied_revision=desired_revision,convergence_status='in_sync' WHERE subscription_id=1`); err != nil {
		t.Fatal(err)
	}
	cmd.Input.ExpectedRevision = first.Revision
	cmd.Input.PHPVersions = []string{"8.3", "8.4", "8.5"}
	cmd.Input.DefaultPHPVersion = "8.4"
	second, err := store.UpdatePlanPHPVersions(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE subscriptions SET plan_revision=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err = store.SyncSubscription(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if before != planPHPNonPHPState(t, db, cmd.PlanID) {
		t.Fatal("contiguous PHP-only history lost raw snapshot")
	}
	plan, err := store.GetPlan(context.Background(), cmd.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	plan.Name = "Explicit full update after narrow revisions"
	full, err := store.UpsertPlan(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if full.Revision != second.Revision+1 {
		t.Fatal("full update revision did not advance")
	}
	var disk int
	if err = db.QueryRow(`SELECT disk_mb FROM subscription_entitlements WHERE subscription_id=1`).Scan(&disk); err != nil || disk == 3456 {
		t.Fatalf("full update stopped applying full entitlements: %d %v", disk, err)
	}
}

func TestPlanPHPMarkedHistoryCorruptionRefusesWritesPostgreSQL(t *testing.T) {
	for _, mutation := range []string{`definition=jsonb_set(definition,'{_operation,kind}','"forged"')`, `definition_hash=repeat('0',64)`, `definition=jsonb_set(definition,'{_operation,from_revision}','999')`} {
		t.Run(mutation, func(t *testing.T) {
			db := planPHPPostgres(t, "20261018000056_dns_managed_defaults.sql")
			cmd := planPHPCommand(t, db)
			store := NewSQLStore(db)
			result, err := store.UpdatePlanPHPVersions(context.Background(), cmd)
			if err != nil {
				t.Fatal(err)
			}
			// Deliberate corruption is confined to this disposable schema. Production
			// immutable triggers remain enabled and no migration changes are made.
			if _, err = db.Exec(`ALTER TABLE plan_revisions DISABLE TRIGGER plan_revisions_immutable_update`); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(`UPDATE plan_revisions SET `+mutation+` WHERE plan_id=$1 AND revision=$2`, cmd.PlanID, result.Revision); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(`ALTER TABLE plan_revisions ENABLE TRIGGER plan_revisions_immutable_update`); err != nil {
				t.Fatal(err)
			}
			before := planPHPAllState(t, db)
			err = store.SyncSubscription(context.Background(), 1)
			var integrity *PlanPHPIntegrityError
			if !errors.As(err, &integrity) {
				t.Fatalf("corrupt marked history accepted: %v", err)
			}
			if before != planPHPAllState(t, db) {
				t.Fatal("corrupt marked history caused a partial snapshot/metadata write")
			}
		})
	}
}

func TestPlanPHPMissingParticipantSnapshotPostgreSQL(t *testing.T) {
	db := planPHPPostgres(t, "20261018000056_dns_managed_defaults.sql")
	cmd := planPHPCommand(t, db)
	if _, err := db.Exec(`DELETE FROM subscription_entitlements WHERE subscription_id=1`); err != nil {
		t.Fatal(err)
	}
	before := planPHPAllState(t, db)
	store := NewSQLStore(db)
	preview, err := store.PreviewPlanPHPVersions(context.Background(), cmd)
	if err != nil || preview.Preview.Allowed || len(preview.Blockers) != 1 {
		t.Fatalf("missing snapshot must be a preview convergence blocker: %+v %v", preview, err)
	}
	_, err = store.UpdatePlanPHPVersions(context.Background(), cmd)
	var conflict *PlanPHPConflictError
	if !errors.As(err, &conflict) || conflict.Code != "plan_sync_pending" {
		t.Fatalf("missing snapshot did not fail admission: %v", err)
	}
	if before != planPHPAllState(t, db) {
		t.Fatal("missing snapshot refusal wrote state")
	}
}

func TestPlanPHPMalformedParticipantMarkerPostgreSQL(t *testing.T) {
	for _, replacement := range []string{`'null'::jsonb`, `jsonb_build_array(jsonb_build_object('subscription_id',1,'addons_sha256',repeat('z',64)))`} {
		t.Run(replacement, func(t *testing.T) {
			db := planPHPPostgres(t, "20261018000056_dns_managed_defaults.sql")
			cmd := planPHPCommand(t, db)
			store := NewSQLStore(db)
			result, err := store.UpdatePlanPHPVersions(context.Background(), cmd)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(`ALTER TABLE plan_revisions DISABLE TRIGGER plan_revisions_immutable_update`); err != nil {
				t.Fatal(err)
			}
			definition := `jsonb_set(definition,'{_operation,subscription_inputs}',` + replacement + `)`
			if _, err = db.Exec(`UPDATE plan_revisions SET definition=`+definition+`,definition_hash=encode(sha256(convert_to((`+definition+`)::text,'UTF8')),'hex') WHERE plan_id=$1 AND revision=$2`, cmd.PlanID, result.Revision); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(`ALTER TABLE plan_revisions ENABLE TRIGGER plan_revisions_immutable_update`); err != nil {
				t.Fatal(err)
			}
			before := planPHPAllState(t, db)
			err = store.SyncSubscription(context.Background(), 1)
			var integrity *PlanPHPIntegrityError
			if !errors.As(err, &integrity) {
				t.Fatalf("hash-valid malformed participant list triggered full write: %v", err)
			}
			if before != planPHPAllState(t, db) {
				t.Fatal("malformed participant marker changed state")
			}
		})
	}
}

func TestPlanPHPUnchangedModeAndAddonFormsPostgreSQL(t *testing.T) {
	for _, operation := range []string{"mode", "addons"} {
		t.Run(operation, func(t *testing.T) {
			db := planPHPPostgres(t, "20261018000056_dns_managed_defaults.sql")
			cmd := planPHPCommand(t, db)
			addon := planPHPAddon(t, db)
			store := NewSQLStore(db)
			if _, err := db.Exec(`UPDATE subscription_entitlements SET disk_mb=3456,service_presets=service_presets||'{"future":{"keep":null}}' WHERE subscription_id=1`); err != nil {
				t.Fatal(err)
			}
			if _, err := store.UpdatePlanPHPVersions(context.Background(), cmd); err != nil {
				t.Fatal(err)
			}
			before := planPHPNonPHPState(t, db, cmd.PlanID)
			var err error
			if operation == "mode" {
				err = store.SetSubscriptionMode(context.Background(), 1, "synced", types.SubscriptionEntitlements{})
			} else {
				err = store.SetSubscriptionAddons(context.Background(), 1, []int64{addon.ID})
			}
			if err != nil {
				t.Fatal(err)
			}
			if before != planPHPNonPHPState(t, db, cmd.PlanID) {
				t.Fatal("unchanged form was mistaken for a new full mutation")
			}
		})
	}
}

func TestPlanPHPActualAddonMutationUsesFullSnapshotPostgreSQL(t *testing.T) {
	db := planPHPPostgres(t, "20261018000056_dns_managed_defaults.sql")
	cmd := planPHPCommand(t, db)
	addon := planPHPAddon(t, db)
	if _, err := db.Exec(`UPDATE subscription_entitlements SET disk_mb=3456 WHERE subscription_id=1`); err != nil {
		t.Fatal(err)
	}
	store := NewSQLStore(db)
	if _, err := store.UpdatePlanPHPVersions(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	addon.Entitlements.DiskMB = 32
	if _, err := store.UpsertAddonPlan(context.Background(), addon); err != nil {
		t.Fatal(err)
	}
	var disk int
	if err := db.QueryRow(`SELECT disk_mb FROM subscription_entitlements WHERE subscription_id=1`).Scan(&disk); err != nil || disk == 3456 {
		t.Fatalf("actual add-on mutation was hidden by the PHP-only marker: %d %v", disk, err)
	}
}

func TestPlanPHPActualPlanReassignmentAndSamePlanRetryPostgreSQL(t *testing.T) {
	db := planPHPPostgres(t, "20261018000056_dns_managed_defaults.sql")
	cmd := planPHPCommand(t, db)
	ctx := context.Background()
	store := NewSQLStore(db)
	a, err := store.GetPlan(ctx, cmd.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	a.ID, a.Name, a.IsActive, a.LifecycleStatus = 0, "Owned full A", true, types.PlanLifecycleActive
	a, err = store.UpsertPlan(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.ChangeSubscriptionPlans(ctx, []int64{1}, a.ID); err != nil {
		t.Fatal(err)
	}
	fullA := planPHPNonPHPState(t, db, a.ID)
	if _, err = db.Exec(`UPDATE subscription_system_accounts SET applied_revision=desired_revision,convergence_status='in_sync',last_error='' WHERE subscription_id=1`); err != nil {
		t.Fatal(err)
	}
	cmd.PlanID, cmd.Input.ExpectedRevision = a.ID, a.Revision
	if _, err = store.UpdatePlanPHPVersions(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	a, err = store.GetPlan(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	b := a
	b.ID, b.Name, b.DiskMB, b.BandwidthMB = 0, "Owned full B", 4096, 8192
	b, err = store.UpsertPlan(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.ChangeSubscriptionPlans(ctx, []int64{1}, b.ID); err != nil {
		t.Fatal(err)
	}
	if fullA == planPHPNonPHPState(t, db, a.ID) {
		t.Fatal("different plan did not replace the full snapshot")
	}
	if err = store.ChangeSubscriptionPlans(ctx, []int64{1}, a.ID); err != nil {
		t.Fatal(err)
	}
	if fullA != planPHPNonPHPState(t, db, a.ID) {
		t.Fatal("A-to-B-to-A failed to restore the entire non-PHP plan/preset/snapshot contract")
	}
	if _, err = db.Exec(`UPDATE subscription_entitlements SET disk_mb=3456,service_presets=service_presets||'{"future":{"keep":null}}' WHERE subscription_id=1`); err != nil {
		t.Fatal(err)
	}
	beforeRetry := planPHPNonPHPState(t, db, a.ID)
	if err = store.ChangeSubscriptionPlans(ctx, []int64{1}, a.ID); err != nil {
		t.Fatal(err)
	}
	if beforeRetry != planPHPNonPHPState(t, db, a.ID) {
		t.Fatal("same-plan synced retry erased PHP-only preservation")
	}
}

func TestPlanPHPMixedHistoryChecksEveryMarkedRevisionPostgreSQL(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid full fallback", true: "corrupt later marker"}[corrupt], func(t *testing.T) {
			db := planPHPPostgres(t, "20261018000056_dns_managed_defaults.sql")
			cmd := planPHPCommand(t, db)
			ctx := context.Background()
			store := NewSQLStore(db)
			plan, err := store.GetPlan(ctx, cmd.PlanID)
			if err != nil {
				t.Fatal(err)
			}
			plan.Name = "Ordinary revision before narrow operation"
			plan, err = store.UpsertPlan(ctx, plan)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(`UPDATE subscription_system_accounts SET applied_revision=desired_revision,convergence_status='in_sync',last_error='' WHERE subscription_id=1`); err != nil {
				t.Fatal(err)
			}
			cmd.Input.ExpectedRevision = plan.Revision
			result, err := store.UpdatePlanPHPVersions(ctx, cmd)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(`UPDATE subscriptions SET plan_revision=$1 WHERE id=1`, plan.Revision-1); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(`UPDATE subscription_entitlements SET disk_mb=3456 WHERE subscription_id=1`); err != nil {
				t.Fatal(err)
			}
			if corrupt {
				if _, err = db.Exec(`ALTER TABLE plan_revisions DISABLE TRIGGER plan_revisions_immutable_update`); err != nil {
					t.Fatal(err)
				}
				if _, err = db.Exec(`UPDATE plan_revisions SET definition_hash=repeat('0',64) WHERE plan_id=$1 AND revision=$2`, cmd.PlanID, result.Revision); err != nil {
					t.Fatal(err)
				}
				if _, err = db.Exec(`ALTER TABLE plan_revisions ENABLE TRIGGER plan_revisions_immutable_update`); err != nil {
					t.Fatal(err)
				}
			}
			driver := riverdatabasesql.New(db)
			migrator, err := rivermigrate.New(driver, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = migrator.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
				t.Fatal(err)
			}
			client, err := river.NewClient(driver, &river.Config{})
			if err != nil {
				t.Fatal(err)
			}
			before := planPHPAllState(t, db)
			err = NewSQLStore(db, client).SyncSubscription(ctx, 1)
			if corrupt {
				var integrity *PlanPHPIntegrityError
				if !errors.As(err, &integrity) || before != planPHPAllState(t, db) {
					t.Fatalf("ordinary row hid corrupt later marker or committed partial state: %v", err)
				}
			} else {
				var disk int
				if err != nil {
					t.Fatal(err)
				}
				if err = db.QueryRow(`SELECT disk_mb FROM subscription_entitlements WHERE subscription_id=1`).Scan(&disk); err != nil || disk == 3456 {
					t.Fatalf("valid mixed history did not use ordinary full behavior: %d %v", disk, err)
				}
			}
		})
	}
}
