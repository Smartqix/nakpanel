package quota

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"
)

func waitPlanPHPSQL(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		var ok bool
		if err := db.QueryRow(query, args...).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		if ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("actual concurrent transaction did not reach the intended lock boundary")
}

func TestPlanPHPFullTransactionContentionPostgreSQL(t *testing.T) {
	for _, kind := range []string{"plan", "addon"} {
		for _, first := range []string{"full", "php"} {
			t.Run(kind+"_"+first+"_first", func(t *testing.T) {
				db := planPHPPostgres(t, "20261018000056_dns_managed_defaults.sql")
				cmd := planPHPCommand(t, db)
				store := NewSQLStore(db)
				addon := planPHPAddon(t, db)
				plan, err := store.GetPlan(context.Background(), cmd.PlanID)
				if err != nil {
					t.Fatal(err)
				}
				key := time.Now().UnixNano()%1000000000 + 1
				gate, err := db.Begin()
				if err != nil {
					t.Fatal(err)
				}
				defer gate.Rollback()
				if _, err = gate.Exec(`SELECT pg_advisory_xact_lock($1)`, key); err != nil {
					t.Fatal(err)
				}
				table, condition := "plans", `NEW.name='Held ordinary full mutation'`
				if kind == "addon" {
					table = "addon_plans"
				}
				if first == "php" {
					table = "plan_revisions"
					condition = `NEW.definition ? '_operation'`
				}
				trigger := fmt.Sprintf(`CREATE FUNCTION test_hold_plan_php() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF %s THEN PERFORM pg_advisory_xact_lock(%d);END IF;RETURN NEW;END$$;CREATE TRIGGER test_hold_plan_php BEFORE INSERT OR UPDATE ON %s FOR EACH ROW EXECUTE FUNCTION test_hold_plan_php()`, condition, key, table)
				if _, err = db.Exec(trigger); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				full := func() error {
					if kind == "plan" {
						plan.Name = "Held ordinary full mutation"
						_, err := store.UpsertPlan(ctx, plan)
						return err
					}
					addon.Name = "Held ordinary full mutation"
					_, err := store.UpsertAddonPlan(ctx, addon)
					return err
				}
				fullDone := make(chan error, 1)
				phpDone := make(chan error, 1)
				waitGate := func() {
					waitPlanPHPSQL(t, db, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND classid=0 AND objid=$1::oid AND NOT granted)`, key)
				}
				if first == "full" {
					go func() { fullDone <- full() }()
					waitGate()
					started := time.Now()
					_, err = store.UpdatePlanPHPVersions(ctx, cmd)
					var conflict *PlanPHPConflictError
					if !errors.As(err, &conflict) || conflict.Code != "plan_busy" || time.Since(started) > time.Second {
						t.Fatalf("full-first failed bounded admission: %v after %v", err, time.Since(started))
					}
					gate.Rollback()
					if err = <-fullDone; err != nil {
						t.Fatal(err)
					}
				} else {
					go func() { _, err := store.UpdatePlanPHPVersions(ctx, cmd); phpDone <- err }()
					waitGate()
					go func() { fullDone <- full() }()
					waitPlanPHPSQL(t, db, `SELECT count(*)>=2 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.application_name=current_setting('application_name') AND NOT l.granted`)
					gate.Rollback()
					if err = <-phpDone; err != nil {
						t.Fatal(err)
					}
					if err = <-fullDone; err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}

func TestPlanPHPLaterSharedLockIsBoundedPostgreSQL(t *testing.T) {
	db := planPHPPostgres(t, "20261018000056_dns_managed_defaults.sql")
	cmd := planPHPCommand(t, db)
	gate, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback()
	if _, err = gate.Exec(`SELECT id FROM settings WHERE id=true FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	before := planPHPAllState(t, db)
	started := time.Now()
	_, err = NewSQLStore(db).UpdatePlanPHPVersions(context.Background(), cmd)
	var conflict *PlanPHPConflictError
	if !errors.As(err, &conflict) || conflict.Code != "plan_busy" {
		t.Fatalf("later shared lock escaped admission budget: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 750*time.Millisecond {
		t.Fatalf("later lock ignored local250ms bound: %v", elapsed)
	}
	if before != planPHPAllState(t, db) {
		t.Fatal("later-lock failure changed state")
	}
}

func TestPlanPHPConcurrentExpectedRevisionPostgreSQL(t *testing.T) {
	db := planPHPPostgres(t, "20261018000056_dns_managed_defaults.sql")
	cmd := planPHPCommand(t, db)
	store := NewSQLStore(db)
	type outcome struct {
		result PlanPHPVersionsResult
		err    error
	}
	start := make(chan struct{})
	done := make(chan outcome, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for range 2 {
		go func() {
			<-start
			result, err := store.UpdatePlanPHPVersions(ctx, cmd)
			done <- outcome{result, err}
		}()
	}
	close(start)
	changed, conflicts := 0, 0
	for range 2 {
		got := <-done
		if got.err == nil && got.result.Changed && got.result.Revision == cmd.Input.ExpectedRevision+1 {
			changed++
		} else {
			var conflict *PlanPHPConflictError
			if !errors.As(got.err, &conflict) || (conflict.Code != "plan_busy" && conflict.Code != "stale_revision") {
				t.Fatalf("concurrent writer unexpected result: %+v %v", got.result, got.err)
			}
			conflicts++
		}
	}
	var audits int
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE action='plan.saved' AND target_type='plan' AND target_id=$1`, cmd.PlanID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if changed != 1 || conflicts != 1 || audits != 1 {
		t.Fatalf("concurrent admission changed=%d conflicts=%d audits=%d", changed, conflicts, audits)
	}
}
