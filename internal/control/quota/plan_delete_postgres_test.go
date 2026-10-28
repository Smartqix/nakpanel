package quota

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

type planDeleter interface {
	DeletePlan(context.Context, int64, int64, bool) error
}

func TestPlanDeletionProtectsSubscriptionsAndProviderOwnership(t *testing.T) {
	files, _ := filepath.Glob("../../../migrations/*.sql")
	db := planPHPPostgres(t, filepath.Base(files[len(files)-1]))
	store, ok := any(NewSQLStore(db)).(planDeleter)
	if !ok {
		t.Fatal("store does not support deleting unused plans")
	}
	var id int64
	if err := db.QueryRow(`INSERT INTO plans(name) VALUES('Unused administrator plan') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	for _, resellerID := range []int64{0, 999} {
		if err := store.DeletePlan(context.Background(), id, resellerID, false); !errors.Is(err, ErrProviderScope) {
			t.Fatalf("reseller access returned %v, want scope rejection", err)
		}
	}
	if err := store.DeletePlan(context.Background(), id, 0, true); err != nil {
		t.Fatalf("administrator cannot delete unused plan: %v", err)
	}
	if err := db.QueryRow(`SELECT id FROM plans WHERE id=$1`, id).Scan(&id); err != sql.ErrNoRows {
		t.Fatalf("plan remains: %v", err)
	}
	var subscriptionID int64
	if err := db.QueryRow(`UPDATE subscriptions SET plan_id=1 WHERE id=(SELECT min(id) FROM subscriptions) RETURNING id`).Scan(&subscriptionID); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"active", "suspended", "cancelled"} {
		if _, err := db.Exec(`UPDATE subscriptions SET status=$1 WHERE id=$2`, status, subscriptionID); err != nil {
			t.Fatal(err)
		}
		if err := store.DeletePlan(context.Background(), 1, 0, true); !errors.Is(err, ErrPlanInUse) {
			t.Fatalf("plan with %s subscription returned %v, want in-use rejection", status, err)
		}
		var count int
		if err := db.QueryRow(`SELECT count(*) FROM plan_revisions WHERE plan_id=1`).Scan(&count); err != nil || count == 0 {
			t.Fatalf("failed deletion removed history: %v", err)
		}
	}
	var resellerID, ownerID int64
	if err := db.QueryRow(`INSERT INTO users(email,password_hash,role) VALUES('delete-owner@example.test','!','reseller') RETURNING id`).Scan(&ownerID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`INSERT INTO reseller_accounts(login_user_id,email) VALUES($1,'delete-owner@example.test') RETURNING id`, ownerID).Scan(&resellerID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`INSERT INTO plans(name,reseller_id) VALUES('Unused reseller plan',$1) RETURNING id`, resellerID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := store.DeletePlan(context.Background(), id, resellerID+1, false); !errors.Is(err, ErrProviderScope) {
		t.Fatalf("cross-reseller deletion: %v", err)
	}
	if err := store.DeletePlan(context.Background(), id, resellerID, false); err != nil {
		t.Fatalf("owner cannot delete their unused plan: %v", err)
	}
}

func TestPlanDeletionRejectsConcurrentSubscriptionAssignment(t *testing.T) {
	files, _ := filepath.Glob("../../../migrations/*.sql")
	db := planPHPPostgres(t, filepath.Base(files[len(files)-1]))
	var id int64
	if err := db.QueryRow(`INSERT INTO plans(name) VALUES('Concurrent assignment') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE subscriptions SET plan_id=$1 WHERE id=(SELECT min(id) FROM subscriptions)`, id); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- NewSQLStore(db).DeletePlan(ctx, id, 0, true) }()
	waitPlanPHPSQL(t, db, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name=current_schema() AND query LIKE 'DELETE FROM plans%' AND wait_event_type='Lock')`)
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-done; !errors.Is(err, ErrPlanInUse) {
		t.Fatalf("concurrent assignment was not protected: %v", err)
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM subscriptions s JOIN plans p ON p.id=s.plan_id WHERE p.id=$1`, id).Scan(&count); err != nil || count != 1 {
		t.Fatalf("assignment not preserved: count=%d err=%v", count, err)
	}
}

func TestUnusedPlanDeletionCascadesOnlyItsOwnHistory(t *testing.T) {
	files, err := filepath.Glob("../../../migrations/*.sql")
	if err != nil || len(files) == 0 {
		t.Fatal("migrations unavailable", err)
	}
	db := planPHPPostgres(t, filepath.Base(files[len(files)-1]))
	var id int64
	if err := db.QueryRow(`INSERT INTO plans(name) VALUES('Disposable plan') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO plan_revisions(plan_id,revision,lifecycle_status,definition,definition_hash,actor_label)
VALUES($1,1,'draft','{}',repeat('a',64),'test'),($1,2,'draft','{}',repeat('b',64),'test');
`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO plan_service_presets(plan_id) VALUES($1)`, id); err != nil {
		t.Fatal(err)
	}
	var others int
	if err := db.QueryRow(`SELECT count(*) FROM plan_revisions WHERE plan_id<>$1`, id).Scan(&others); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM plan_revisions WHERE plan_id=$1`, id); err == nil {
		t.Fatal("individual revisions must remain immutable")
	}
	if _, err := db.Exec(`UPDATE plan_revisions SET change_reason='tampered' WHERE plan_id=$1`, id); err == nil {
		t.Fatal("revision edits must remain blocked")
	}
	if _, err := db.Exec(`DELETE FROM plans WHERE id=$1`, id); err != nil {
		t.Fatalf("deleting an unused plan must remove its owned revisions: %v", err)
	}
	for _, table := range []string{"plan_revisions", "plan_service_presets"} {
		var count int
		if err := db.QueryRow(`SELECT count(*) FROM `+table+` WHERE plan_id=$1`, id).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s remains: %d, %v", table, count, err)
		}
	}
	var after int
	if err := db.QueryRow(`SELECT count(*) FROM plan_revisions`).Scan(&after); err != nil || after != others {
		t.Fatalf("other plans' revisions changed: %d -> %d (%v)", others, after, err)
	}
}
