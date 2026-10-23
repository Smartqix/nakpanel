package operations_test

import (
	"context"
	"errors"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"strings"
	"testing"
	"time"
)

func TestEmailDeliveryRetriesAreBoundedAndDoNotRecurse(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	if err := s.SaveDeliveryPolicy(ctx, admin, operations.DeliveryPolicy{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePreferences(ctx, admin, operations.Preferences{EmailMode: "immediate"}); err != nil {
		t.Fatal(err)
	}
	i, err := s.ObserveIssue(ctx, observation("mail-source", 51))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Dispatch(ctx, 100); err != nil {
		t.Fatal(err)
	}
	calls := 0
	sender := operations.NewEmailService(db, func(context.Context, string, string, string) error {
		calls++
		return errors.New("password=do-not-store")
	}, "fixture-smtp")
	for n := 0; n < 10; n++ {
		if _, err = db.Exec(`UPDATE notification_email_batches SET next_attempt_at=now()`); err != nil {
			t.Fatal(err)
		}
		if err = sender.Deliver(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err = s.Dispatch(ctx, 100); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 8 {
		t.Fatal("unbounded delivery attempts", calls)
	}
	var batches, issues int
	var lastError string
	if err = db.QueryRow(`SELECT count(*),max(last_error) FROM notification_email_batches`).Scan(&batches, &lastError); err != nil || batches != 1 || strings.Contains(lastError, "do-not-store") {
		t.Fatal(batches, lastError, err)
	}
	if err = db.QueryRow(`SELECT count(*) FROM issues WHERE kind='notification_delivery'`).Scan(&issues); err != nil || issues != 1 {
		t.Fatal("recursive delivery issues", issues, err)
	}
	still, err := s.Issue(ctx, admin, i.ID)
	if err != nil || still.ResolvedAt != nil {
		t.Fatal("SMTP failure altered source issue", still, err)
	}
}
func TestEmailDigestDedupesAndRechecksCurrentOwnershipAtSend(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	if err := s.SaveDeliveryPolicy(ctx, admin, operations.DeliveryPolicy{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePreferences(ctx, client, operations.Preferences{EmailMode: "digest"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ObserveIssue(ctx, observation("digest-source", 51)); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 2; n++ {
		if _, err := s.Dispatch(ctx, 100); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM notification_email_items`).Scan(&count); err != nil || count != 1 {
		t.Fatal("digest not deduplicated", count, err)
	}
	if _, err := db.Exec(`UPDATE customers SET login_user_id=22 WHERE id=10; UPDATE notification_email_batches SET next_attempt_at=now()`); err != nil {
		t.Fatal(err)
	}
	calls := 0
	sender := operations.NewEmailService(db, func(context.Context, string, string, string) error { calls++; return nil }, "fixture")
	if err := sender.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("revoked scope leaked by email")
	}
	var state string
	if err := db.QueryRow(`SELECT status FROM notification_email_batches`).Scan(&state); err != nil || state != "skipped" {
		t.Fatal(state, err)
	}
}

func TestEmailAcceptanceResolvesOnlyItsPrivateDeliveryIssue(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	if err := s.SaveDeliveryPolicy(ctx, admin, operations.DeliveryPolicy{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePreferences(ctx, admin, operations.Preferences{EmailMode: "immediate"}); err != nil {
		t.Fatal(err)
	}
	source, err := s.ObserveIssue(ctx, observation("smtp-recovery-source", 51))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Dispatch(ctx, 100); err != nil {
		t.Fatal(err)
	}
	fail := operations.NewEmailService(db, func(context.Context, string, string, string) error { return errors.New("unavailable") }, "same-smtp")
	if err = fail.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE notification_email_batches SET next_attempt_at=now()`); err != nil {
		t.Fatal(err)
	}
	accepted := operations.NewEmailService(db, func(context.Context, string, string, string) error { return nil }, "same-smtp")
	if err = accepted.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	var resolved bool
	var receipt string
	if err = db.QueryRow(`SELECT resolved_at IS NOT NULL,verification->>'summary' FROM issues WHERE kind='notification_delivery'`).Scan(&resolved, &receipt); err != nil || !resolved || !strings.Contains(receipt, "Accepted by SMTP") {
		t.Fatal(resolved, receipt, err)
	}
	still, err := s.Issue(ctx, admin, source.ID)
	if err != nil || still.ResolvedAt != nil {
		t.Fatal("email acceptance resolved source incident", err)
	}
}
func TestEmailOffNeverSilencesMandatoryInbox(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	if _, err := s.ObserveIssue(ctx, observation("mandatory-inbox", 51)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Dispatch(ctx, 100); err != nil {
		t.Fatal(err)
	}
	p, err := s.Page(ctx, admin, "inbox", operations.Filter{})
	if err != nil || p.Counts.Unread != 1 {
		t.Fatal(p, err)
	}
	var n int
	if err = db.QueryRow(`SELECT count(*) FROM notification_email_batches`).Scan(&n); err != nil || n != 0 {
		t.Fatal(n, err)
	}
}

func TestEmailSelectionCannotSendToAnUnscopedAddress(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	if err := s.SaveDeliveryPolicy(ctx, admin, operations.DeliveryPolicy{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePreferences(ctx, client, operations.Preferences{EmailMode: "immediate"}); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := db.QueryRow(`INSERT INTO notifications(kind,severity,title,body,dedupe_key) VALUES('server_backup_failed','critical','Server backup failed','Review Activity','server-only') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = operations.EnqueueNotificationForEmailTx(ctx, tx, id, "one@example.test"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM notification_email_batches`).Scan(&count); err != nil || count != 0 {
		t.Fatal("unscoped address was selected", count, err)
	}
}

func TestEmailOwnershipCannotChangeDuringFinalAuthorizationAndSMTP(t *testing.T) {
	db := testDB(t)
	s := operations.NewStore(db)
	if err := s.SaveDeliveryPolicy(ctx, admin, operations.DeliveryPolicy{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePreferences(ctx, client, operations.Preferences{EmailMode: "immediate"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ObserveIssue(ctx, observation("concurrent-transfer", 51)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Dispatch(ctx, 100); err != nil {
		t.Fatal(err)
	}
	entered, finish := make(chan struct{}), make(chan struct{})
	sender := operations.NewEmailService(db, func(context.Context, string, string, string) error { close(entered); <-finish; return nil }, "guarded")
	done := make(chan error, 1)
	go func() { done <- sender.Deliver(ctx) }()
	<-entered
	attempt, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	_, err := db.ExecContext(attempt, `UPDATE customers SET login_user_id=22 WHERE id=10`)
	close(finish)
	if err == nil {
		t.Error("ownership changed while a scoped email was being transmitted")
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}
