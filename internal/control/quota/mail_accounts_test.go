package quota

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestUpsertMailboxRejectsInvalidInputBeforeSQL(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := NewSQLStore(db)
	for name, input := range map[string]types.MailboxInput{
		"missing domain":    {LocalPart: "alice", Password: "longenough-pass", Enabled: true},
		"invalid local":     {MailDomainID: 4, LocalPart: "bad local", Password: "longenough-pass", Enabled: true},
		"uppercase at sign": {MailDomainID: 4, LocalPart: "alice@example.test", Password: "longenough-pass", Enabled: true},
		"missing password":  {MailDomainID: 4, LocalPart: "alice", Enabled: true},
		"short password":    {MailDomainID: 4, LocalPart: "alice", Password: "short", Enabled: true},
	} {
		if _, err := store.UpsertMailbox(context.Background(), 83, 7, input); err == nil {
			t.Fatalf("%s: invalid mailbox input was accepted", name)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("validation must reject input before touching the database: %v", err)
	}
}

func TestEnforceMailCountTxScopesCountToSubscription(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := enforceMailCountTx(context.Background(), tx, "mailboxes", 83, -1); err != nil {
		t.Fatalf("unlimited plan must not query or fail: %v", err)
	}
	if err := enforceMailCountTx(context.Background(), tx, "mailboxes", 83, 0); !errors.Is(err, ErrExceeded) {
		t.Fatalf("zero limit must fail closed with ErrExceeded, got %v", err)
	}
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM mailboxes mb JOIN mail_domains md ON md\.id=mb\.mail_domain_id WHERE md\.subscription_id=\$1`).
		WithArgs(int64(83)).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	if err := enforceMailCountTx(context.Background(), tx, "mailboxes", 83, 2); !errors.Is(err, ErrExceeded) {
		t.Fatalf("creating the (limit+1)th mailbox must return ErrExceeded, got %v", err)
	}
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM mail_aliases alias JOIN mail_domains md ON md\.id=alias\.mail_domain_id WHERE md\.subscription_id=\$1`).
		WithArgs(int64(83)).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	if err := enforceMailCountTx(context.Background(), tx, "mail_aliases", 83, 5); err != nil {
		t.Fatalf("alias count below the limit must pass: %v", err)
	}
	mock.ExpectRollback()
	_ = tx.Rollback()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureMailDomainBelongsTxRejectsForeignDomain(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM mail_domains WHERE id=\$1 AND subscription_id=\$2 AND NOT delete_requested\)`).
		WithArgs(int64(49), int64(83)).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	if err := ensureMailDomainBelongsTx(context.Background(), tx, 83, 49); err == nil {
		t.Fatal("a mail domain owned by another subscription was accepted")
	}
	mock.ExpectRollback()
	_ = tx.Rollback()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureAliasDestinationTxRejectsForeignMailbox(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM mailboxes mb JOIN mail_domains md ON md\.id=mb\.mail_domain_id\s+WHERE md\.subscription_id=\$2 AND lower\(mb\.local_part\)\|\|'@'\|\|md\.domain=\$1\)`).
		WithArgs("victim@other-tenant.test", int64(83)).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	if err := ensureAliasDestinationTx(context.Background(), tx, 83, "victim@other-tenant.test"); err == nil {
		t.Fatal("an alias destination in another tenant was accepted")
	}
	mock.ExpectRollback()
	_ = tx.Rollback()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteMailboxAndAliasScopeToSubscription(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		query string
		call  func(*SQLStore) error
	}{
		{name: "mailbox", query: `DELETE FROM mailboxes mb USING mail_domains md`, call: func(store *SQLStore) error { return store.DeleteMailbox(context.Background(), 83, 7) }},
		{name: "alias", query: `DELETE FROM mail_aliases alias USING mail_domains md`, call: func(store *SQLStore) error { return store.DeleteMailAlias(context.Background(), 83, 7) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectBegin()
			mock.ExpectExec(test.query).WithArgs(int64(7), int64(83)).WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectRollback()
			if err := test.call(NewSQLStore(db)); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("cross-tenant delete must affect no rows and fail, got %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestMailTenantIsolationTwoTenants is the real-database two-tenant fixture:
// it runs only when NAKPANEL_TEST_DATABASE_URL points at a migrated, disposable
// Postgres (the phase 18 multipass verifier provides one) and proves that
// mailboxes, aliases, the max_mailboxes gate, and the Stalwart directory views
// all stay inside the owning subscription.
func TestMailTenantIsolationTwoTenants(t *testing.T) {
	dsn := os.Getenv("NAKPANEL_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NAKPANEL_TEST_DATABASE_URL is not set")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	store := NewSQLStore(db)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	createTenant := func(label string, maxMailboxes int) (subscriptionID, mailDomainID int64, domain string) {
		t.Helper()
		domain = fmt.Sprintf("%s-%s.test", label, suffix)
		var userID, customerID, planID int64
		if err := db.QueryRowContext(ctx, `INSERT INTO users(email,password_hash,role) VALUES($1,'!test','client') RETURNING id`,
			fmt.Sprintf("%s-%s@nakpanel.test", label, suffix)).Scan(&userID); err != nil {
			t.Fatalf("create user %s: %v", label, err)
		}
		if err := db.QueryRowContext(ctx, `INSERT INTO customers(login_user_id,email,display_name) VALUES($1,$2,$3) RETURNING id`,
			userID, fmt.Sprintf("%s-%s@nakpanel.test", label, suffix), label).Scan(&customerID); err != nil {
			t.Fatalf("create customer %s: %v", label, err)
		}
		if err := db.QueryRowContext(ctx, `INSERT INTO plans(name,max_mailboxes,php_allowlist) VALUES($1,$2,'8.3') RETURNING id`,
			fmt.Sprintf("mail-test-%s-%s", label, suffix), maxMailboxes).Scan(&planID); err != nil {
			t.Fatalf("create plan %s: %v", label, err)
		}
		if err := db.QueryRowContext(ctx, `INSERT INTO subscriptions(customer_user_id,customer_id,plan_id,name,status) VALUES($1,$2,$3,$4,'active') RETURNING id`,
			userID, customerID, planID, label+" subscription").Scan(&subscriptionID); err != nil {
			t.Fatalf("create subscription %s: %v", label, err)
		}
		mailDomainID, err = store.UpsertMailDomain(ctx, subscriptionID, userID, types.MailDomainInput{
			Domain: domain, Enabled: true, DKIM: true, DMARCPolicy: "none",
		})
		if err != nil {
			t.Fatalf("enable mail domain %s: %v", label, err)
		}
		return subscriptionID, mailDomainID, domain
	}

	subA, domainAID, domainA := createTenant("tenant-a", 2)
	subB, domainBID, domainB := createTenant("tenant-b", 2)

	alicePassword := "correct-horse-battery"
	aliceID, err := store.UpsertMailbox(ctx, subA, 0, types.MailboxInput{
		MailDomainID: domainAID, LocalPart: "alice", Password: alicePassword, QuotaMB: 512, Enabled: true,
	})
	if err != nil {
		t.Fatalf("tenant A mailbox create: %v", err)
	}

	// Tenant B must not be able to create, modify, or delete anything under
	// tenant A's domain — the scoping is enforced in SQL.
	if _, err := store.UpsertMailbox(ctx, subB, 0, types.MailboxInput{
		MailDomainID: domainAID, LocalPart: "intruder", Password: "intruder-password", Enabled: true,
	}); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Fatalf("tenant B created a mailbox under tenant A's domain: %v", err)
	}
	if _, err := store.UpsertMailbox(ctx, subB, 0, types.MailboxInput{
		ID: aliceID, MailDomainID: domainBID, LocalPart: "hijack", Password: "hijack-password!", Enabled: true,
	}); err == nil {
		t.Fatal("tenant B hijacked tenant A's mailbox row by id")
	}
	if err := store.DeleteMailbox(ctx, subB, aliceID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("tenant B deleted tenant A's mailbox: %v", err)
	}
	if _, err := store.UpsertMailAlias(ctx, subB, 0, types.MailAliasInput{
		MailDomainID: domainBID, LocalPart: "steal", Destinations: []string{"alice@" + domainA},
	}); err == nil {
		t.Fatal("tenant B forwarded mail to tenant A's mailbox")
	}

	// The visible surface is scoped too: tenant B sees none of tenant A's rows.
	var visible int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mailboxes mb JOIN mail_domains md ON md.id=mb.mail_domain_id WHERE md.subscription_id=$1`, subB).Scan(&visible); err != nil {
		t.Fatal(err)
	}
	if visible != 0 {
		t.Fatalf("tenant B sees %d foreign mailboxes", visible)
	}

	// Aliases resolve inside the tenant.
	if _, err := store.UpsertMailAlias(ctx, subA, 0, types.MailAliasInput{
		MailDomainID: domainAID, LocalPart: "sales", Destinations: []string{"alice@" + domainA},
	}); err != nil {
		t.Fatalf("tenant A alias create: %v", err)
	}

	// The plan gate fails closed: the (max_mailboxes+1)th mailbox is rejected.
	if _, err := store.UpsertMailbox(ctx, subA, 0, types.MailboxInput{
		MailDomainID: domainAID, LocalPart: "bob", Password: "bob-password-ok!", Enabled: true,
	}); err != nil {
		t.Fatalf("tenant A second mailbox create: %v", err)
	}
	if _, err := store.UpsertMailbox(ctx, subA, 0, types.MailboxInput{
		MailDomainID: domainAID, LocalPart: "carol", Password: "carol-password-x", Enabled: true,
	}); !errors.Is(err, ErrExceeded) {
		t.Fatalf("mailbox over plan limit must return ErrExceeded, got %v", err)
	}

	// Stalwart's directory views expose argon2id hashes, never plaintext, and
	// resolve aliases only to same-tenant mailboxes.
	var secret string
	if err := db.QueryRowContext(ctx, `SELECT secret FROM stalwart_accounts WHERE name=$1`, "alice@"+domainA).Scan(&secret); err != nil {
		t.Fatalf("stalwart_accounts view: %v", err)
	}
	if !strings.HasPrefix(secret, "$argon2id$") {
		t.Fatalf("stored mailbox secret is not an argon2id hash: %q", secret[:min(12, len(secret))])
	}
	if ok, err := auth.VerifyPassword(alicePassword, secret); err != nil || !ok {
		t.Fatalf("stored hash does not verify the mailbox password: ok=%v err=%v", ok, err)
	}
	var resolved string
	if err := db.QueryRowContext(ctx, `SELECT name FROM stalwart_emails WHERE address=$1 AND type='alias'`, "sales@"+domainA).Scan(&resolved); err != nil {
		t.Fatalf("alias resolution through stalwart_emails: %v", err)
	}
	if resolved != "alice@"+domainA {
		t.Fatalf("alias resolved to %q", resolved)
	}

	// Deleting the mailbox removes it from the directory views immediately —
	// this is what makes Stalwart stop authenticating and accepting mail.
	if err := store.DeleteMailbox(ctx, subA, aliceID); err != nil {
		t.Fatalf("tenant A mailbox delete: %v", err)
	}
	var remaining int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM stalwart_accounts WHERE name=$1`, "alice@"+domainA).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatal("deleted mailbox is still visible to the Stalwart directory")
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM stalwart_emails WHERE address=$1`, "sales@"+domainA).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatal("alias to a deleted mailbox still resolves in the directory")
	}
	_ = domainB
}
