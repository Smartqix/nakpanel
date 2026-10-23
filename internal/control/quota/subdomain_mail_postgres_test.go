package quota

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"github.com/nakroteck/nakpanel/internal/types"
)

type subdomainMailFixture struct {
	db                     *sql.DB
	store                  *SQLStore
	parent, child, foreign int64
}

func newSubdomainMailFixture(t *testing.T) subdomainMailFixture {
	t.Helper()
	db := removaldb.New(t, "")
	parent := removaldb.Site(t, db, 1, "example.test", nil)
	child := removaldb.Site(t, db, 1, "shop.example.test", parent)
	foreign := removaldb.Site(t, db, 2, "foreign.test", nil)
	return subdomainMailFixture{db: db, store: NewSQLStore(db), parent: parent, child: child, foreign: foreign}
}

func (f subdomainMailFixture) enable(t *testing.T, subscription, siteID int64) int64 {
	t.Helper()
	id, err := f.store.UpsertMailDomain(context.Background(), subscription, 1, types.MailDomainInput{
		SiteID: siteID, Enabled: true, DKIM: true, DMARCPolicy: "none",
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (f subdomainMailFixture) mailbox(t *testing.T, subscription, domainID int64) int64 {
	t.Helper()
	id, err := f.store.UpsertMailbox(context.Background(), subscription, 1, types.MailboxInput{
		MailDomainID: domainID, LocalPart: "hello", Password: "subdomain-mail-fixture-password", QuotaMB: 128, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (f subdomainMailFixture) alias(t *testing.T, domainID int64) int64 {
	t.Helper()
	id, err := f.store.UpsertMailAlias(context.Background(), 1, 1, types.MailAliasInput{
		MailDomainID: domainID, LocalPart: "sales", Destinations: []string{"hello@shop.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestSubdomainMailEnableMailboxAndAlias(t *testing.T) {
	f := newSubdomainMailFixture(t)
	parentDomain := f.enable(t, 1, f.parent)
	childDomain := f.enable(t, 1, f.child)
	foreignDomain := f.enable(t, 2, f.foreign)
	f.mailbox(t, 1, parentDomain)
	childMailbox := f.mailbox(t, 1, childDomain)
	foreignMailbox := f.mailbox(t, 2, foreignDomain)
	f.alias(t, childDomain)

	// Model a successful agent acknowledgement; this fixture runs no mail server.
	if _, err := f.db.Exec(`UPDATE mail_domains SET effective_enabled=true,convergence_status='in_sync' WHERE id IN ($1,$2,$3)`, parentDomain, childDomain, foreignDomain); err != nil {
		t.Fatal(err)
	}
	var address, hash string
	if err := f.db.QueryRow(`SELECT lower(mb.local_part)||'@'||md.domain,mb.password_hash FROM mailboxes mb JOIN mail_domains md ON md.id=mb.mail_domain_id WHERE mb.id=$1`, childMailbox).Scan(&address, &hash); err != nil {
		t.Fatal(err)
	}
	if address != "hello@shop.example.test" {
		t.Fatalf("mailbox address = %q", address)
	}
	if valid, err := auth.VerifyPassword("subdomain-mail-fixture-password", hash); err != nil || !valid {
		t.Fatalf("mailbox password was not stored as a valid hash: %v", err)
	}
	var destination string
	if err := f.db.QueryRow(`SELECT name FROM stalwart_emails WHERE address='sales@shop.example.test' AND type='alias'`).Scan(&destination); err != nil || destination != address {
		t.Fatalf("child alias routing = %q, %v", destination, err)
	}
	for _, name := range []string{"hello@example.test", address, "hello@foreign.test"} {
		var n int
		if err := f.db.QueryRow(`SELECT count(*) FROM stalwart_accounts WHERE name=$1`, name).Scan(&n); err != nil || n != 1 {
			t.Fatalf("mail directory entry %q: count=%d error=%v", name, n, err)
		}
	}

	t.Run("foreign site", func(t *testing.T) {
		if _, err := f.store.UpsertMailDomain(context.Background(), 1, 1, types.MailDomainInput{SiteID: f.foreign, Enabled: true, DMARCPolicy: "none"}); err == nil {
			t.Fatal("foreign hosted site accepted")
		}
	})
	t.Run("foreign mail domain", func(t *testing.T) {
		if _, err := f.store.UpsertMailbox(context.Background(), 1, 1, types.MailboxInput{MailDomainID: foreignDomain, LocalPart: "intruder", Password: "subdomain-mail-fixture-password", Enabled: true}); err == nil {
			t.Fatal("foreign mail domain accepted")
		}
	})
	t.Run("foreign mailbox", func(t *testing.T) {
		if _, err := f.store.UpsertMailbox(context.Background(), 1, 1, types.MailboxInput{ID: foreignMailbox, MailDomainID: childDomain, LocalPart: "hijack", Enabled: true}); err == nil {
			t.Fatal("foreign mailbox reassigned to child")
		}
	})
	t.Run("foreign alias destination", func(t *testing.T) {
		if _, err := f.store.UpsertMailAlias(context.Background(), 1, 1, types.MailAliasInput{MailDomainID: childDomain, LocalPart: "foreign", Destinations: []string{"hello@foreign.test"}}); err == nil {
			t.Fatal("foreign mailbox accepted as alias destination")
		}
	})
	var foreignAddress string
	if err := f.db.QueryRow(`SELECT lower(mb.local_part)||'@'||md.domain FROM mailboxes mb JOIN mail_domains md ON md.id=mb.mail_domain_id WHERE mb.id=$1`, foreignMailbox).Scan(&foreignAddress); err != nil || foreignAddress != "hello@foreign.test" {
		t.Fatalf("foreign mailbox changed: %q, %v", foreignAddress, err)
	}
}

func TestSubdomainMailRepeatedEnableKeepsAccounts(t *testing.T) {
	f := newSubdomainMailFixture(t)
	domainID := f.enable(t, 1, f.child)
	mailboxID := f.mailbox(t, 1, domainID)
	aliasID := f.alias(t, domainID)

	got, err := f.store.UpsertMailDomain(context.Background(), 1, 1, types.MailDomainInput{
		SiteID: f.child, Domain: "forged.example.test", Enabled: true, DKIM: true, DMARCPolicy: "quarantine",
	})
	if err != nil || got != domainID {
		t.Fatalf("repeat enable must return the existing child mail domain %d: got %d, %v", domainID, got, err)
	}
	var name, policy string
	var count int
	if err := f.db.QueryRow(`SELECT domain,dmarc_policy FROM mail_domains WHERE id=$1`, domainID).Scan(&name, &policy); err != nil || name != "shop.example.test" || policy != "quarantine" {
		t.Fatalf("child mail settings = %q/%q, %v", name, policy, err)
	}
	got, err = f.store.UpsertMailDomain(context.Background(), 1, 1, types.MailDomainInput{
		ID: domainID, SiteID: f.child, Enabled: true, DKIM: true, DMARCPolicy: "reject",
	})
	if err != nil || got != domainID {
		t.Fatalf("editing the existing child mail domain failed: got %d, %v", got, err)
	}
	if err := f.db.QueryRow(`SELECT dmarc_policy FROM mail_domains WHERE id=$1`, domainID).Scan(&policy); err != nil || policy != "reject" {
		t.Fatalf("explicit child settings update = %q, %v", policy, err)
	}
	if err := f.db.QueryRow(`SELECT count(*) FROM mail_domains WHERE site_id=$1`, f.child).Scan(&count); err != nil || count != 1 {
		t.Fatalf("repeat enable duplicated mail domain: count=%d error=%v", count, err)
	}
	if err := f.db.QueryRow(`SELECT count(*) FROM mailboxes mb JOIN mail_aliases alias ON alias.mail_domain_id=mb.mail_domain_id WHERE mb.id=$1 AND alias.id=$2 AND mb.mail_domain_id=$3`, mailboxID, aliasID, domainID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("repeat enable changed child accounts: count=%d error=%v", count, err)
	}
}

func TestSubdomainMailRejectsRetargetedDomainID(t *testing.T) {
	for _, source := range []string{"parent", "foreign", "missing"} {
		t.Run(source, func(t *testing.T) {
			f := newSubdomainMailFixture(t)
			parentDomain := f.enable(t, 1, f.parent)
			foreignDomain := f.enable(t, 2, f.foreign)
			f.mailbox(t, 1, parentDomain)
			id := map[string]int64{"parent": parentDomain, "foreign": foreignDomain, "missing": 99999}[source]
			_, err := f.store.UpsertMailDomain(context.Background(), 1, 1, types.MailDomainInput{ID: id, SiteID: f.child, Enabled: true, DMARCPolicy: "none"})
			if err == nil {
				t.Fatal("supplied mail-domain ID was accepted for a different hosted site")
			}
			var got string
			if err = f.db.QueryRow(`SELECT domain||':'||site_id FROM mail_domains WHERE id=$1`, parentDomain).Scan(&got); err != nil || got != fmt.Sprintf("example.test:%d", f.parent) {
				t.Fatalf("parent mail identity changed: %q, %v", got, err)
			}
			var count int
			if err = f.db.QueryRow(`SELECT count(*) FROM mail_domains WHERE site_id=$1`, f.child).Scan(&count); err != nil || count != 0 {
				t.Fatalf("forged update created child mail domain: count=%d error=%v", count, err)
			}
		})
	}
}
