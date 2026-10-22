package quota

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"github.com/nakroteck/nakpanel/internal/types"
)

func subdomainMailLimits(t *testing.T, f subdomainMailFixture, boxes, aliases, size int) {
	t.Helper()
	patch, _ := json.Marshal(map[string]any{"resources": map[string]int{"max_mailboxes": boxes, "max_mail_aliases": aliases}, "mail": map[string]int{"mailbox_quota_mb": size}})
	if err := f.store.SetSubscriptionPolicy(context.Background(), 1, 1, patch, true); err != nil {
		t.Fatal(err)
	}
}

func TestSubdomainMailSharedQuotaLastSlot(t *testing.T) {
	for _, kind := range []string{"mailbox", "alias"} {
		t.Run(kind, func(t *testing.T) {
			f := newSubdomainMailFixture(t)
			sibling := removaldb.Site(t, f.db, 1, "news.example.test", f.parent)
			parentDomain := f.enable(t, 1, f.parent)
			childDomain := f.enable(t, 1, f.child)
			siblingDomain := f.enable(t, 1, sibling)
			f.mailbox(t, 1, parentDomain)
			boxes := 2
			if kind == "alias" {
				boxes = -1
			}
			subdomainMailLimits(t, f, boxes, 2, 64)
			if kind == "alias" {
				if _, err := f.store.UpsertMailAlias(context.Background(), 1, 1, types.MailAliasInput{MailDomainID: parentDomain, LocalPart: "sales", Destinations: []string{"hello@example.test"}}); err != nil {
					t.Fatal(err)
				}
			}
			start := make(chan struct{})
			results := make(chan error, 2)
			var wg sync.WaitGroup
			for _, domain := range []int64{childDomain, siblingDomain} {
				wg.Add(1)
				go func(id int64) {
					defer wg.Done()
					<-start
					var err error
					if kind == "mailbox" {
						_, err = f.store.UpsertMailbox(context.Background(), 1, 1, types.MailboxInput{MailDomainID: id, LocalPart: "last", Password: "subdomain-mail-fixture-password", QuotaMB: 10000, Enabled: true})
					} else {
						_, err = f.store.UpsertMailAlias(context.Background(), 1, 1, types.MailAliasInput{MailDomainID: id, LocalPart: "last", Destinations: []string{"hello@example.test"}})
					}
					results <- err
				}(domain)
			}
			close(start)
			wg.Wait()
			close(results)
			success, exceeded := 0, 0
			for err := range results {
				if err == nil {
					success++
				} else if errors.Is(err, ErrExceeded) {
					exceeded++
				} else {
					t.Fatal(err)
				}
			}
			if success != 1 || exceeded != 1 {
				t.Fatalf("last shared slot: success=%d exceeded=%d", success, exceeded)
			}
			table := "mailboxes"
			if kind == "alias" {
				table = "mail_aliases"
			}
			var count int
			if err := f.db.QueryRow(`SELECT count(*) FROM ` + table + ` entry JOIN mail_domains domain ON domain.id=entry.mail_domain_id WHERE domain.subscription_id=1`).Scan(&count); err != nil || count != 2 {
				t.Fatalf("shared %s count=%d err=%v", kind, count, err)
			}
			if kind == "mailbox" {
				if err := f.db.QueryRow(`SELECT count(*) FROM mailboxes WHERE local_part='last' AND quota_mb=64`).Scan(&count); err != nil || count != 1 {
					t.Fatalf("per-mailbox cap was bypassed: count=%d err=%v", count, err)
				}
			}
		})
	}
}

func TestSubdomainMailRejectsMissingUpdateIDs(t *testing.T) {
	for _, kind := range []string{"mailbox", "alias"} {
		t.Run(kind, func(t *testing.T) {
			f := newSubdomainMailFixture(t)
			parentDomain := f.enable(t, 1, f.parent)
			childDomain := f.enable(t, 1, f.child)
			f.mailbox(t, 1, parentDomain)
			subdomainMailLimits(t, f, 0, 0, 64)
			var err error
			if kind == "mailbox" {
				_, err = f.store.UpsertMailbox(context.Background(), 1, 1, types.MailboxInput{ID: 999999, MailDomainID: childDomain, LocalPart: "bypass", Enabled: true})
			} else {
				_, err = f.store.UpsertMailAlias(context.Background(), 1, 1, types.MailAliasInput{ID: 999999, MailDomainID: childDomain, LocalPart: "bypass", Destinations: []string{"hello@example.test"}})
			}
			if err == nil {
				t.Error("missing update ID created an account and bypassed the shared quota")
			}
			var count int
			if err := f.db.QueryRow(`SELECT (SELECT count(*) FROM mailboxes WHERE local_part='bypass')+(SELECT count(*) FROM mail_aliases WHERE local_part='bypass')`).Scan(&count); err != nil || count != 0 {
				t.Fatalf("forged update persisted: count=%d err=%v", count, err)
			}
		})
	}
}

func TestSubdomainMailMailboxStorageCap(t *testing.T) {
	f := newSubdomainMailFixture(t)
	domain := f.enable(t, 1, f.child)
	subdomainMailLimits(t, f, -1, -1, 64)
	for _, size := range []int{0, -1, 100000, 32} {
		id, err := f.store.UpsertMailbox(context.Background(), 1, 1, types.MailboxInput{MailDomainID: domain, LocalPart: "bounded", Password: "subdomain-mail-fixture-password", QuotaMB: size, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		want := 64
		if size == 32 {
			want = 32
		}
		var got int
		if err := f.db.QueryRow(`SELECT quota_mb FROM mailboxes WHERE id=$1`, id).Scan(&got); err != nil || got != want {
			t.Fatalf("quota input %d: got %d want %d err=%v", size, got, want, err)
		}
		if err := f.store.DeleteMailbox(context.Background(), 1, id); err != nil {
			t.Fatal(err)
		}
	}
}
