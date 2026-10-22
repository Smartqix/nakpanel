package provision

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"

	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

type childMailLifecycleFixture struct {
	childMailDNSFixture
	store   *controlquota.SQLStore
	foreign int64
	domains map[int64]int64
}

func newChildMailLifecycleFixture(t *testing.T) childMailLifecycleFixture {
	t.Helper()
	f := newChildMailDNSFixture(t)
	foreign := removaldb.Site(t, f.db, 2, "foreign-lifecycle.test", nil)
	result := childMailLifecycleFixture{f, controlquota.NewSQLStore(f.db, f.worker.phase6.river), foreign, map[int64]int64{}}
	for _, site := range []int64{f.parent, f.child, f.sibling, foreign} {
		var id int64
		if err := f.db.QueryRow(`INSERT INTO mail_domains(subscription_id,site_id,domain,enabled,dkim_enabled,dmarc_policy) SELECT subscription_id,id,domain,id<>$2,true,'none' FROM sites WHERE id=$1 RETURNING id`, site, f.sibling).Scan(&id); err != nil {
			t.Fatal(err)
		}
		result.domains[site] = id
		if _, err := f.db.Exec(`INSERT INTO mailboxes(mail_domain_id,local_part,password_hash,quota_mb,enabled) VALUES($1,'hello','preserved-fixture-hash',128,true)`, id); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.Exec(`INSERT INTO mail_aliases(mail_domain_id,local_part,destinations) SELECT id,'sales',ARRAY['hello@'||domain] FROM mail_domains WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
	}
	f.worker.agent = childMailDNSAgent{}
	result.converge(t)
	return result
}

func (f childMailLifecycleFixture) converge(t *testing.T) {
	t.Helper()
	if err := f.worker.Work(context.Background(), &river.Job[controlquota.ConfigureMailArgs]{Args: controlquota.NewConfigureMailArgs()}); err != nil {
		t.Fatal(err)
	}
}

func (f childMailLifecycleFixture) mailData(t *testing.T) string {
	t.Helper()
	var data string
	if err := f.db.QueryRow(`SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(m) ORDER BY id) FROM mailboxes m),(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM mail_aliases a))::text`).Scan(&data); err != nil {
		t.Fatal(err)
	}
	return data
}

func (f childMailLifecycleFixture) visible(t *testing.T, site int64, want bool) {
	t.Helper()
	var count int
	if err := f.db.QueryRow(`SELECT count(*) FROM stalwart_accounts account JOIN mail_domains domain ON account.name='hello@'||domain.domain WHERE domain.site_id=$1`, site).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if (count == 1) != want {
		t.Errorf("site %d mailbox visibility=%d want enabled=%t", site, count, want)
	}
	if err := f.db.QueryRow(`SELECT count(*) FROM stalwart_emails email JOIN mail_domains domain ON email.address='sales@'||domain.domain WHERE domain.site_id=$1`, site).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if (count == 1) != want {
		t.Errorf("site %d alias visibility=%d want enabled=%t", site, count, want)
	}
}

func TestSubdomainMailSuspensionAndReactivation(t *testing.T) {
	for _, kind := range []string{"subscription", "customer", "entitlement"} {
		t.Run(kind, func(t *testing.T) {
			f := newChildMailLifecycleFixture(t)
			before := f.mailData(t)
			set := func(active bool) {
				t.Helper()
				var err error
				state := "suspended"
				if active {
					state = "active"
				}
				switch kind {
				case "subscription":
					err = f.store.SetSubscriptionStatus(context.Background(), 1, state)
				case "customer":
					var id int64
					if e := f.db.QueryRow(`SELECT customer_id FROM subscriptions WHERE id=1`).Scan(&id); e != nil {
						t.Fatal(e)
					}
					err = f.store.SetCustomerStatus(context.Background(), id, state)
				case "entitlement":
					patch, _ := json.Marshal(map[string]any{"permissions": map[string]bool{"mail": active}, "mail": map[string]bool{"enabled": active}})
					err = f.store.SetSubscriptionPolicy(context.Background(), 1, 1, patch, true)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			set(false)
			f.visible(t, f.child, false)
			f.visible(t, f.parent, false)
			f.visible(t, f.foreign, true)
			if _, err := f.store.UpsertMailAlias(context.Background(), 1, 1, types.MailAliasInput{MailDomainID: f.domains[f.child], LocalPart: "bypass", Destinations: []string{"hello@child.parent-mail.test"}}); err == nil {
				t.Fatal("suspension/entitlement bypassed through child alias creation")
			}
			f.converge(t)
			f.visible(t, f.child, false)
			set(true)
			f.converge(t)
			f.visible(t, f.child, true)
			f.visible(t, f.parent, true)
			f.visible(t, f.sibling, false)
			f.visible(t, f.foreign, true)
			if f.mailData(t) != before {
				t.Fatal("suspension or reactivation changed mailbox data/aliases")
			}
		})
	}
}

func TestSubdomainMailWebsiteAndMailDisablePreserveData(t *testing.T) {
	f := newChildMailLifecycleFixture(t)
	before := f.mailData(t)
	canaries := f.records(t, "owner_site_id<>"+strconv.FormatInt(f.child, 10))
	policy, err := f.store.EffectiveSubscriptionPolicy(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.UpdateSiteSettings(context.Background(), types.UpdateSiteSettingsReq{SiteID: f.child, DesiredStatus: "suspended", DesiredPHPVersion: policy.PHP.DefaultVersion}); err != nil {
		t.Fatal(err)
	}
	// Model the hosting agent's acknowledgement; no server is contacted.
	if _, err := f.db.Exec(`UPDATE sites SET status=desired_status WHERE id=$1`, f.child); err != nil {
		t.Fatal(err)
	}
	f.converge(t)
	f.visible(t, f.child, true)
	for _, enabled := range []bool{false, true} {
		if _, err := f.store.UpsertMailDomain(context.Background(), 1, 1, types.MailDomainInput{ID: f.domains[f.child], SiteID: f.child, Enabled: enabled, DKIM: true, DMARCPolicy: "none"}); err != nil {
			t.Errorf("mail settings coupled to disabled website: %v", err)
			continue
		}
		if !enabled {
			f.visible(t, f.child, false)
		}
		f.converge(t)
		f.visible(t, f.child, enabled)
		f.visible(t, f.parent, true)
		f.visible(t, f.foreign, true)
		if f.mailData(t) != before || f.records(t, "owner_site_id<>"+strconv.FormatInt(f.child, 10)) != canaries {
			t.Fatal("child mail toggle changed data or parent/sibling DNS")
		}
	}
}

type childMailLifecycleAgent struct{ hook func() }

func (a childMailLifecycleAgent) ConfigureMail(ctx context.Context, req types.ConfigureMailReq) (types.Response, error) {
	a.hook()
	return (childMailDNSAgent{}).ConfigureMail(ctx, req)
}

func TestSubdomainMailStaleAcknowledgementCannotUndoSuspension(t *testing.T) {
	f := newChildMailLifecycleFixture(t)
	before := f.mailData(t)
	f.worker.agent = childMailLifecycleAgent{hook: func() {
		if err := f.store.SetSubscriptionStatus(context.Background(), 1, "suspended"); err != nil {
			t.Fatal(err)
		}
	}}
	if err := f.worker.Work(context.Background(), &river.Job[controlquota.ConfigureMailArgs]{Args: controlquota.NewConfigureMailArgs()}); err == nil {
		t.Error("stale mail intent was acknowledged after suspension")
	}
	f.visible(t, f.child, false)
	f.visible(t, f.parent, false)
	f.visible(t, f.foreign, true)
	if f.mailData(t) != before {
		t.Fatal("stale convergence changed stored mailbox data")
	}
}

func TestSubdomainMailDisableImmediatelyPreservesData(t *testing.T) {
	f := newChildMailLifecycleFixture(t)
	before := f.mailData(t)
	if _, err := f.store.UpsertMailDomain(context.Background(), 1, 1, types.MailDomainInput{ID: f.domains[f.child], SiteID: f.child, Enabled: false, DKIM: true, DMARCPolicy: "none"}); err != nil {
		t.Fatal(err)
	}
	f.visible(t, f.child, false)
	f.visible(t, f.parent, true)
	f.visible(t, f.foreign, true)
	if f.mailData(t) != before {
		t.Fatal("disabling mail changed persisted mailboxes or aliases")
	}
}
