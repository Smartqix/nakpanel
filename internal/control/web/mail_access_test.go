package web

import (
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
	"testing"
)

func TestMailWebmailURLRequiresOwnedActiveHTTPSHostname(t *testing.T) {
	site := dashboard.Site{ID: 1, SubscriptionID: 2, Domain: "example.test", Status: "active"}
	sub := types.SubscriptionSummary{ID: 2, Status: "active", MaxMailboxes: 5, ServicePresets: types.PlanServicePresets{}}
	sub.ServicePresets.Mail.WebmailEnabled = true
	domain := dashboard.MailDomain{ID: 3, SiteID: 1, SubscriptionID: 2, Enabled: true, Status: "in_sync"}
	data := dashboard.Data{SubscriptionServices: dashboard.SubscriptionServicesData{WebmailHosts: []dashboard.WebmailHost{{SiteID: 1, SubscriptionID: 2, Hostname: "webmail.example.test", Status: "active"}}}}
	if got := mailWebmailURL(site, sub, domain, data); got != "https://webmail.example.test/" {
		t.Fatalf("url=%q", got)
	}
	for _, host := range []string{"https://evil.test", "evil.test/path", "user@evil.test", "evil.test:443", "127.0.0.1", ""} {
		data.SubscriptionServices.WebmailHosts[0].Hostname = host
		if mailWebmailURL(site, sub, domain, data) != "" {
			t.Fatalf("accepted hostname %q", host)
		}
	}
	data.SubscriptionServices.WebmailHosts[0].Hostname = "webmail.example.test"
	data.SubscriptionServices.WebmailHosts[0].SubscriptionID = 99
	if mailWebmailURL(site, sub, domain, data) != "" {
		t.Fatal("cross-subscription host allowed")
	}
	data.SubscriptionServices.WebmailHosts[0].SubscriptionID = 2
	domain.Enabled = false
	if mailWebmailURL(site, sub, domain, data) != "" {
		t.Fatal("disabled service allowed")
	}
}
