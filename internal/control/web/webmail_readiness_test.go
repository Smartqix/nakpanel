package web

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestWebmailReadinessExplainsBlockedAccessAndOffersSetup(t *testing.T) {
	for _, tc := range []struct {
		name, status, error, want string
		allowed, configured       bool
	}{
		{name: "plan disabled", want: "Disabled by policy"},
		{name: "not configured", allowed: true, want: "Not configured"},
		{name: "queued", allowed: true, configured: true, status: "pending", want: "Setting up"},
		{name: "failed", allowed: true, configured: true, status: "failed", error: "HTTPS certificate is unavailable", want: "Setup failed"},
		{name: "ready", allowed: true, configured: true, status: "active", want: "Ready"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			site := dashboard.Site{ID: 1, SubscriptionID: 2, Domain: "example.test", Status: "active"}
			sub := types.SubscriptionSummary{ID: 2, Status: "active", MaxMailboxes: 5}
			sub.ServicePresets.Mail.WebmailEnabled = tc.allowed
			domain := dashboard.MailDomain{ID: 3, SiteID: 1, SubscriptionID: 2, Enabled: true, EffectiveEnabled: true, Status: "in_sync"}
			data := dashboard.Data{}
			if tc.configured {
				data.SubscriptionServices.WebmailHosts = []dashboard.WebmailHost{{SiteID: 1, SubscriptionID: 2, Hostname: "webmail.example.test", Status: tc.status, LastError: tc.error}}
			}
			var out bytes.Buffer
			if err := mailDomainWorkspace(site, sub, domain, data, WorkspaceView{}).Render(context.Background(), &out); err != nil {
				t.Fatal(err)
			}
			body := out.String()
			if !strings.Contains(body, "<dd>"+tc.want+"</dd>") {
				t.Fatalf("missing readiness %q", tc.want)
			}
			if tc.allowed && !tc.configured && !strings.Contains(body, ">Enable webmail</a>") {
				t.Fatal("unconfigured webmail has no setup action")
			}
			if tc.error != "" && !strings.Contains(body, tc.error) {
				t.Fatal("setup failure has no explanation")
			}
			if tc.status != "active" && strings.Contains(body, `href="https://webmail.example.test/"`) {
				t.Fatal("unready webmail offered as working access")
			}
		})
	}
}
