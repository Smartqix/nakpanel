package web

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/dashboard"
)

func TestSubdomainMailDNSReadinessFeedback(t *testing.T) {
	for _, test := range []struct {
		name, status, zoneStatus, note, want string
		desired, applied                     int64
		external                             bool
	}{
		{name: "applied locally", status: "in_sync", zoneStatus: "active", desired: 2, applied: 2, want: "DNS applied locally"},
		{name: "pending DNS", status: "in_sync", zoneStatus: "active", desired: 3, applied: 2, want: "DNS pending"},
		{name: "DNS failure", status: "in_sync", zoneStatus: "failed", desired: 3, applied: 2, want: "DNS update failed"},
		{name: "external", status: "in_sync", external: true, want: "External DNS action required"},
		{name: "custom routing", status: "in_sync", zoneStatus: "active", desired: 2, applied: 2, note: "Custom DNS: preserve mx.external.test; confirm routing", want: "DNS action required"},
		{name: "agent failed", status: "failed", zoneStatus: "active", desired: 2, applied: 2, note: "agent refused configuration", want: "Mail setup failed"},
		{name: "agent pending", status: "pending", zoneStatus: "active", desired: 2, applied: 2, want: "Mail setup pending"},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, _ := domainDesignFixture()
			child := data.Sites[1]
			child.DNSZoneMode = "parent"
			sub := data.Subscriptions[0]
			sub.MaxMailboxes = 5
			domain := dashboard.MailDomain{ID: 42, SiteID: child.ID, SubscriptionID: sub.ID, Domain: child.Domain, Enabled: true, DKIM: true, DMARCPolicy: "none", Status: test.status, LastError: test.note}
			if !test.external {
				data.Phase6.DNSZones = []dashboard.DNSZone{{ID: 31, SiteID: child.ParentSiteID, Domain: "example.test", Mode: "primary", Address: "192.0.2.1", Status: test.zoneStatus, DesiredRevision: test.desired, AppliedRevision: test.applied, LastError: "named could not apply zone"}}
				if test.zoneStatus != "failed" {
					data.Phase6.DNSZones[0].LastError = ""
				}
			}
			var out bytes.Buffer
			if err := mailDomainWorkspace(child, sub, domain, data, WorkspaceView{DetailID: child.ID, Tab: "mail"}).Render(context.Background(), &out); err != nil {
				t.Fatal(err)
			}
			body := out.String()
			if !strings.Contains(body, test.want) {
				t.Errorf("missing readiness feedback %q", test.want)
			}
			if test.want != "DNS applied locally" && strings.Contains(body, "DNS applied locally") {
				t.Fatal("unready DNS presented as applied")
			}
			if test.zoneStatus == "failed" && !strings.Contains(body, "named could not apply zone") {
				t.Fatal("DNS failure detail hidden")
			}
			if test.external {
				for _, want := range []string{"mail.blog.example.test", "v=spf1 mx ~all", "nak1._domainkey.blog.example.test", "_dmarc.blog.example.test"} {
					if !strings.Contains(body, want) {
						t.Errorf("missing external DNS guidance %q", want)
					}
				}
			}
		})
	}
}
