package web

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/control/workspace"
	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
)

// The post-convergence fixture keeps explicit mail intent enabled while its
// effective availability follows the customer. Read it through the real
// workspace store so ignoring that persisted state cannot produce readiness.
func TestSubdomainMailDNSReadinessUsesEffectiveAvailability(t *testing.T) {
	db := removaldb.New(t, "")
	parent := removaldb.Site(t, db, 1, "availability.test", nil)
	childID := removaldb.Site(t, db, 1, "shop.availability.test", parent)
	if _, err := db.Exec(`INSERT INTO mail_domains(subscription_id,site_id,domain,enabled,effective_enabled,convergence_status) VALUES(1,$1,'shop.availability.test',true,true,'in_sync')`, childID); err != nil {
		t.Fatal(err)
	}
	for _, state := range []struct {
		name, customer, website string
		available               bool
	}{
		{"customer suspended after convergence", "suspended", "suspended", false},
		{"customer reactivated after convergence", "active", "active", true},
		{"website-only suspension preserves mail", "active", "suspended", true},
	} {
		t.Run(state.name, func(t *testing.T) {
			if _, err := db.Exec(`UPDATE customers SET status=$1 WHERE id=(SELECT customer_id FROM subscriptions WHERE id=1)`, state.customer); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`UPDATE mail_domains SET effective_enabled=$1,convergence_status='in_sync',last_error='' WHERE site_id=$2`, state.available, childID); err != nil {
				t.Fatal(err)
			}
			services, err := workspace.NewStore(db).ListSubscriptionServicesFor(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, 1)
			if err != nil {
				t.Fatal(err)
			}
			domain, found := mailDomainForSite(services.MailDomains, dashboard.Site{ID: childID, SubscriptionID: 1})
			if !found || !domain.Enabled {
				t.Fatal("configured child mail intent was lost")
			}
			data, _ := domainDesignFixture()
			sub := data.Subscriptions[0]
			sub.ID = 1
			sub.MaxMailboxes = 5
			child := dashboard.Site{ID: childID, ParentSiteID: parent, SubscriptionID: 1, Domain: "shop.availability.test", DNSZoneMode: "parent", Status: state.website}
			data.SubscriptionServices = services
			data.Phase6.DNSZones = []dashboard.DNSZone{{SiteID: parent, Mode: "primary", Status: "active", DesiredRevision: 2, AppliedRevision: 2}}
			var out bytes.Buffer
			if err := mailDomainWorkspace(child, sub, domain, data, WorkspaceView{DetailID: childID, Tab: "mail"}).Render(context.Background(), &out); err != nil {
				t.Fatal(err)
			}
			body := out.String()
			if !state.available && mailDomainState(domain) == "active" {
				t.Fatal("unavailable mail service presented as active")
			}
			if state.available {
				if !strings.Contains(body, "DNS applied locally") || strings.Contains(body, "Mail unavailable") {
					t.Fatal("available mail not presented as ready")
				}
			} else if strings.Contains(body, "DNS applied locally") || !strings.Contains(body, "Mail unavailable") {
				t.Fatal("suspended customer mail presented as ready")
			}
		})
	}
}
