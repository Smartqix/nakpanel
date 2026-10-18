package web

import (
	"bytes"
	"context"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestScopedSubscriptionServicesPreserveMainAndShell(t *testing.T) {
	scoped := detailFixture()
	scoped.SubscriptionServices.Tasks = []dashboard.ScheduledTask{{ID: 1, SubscriptionID: 42, Name: "owned", Status: "in_sync"}}
	scoped.SubscriptionServices.MailDomains = []dashboard.MailDomain{{ID: 1, SubscriptionID: 42, Domain: "owned.test"}}
	scoped.SubscriptionServices.Applications = []dashboard.Application{{ID: 1, SubscriptionID: 42, Name: "owned", Status: "in_sync"}}
	for _, tab := range subscriptionTabs {
		for _, support := range []int64{0, 88} {
			whole := scoped
			whole.SubscriptionServices.Accounts = append(append([]types.SubscriptionSystemAccount{}, scoped.SubscriptionServices.Accounts...), types.SubscriptionSystemAccount{ID: 999, SubscriptionID: 999, Username: "other", LastError: "unrelated failure"})
			whole.SubscriptionServices.Tasks = append(append([]dashboard.ScheduledTask{}, scoped.SubscriptionServices.Tasks...), dashboard.ScheduledTask{ID: 999, SubscriptionID: 999, Name: "unrelated"})
			whole.SubscriptionServices.MailDomains = append(append([]dashboard.MailDomain{}, scoped.SubscriptionServices.MailDomains...), dashboard.MailDomain{ID: 999, SubscriptionID: 999, Domain: "other.test"})
			whole.SubscriptionServices.Applications = append(append([]dashboard.Application{}, scoped.SubscriptionServices.Applications...), dashboard.Application{ID: 999, SubscriptionID: 999, Name: "unrelated"})
			view := WorkspaceView{Route: "subscription-detail", DetailID: 42, Tab: tab, SupportCustomerID: support}
			render := func(data dashboard.Data) string {
				var b bytes.Buffer
				if err := RoutedFragment("Panel", auth.SessionUser{Role: auth.RoleAdmin}, data, DashboardActions{}, view).Render(context.Background(), &b); err != nil {
					t.Fatal(err)
				}
				return b.String()
			}
			if render(scoped) != render(whole) {
				t.Fatalf("tab %s support %d changed after scoping", tab, support)
			}
		}
	}
}
