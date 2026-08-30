package phpapp

import "testing"

func TestLifecycleStateComesFromAuthoritativeApplicationRecord(t *testing.T) {
	record := applicationRecord{
		subscriptionStatus: "active",
		customerStatus:     "suspended",
		siteStatus:         "active",
		providerActive:     false,
	}
	got := lifecycleState(record)
	if got.SubscriptionStatus != "active" || got.CustomerStatus != "suspended" || got.SiteStatus != "active" || got.ProviderActive {
		t.Fatalf("lifecycleState = %#v", got)
	}
}
