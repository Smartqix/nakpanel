package web

import (
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
	"testing"
)

func TestMailboxFormHidesUnlimitedSentinel(t *testing.T) {
	for _, value := range []int{-1, 0} {
		if got := formatMailboxQuotaInput(value); got != "" {
			t.Errorf("unlimited quota %d rendered as %q", value, got)
		}
	}
	if got := formatMailboxQuotaInput(256); got != "256" {
		t.Errorf("finite quota changed to %q", got)
	}
}
func TestMailboxCreationDefaultsToEffectiveSubscriptionLimit(t *testing.T) {
	sub := types.SubscriptionSummary{ID: 3}
	data := dashboard.Data{}
	data.SubscriptionServices.Accounts = []types.SubscriptionSystemAccount{{SubscriptionID: 3, EffectivePolicy: types.HostingPolicy{Mail: types.HostingMailPolicy{MailboxQuotaMB: 256}}}}
	if got := mailboxDefaultQuota(sub, data); got != 256 {
		t.Fatalf("quota %d does not match effective limit", got)
	}
	data.SubscriptionServices.Accounts[0].EffectivePolicy.Mail.MailboxQuotaMB = -1
	if got := mailboxDefaultQuota(sub, data); got != -1 {
		t.Fatalf("unlimited quota changed to %d", got)
	}
}
