package web

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestNewCacheFormUsesSubscriptionCeilings(t *testing.T) {
	data := detailFixture()
	data.SubscriptionServices.Accounts[0].EffectivePolicy = types.HostingPolicy{
		Permissions: types.HostingPermissionPolicy{Valkey: true},
		Resources:   types.HostingResourcePolicy{ValkeyMemoryMB: 24, CPUPercent: 5, MaxTasks: 12},
		Valkey:      types.HostingValkeyPolicy{Enabled: true, MemoryMB: 32, MaxClients: 16, IdleTimeoutSeconds: 120, CPUPercent: 10, ProcessLimit: 16},
	}
	body := renderIntegratedSubscription(t, data, auth.RoleAdmin, "cache", 0)
	for _, field := range []string{
		`name="memory_mb" value="24"`, `name="max_clients" value="16"`,
		`name="idle_timeout_seconds" value="120"`, `name="cpu_percent" value="5"`, `name="process_limit" value="12"`,
	} {
		if !strings.Contains(body, field) {
			t.Errorf("new cache exceeds its entitlement: missing %s", field)
		}
	}
	if !strings.Contains(body, `type="hidden" name="rotate_credential" value="true"`) {
		t.Error("first cache setup must generate its required one-time credential")
	}
	if strings.Contains(body, "Rotate application credential") {
		t.Error("new cache must not ask to rotate a nonexistent credential")
	}
}

func TestExistingCacheDoesNotRotateCredentialsByDefault(t *testing.T) {
	var body bytes.Buffer
	instance := types.ValkeyInstance{DesiredState: "enabled", MemoryMB: 32, MaxClients: 16, IdleTimeoutSeconds: 120, CPUPercent: 10, ProcessLimit: 16}
	if err := valkeyConfigurationForms(types.SubscriptionSummary{ID: 42}, WorkspaceView{}, 0, instance, true).Render(context.Background(), &body); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body.String(), `type="hidden" name="rotate_credential"`) || strings.Contains(body.String(), `value="true" checked`) {
		t.Fatal("saving an existing cache must preserve its credential")
	}
	if !strings.Contains(body.String(), "Rotate application credential") {
		t.Fatal("explicit rotation must remain available")
	}
}

func TestCacheWithoutEnoughAllocationDoesNotOfferCreation(t *testing.T) {
	data := detailFixture()
	data.SubscriptionServices.Accounts[0].EffectivePolicy = types.HostingPolicy{
		Permissions: types.HostingPermissionPolicy{Valkey: true},
		Resources:   types.HostingResourcePolicy{ValkeyMemoryMB: 8},
		Valkey:      types.HostingValkeyPolicy{Enabled: true, MemoryMB: 64, MaxClients: 64, CPUPercent: 25, ProcessLimit: 64},
	}
	body := renderIntegratedSubscription(t, data, auth.RoleAdmin, "cache", 0)
	if strings.Contains(body, `action="/subscriptions/42/valkey"`) {
		t.Fatal("a cache below the 16 MB minimum must not offer an unusable creation form")
	}
}

func TestReducedCacheAllocationPreservesExistingInventory(t *testing.T) {
	data := detailFixture()
	data.SubscriptionServices.Valkey = []types.ValkeyInstance{{SubscriptionID: 42, DesiredState: "enabled", AppliedState: "running", ConvergenceStatus: "failed", SocketPath: "/run/nakpanel/valkey/sub-42/valkey.sock", LastError: "Reduced allocation needs attention", MemoryMB: 64, CredentialSet: true}}
	body := renderIntegratedSubscription(t, data, auth.RoleClient, "cache", 0)
	if !strings.Contains(body, "/run/nakpanel/valkey/sub-42/valkey.sock") || !strings.Contains(body, "Reduced allocation needs attention") {
		t.Fatal("creation gate hid retained cache state and failure")
	}
	if strings.Contains(body, `action="/subscriptions/42/valkey"`) {
		t.Fatal("revoked policy still offered cache configuration")
	}
}

func TestCacheAccountProcessAllocationBelowMinimumBlocksCreation(t *testing.T) {
	data := detailFixture()
	data.SubscriptionServices.Accounts[0].EffectivePolicy = types.HostingPolicy{
		Permissions: types.HostingPermissionPolicy{Valkey: true},
		Resources:   types.HostingResourcePolicy{ValkeyMemoryMB: 64, CPUPercent: 100, MaxTasks: 4},
		Valkey:      types.HostingValkeyPolicy{Enabled: true, MemoryMB: 64, MaxClients: 64, CPUPercent: 25, ProcessLimit: 64},
	}
	if strings.Contains(renderIntegratedSubscription(t, data, auth.RoleAdmin, "cache", 0), `action="/subscriptions/42/valkey"`) {
		t.Fatal("cache cannot fit the account process allowance")
	}
}

func TestCacheUnlimitedAllocationUsesFiniteDefaults(t *testing.T) {
	policy := types.HostingPolicy{
		Permissions: types.HostingPermissionPolicy{Valkey: true},
		Resources:   types.HostingResourcePolicy{ValkeyMemoryMB: -1, CPUPercent: -1, MaxTasks: -1},
		Valkey:      types.HostingValkeyPolicy{Enabled: true, MemoryMB: -1, MaxClients: -1, IdleTimeoutSeconds: -1, CPUPercent: -1, ProcessLimit: -1},
	}
	got := defaultValkeyInstance(policy)
	if got.MemoryMB != 64 || got.MaxClients != 64 || got.CPUPercent != 25 || got.ProcessLimit != 64 || got.IdleTimeoutSeconds != 300 {
		t.Fatalf("unlimited allocation offered an unbounded runtime: %+v", got)
	}
	policy.Valkey.IdleTimeoutSeconds = 0
	if defaultValkeyInstance(policy).IdleTimeoutSeconds != 0 {
		t.Fatal("zero idle timeout must remain valid")
	}
	policy.Resources.CPUPercent = 0
	if !subscriptionValkeyUnavailable([]types.SubscriptionSystemAccount{{SubscriptionID: 42, EffectivePolicy: policy}}, 42) {
		t.Fatal("zero account CPU allocation must block creation")
	}
}
