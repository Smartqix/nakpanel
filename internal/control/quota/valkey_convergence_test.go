package quota

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/nakroteck/nakpanel/internal/types"
)

func runnableValkeyPolicy() types.HostingPolicy {
	return types.HostingPolicy{Permissions: types.HostingPermissionPolicy{Valkey: true}, Resources: types.HostingResourcePolicy{ValkeyMemoryMB: 128, CPUPercent: 100, MaxTasks: 128}, Valkey: types.HostingValkeyPolicy{Enabled: true, MemoryMB: 128, MaxClients: 64, CPUPercent: 25, ProcessLimit: 64, IdleTimeoutSeconds: 300}}
}

type valkeyConvergenceAgentTest struct{ requests []types.EnsureValkeyReq }

func (a *valkeyConvergenceAgentTest) EnsureValkey(_ context.Context, req types.EnsureValkeyReq) (types.EnsureValkeyResult, error) {
	a.requests = append(a.requests, req)
	if req.State == "enabled" {
		return types.EnsureValkeyResult{}, errors.New("injected bounded allocation failure")
	}
	return types.EnsureValkeyResult{SocketPath: "/run/cache.sock"}, nil
}

func TestFailedValkeyAllocationStopsPreviousOverCeilingRuntime(t *testing.T) {
	agent := &valkeyConvergenceAgentTest{}
	req := types.EnsureValkeyReq{State: "enabled", ACLHash: strings.Repeat("a", 64), Flush: true}
	result, err := applyValkeyConvergence(context.Background(), agent, req)
	if err == nil || result.Running || len(agent.requests) != 2 {
		t.Fatalf("failed bounded update did not stop old allocation: %#v, %v, %#v", result, err, agent.requests)
	}
	if agent.requests[1].State != "disabled" || agent.requests[1].Flush || agent.requests[1].ACLHash != req.ACLHash {
		t.Fatalf("unsafe fallback stop: %#v", agent.requests[1])
	}
}

func TestValkeyConvergenceBoundsStoredAllocation(t *testing.T) {
	policy := runnableValkeyPolicy()
	request := types.EnsureValkeyReq{SubscriptionID: 42, Username: "npaccount", State: "enabled", MemoryMB: 512, MaxClients: 200, CPUPercent: 100, ProcessLimit: 200, IdleTimeout: 0, ACLHash: strings.Repeat("a", 64), Flush: true}
	got, err := boundedValkeyRequest("active", request, policy, 96)
	if err != nil {
		t.Fatal(err)
	}
	if got.MemoryMB != 96 || got.MaxClients != 64 || got.CPUPercent != 25 || got.ProcessLimit != 64 || got.IdleTimeout != 300 || got.State != "enabled" {
		t.Fatalf("old allocation remains above ceiling: %#v", got)
	}
	if got.ACLHash != request.ACLHash || !got.Flush {
		t.Fatal("allocation enforcement changed credential or flush intent")
	}
	policy.Resources.ValkeyMemoryMB = -1
	policy.Valkey.MemoryMB = -1
	got, err = boundedValkeyRequest("active", request, policy, -1)
	if err != nil || got.MemoryMB != 512 {
		t.Fatalf("unlimited memory became capped: %#v, %v", got, err)
	}
}

func TestValkeyConvergenceStopsBelowRuntimeMinimum(t *testing.T) {
	request := types.EnsureValkeyReq{State: "enabled", MemoryMB: 128, MaxClients: 64, CPUPercent: 25, ProcessLimit: 64}
	policy := runnableValkeyPolicy()
	policy.Valkey.MemoryMB = 8
	got, err := boundedValkeyRequest("active", request, policy, -1)
	if err == nil || got.State != "disabled" || got.MemoryMB < 16 {
		t.Fatalf("unrunnable ceiling did not produce safe stop and noncompliance: %#v, %v", got, err)
	}
	policy = runnableValkeyPolicy()
	policy.Permissions.Valkey = false
	request.Flush = true
	got, err = boundedValkeyRequest("active", request, policy, -1)
	if err != nil || got.State != "disabled" || got.Flush {
		t.Fatalf("revocation did not stop without flushing: %#v, %v", got, err)
	}
}

func TestValkeyConvergenceRespectsAccountResourceAndProviderCeilings(t *testing.T) {
	request := types.EnsureValkeyReq{State: "enabled", MemoryMB: 128, MaxClients: 64, CPUPercent: 25, ProcessLimit: 64, IdleTimeout: 120}
	policy := runnableValkeyPolicy()
	policy.Resources.CPUPercent, policy.Resources.MaxTasks = 10, 16
	got, err := boundedValkeyRequest("active", request, policy, 32)
	if err != nil || got.MemoryMB != 32 || got.CPUPercent != 10 || got.ProcessLimit != 16 || got.IdleTimeout != 120 {
		t.Fatalf("account/provider ceiling was ignored: %#v, %v", got, err)
	}
	for _, headroom := range []int{0, 8} {
		got, err = boundedValkeyRequest("active", request, policy, headroom)
		if err == nil || got.State != "disabled" {
			t.Fatalf("insufficient provider capacity still runs: %#v, %v", got, err)
		}
	}
	request.Flush = true
	got, err = boundedValkeyRequest("suspended", request, policy, 32)
	if err != nil || got.State != "suspended" || got.Flush {
		t.Fatalf("account suspension did not safely defer flush: %#v, %v", got, err)
	}
}

func TestValkeyStoppedAcknowledgementPreservesPendingFlushAndAllocation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	request := types.EnsureValkeyReq{SubscriptionID: 42, State: "disabled", MemoryMB: 128, MaxClients: 64, CPUPercent: 25, ProcessLimit: 64, IdleTimeout: 300}
	mock.ExpectExec(`(?s)UPDATE valkey_instances.*flush_requested=CASE WHEN \$5 THEN false ELSE flush_requested END.*memory_mb=CASE WHEN \$3='running' THEN \$6 ELSE memory_mb END.*desired_revision=\$2`).WithArgs(int64(42), int64(7), "stopped", "/run/cache.sock", false, 128, 64, 300, 25, 64, "failed", "allocation cannot fit").WillReturnResult(sqlmock.NewResult(0, 1))
	updated, err := acknowledgeValkeyConvergence(context.Background(), db, request, 7, types.EnsureValkeyResult{SocketPath: "/run/cache.sock"}, errors.New("allocation cannot fit"))
	if err != nil || !updated {
		t.Fatalf("stopped failure not honestly acknowledged: %v, %v", updated, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestValkeyAcknowledgementRejectsUnconfirmedRuntimeWithoutWrites(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, result := range []types.EnsureValkeyResult{{}, {Running: true}} {
		updated, err := acknowledgeValkeyConvergence(context.Background(), db, types.EnsureValkeyReq{SubscriptionID: 42, State: "enabled", Flush: true}, 7, result, nil)
		if err == nil || updated {
			t.Fatalf("unconfirmed state/flush acknowledged: %v, %v", updated, err)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestValkeyAcknowledgementPersistsBoundedAllocationWithRevisionFence(t *testing.T) {
	for _, affected := range []int64{0, 1} {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		request := types.EnsureValkeyReq{SubscriptionID: 42, State: "enabled", MemoryMB: 64, MaxClients: 32, CPUPercent: 10, ProcessLimit: 16, IdleTimeout: 120}
		mock.ExpectExec(`(?s)UPDATE valkey_instances.*memory_mb=.*desired_revision=\$2`).WithArgs(int64(42), int64(7), "running", "/run/valkey.sock", false, 64, 32, 120, 10, 16, "in_sync", "").WillReturnResult(sqlmock.NewResult(0, affected))
		applied, err := acknowledgeValkeyConvergence(context.Background(), db, request, 7, types.EnsureValkeyResult{Running: true, SocketPath: "/run/valkey.sock"}, nil)
		if err != nil || applied != (affected == 1) {
			t.Fatalf("applied=%v err=%v", applied, err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
		db.Close()
	}
}

func TestValkeyStateStopsForDisabledResourceCeilings(t *testing.T) {
	for _, name := range []string{"resource memory", "cache memory", "clients", "cpu", "processes"} {
		t.Run(name, func(t *testing.T) {
			policy := runnableValkeyPolicy()
			switch name {
			case "resource memory":
				policy.Resources.ValkeyMemoryMB = 0
			case "cache memory":
				policy.Valkey.MemoryMB = 0
			case "clients":
				policy.Valkey.MaxClients = 0
			case "cpu":
				policy.Valkey.CPUPercent = 0
			case "processes":
				policy.Valkey.ProcessLimit = 0
			}
			if state := effectiveValkeyState("active", "enabled", policy); state != "disabled" {
				t.Fatalf("zero %s ceiling still runs Valkey: %s", name, state)
			}
		})
	}
}
