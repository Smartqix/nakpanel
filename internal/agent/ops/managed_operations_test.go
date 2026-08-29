package ops

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

type managedOpsCall struct {
	name string
	args []string
}

type managedOpsRunner struct {
	calls  []managedOpsCall
	output map[string][]byte
	err    map[string]error
}

func (r *managedOpsRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, managedOpsCall{name: name, args: append([]string(nil), args...)})
	key := strings.Join(append([]string{name}, args...), " ")
	return r.output[key], r.err[key]
}

type managedOpsServices struct {
	active string
}

func (s managedOpsServices) InspectManagedServices(_ context.Context, req types.InspectManagedServicesReq) ([]types.ManagedService, error) {
	if len(req.ServiceIDs) != 1 {
		return nil, errors.New("one service id required")
	}
	return []types.ManagedService{{ID: req.ServiceIDs[0], Available: true, ActiveState: s.active}}, nil
}

func TestManagedOperationsControlsOnlyRegisteredServicesWithoutShell(t *testing.T) {
	runner := &managedOpsRunner{output: map[string][]byte{}, err: map[string]error{}}
	manager := NewManagedOperations(ManagedOperationsOptions{
		Runner: runner, Services: managedOpsServices{active: "active"},
	})
	result, err := manager.ControlManagedService(context.Background(), types.ControlManagedServiceReq{
		ServiceID: "web", Action: "restart", OperationID: "op-restart-web",
	})
	if err != nil {
		t.Fatalf("ControlManagedService returned error: %v", err)
	}
	if result.Validation != "passed" || len(runner.calls) != 2 {
		t.Fatalf("result/calls = %#v / %#v", result, runner.calls)
	}
	if runner.calls[0].name != "nginx" || strings.Join(runner.calls[0].args, " ") != "-t" {
		t.Fatalf("validator call = %#v", runner.calls[0])
	}
	if runner.calls[1].name != "systemctl" || strings.Join(runner.calls[1].args, " ") != "restart nginx" {
		t.Fatalf("service call = %#v", runner.calls[1])
	}
}

func TestManagedOperationsRejectsServiceAndPackageInjection(t *testing.T) {
	manager := NewManagedOperations(ManagedOperationsOptions{Runner: &managedOpsRunner{}})
	if _, err := manager.ControlManagedService(context.Background(), types.ControlManagedServiceReq{
		ServiceID: "nginx;reboot", Action: "restart", OperationID: "op-1",
	}); err == nil {
		t.Fatal("service injection was accepted")
	}
	if _, err := manager.ApplyUpdates(context.Background(), types.ApplyUpdatesReq{
		PackageNames: []string{"nginx;touch-/tmp/pwned"}, DryRun: true, OperationID: "op-2",
	}); err == nil {
		t.Fatal("package injection was accepted")
	}
}

func TestManagedOperationsJournalIsAllowlistedAndBounded(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	runner := &managedOpsRunner{output: map[string][]byte{}, err: map[string]error{}}
	manager := NewManagedOperations(ManagedOperationsOptions{Runner: runner, Now: func() time.Time { return now }})
	if _, err := manager.ReadJournal(context.Background(), types.ReadJournalReq{SourceIDs: []string{"../../etc/shadow"}}); err == nil {
		t.Fatal("arbitrary journal source was accepted")
	}
	if _, err := manager.ReadJournal(context.Background(), types.ReadJournalReq{Limit: 1001}); err == nil {
		t.Fatal("oversized journal page was accepted")
	}
}

func TestJournalMessageRedactsCredentials(t *testing.T) {
	input := `Authorization: Bearer abc.def.ghi password=hunter2 dsn=postgres://user:secret@example.test/db token='opaque-token' jwt=abcdefghijklmnop.qrstuvwx.yz012345 {"password":"json-secret","Authorization":"Bearer json-bearer","cookie":"session-value"}`
	redacted := redactJournalMessage(input)
	for _, secret := range []string{"abc.def.ghi", "hunter2", "user:secret@", "opaque-token", "abcdefghijklmnop.qrstuvwx.yz012345", "json-secret", "json-bearer", "session-value"} {
		if strings.Contains(redacted, secret) {
			t.Fatalf("redacted message contains %q: %s", secret, redacted)
		}
	}
	for _, public := range []string{"Authorization", "password", "postgres://user:", "token"} {
		if !strings.Contains(redacted, public) {
			t.Fatalf("redacted message lost context %q: %s", public, redacted)
		}
	}
}

func TestJournalCommandFailureRedactsOutput(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	args := []string{
		"--output=json", "--no-pager",
		"--since=" + now.Add(-time.Hour).Format(time.RFC3339),
		"--until=" + now.Format(time.RFC3339),
		"--lines=10", "--unit=stalwart-mail.service",
	}
	key := strings.Join(append([]string{"journalctl"}, args...), " ")
	runner := &managedOpsRunner{
		output: map[string][]byte{key: []byte(`password=hunter2 Authorization: Bearer secret-token`)},
		err:    map[string]error{key: errors.New("journal failed")},
	}
	manager := NewManagedOperations(ManagedOperationsOptions{Runner: runner, Now: func() time.Time { return now }})
	_, err := manager.ReadJournal(context.Background(), types.ReadJournalReq{
		SourceIDs: []string{"mail"}, Since: now.Add(-time.Hour), Until: now, Limit: 10,
	})
	if err == nil {
		t.Fatal("journal command failure returned nil")
	}
	for _, secret := range []string{"hunter2", "secret-token"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("journal command error contains %q: %v", secret, err)
		}
	}
	if !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("journal command error lost redaction marker: %v", err)
	}
}

func TestParseAPTUpgradeSimulation(t *testing.T) {
	items := parseAPTUpgradeSimulation([]byte(
		"Inst openssl [3.0.1] (3.0.2 Ubuntu:24.04/noble-security [arm64])\n" +
			"Inst nginx [1.24.0] (1.24.1 Ubuntu:24.04/noble-updates [arm64])\n",
	))
	if len(items) != 2 || !items[0].Security || items[1].Security {
		t.Fatalf("items = %#v", items)
	}
	if items[0].Current != "3.0.1" || items[0].Candidate != "3.0.2" ||
		items[0].Origin != "Ubuntu:24.04/noble-security" {
		t.Fatalf("openssl versions = %#v", items[0])
	}
}

func TestApplyUpdatesRequiresCurrentInventorySelection(t *testing.T) {
	const inventory = "Inst openssl [3.0.1] (3.0.2 Ubuntu:24.04/noble-security [arm64])\n"
	runner := &managedOpsRunner{
		output: map[string][]byte{"apt-get -s -o APT::Get::Show-Upgraded=true upgrade": []byte(inventory)},
		err:    map[string]error{},
	}
	manager := NewManagedOperations(ManagedOperationsOptions{Runner: runner})

	if _, err := manager.ApplyUpdates(context.Background(), types.ApplyUpdatesReq{
		PackageNames: []string{"curl"}, DryRun: true, OperationID: "op-current-inventory",
	}); err == nil || !strings.Contains(err.Error(), "current managed update inventory") {
		t.Fatalf("unavailable package error = %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("unavailable package invoked update: %#v", runner.calls)
	}

	result, err := manager.ApplyUpdates(context.Background(), types.ApplyUpdatesReq{
		PackageNames: []string{"openssl"}, SecurityOnly: true, DryRun: true, OperationID: "op-current-inventory-ok",
	})
	if err != nil {
		t.Fatalf("available package: %v", err)
	}
	if !result.LastInstallAt.IsZero() {
		t.Fatalf("dry-run reported a real installation timestamp: %v", result.LastInstallAt)
	}
	if len(runner.calls) != 3 ||
		strings.Join(append([]string{runner.calls[2].name}, runner.calls[2].args...), " ") !=
			"apt-get -s --no-remove install --only-upgrade openssl" {
		t.Fatalf("managed update calls = %#v", runner.calls)
	}
}

func TestApplyUpdatesRejectsCandidateChangedAfterConfirmation(t *testing.T) {
	const inventory = "Inst openssl [3.0.1] (3.0.3 Ubuntu:24.04/noble-security [arm64])\n"
	runner := &managedOpsRunner{
		output: map[string][]byte{"apt-get -s -o APT::Get::Show-Upgraded=true upgrade": []byte(inventory)},
		err:    map[string]error{},
	}
	manager := NewManagedOperations(ManagedOperationsOptions{Runner: runner})
	_, err := manager.ApplyUpdates(context.Background(), types.ApplyUpdatesReq{
		PackageNames: []string{"openssl"},
		Packages: []types.UpdatePackage{{
			Name: "openssl", Candidate: "3.0.2", Origin: "Ubuntu:24.04/noble-security",
		}},
		OperationID: "op-candidate-bound",
	})
	if err == nil || !strings.Contains(err.Error(), "candidate changed") {
		t.Fatalf("candidate drift error = %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("candidate drift invoked install: %#v", runner.calls)
	}
}
