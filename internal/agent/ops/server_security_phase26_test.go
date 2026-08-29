package ops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

type securityCommandRunner struct {
	calls       [][]string
	failApplyAt int
	applyCalls  int
}

func (r *securityCommandRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := append([]string{name}, args...)
	r.calls = append(r.calls, call)
	if name == "nft" && len(args) == 2 && args[0] == "-f" {
		r.applyCalls++
		if r.failApplyAt == r.applyCalls {
			return []byte("candidate rejected"), errors.New("exit 1")
		}
	}
	if name == "sshd" {
		return []byte("port 22\npermitrootlogin no\npasswordauthentication no\npubkeyauthentication yes\nallowtcpforwarding no\n"), nil
	}
	return []byte("ok"), nil
}

type fakeServerSecurityApplier struct {
	current      SecurityPreviousConfig
	applied      []byte
	applyErr     error
	restoreErr   error
	restoreCalls int
}

func (f *fakeServerSecurityApplier) CurrentNftables(context.Context) (SecurityPreviousConfig, error) {
	return f.current, nil
}

func (f *fakeServerSecurityApplier) ValidateAndApplyNftables(_ context.Context, candidate []byte) error {
	f.applied = append([]byte(nil), candidate...)
	return f.applyErr
}

func (f *fakeServerSecurityApplier) RestoreNftables(_ context.Context, previous SecurityPreviousConfig) error {
	f.restoreCalls++
	f.current = previous
	return f.restoreErr
}

func (f *fakeServerSecurityApplier) InspectServerSecurity(context.Context) (types.ServerSecurityPolicy, error) {
	return types.ServerSecurityPolicy{Firewall: types.FirewallPolicy{Enabled: true}}, nil
}

func TestServerSecurityControllerStagesAndConfirmsManagedFirewall(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	applier := &fakeServerSecurityApplier{current: SecurityPreviousConfig{Exists: true, Data: []byte("old")}}
	controller := NewServerSecurityController(ServerSecurityControllerOptions{
		Stages:  NewSecurityStageStore(SecurityStageStoreOptions{Root: t.TempDir(), Now: func() time.Time { return now }}),
		Applier: applier,
	})
	request := validFirewallStageRequest("op_firewall_123")
	result, err := controller.StageServerSecurity(context.Background(), request)
	if err != nil {
		t.Fatalf("StageServerSecurity returned error: %v", err)
	}
	if result.Scope != ServerSecurityFirewallScope || result.State != string(SecurityStagePending) {
		t.Fatalf("staged result = %+v", result)
	}
	if result.RollbackDeadline.Sub(now) != securityConfirmationWindow {
		t.Fatalf("confirmation window = %v", result.RollbackDeadline.Sub(now))
	}
	rendered := string(applier.applied)
	for _, want := range []string{"table inet nakpanel", "policy drop;", "tcp dport 7443", "tcp dport 22"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered firewall missing %q:\n%s", want, rendered)
		}
	}
	confirmed, err := controller.ConfirmServerSecurity(context.Background(), request.OperationID)
	if err != nil {
		t.Fatalf("ConfirmServerSecurity returned error: %v", err)
	}
	if confirmed.State != string(SecurityStageConfirmedStatus) {
		t.Fatalf("confirmed state = %q", confirmed.State)
	}
	now = now.Add(3 * time.Minute)
	if err := controller.RecoverDue(context.Background()); err != nil {
		t.Fatalf("RecoverDue after confirmation returned error: %v", err)
	}
	if applier.restoreCalls != 0 {
		t.Fatalf("confirmed policy was restored %d times", applier.restoreCalls)
	}
}

func TestServerSecurityControllerRecoversExpiredStageAfterRestart(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	applier := &fakeServerSecurityApplier{current: SecurityPreviousConfig{Exists: true, Data: []byte("old")}}
	stages := NewSecurityStageStore(SecurityStageStoreOptions{Root: root, Now: func() time.Time { return now }})
	controller := NewServerSecurityController(ServerSecurityControllerOptions{Stages: stages, Applier: applier})
	if _, err := controller.StageServerSecurity(context.Background(), validFirewallStageRequest("op_recovery_123")); err != nil {
		t.Fatalf("stage firewall: %v", err)
	}

	now = now.Add(securityConfirmationWindow + time.Second)
	restarted := NewServerSecurityController(ServerSecurityControllerOptions{
		Stages:  NewSecurityStageStore(SecurityStageStoreOptions{Root: root, Now: func() time.Time { return now }}),
		Applier: applier,
	})
	if err := restarted.RecoverDue(context.Background()); err != nil {
		t.Fatalf("RecoverDue returned error: %v", err)
	}
	if applier.restoreCalls != 1 || string(applier.current.Data) != "old" {
		t.Fatalf("rollback = calls:%d current:%q", applier.restoreCalls, applier.current.Data)
	}
	record, err := stages.Load(SecurityStageNftables, "op_recovery_123")
	if err != nil || record.Status != SecurityStageRolledBack {
		t.Fatalf("recovered record = %+v, %v", record, err)
	}
}

func TestServerSecurityControllerApplyFailureRollsBack(t *testing.T) {
	applier := &fakeServerSecurityApplier{
		current:  SecurityPreviousConfig{Exists: true, Data: []byte("old")},
		applyErr: errors.New("validation failed"),
	}
	controller := NewServerSecurityController(ServerSecurityControllerOptions{
		Stages:  NewSecurityStageStore(SecurityStageStoreOptions{Root: t.TempDir()}),
		Applier: applier,
	})
	_, err := controller.StageServerSecurity(context.Background(), validFirewallStageRequest("op_failure_123"))
	if err == nil || !strings.Contains(err.Error(), "validation failed") {
		t.Fatalf("StageServerSecurity error = %v", err)
	}
	if applier.restoreCalls != 1 {
		t.Fatalf("restore calls = %d", applier.restoreCalls)
	}
}

func TestServerSecurityControllerRejectsUnsupportedScopesAndRawPolicyShapes(t *testing.T) {
	controller := NewServerSecurityController(ServerSecurityControllerOptions{
		Stages:  NewSecurityStageStore(SecurityStageStoreOptions{Root: t.TempDir()}),
		Applier: &fakeServerSecurityApplier{},
	})
	request := validFirewallStageRequest("op_invalid_123")
	request.Scope = "ssh"
	if _, err := controller.StageServerSecurity(context.Background(), request); err == nil {
		t.Fatal("SSH mutation was accepted")
	}
	request = validFirewallStageRequest("op_invalid_124")
	request.Policy.Firewall.Rules[0].Direction = "output"
	if _, err := controller.StageServerSecurity(context.Background(), request); err == nil {
		t.Fatal("outbound raw policy shape was accepted")
	}
}

func TestNftablesSecurityApplierValidatesBeforeFixedTableActivation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nakpanel.nft")
	runner := &securityCommandRunner{}
	applier := &nftablesSecurityApplier{path: path, runner: runner}
	candidate := []byte("table inet nakpanel {}\n")
	if err := applier.ValidateAndApplyNftables(context.Background(), candidate); err != nil {
		t.Fatalf("ValidateAndApplyNftables returned error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != string(candidate) {
		t.Fatalf("installed candidate = %q, %v", data, err)
	}
	if len(runner.calls) < 3 ||
		len(runner.calls[0]) != 4 || runner.calls[0][0] != "nft" ||
		runner.calls[0][1] != "-c" || runner.calls[0][2] != "-f" ||
		strings.Join(runner.calls[1], " ") != "nft -f "+path ||
		strings.Join(runner.calls[2], " ") != "nft list table inet nakpanel" {
		t.Fatalf("nft command order = %#v", runner.calls)
	}
}

func TestNftablesSecurityApplierRestoresFileWhenActivationFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nakpanel.nft")
	if err := os.WriteFile(path, []byte("old policy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &securityCommandRunner{failApplyAt: 1}
	applier := &nftablesSecurityApplier{path: path, runner: runner}
	err := applier.ValidateAndApplyNftables(context.Background(), []byte("new policy\n"))
	if err == nil || !strings.Contains(err.Error(), "activate nftables candidate") {
		t.Fatalf("activation error = %v", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil || string(data) != "old policy\n" {
		t.Fatalf("restored policy = %q, %v", data, readErr)
	}
	if runner.applyCalls != 2 {
		t.Fatalf("nft apply calls = %d, want candidate and previous", runner.applyCalls)
	}
}

func TestNftablesSecurityApplierRejectsSymlinkTarget(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "nakpanel.nft")
	if err := os.Symlink(outside, target); err != nil {
		t.Fatal(err)
	}
	applier := &nftablesSecurityApplier{path: target, runner: &securityCommandRunner{}}
	if err := applier.ValidateAndApplyNftables(context.Background(), []byte("new")); err == nil {
		t.Fatal("symlink target was accepted")
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "do not replace" {
		t.Fatalf("outside file changed: %q, %v", data, err)
	}
}

func validFirewallStageRequest(operationID string) types.StageServerSecurityReq {
	return types.StageServerSecurityReq{
		Scope:       ServerSecurityFirewallScope,
		OperationID: operationID,
		Policy: types.ServerSecurityPolicy{
			Revision: 1,
			Firewall: types.FirewallPolicy{
				Enabled: true, DefaultInbound: "drop",
				Rules: []types.FirewallRule{{
					ID: "web", Enabled: true, Direction: "inbound",
					Action: "accept", Protocol: "tcp", Ports: []int{80, 443},
				}},
			},
			SSH: types.SSHSecurityPolicy{Port: 22},
		},
	}
}
