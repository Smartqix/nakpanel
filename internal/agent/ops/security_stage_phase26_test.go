package ops

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSecurityStageStoreStagesTypedCandidateAndConfirms(t *testing.T) {
	now := time.Date(2026, time.July, 23, 12, 0, 0, 0, time.UTC)
	store := NewSecurityStageStore(SecurityStageStoreOptions{
		Root: t.TempDir(),
		Now:  func() time.Time { return now },
	})
	previous := SecurityPreviousConfig{Exists: true, Data: []byte("previous firewall\n")}
	record, err := store.StageNftables("change-123", previous, NftablesPolicy{
		DefaultInput: NftablesInputDrop, PanelPort: 7443, SSHPorts: []uint16{22},
	}, 2*time.Minute)
	if err != nil {
		t.Fatalf("StageNftables returned error: %v", err)
	}
	if record.TargetPath != NftablesConfigPath || record.Status != SecurityStagePending {
		t.Fatalf("unexpected stage record: %+v", record)
	}
	stageDir := filepath.Join(store.root, "nftables-change-123")
	candidate, err := os.ReadFile(filepath.Join(stageDir, securityStageCandidate))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(candidate), "table inet nakpanel") {
		t.Fatalf("candidate was not produced by the typed renderer:\n%s", candidate)
	}
	staged, err := store.Candidate(SecurityStageNftables, "change-123")
	if err != nil {
		t.Fatalf("Candidate returned error: %v", err)
	}
	if string(staged.Candidate) != string(candidate) || staged.Record.CandidateSHA != record.CandidateSHA {
		t.Fatal("Candidate did not return the exact integrity-checked staged bytes")
	}
	for _, name := range []string{securityStageCandidate, securityStagePrevious, securityStageState} {
		info, err := os.Stat(filepath.Join(stageDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o, want 600", name, info.Mode().Perm())
		}
	}

	now = now.Add(time.Minute)
	confirmed, err := store.Confirm(SecurityStageNftables, "change-123")
	if err != nil {
		t.Fatalf("Confirm returned error: %v", err)
	}
	if confirmed.Status != SecurityStageConfirmedStatus || confirmed.ConfirmedAt == nil {
		t.Fatalf("unexpected confirmed record: %+v", confirmed)
	}
	again, err := store.Confirm(SecurityStageNftables, "change-123")
	if err != nil || again.Status != SecurityStageConfirmedStatus {
		t.Fatalf("idempotent Confirm = %+v, %v", again, err)
	}
	if _, err := store.BeginRollback(SecurityStageNftables, "change-123"); !errors.Is(err, ErrSecurityStageConfirmed) {
		t.Fatalf("BeginRollback after confirmation error = %v, want ErrSecurityStageConfirmed", err)
	}
}

func TestSecurityStageStorePersistsRetryableRollback(t *testing.T) {
	now := time.Date(2026, time.July, 23, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	store := NewSecurityStageStore(SecurityStageStoreOptions{Root: root, Now: func() time.Time { return now }})
	previous := SecurityPreviousConfig{Exists: true, Data: []byte("Port 22\n")}
	if _, err := store.StageSSH("ssh-port", previous, validTestSSHPolicy(), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginRollback(SecurityStageSSH, "ssh-port"); !errors.Is(err, ErrSecurityStageNotExpired) {
		t.Fatalf("early BeginRollback error = %v, want ErrSecurityStageNotExpired", err)
	}
	now = now.Add(time.Minute)
	if _, err := store.Confirm(SecurityStageSSH, "ssh-port"); !errors.Is(err, ErrSecurityStageExpired) {
		t.Fatalf("late Confirm error = %v, want ErrSecurityStageExpired", err)
	}

	due, err := store.RollbacksDue()
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 || due[0].OperationID != "ssh-port" {
		t.Fatalf("RollbacksDue = %+v, want ssh-port", due)
	}
	material, err := store.BeginRollback(SecurityStageSSH, "ssh-port")
	if err != nil {
		t.Fatalf("BeginRollback returned error: %v", err)
	}
	if !material.Previous.Exists || string(material.Previous.Data) != "Port 22\n" ||
		material.Record.Status != SecurityStageRollbackPending {
		t.Fatalf("unexpected rollback material: %+v", material)
	}

	// A fresh store simulates agent restart. rollback_pending remains retryable.
	restarted := NewSecurityStageStore(SecurityStageStoreOptions{Root: root, Now: func() time.Time { return now }})
	retry, err := restarted.BeginRollback(SecurityStageSSH, "ssh-port")
	if err != nil || string(retry.Previous.Data) != "Port 22\n" {
		t.Fatalf("retry BeginRollback = %+v, %v", retry, err)
	}
	completed, err := restarted.CompleteRollback(SecurityStageSSH, "ssh-port")
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != SecurityStageRolledBack || completed.RolledBackAt == nil {
		t.Fatalf("unexpected completed rollback: %+v", completed)
	}
	if _, err := restarted.CompleteRollback(SecurityStageSSH, "ssh-port"); err != nil {
		t.Fatalf("idempotent CompleteRollback returned error: %v", err)
	}
}

func TestSecurityStageStoreForceRollbackBeforeDeadline(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	store := NewSecurityStageStore(SecurityStageStoreOptions{Root: t.TempDir(), Now: func() time.Time { return now }})
	if _, err := store.StageNftables("manual-revert", SecurityPreviousConfig{Exists: true, Data: []byte("old")}, NftablesPolicy{
		DefaultInput: NftablesInputDrop, PanelPort: 7443, SSHPorts: []uint16{22},
	}, 2*time.Minute); err != nil {
		t.Fatalf("StageNftables returned error: %v", err)
	}
	material, err := store.ForceRollback(SecurityStageNftables, "manual-revert")
	if err != nil {
		t.Fatalf("ForceRollback returned error: %v", err)
	}
	if material.Record.Status != SecurityStageRollbackPending || string(material.Previous.Data) != "old" {
		t.Fatalf("force rollback material = %+v", material)
	}
}

func TestSecurityStageStoreRepresentsAbsentPreviousConfig(t *testing.T) {
	now := time.Date(2026, time.July, 23, 12, 0, 0, 0, time.UTC)
	store := NewSecurityStageStore(SecurityStageStoreOptions{Root: t.TempDir(), Now: func() time.Time { return now }})
	if _, err := store.StageNftables("first-policy", SecurityPreviousConfig{}, NftablesPolicy{
		DefaultInput: NftablesInputDrop, PanelPort: 7443, SSHPorts: []uint16{22},
	}, time.Minute); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	material, err := store.BeginRollback(SecurityStageNftables, "first-policy")
	if err != nil {
		t.Fatal(err)
	}
	if material.Previous.Exists || len(material.Previous.Data) != 0 {
		t.Fatalf("absent previous configuration was not preserved: %+v", material.Previous)
	}
}

func TestSecurityStageStoreRejectsPathInjectionAndSymlinks(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, time.July, 23, 12, 0, 0, 0, time.UTC)
	store := NewSecurityStageStore(SecurityStageStoreOptions{Root: root, Now: func() time.Time { return now }})
	if _, err := store.StageSSH("../../escape", SecurityPreviousConfig{}, validTestSSHPolicy(), time.Minute); err == nil {
		t.Fatal("StageSSH accepted a path-injecting operation id")
	}
	if _, err := store.StageSSH("good", SecurityPreviousConfig{}, validTestSSHPolicy(), time.Minute); err != nil {
		t.Fatal(err)
	}
	stageDir := filepath.Join(root, "ssh-good")
	candidatePath := filepath.Join(stageDir, securityStageCandidate)
	if err := os.Remove(candidatePath); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("safe outside data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, candidatePath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(SecurityStageSSH, "good"); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("Load with candidate symlink error = %v, want regular-file rejection", err)
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "safe outside data" {
		t.Fatalf("outside symlink target was changed: %q, %v", data, err)
	}
}

func TestSecurityStageStoreDetectsCandidateAndRollbackTampering(t *testing.T) {
	now := time.Date(2026, time.July, 23, 12, 0, 0, 0, time.UTC)
	store := NewSecurityStageStore(SecurityStageStoreOptions{Root: t.TempDir(), Now: func() time.Time { return now }})
	if _, err := store.StageSSH("tamper", SecurityPreviousConfig{Exists: true, Data: []byte("Port 22\n")}, validTestSSHPolicy(), time.Minute); err != nil {
		t.Fatal(err)
	}
	stageDir := filepath.Join(store.root, "ssh-tamper")
	if err := os.WriteFile(filepath.Join(stageDir, securityStageCandidate), []byte("Port 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(SecurityStageSSH, "tamper"); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("candidate tamper error = %v, want integrity failure", err)
	}
}

func TestSecurityStageStoreRejectsSymlinkRoot(t *testing.T) {
	parent := t.TempDir()
	realRoot := filepath.Join(parent, "real")
	if err := os.Mkdir(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkRoot := filepath.Join(parent, "link")
	if err := os.Symlink(realRoot, symlinkRoot); err != nil {
		t.Fatal(err)
	}
	store := NewSecurityStageStore(SecurityStageStoreOptions{Root: symlinkRoot})
	if _, err := store.StageSSH("unsafe-root", SecurityPreviousConfig{}, validTestSSHPolicy(), time.Minute); err == nil {
		t.Fatal("security stage accepted a symlink root")
	}
}

func validTestSSHPolicy() SSHPolicy {
	return SSHPolicy{
		Ports: []uint16{22, 2222}, RootLogin: SSHRootLoginDisabled,
		MaxAuthTries: 4, LoginGraceSeconds: 30, ClientAliveSeconds: 300,
	}
}
