package provision

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

type recordingReconcileAgent struct {
	req types.ReconcileSystemReq
}

func (a *recordingReconcileAgent) ReconcileSystem(_ context.Context, req types.ReconcileSystemReq) (types.Response, error) {
	a.req = req
	data, _ := json.Marshal(types.ReconcileSystemResult{SitesTotal: len(req.Sites), SitesOK: len(req.Sites)})
	return types.Response{OK: true, Data: data}, nil
}

type refreshingPhase6StatusStore struct {
	refreshed     ReconcileSystemArgs
	activeID      int64
	databaseNames []string
}

type recordingSiteApplicationReconciler struct {
	siteIDs []int64
}

func (r *recordingSiteApplicationReconciler) ReconcileSiteApplication(_ context.Context, siteID int64) error {
	r.siteIDs = append(r.siteIDs, siteID)
	return nil
}

func (s *refreshingPhase6StatusStore) RefreshReconcileIntent(_ context.Context, args ReconcileSystemArgs) (ReconcileSystemArgs, error) {
	args.Sites = s.refreshed.Sites
	args.Databases = s.refreshed.Databases
	return args, nil
}

func (s *refreshingPhase6StatusStore) MarkBackupActive(_ context.Context, _ int64, _ types.CreateBackupResult, databaseNames []string) error {
	s.databaseNames = databaseNames
	return nil
}
func (*refreshingPhase6StatusStore) MarkBackupFailed(context.Context, int64, string) error {
	return nil
}
func (*refreshingPhase6StatusStore) MarkRestoreActive(context.Context, int64, types.RestoreBackupResult) error {
	return nil
}
func (*refreshingPhase6StatusStore) MarkRestoreFailed(context.Context, int64, string) error {
	return nil
}
func (*refreshingPhase6StatusStore) MarkWebmailActive(context.Context, int64, types.ConfigureWebmailResult) error {
	return nil
}
func (*refreshingPhase6StatusStore) MarkWebmailFailed(context.Context, int64, string) error {
	return nil
}
func (*refreshingPhase6StatusStore) MarkDNSActive(context.Context, int64, types.ConfigureDNSZoneResult) error {
	return nil
}
func (*refreshingPhase6StatusStore) MarkDNSFailed(context.Context, int64, string) error {
	return nil
}
func (s *refreshingPhase6StatusStore) MarkReconcileActive(_ context.Context, id int64, _ types.ReconcileSystemResult) error {
	s.activeID = id
	return nil
}
func (*refreshingPhase6StatusStore) MarkReconcileFailed(context.Context, int64, string) error {
	return nil
}

func TestReconcileWorkerRefreshesCurrentIntentBeforeAgentDispatch(t *testing.T) {
	agent := &recordingReconcileAgent{}
	store := &refreshingPhase6StatusStore{refreshed: ReconcileSystemArgs{Sites: []types.ReconcileSiteReq{{SiteID: 7, Domain: "current.test", State: "active"}}}}
	worker := NewReconcileSystemWorker(agent, store)
	applications := &recordingSiteApplicationReconciler{}
	worker.SetApplicationReconciler(applications)
	job := &river.Job[ReconcileSystemArgs]{Args: ReconcileSystemArgs{
		RunID: 42,
		Sites: []types.ReconcileSiteReq{{SiteID: 7, Domain: "stale.test", State: "suspended"}},
	}}

	if err := worker.Work(context.Background(), job); err != nil {
		t.Fatalf("Work returned error: %v", err)
	}
	if len(agent.req.Sites) != 1 || agent.req.Sites[0].Domain != "current.test" || agent.req.Sites[0].State != "active" {
		t.Fatalf("agent request = %#v, want refreshed active intent", agent.req.Sites)
	}
	if store.activeID != 42 {
		t.Fatalf("active reconciliation run = %d, want 42", store.activeID)
	}
	if len(applications.siteIDs) != 1 || applications.siteIDs[0] != 7 {
		t.Fatalf("reconciled PHP application sites = %v, want [7]", applications.siteIDs)
	}
}

type successfulBackupAgent struct{}

func (successfulBackupAgent) CreateBackup(context.Context, types.CreateBackupReq) (types.Response, error) {
	data, _ := json.Marshal(types.CreateBackupResult{
		ArchivePath: "/var/lib/nakpanel/backups/site.tar.zst",
		SizeBytes:   4096,
		SHA256:      strings.Repeat("a", 64),
	})
	return types.Response{OK: true, Data: data}, nil
}

func TestCreateBackupWorkerPersistsDatabaseCoverage(t *testing.T) {
	store := &refreshingPhase6StatusStore{}
	worker := NewCreateBackupWorker(successfulBackupAgent{}, store)
	databaseNames := []string{"wp_s7_deadbeef"}
	job := &river.Job[CreateBackupArgs]{Args: CreateBackupArgs{
		BackupID: 41, SiteID: 7, SubscriptionID: 3, Databases: databaseNames,
	}}
	if err := worker.Work(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	databaseNames[0] = "mutated_after_work"
	if !slices.Equal([]string{"wp_s7_deadbeef"}, store.databaseNames) {
		t.Fatalf("database coverage mismatch: %v", store.databaseNames)
	}
}
