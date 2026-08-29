package serveradmin

import (
	"context"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/types"
)

type coreReadTestAgent struct {
	testServerAdminAgent
	journalResult types.ReadJournalResult
	journalReq    types.ReadJournalReq
	updateState   types.UpdateState
}

func (a *coreReadTestAgent) ReadJournal(_ context.Context, req types.ReadJournalReq) (types.ReadJournalResult, error) {
	a.journalReq = req
	return a.journalResult, nil
}

func (a *coreReadTestAgent) InspectUpdates(context.Context) (types.UpdateState, error) {
	return a.updateState, nil
}

func (a *coreReadTestAgent) ApplyUpdates(_ context.Context, _ types.ApplyUpdatesReq) (types.UpdateState, error) {
	return a.updateState, nil
}

func TestCoreReadsDelegateOnlyTypedBoundedRequests(t *testing.T) {
	agent := &coreReadTestAgent{
		journalResult: types.ReadJournalResult{Entries: []types.JournalEntry{{SourceID: "panel", Message: "ready"}}},
		updateState: types.UpdateState{Packages: []types.UpdatePackage{
			{Name: "openssl", Candidate: "2"},
			{Name: "held-kernel", Candidate: "3", Held: true},
		}},
	}
	manager := &Manager{agent: agent, now: time.Now}

	journal, err := manager.ReadJournal(context.Background(), types.ReadJournalReq{
		SourceIDs: []string{"panel"}, Limit: 100,
	})
	if err != nil || len(journal.Entries) != 1 || agent.journalReq.SourceIDs[0] != "panel" {
		t.Fatalf("ReadJournal result=%#v request=%#v err=%v", journal, agent.journalReq, err)
	}

	updates, err := manager.InspectUpdates(context.Background())
	if err != nil || len(updates.Packages) != 2 {
		t.Fatalf("InspectUpdates result=%#v err=%v", updates, err)
	}
}
