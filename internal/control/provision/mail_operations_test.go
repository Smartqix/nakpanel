package provision

import (
	"context"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/platformadmin"
	"github.com/nakroteck/nakpanel/internal/types"
)

type mailOperationsAgent struct {
	queueReq   types.MailQueueQueryReq
	inspectReq types.InspectQueuedMailReq
	journalReq types.ReadJournalReq
}

func (a *mailOperationsAgent) MailStatus(context.Context) (types.MailServerStatus, error) {
	return types.MailServerStatus{}, nil
}

func (a *mailOperationsAgent) ReloadService(context.Context, string) (types.Response, error) {
	return types.Response{OK: true}, nil
}

func (a *mailOperationsAgent) QueryMailQueue(_ context.Context, req types.MailQueueQueryReq) (types.MailQueueQueryResult, error) {
	a.queueReq = req
	return types.MailQueueQueryResult{Messages: []types.MailQueueMessage{{ID: "41"}}}, nil
}

func (a *mailOperationsAgent) InspectQueuedMail(_ context.Context, req types.InspectQueuedMailReq) (types.MailQueueMessage, error) {
	a.inspectReq = req
	return types.MailQueueMessage{ID: req.MessageID}, nil
}

func (a *mailOperationsAgent) ReadJournal(_ context.Context, req types.ReadJournalReq) (types.ReadJournalResult, error) {
	a.journalReq = req
	return types.ReadJournalResult{Entries: []types.JournalEntry{{SourceID: "mail"}}}, nil
}

func TestMailOperationsAreAdminOnlyAndForceTypedSources(t *testing.T) {
	agent := &mailOperationsAgent{}
	manager := NewManager(nil, WithMailAgent(agent))
	admin := auth.SessionUser{ID: 1, Role: auth.RoleAdmin}

	queue, err := manager.SearchMailQueue(context.Background(), admin, platformadmin.MailQueueFilter{
		State: platformadmin.MailQueueStateDeferred, SenderDomain: "example.test", Limit: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(queue.Messages) != 1 || agent.queueReq.State != types.MailQueueStateDeferred ||
		agent.queueReq.SenderDomain != "example.test" || agent.queueReq.Limit != 25 {
		t.Fatalf("queue request/result = %+v / %+v", agent.queueReq, queue)
	}

	if _, err := manager.InspectQueuedMail(context.Background(), admin, "42"); err != nil {
		t.Fatal(err)
	}
	if agent.inspectReq.MessageID != "42" {
		t.Fatalf("inspect request = %+v", agent.inspectReq)
	}

	logs, err := manager.ReadMailLogs(context.Background(), admin, time.Now().Add(-time.Hour), "cursor", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs.Entries) != 1 || len(agent.journalReq.SourceIDs) != 1 ||
		agent.journalReq.SourceIDs[0] != "mail" || agent.journalReq.Limit != 50 {
		t.Fatalf("journal request/result = %+v / %+v", agent.journalReq, logs)
	}

	client := auth.SessionUser{ID: 2, Role: auth.RoleClient}
	if _, err := manager.SearchMailQueue(context.Background(), client, platformadmin.MailQueueFilter{Limit: 10}); err != ErrForbidden {
		t.Fatalf("client queue error = %v, want forbidden", err)
	}
	if _, err := manager.InspectQueuedMail(context.Background(), client, "42"); err != ErrForbidden {
		t.Fatalf("client inspect error = %v, want forbidden", err)
	}
	if _, err := manager.ReadMailLogs(context.Background(), client, time.Now().Add(-time.Hour), "", 10); err != ErrForbidden {
		t.Fatalf("client logs error = %v, want forbidden", err)
	}
}

func TestMailOperationsHideUnsupportedQueueStates(t *testing.T) {
	manager := NewManager(nil, WithMailAgent(&mailOperationsAgent{}))
	_, err := manager.SearchMailQueue(context.Background(), auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, platformadmin.MailQueueFilter{
		State: platformadmin.MailQueueStateHeld, Limit: 10,
	})
	if err == nil {
		t.Fatal("held queue state should remain hidden for Stalwart v0.11")
	}
}
