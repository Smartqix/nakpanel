package rpc

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

type mailStatusProvisioner struct {
	status   types.MailServerStatus
	queueReq types.MailQueueQueryReq
}

func (p *mailStatusProvisioner) ConfigureMail(context.Context, types.ConfigureMailReq) (types.ConfigureMailResult, error) {
	return types.ConfigureMailResult{}, nil
}

func (p *mailStatusProvisioner) CollectMailQueue(context.Context) (types.CollectMailQueueResult, error) {
	return types.CollectMailQueueResult{}, nil
}

func (p *mailStatusProvisioner) MailStatus(context.Context) (types.MailServerStatus, error) {
	return p.status, nil
}

func (p *mailStatusProvisioner) QueryMailQueue(_ context.Context, req types.MailQueueQueryReq) (types.MailQueueQueryResult, error) {
	p.queueReq = req
	return types.MailQueueQueryResult{Messages: []types.MailQueueMessage{{ID: "42"}}}, nil
}

func (p *mailStatusProvisioner) InspectQueuedMail(_ context.Context, req types.InspectQueuedMailReq) (types.MailQueueMessage, error) {
	return types.MailQueueMessage{ID: req.MessageID}, nil
}

func TestDispatchGetMailStatus(t *testing.T) {
	mail := &mailStatusProvisioner{status: types.MailServerStatus{State: "active", Listeners: []int{25, 993}, TotalQueued: 4}}
	dispatcher := NewDispatcher(&fakeReloader{}, Options{Mail: mail})
	response := dispatcher.Dispatch(context.Background(), types.Request{Op: types.OpGetMailStatus, ID: "mail-status", Data: json.RawMessage(`{}`)})
	if !response.OK {
		t.Fatalf("mail status dispatch failed: %s", response.Error)
	}
	var status types.MailServerStatus
	if err := json.Unmarshal(response.Data, &status); err != nil {
		t.Fatal(err)
	}
	if status.State != "active" || status.TotalQueued != 4 || len(status.Listeners) != 2 {
		t.Fatalf("mail status response = %+v", status)
	}
}

func TestDispatchMailQueueReadOperations(t *testing.T) {
	mail := &mailStatusProvisioner{}
	dispatcher := NewDispatcher(&fakeReloader{}, Options{Mail: mail})
	response := dispatcher.Dispatch(context.Background(), types.Request{
		Op: types.OpQueryMailQueue, ID: "mail-queue",
		Data: json.RawMessage(`{"state":"deferred","sender_domain":"example.test","limit":25}`),
	})
	if !response.OK || mail.queueReq.State != "deferred" || mail.queueReq.Limit != 25 {
		t.Fatalf("mail queue response=%+v request=%+v", response, mail.queueReq)
	}
	var queue types.MailQueueQueryResult
	if err := json.Unmarshal(response.Data, &queue); err != nil {
		t.Fatal(err)
	}
	if len(queue.Messages) != 1 || queue.Messages[0].ID != "42" {
		t.Fatalf("mail queue = %+v", queue)
	}

	response = dispatcher.Dispatch(context.Background(), types.Request{
		Op: types.OpInspectQueuedMail, ID: "mail-detail",
		Data: json.RawMessage(`{"message_id":"42"}`),
	})
	if !response.OK || !strings.Contains(string(response.Data), `"id":"42"`) {
		t.Fatalf("mail detail response = %+v", response)
	}

	response = dispatcher.Dispatch(context.Background(), types.Request{
		Op: types.OpQueryMailQueue, ID: "mail-queue-invalid",
		Data: json.RawMessage(`{"limit":25,"expression":"*"}`),
	})
	if response.OK {
		t.Fatal("strict queue dispatch accepted an arbitrary expression")
	}
}
