package rpc

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

type mailStatusProvisioner struct {
	status types.MailServerStatus
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
