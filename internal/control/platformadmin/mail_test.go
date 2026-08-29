package platformadmin

import (
	"strings"
	"testing"
)

func TestNormalizeMailQueueFilter(t *testing.T) {
	filter, err := NormalizeMailQueueFilter(MailQueueFilter{
		State:           MailQueueStateDeferred,
		SenderDomain:    " Sender.Example ",
		RecipientDomain: "RECIPIENT.EXAMPLE",
		OlderThanMins:   60,
	})
	if err != nil {
		t.Fatalf("normalize filter: %v", err)
	}
	if filter.SenderDomain != "sender.example" || filter.RecipientDomain != "recipient.example" {
		t.Fatalf("domains were not canonicalized: %#v", filter)
	}
	if filter.Limit != 50 {
		t.Fatalf("default limit = %d, want 50", filter.Limit)
	}
}

func TestMailQueueFilterRejectsUnboundedOrExpressionInputs(t *testing.T) {
	tests := []MailQueueFilter{
		{State: "queued OR true", Limit: 50},
		{SenderDomain: "example.test\nHeader: value", Limit: 50},
		{RecipientDomain: "*.example.test", Limit: 50},
		{Limit: 201},
		{Limit: 50, OlderThanMins: 60*24*90 + 1},
		{Limit: 50, Cursor: "opaque cursor"},
	}
	for _, test := range tests {
		if err := test.Validate(); err == nil {
			t.Fatalf("expected filter rejection for %#v", test)
		}
	}
}

func TestMailQueueActions(t *testing.T) {
	for _, action := range []MailQueueAction{
		MailQueueActionRetry, MailQueueActionHold, MailQueueActionRelease,
	} {
		if err := (MailQueueActionRequest{Action: action, MessageIDs: []string{"q_abc-123"}}).Validate(); err != nil {
			t.Fatalf("%s should be valid: %v", action, err)
		}
	}
	if err := (MailQueueActionRequest{
		Action: MailQueueActionDelete, MessageIDs: []string{"q_abc-123"}, Confirmed: true,
	}).Validate(); err != nil {
		t.Fatalf("confirmed delete should be valid: %v", err)
	}
}

func TestMailQueueActionRejectsInjectionDuplicatesAndUnconfirmedDelete(t *testing.T) {
	tests := []MailQueueActionRequest{
		{Action: "retry; rm", MessageIDs: []string{"q1"}},
		{Action: MailQueueActionRetry, MessageIDs: nil},
		{Action: MailQueueActionRetry, MessageIDs: []string{"q1\nq2"}},
		{Action: MailQueueActionRetry, MessageIDs: []string{"q1", "q1"}},
		{Action: MailQueueActionDelete, MessageIDs: []string{"q1"}},
		{Action: MailQueueActionRetry, MessageIDs: make([]string, 101)},
	}
	for _, test := range tests {
		if err := test.Validate(); err == nil {
			t.Fatalf("expected action rejection for %#v", test)
		}
	}

	oversized := MailQueueActionRequest{
		Action: MailQueueActionRetry, MessageIDs: []string{strings.Repeat("a", 129)},
	}
	if err := oversized.Validate(); err == nil {
		t.Fatal("expected oversized message ID to be rejected")
	}
}
