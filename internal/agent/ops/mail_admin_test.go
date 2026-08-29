package ops

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

func TestMailQueueReadsBoundedMetadataAndDetail(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "admin" || password != "mail-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/queue/messages":
			if r.URL.Query().Get("values") != "1" || r.URL.Query().Get("limit") != "200" {
				t.Errorf("unsafe or unbounded queue query: %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"data":{"items":[
				{"id":217700302698266624,"return_path":"sender@example.test","created":"2026-07-20T10:00:00Z","size":1451,"domains":[{"name":"remote.test","status":"scheduled","retry_num":0,"next_retry":"2026-07-23T10:00:00Z","expires":"2026-07-27T10:00:00Z","recipients":[{"address":"one@remote.test","status":"scheduled"}]}]},
				{"id":217700302698266625,"return_path":"alerts@other.test","created":"2026-07-20T11:00:00Z","size":921,"domains":[{"name":"remote.test","status":{"temp_fail":"connection refused"},"retry_num":2,"next_retry":"2026-07-23T11:00:00Z","expires":"2026-07-27T11:00:00Z","recipients":[{"address":"two@remote.test","status":{"temp_fail":"connection refused"}}]}]}
			],"total":2,"status":true}}`))
		case "/api/queue/messages/217700302698266624":
			_, _ = w.Write([]byte(`{"data":{"id":217700302698266624,"return_path":"sender@example.test","created":"2026-07-20T10:00:00Z","size":1451,"domains":[{"name":"remote.test","status":"scheduled","retry_num":0,"recipients":[{"address":"one@remote.test","status":"scheduled"}]}]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	secretPath := filepath.Join(t.TempDir(), "admin-secret")
	if err := os.WriteFile(secretPath, []byte("mail-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	provisioner := NewMailProvisioner(MailProvisionerOptions{
		AdminSecretPath: secretPath, ManagementURL: server.URL,
	})

	queue, err := provisioner.QueryMailQueue(context.Background(), types.MailQueueQueryReq{
		State: types.MailQueueStateDeferred, RecipientDomain: "remote.test", Limit: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(queue.Messages) != 1 || queue.Messages[0].ID != "217700302698266625" ||
		queue.Messages[0].State != types.MailQueueStateDeferred || queue.Messages[0].SizeBytes != 921 {
		t.Fatalf("filtered queue = %+v", queue)
	}

	message, err := provisioner.InspectQueuedMail(context.Background(), types.InspectQueuedMailReq{
		MessageID: "217700302698266624",
	})
	if err != nil {
		t.Fatal(err)
	}
	if message.ID != "217700302698266624" || message.ReturnPath != "sender@example.test" ||
		len(message.Domains) != 1 || len(message.Domains[0].Recipients) != 1 {
		t.Fatalf("queued message = %+v", message)
	}
}

func TestMailQueueReadRejectsExpressionsAndInvalidIDs(t *testing.T) {
	t.Parallel()
	provisioner := NewMailProvisioner(MailProvisionerOptions{})
	for _, req := range []types.MailQueueQueryReq{
		{Limit: 201},
		{Limit: 10, State: "held"},
		{Limit: 10, SenderDomain: "example.test?text=*"},
		{Limit: 10, RecipientDomain: "../example.test"},
	} {
		if _, err := provisioner.QueryMailQueue(context.Background(), req); err == nil {
			t.Fatalf("unsafe queue query was accepted: %+v", req)
		}
	}
	for _, id := range []string{"0", "../1", "1?filter=*", "q_abc", strings.Repeat("9", 21)} {
		if _, err := provisioner.InspectQueuedMail(context.Background(), types.InspectQueuedMailReq{MessageID: id}); err == nil {
			t.Fatalf("unsafe queue id %q was accepted", id)
		}
	}
}
