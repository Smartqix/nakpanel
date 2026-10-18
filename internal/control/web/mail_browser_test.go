package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestMailWorkspaceBrowserPreview(t *testing.T) {
	if os.Getenv("NAKPANEL_MAIL_UI_PREVIEW") != "1" {
		t.Skip("opt-in loopback mail preview")
	}
	data, actions := domainDesignFixture()
	data.Sites[0].Status = "active"
	data.Subscriptions[0].Status = "active"
	data.Subscriptions[0].MaxMailboxes = 5
	policy := types.HostingPolicy{}
	policy.Permissions.Mail = true
	policy.Mail.Enabled = true
	policy.Mail.Webmail = true
	policy.Resources.MaxMailboxes = 5
	data.SubscriptionServices.Accounts = []types.SubscriptionSystemAccount{{SubscriptionID: 20, EffectivePolicy: policy}}
	data.SubscriptionServices.MailDomains = []dashboard.MailDomain{{ID: 41, SubscriptionID: 20, SiteID: 1, Domain: "example.test", Enabled: true, DKIM: true, DMARCPolicy: "none", Status: "in_sync"}}
	data.SubscriptionServices.Mailboxes = []dashboard.Mailbox{{ID: 51, SubscriptionID: 20, MailDomainID: 41, Address: "admin@example.test", QuotaMB: 1024, Enabled: true}, {ID: 52, SubscriptionID: 20, MailDomainID: 41, Address: "notifications@example.test", QuotaMB: 1024, Enabled: true}}
	data.SubscriptionServices.MailAliases = []dashboard.MailAlias{{ID: 61, SubscriptionID: 20, MailDomainID: 41, Address: "sales@example.test", Destinations: "admin@example.test"}}
	data.SubscriptionServices.WebmailHosts = []dashboard.WebmailHost{{ID: 71, SubscriptionID: 20, SiteID: 1, Hostname: "webmail.example.test", Status: "active"}}
	stop := make(chan struct{})
	var once sync.Once
	mux := http.NewServeMux()
	mux.Handle("/assets/", http.StripPrefix("/assets", StaticHandler()))
	mux.HandleFunc("POST /__stop", func(w http.ResponseWriter, r *http.Request) { once.Do(func() { close(stop) }); w.WriteHeader(204) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		view := WorkspaceView{Route: "site-detail", Tab: "mail", DetailID: 1, CSRFToken: "fixture", MailView: r.URL.Query().Get("mail_view")}
		if r.URL.Query().Get("support") == "1" {
			view.SupportCustomerID = 88
			view.SupportCustomerName = "Example Customer"
		}
		if view.MailView == "connection" {
			view.MailClientAddress = "admin@example.test"
			if r.URL.Query().Get("mailbox_id") == "52" {
				view.MailClientAddress = "notifications@example.test"
			}
			view.MailClient = types.MailClientProfile{Hostname: "mail.example.test", IMAPTLS: true, SMTPTLS: true, SMTPSTARTTLS: true, CheckedAt: time.Now()}
			if r.Header.Get("X-Nakpanel-Mail") == "connection" {
				if err := MailClientContent(view).Render(r.Context(), w); err != nil {
					t.Error(err)
				}
				return
			}
		}
		if err := RoutedDashboardPage("Mail", auth.SessionUser{Role: auth.RoleAdmin, Email: "admin@example.test"}, data, actions, view).Render(r.Context(), w); err != nil {
			t.Error(err)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	fmt.Println("MAIL_PREVIEW_URL=" + server.URL)
	select {
	case <-stop:
	case <-time.After(30 * time.Minute):
		t.Fatal("mail preview timeout")
	}
}
