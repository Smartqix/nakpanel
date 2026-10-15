package web

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestMailImportRenderAndBrowserFixtures(t *testing.T) {
	for _, state := range []string{"preview", "copying", "attention_required", "complete"} {
		t.Run(state, func(t *testing.T) {
			item := types.MailImport{ID: "imp_fixture", MailboxID: 1, State: state, Discovered: 2, Copied: 1, Verified: 1}
			if state == "attention_required" {
				item.LastError = "The append acknowledgement was lost. Reconcile the receipt before retrying."
			}
			if state == "complete" {
				item.Copied = 2
				item.Verified = 2
			}
			imports := types.MailImportWorkspace{SiteID: 7, Domain: "owned.test", Mailboxes: []types.MailImportMailbox{{ID: 1, Address: "test@owned.test", Active: true}}, Imports: []types.MailImport{item}, Selected: &item, Folders: []types.MailImportFolder{{ID: 1, Source: "INBOX", Target: "INBOX", Messages: 2, Bytes: 1234, Approved: true}}}
			data := dashboard.Data{Sites: []dashboard.Site{{ID: 7, Domain: "owned.test", SubscriptionID: 20, Status: "active"}}, Subscriptions: []types.SubscriptionSummary{{ID: 20, PlanName: "Business", SubscriptionName: "Hosting", Status: "active"}}}
			var output bytes.Buffer
			err := RoutedDashboardPage("Mail imports", auth.SessionUser{ID: 1, Role: auth.RoleAdmin}, data, DashboardActions{}, WorkspaceView{Route: "site-detail", Tab: "mail-imports", DetailID: 7, CSRFToken: "test-token", MailImports: &imports}).Render(context.Background(), &output)
			if err != nil {
				t.Fatal(err)
			}
			for _, label := range []string{"Import mail", "Source IMAP hostname", "Destination mailbox password", "/assets/mail-import.js", "data-mail-import-count"} {
				if !strings.Contains(output.String(), label) {
					t.Fatalf("missing %s", label)
				}
			}
			if strings.Contains(output.String(), `value="source-secret"`) {
				t.Fatal("password rendered")
			}
			if strings.Contains(output.String(), "Before switching mail delivery") != (state == "complete") {
				t.Fatal("mail cutover guidance must follow completed verification")
			}
			if dir := os.Getenv("NAKPANEL_MAIL_UI_FIXTURES"); dir != "" {
				if err = os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, state+".html"), output.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
