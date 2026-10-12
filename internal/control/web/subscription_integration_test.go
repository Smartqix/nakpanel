package web

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

func renderIntegratedSubscription(t *testing.T, data dashboard.Data, role auth.Role, tab string, support int64) string {
	t.Helper()
	var body bytes.Buffer
	if err := routedSubscriptionDetail(auth.SessionUser{Role: role}, data, DashboardActions{CanCreateSite: true}, WorkspaceView{Route: "subscription-detail", DetailID: 42, Tab: tab, SupportCustomerID: support, CSRFToken: "integration-token"}).Render(context.Background(), &body); err != nil {
		t.Fatal(err)
	}
	return body.String()
}

func TestSubscriptionRetainsInventoryWhenPermissionsAreRevoked(t *testing.T) {
	data := detailFixture()
	data.SubscriptionServices.SFTP = []dashboard.SFTPIdentity{{ID: 71, SubscriptionID: 42, Name: "Retained SFTP"}}
	data.SubscriptionServices.FTP = []types.FTPAccount{{ID: 72, SubscriptionID: 42, Name: "retained-ftp"}}
	data.SubscriptionServices.Tasks = []dashboard.ScheduledTask{{ID: 73, SubscriptionID: 42, SiteID: 7, Name: "Retained task"}}
	data.SubscriptionServices.Applications = []dashboard.Application{{ID: 74, SubscriptionID: 42, SiteID: 7, Name: "Retained container"}}
	for _, test := range []struct{ tab, name, deletePath, createPath string }{
		{"access", "Retained SFTP", "/services/sftp/71/delete", "/42/sftp"},
		{"access", "retained-ftp", "/services/ftp/72/delete", "/42/ftp"},
		{"tasks", "Retained task", "/services/task/73/delete", "/42/scheduled-tasks"},
		{"applications", "Retained container", "/services/application/74/delete", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			html := renderIntegratedSubscription(t, data, auth.RoleAdmin, test.tab, 0)
			if !strings.Contains(html, test.name) || !strings.Contains(html, test.deletePath) {
				t.Fatal("revoked capability hid retained inventory or deletion")
			}
			if test.createPath != "" && strings.Contains(html, `action="/subscriptions`+test.createPath+`"`) {
				t.Fatal("revoked capability still permits creation")
			}
			if test.tab == "tasks" && strings.Contains(html, "/scheduled-tasks/73/run") {
				t.Fatal("revoked task capability still offers Run now")
			}
		})
	}
}

func TestSubscriptionUsageCountsAllOwnedAccessAndMailResources(t *testing.T) {
	data := detailFixture()
	data.SubscriptionServices.FTP = []types.FTPAccount{{SubscriptionID: 42}, {SubscriptionID: 42, SiteID: 7}, {SubscriptionID: 99}}
	data.SubscriptionServices.Mailboxes = []dashboard.Mailbox{{SubscriptionID: 42, MailDomainID: 100}, {SubscriptionID: 99}}
	if got := subscriptionFTPUsed(data.Subscriptions[0], data); got != 2 {
		t.Fatalf("FTP usage = %d, want primary and domain accounts", got)
	}
	if got := subscriptionMailboxesUsed(data.Subscriptions[0], data); got != 1 {
		t.Fatalf("mailbox usage = %d, want retained domain mailbox", got)
	}
	if got := subscriptionAccessObjects(data.Subscriptions[0], data); got != 1 {
		t.Fatalf("access tab badge = %d, want only primary account", got)
	}
}

func TestSubscriptionMetersUseCollectedAggregateUsage(t *testing.T) {
	data := detailFixture()
	data.SubscriptionServices.SiteUsage = []dashboard.SiteUsage{{SiteID: 7, DocumentRootBytes: 100, TrafficBytes: 200}}
	data.SubscriptionUsage = []types.SubscriptionUsage{{SubscriptionID: 42, DiskBytes: 2 << 30, TrafficBytes: 3 << 30, Complete: true, CollectedAt: time.Now()}}
	if subscriptionDiskUsedBytes(data.Subscriptions[0], data) != 2<<30 || subscriptionTrafficUsedBytes(data.Subscriptions[0], data) != 3<<30 {
		t.Fatal("subscription meter excluded account/database/container or historical traffic usage")
	}
	data.SubscriptionUsage = nil
	for _, row := range subscriptionLimitRows(data.Subscriptions[0], data) {
		if row.Label == "Disk" || row.Label == "Monthly traffic" {
			if row.Used != "Not measured" || row.HasBar {
				t.Fatalf("missing aggregate scan rendered authoritative usage: %+v", row)
			}
		}
	}
}

func TestSubscriptionIncompleteMeasurementsDoNotClaimCompliance(t *testing.T) {
	data := detailFixture()
	data.SubscriptionUsage = []types.SubscriptionUsage{{SubscriptionID: 42, DiskBytes: 2 << 30, Complete: false, CollectedAt: time.Now(), LastError: "scan failed"}}
	for _, row := range subscriptionLimitRows(data.Subscriptions[0], data) {
		if row.Label == "Disk" && (row.HasBar || row.Severity != 0 || !strings.Contains(row.Note, "incomplete")) {
			t.Fatalf("incomplete scan claimed an authoritative breach: %+v", row)
		}
	}
	data.ServiceLoadError = "git_repositories unavailable"
	html := renderIntegratedSubscription(t, data, auth.RoleClient, "access", 0)
	if !strings.Contains(html, "Resource lists and counts may be incomplete") {
		t.Fatal("partial service load was mistaken for complete empty inventory")
	}
}

func TestClientDoesNotReceiveProviderSynchronizationRetry(t *testing.T) {
	data := detailFixture()
	data.Subscriptions[0].SyncError = "Retry required"
	html := renderIntegratedSubscription(t, data, auth.RoleClient, "overview", 0)
	if !strings.Contains(html, "Retry required") || strings.Contains(html, `action="/subscriptions/42/sync"`) {
		t.Fatal("client error recovery exposes a provider-only operation")
	}
}

func TestSupportSubscriptionDoesNotLinkToUnsupportedProviderPages(t *testing.T) {
	html := renderIntegratedSubscription(t, detailFixture(), auth.RoleAdmin, "overview", 88)
	for _, forbidden := range []string{`href="/support/customers/88/customers`, `href="/service-plans/10"`, `action="/support/customers/88/enter"`} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("support view leaked invalid/provider navigation: %s", forbidden)
		}
	}
}

func TestSubscriptionMailAvailabilityUsesEffectivePolicy(t *testing.T) {
	data := detailFixture()
	data.Subscriptions[0].MaxMailboxes = 5
	html := renderIntegratedSubscription(t, data, auth.RoleClient, "mail", 0)
	if strings.Contains(html, "Configure Mail") {
		t.Fatal("mail-disabled effective policy offered configuration")
	}
	data.Subscriptions[0].MaxMailboxes = 0
	policy := &data.SubscriptionServices.Accounts[0].EffectivePolicy
	policy.SchemaVersion = 4
	policy.Permissions.Mail, policy.Mail.Enabled, policy.Resources.MaxMailboxes = true, true, 5
	html = renderIntegratedSubscription(t, data, auth.RoleClient, "mail", 0)
	if !strings.Contains(html, "Configure Mail") || strings.Contains(html, "allows no mailboxes") {
		t.Fatal("effective mailbox allowance was replaced by stale snapshot limits")
	}
}

func TestSubscriptionAccessMetersUseEffectiveAllowances(t *testing.T) {
	data := detailFixture()
	policy := &data.SubscriptionServices.Accounts[0].EffectivePolicy
	policy.Resources.MaxMailboxes, policy.Resources.MaxFTPAccounts = 5, 5
	data.SubscriptionServices.Mailboxes = []dashboard.Mailbox{{SubscriptionID: 42}}
	data.SubscriptionServices.FTP = []types.FTPAccount{{SubscriptionID: 42}}
	for _, row := range subscriptionLimitRows(data.Subscriptions[0], data) {
		if row.Label == "Mailboxes" || row.Label == "FTP accounts" {
			if row.Limit != "5" || row.Tone == limitToneOver {
				t.Fatalf("effective allowance ignored: %+v", row)
			}
		}
	}
}

func TestSubscriptionBackupStandingIgnoresFailedAndTruncatedInventory(t *testing.T) {
	data := detailFixture()
	data.Subscriptions[0].MaxBackups, data.Subscriptions[0].BackupsUsed = 2, 1
	data.Phase6.Backups = []dashboard.Backup{{ID: 1, SubscriptionID: 42, Status: "active"}, {ID: 2, SubscriptionID: 42, Status: "failed"}, {ID: 3, SubscriptionID: 42, Status: "failed"}}
	html := renderIntegratedSubscription(t, data, auth.RoleClient, "backups", 0)
	if strings.Contains(html, "beyond the plan limit") {
		t.Fatal("failed backups consume displayed plan allowance")
	}
	data.Phase6.Backups = nil
	html = renderIntegratedSubscription(t, data, auth.RoleClient, "backups", 0)
	if strings.Contains(html, "No backups have been taken") {
		t.Fatal("bounded recent inventory was mistaken for no stored backups")
	}
}

func TestSubscriptionOveruseCopyDoesNotPromiseUniversalRefusal(t *testing.T) {
	for _, policy := range []types.PlanOverusePolicy{types.PlanOveruseNormal, types.PlanOveruseNotify} {
		data := detailFixture()
		data.Subscriptions[0].OverusePolicy = policy
		html := renderIntegratedSubscription(t, data, auth.RoleClient, "backups", 0)
		if strings.Contains(html, "will be refused") || strings.Contains(html, "no room for another") {
			t.Fatalf("policy %s incorrectly promises a hard count gate", policy)
		}
	}
}
