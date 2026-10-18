package web

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/a-h/templ"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

func renderDrawerComponent(t *testing.T, component templ.Component) string {
	t.Helper()
	var out bytes.Buffer
	if err := component.Render(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func requireDrawer(t *testing.T, html, id, action string, fields ...string) {
	t.Helper()
	for _, dialog := range regexp.MustCompile(`(?s)<dialog\b.*?</dialog>`).FindAllString(html, -1) {
		head := strings.SplitN(dialog, ">", 2)[0]
		if !strings.Contains(head, `id="`+id+`"`) {
			continue
		}
		if !strings.Contains(head, "np-drawer") || !strings.Contains(head, "data-np-dialog") {
			t.Errorf("%s must use the shared dialog controller and drawer variant", id)
		}
		for _, want := range append([]string{`action="` + action + `"`, "np-drawer-body", "aria-label=", "np-dialog-actions"}, fields...) {
			if !strings.Contains(dialog, want) {
				t.Errorf("drawer %s missing %q", id, want)
			}
		}
		return
	}
	t.Fatalf("missing drawer %s", id)
}

func TestCreateEditDrawersKeepFormContracts(t *testing.T) {
	site := dashboard.Site{ID: 7, SubscriptionID: 42, Domain: "example.test"}
	subscription := types.SubscriptionSummary{ID: 42, MaxDatabases: -1}
	data := dashboard.Data{Sites: []dashboard.Site{site}, SubscriptionServices: dashboard.SubscriptionServicesData{
		SitePolicies: []dashboard.SitePolicy{{SiteID: 7, EffectivePolicy: types.HostingPolicy{}}},
	}}
	data.SubscriptionServices.SitePolicies[0].EffectivePolicy.Permissions.Git = true
	data.SubscriptionServices.SitePolicies[0].EffectivePolicy.Permissions.Applications = true
	view := WorkspaceView{CSRFToken: "fresh-csrf"}
	domain := dashboard.MailDomain{ID: 9, Domain: "example.test"}
	for _, tt := range []struct {
		id, action string
		component  templ.Component
		fields     []string
	}{
		{"site-dialog", "/sites", routedSiteDialog([]types.SubscriptionSummary{subscription}, types.RuntimeCapabilities{}, view), []string{`name="domain"`, `name="subscription_id"`, `name="username"`, `name="php_version"`}},
		{"database-create-dialog-7", "/databases", domainDatabases(site, subscription, nil, DashboardActions{CanCreateDatabase: true}, view), []string{`name="subscription_id"`, `name="site_id"`, `name="engine"`, `name="db_name"`, `name="db_user"`, `name="password"`}},
		{"customer-dialog", "/customers", customerDialog(view), []string{`name="customer_email"`, `name="customer_name"`, `name="company"`, `name="notes"`, `name="enable_login"`, `name="password"`}},
		{"deploy-container-dialog", "/subscriptions/42/applications", containerDeployDialog(auth.SessionUser{Role: auth.RoleAdmin}, site, subscription, data, view), []string{`name="site_id"`, `name="runtime"`, `name="name"`, `name="catalog_slug"`, `name="environment"`, `name="secrets"`}},
		{"git-connect", "/sites/7/git", gitWorkspace(site, subscription, data, view), []string{`name="subscription_id"`, `name="remote_url"`, `name="branch"`, `name="deploy_target"`, `name="known_host_key"`}},
		{"mail-domain-42-9", "/subscriptions/42/mail-domains", mailDomainDialog(subscription, domain, data, view, "subscription-mail", 0), []string{`name="resource_id"`, `name="site_id"`, `name="dmarc_policy"`, `name="dkim"`, `name="enabled"`}},
		{"mail-domain-42", "/subscriptions/42/mail-domains", mailDomainDialog(subscription, dashboard.MailDomain{}, data, view, "subscription-mail", 0), []string{`name="resource_id"`, `name="site_id"`, `name="dmarc_policy"`, `name="dkim"`, `name="enabled"`}},
		{"mail-mailbox-42-9", "/subscriptions/42/mailboxes", mailboxDialog(subscription, domain, dashboard.Mailbox{}, view, "subscription-mail", 0), []string{`name="resource_id"`, `name="mail_domain_id"`, `name="local_part"`, `name="password"`, `name="quota_mb"`}},
		{"mail-mailbox-edit-42-11", "/subscriptions/42/mailboxes", mailboxDialog(subscription, domain, dashboard.Mailbox{ID: 11}, view, "subscription-mail", 0), []string{`name="resource_id"`, `name="mail_domain_id"`, `name="local_part"`, `name="password"`, `name="quota_mb"`}},
		{"mail-alias-42-9", "/subscriptions/42/mail-aliases", mailAliasDialog(subscription, domain, dashboard.MailAlias{}, view, "subscription-mail", 0), []string{`name="resource_id"`, `name="mail_domain_id"`, `name="local_part"`, `name="destinations"`}},
		{"mail-alias-edit-42-12", "/subscriptions/42/mail-aliases", mailAliasDialog(subscription, domain, dashboard.MailAlias{ID: 12}, view, "subscription-mail", 0), []string{`name="resource_id"`, `name="mail_domain_id"`, `name="local_part"`, `name="destinations"`}},
	} {
		t.Run(tt.id, func(t *testing.T) {
			html := renderDrawerComponent(t, tt.component)
			requireDrawer(t, html, tt.id, tt.action, append(tt.fields, `value="fresh-csrf"`)...)
		})
	}
}

func TestSubscriptionInlineFormsMoveIntoDrawers(t *testing.T) {
	for _, tt := range []struct {
		tab, id, action string
		fields          []string
	}{
		{"access", "subscription-sftp-dialog-42", "/subscriptions/42/sftp", []string{`name="name"`, `name="relative_root"`, `name="public_key"`, `name="enabled"`, "Add SFTP identity"}},
		{"access", "subscription-ftps-dialog-42", "/subscriptions/42/ftp", []string{`name="name"`, `name="password"`, `name="enabled"`, "Create or reset FTPS account"}},
		{"tasks", "subscription-task-dialog-42", "/subscriptions/42/scheduled-tasks", []string{`name="site_id"`, `name="name"`, `name="schedule"`, `name="working_directory"`, `name="timeout_seconds"`, `name="command"`, `name="enabled"`, "Add scheduled task"}},
		{"resources", "subscription-plan-dialog-42", "/subscriptions/42/status", []string{`name="customer_id"`, `name="subscription_name"`, `name="sync_mode"`, `name="status"`, `name="plan_id"`, `data-np-confirm="Move this subscription onto the selected plan?"`, ">Change plan</button>"}},
		{"resources", "subscription-status-dialog-42", "/subscriptions/42/status", []string{`name="customer_id"`, `name="subscription_name"`, `name="sync_mode"`, `name="plan_id"`, `name="status"`, `data-np-confirm="Apply this status change to the subscription and its websites?"`, "Apply status"}},
	} {
		t.Run(tt.id, func(t *testing.T) {
			data := detailFixture()
			data.SubscriptionServices.Accounts[0].EffectivePolicy.Permissions.SFTP = true
			data.SubscriptionServices.Accounts[0].EffectivePolicy.Permissions.FTPS = true
			data.SubscriptionServices.Accounts[0].EffectivePolicy.Access.FTPSEnabled = true
			data.SubscriptionServices.Accounts[0].EffectivePolicy.Permissions.ScheduledTasks = true
			html := renderDrawerComponent(t, routedSubscriptionDetail(auth.SessionUser{Role: auth.RoleAdmin}, data, DashboardActions{CanCreateSite: true}, WorkspaceView{Route: "subscription-detail", DetailID: 42, Tab: tt.tab}))
			requireDrawer(t, html, tt.id, tt.action, tt.fields...)
			if !strings.Contains(html, `data-np-dialog-open="`+tt.id+`"`) {
				t.Fatal("missing drawer trigger")
			}
		})
	}
	client := renderSubscriptionDetail(t, auth.RoleClient, "resources")
	for _, forbidden := range []string{"subscription-plan-dialog", "subscription-status-dialog", `action="/subscriptions/42/status"`} {
		if strings.Contains(client, forbidden) {
			t.Errorf("client sees provider form: %s", forbidden)
		}
	}
}

func TestSubscriptionAddDomainKeepsFallbackAndPrefillsWhenShellDialogPresent(t *testing.T) {
	for _, present := range []bool{true, false} {
		html := renderDrawerComponent(t, subscriptionObjectHead(auth.SessionUser{Role: auth.RoleAdmin}, detailFixture().Subscriptions[0], detailFixture(), DashboardActions{CanCreateSite: true}, WorkspaceView{Route: map[bool]string{true: "subscription-detail", false: "site-new"}[present]}))
		var addDomain string
		for _, anchor := range regexp.MustCompile(`(?s)<a\b.*?</a>`).FindAllString(html, -1) {
			if strings.Contains(anchor, "Add Domain") {
				addDomain = anchor
			}
		}
		if !strings.Contains(addDomain, `href="/sites/new?subscription_id=42&amp;type=php"`) {
			t.Fatalf("fallback link missing: %s", addDomain)
		}
		if strings.Contains(addDomain, `data-np-dialog-open="site-dialog"`) != present || strings.Contains(addDomain, "data-np-dialog-prefill=") != present {
			t.Fatalf("dialog trigger availability mismatch: %s", addDomain)
		}
		if present && !strings.Contains(addDomain, `subscription_id&#34;:&#34;42`) {
			t.Fatalf("missing subscription prefill: %s", addDomain)
		}
	}
}

func TestSubscriptionDrawerTriggersHaveFallbackLinks(t *testing.T) {
	// Creating something is the primary action; changing the plan or status of
	// an existing subscription is secondary.
	for _, tt := range []struct{ tab, id, class string }{
		{"access", "subscription-sftp-dialog-42", "np-primary-link"},
		{"access", "subscription-ftps-dialog-42", "np-primary-link"},
		{"tasks", "subscription-task-dialog-42", "np-primary-link"},
		{"resources", "subscription-plan-dialog-42", "np-secondary-button"},
		{"resources", "subscription-status-dialog-42", "np-secondary-button"},
	} {
		t.Run(tt.id, func(t *testing.T) {
			data := detailFixture()
			policy := &data.SubscriptionServices.Accounts[0].EffectivePolicy
			policy.Permissions.SFTP = true
			policy.Permissions.FTPS = true
			policy.Access.FTPSEnabled = true
			policy.Permissions.ScheduledTasks = true
			html := renderDrawerComponent(t, routedSubscriptionDetail(auth.SessionUser{Role: auth.RoleAdmin}, data, DashboardActions{}, WorkspaceView{Route: "subscription-detail", DetailID: 42, Tab: tt.tab}))
			for _, anchor := range regexp.MustCompile(`(?s)<a\b.*?</a>`).FindAllString(html, -1) {
				if !strings.Contains(anchor, `data-np-dialog-open="`+tt.id+`"`) {
					continue
				}
				want := `href="/subscriptions/42?tab=` + tt.tab + `&amp;drawer=` + tt.id + `"`
				if !strings.Contains(anchor, want) || !strings.Contains(anchor, `class="`+tt.class+`"`) {
					t.Fatalf("drawer link must retain its tab and button styling: %s", anchor)
				}
				return
			}
			t.Fatal("drawer trigger has no fallback anchor")
		})
	}
}
