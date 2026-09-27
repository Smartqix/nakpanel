package web

import (
	"strings"
	"testing"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	controlwordpress "github.com/nakroteck/nakpanel/internal/control/wordpress"
	"github.com/nakroteck/nakpanel/internal/types"
)

func wordpressRenderData() dashboard.Data {
	return dashboard.Data{
		Sites:         []dashboard.Site{{ID: 7, Domain: "owned.test", Status: "active", DesiredStatus: "active", CustomerID: 88, SubscriptionID: 20}},
		Subscriptions: []types.SubscriptionSummary{{ID: 20, CustomerID: 88, SubscriptionName: "Production", PlanName: "WordPress Pro", Status: "active"}},
		Customers:     []types.Customer{{ID: 88, Status: "active"}},
	}
}

func wordpressPolicy() types.HostingPolicy {
	return types.HostingPolicy{
		SchemaVersion: 4,
		Permissions:   types.HostingPermissionPolicy{Hosting: true, WordPressToolkit: true},
		Resources:     types.HostingResourcePolicy{MaxWordPressSites: 3},
	}
}

func TestWordPressWorkspaceRendersUnavailableAndInstallStates(t *testing.T) {
	data := wordpressRenderData()
	unavailable := controlwordpress.Workspace{
		Policy: wordpressPolicy(), Reason: controlwordpress.ErrNotClassic.Error(),
		Site: controlwordpress.SiteIdentity{HostingMode: types.PHPHostingModeManaged},
	}
	body := renderPhase30Page(t, data, WorkspaceView{Route: "site-detail", DetailID: 7, Tab: "wordpress", WordPress: &unavailable, CSRFToken: "csrf"})
	if !strings.Contains(body, "WordPress Toolkit requires Classic PHP hosting") ||
		!strings.Contains(body, "Managed Deployment") || strings.Contains(body, `id="wordpress-install-dialog"`) {
		t.Fatalf("unavailable workspace rendered the wrong state:\n%s", body)
	}

	available := controlwordpress.Workspace{Policy: wordpressPolicy(), Available: true,
		Site: controlwordpress.SiteIdentity{HostingMode: types.PHPHostingModeClassic}}
	body = renderPhase30Page(t, data, WorkspaceView{Route: "site-detail", DetailID: 7, Tab: "wordpress", WordPress: &available, CSRFToken: "csrf"})
	for _, want := range []string{
		`href="/sites/7/wordpress"`, `aria-current="page"`, "No managed WordPress installation",
		`id="wordpress-install-dialog"`, `name="admin_password"`, `value="discover"`, "write-only",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("install workspace missing %q:\n%s", want, body)
		}
	}
}

func TestWordPressWorkspaceShowsRecoverableDiscoveryFailure(t *testing.T) {
	data := wordpressRenderData()
	workspace := controlwordpress.Workspace{
		Policy:    wordpressPolicy(),
		Available: true,
		Reason:    "No valid WordPress installation was found in this document root.",
	}
	body := renderPhase30Page(t, data, WorkspaceView{Route: "site-detail", DetailID: 7, Tab: "wordpress", WordPress: &workspace, CSRFToken: "csrf"})
	if !strings.Contains(body, workspace.Reason) || !strings.Contains(body, `id="wordpress-install-dialog"`) {
		t.Fatalf("recoverable discovery failure did not retain the reason and retry actions:\n%s", body)
	}
}

func TestWordPressWorkspaceRendersCredentialFreeFailedInstallRecovery(t *testing.T) {
	data := wordpressRenderData()
	workspace := controlwordpress.Workspace{
		Policy:    wordpressPolicy(),
		Available: true,
		Instance: &controlwordpress.Instance{
			ID: 9, SiteID: 7, SubscriptionID: 20, DatabaseID: 41, AdminUser: "siteadmin",
			ObservedState: "failed", ConvergenceStatus: "failed", LastError: "WordPress installation did not finish.",
		},
	}
	body := renderPhase30Page(t, data, WorkspaceView{Route: "site-detail", DetailID: 7, Tab: "wordpress", WordPress: &workspace, CSRFToken: "csrf"})
	for _, want := range []string{"Installation needs attention", "WordPress installation did not finish.", `name="action" value="install"`, "Retry installation", "reuses the existing encrypted credentials"} {
		if !strings.Contains(body, want) {
			t.Fatalf("failed-install recovery workspace missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `name="admin_password"`) {
		t.Fatal("failed-install retry asks the browser to resubmit a password")
	}
}

func TestWordPressPendingInstallationOffersSafeProgressRefresh(t *testing.T) {
	data := wordpressRenderData()
	workspace := controlwordpress.Workspace{Policy: wordpressPolicy(), Available: true,
		Instance: &controlwordpress.Instance{ID: 9, SiteID: 7, SubscriptionID: 20, DesiredState: "present", ObservedState: "pending", ConvergenceStatus: "pending"}}
	body := renderPhase30Page(t, data, WorkspaceView{Route: "site-detail", DetailID: 7, Tab: "wordpress", WordPress: &workspace, CSRFToken: "csrf"})
	if !strings.Contains(body, `data-np-wordpress-progress`) || !strings.Contains(body, "Installation is in progress") {
		t.Fatal("pending WordPress setup did not expose a refreshable progress state")
	}
	workspace.Instance.ObservedState = "failed"
	body = renderPhase30Page(t, data, WorkspaceView{Route: "site-detail", DetailID: 7, Tab: "wordpress", WordPress: &workspace, CSRFToken: "csrf"})
	if strings.Contains(body, `data-np-wordpress-progress`) {
		t.Fatal("failed WordPress setup should not keep auto-refreshing")
	}
}

func TestWebsiteOverviewDistinguishesWordPressProgressAndFailure(t *testing.T) {
	data := wordpressRenderData()
	for _, tc := range []struct {
		name, observed, desired, version, heading, description string
	}{
		{"pending", "pending", "present", "", "Installing WordPress", "installation is still running"},
		{"healthy", "healthy", "present", "7.1", "Website is active", "configured for PHP"},
		{"failed", "failed", "present", "", "WordPress needs attention", "WordPress installation needs attention"},
		{"removed", "removed", "absent", "", "Website is active", "configured for PHP"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			workspace := controlwordpress.Workspace{Instance: &controlwordpress.Instance{ObservedState: tc.observed, DesiredState: tc.desired, InstalledVersion: tc.version}}
			body := renderPhase30Page(t, data, WorkspaceView{Route: "site-detail", DetailID: 7, Tab: "overview", WordPress: &workspace, CSRFToken: "csrf"})
			if !strings.Contains(body, tc.heading) || !strings.Contains(body, tc.description) {
				t.Fatalf("overview missing %q / %q", tc.heading, tc.description)
			}
			if tc.observed != "pending" && strings.Contains(body, "installation is still running") {
				t.Fatal("non-pending WordPress installation still reported in progress")
			}
		})
	}
}

func TestWordPressWorkspaceRendersInventoryWithoutSecrets(t *testing.T) {
	const secret = "this-password-must-never-render"
	now := time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)
	workspace := controlwordpress.Workspace{
		Policy:    wordpressPolicy(),
		Available: true,
		Instance: &controlwordpress.Instance{
			ID: 9, SiteID: 7, SubscriptionID: 20, AdminUser: "siteadmin", AdminEmail: "admin@owned.test", SiteTitle: "Owned site",
			InstalledVersion: "7.1", DesiredState: "present", ObservedState: "healthy", DesiredRevision: 4, AppliedRevision: 4,
			ConvergenceStatus: "in_sync", ChecksumStatus: "valid", LastScannedAt: now,
			Inventory: types.WordPressInventory{CoreVersion: "7.1", SiteURL: "https://owned.test", HomeURL: "https://owned.test", PHPVersion: "8.4", UpdatesAvailable: 1,
				Plugins: []types.WordPressComponent{{Slug: "akismet", Version: "5.4", Status: "active", UpdateVersion: "5.5"}},
				Themes:  []types.WordPressComponent{{Slug: "twentytwentyfive", Version: "1.0", Status: "active"}}},
			Security: types.WordPressSecurityState{CoreChecksumsValid: true, FilePermissionsSafe: true, FileEditingDisabled: true, DebugDisabled: true, HTTPSConfigured: true, Score: 100},
		},
		Operations: []controlwordpress.Operation{{ID: 12, Kind: types.WordPressActionRefresh, Status: "succeeded", Output: "Inventory refreshed", CreatedAt: now}, {ID: 11, Kind: types.WordPressActionUpdate, Status: "failed", LastError: "sanitized failure", Output: secret, CreatedAt: now}},
	}
	data := wordpressRenderData()
	for tab, wants := range map[string][]string{
		"overview": {"Owned site", "https://owned.test", "siteadmin", "4 / 4", "valid", "Enable maintenance mode", `name="maintenance" value="true"`, "Detach from Toolkit", "does not delete WordPress files or its database"},
		"plugins":  {"Plugins", "akismet", "5.4", "5.5", "Update"},
		"themes":   {"Themes", "twentytwentyfive", "Current"},
		"security": {"Security status", "Core checksums", "Apply safe hardening", "100"},
		"updates":  {"Back up and update all", "Update core", "recovery-point backup"},
		"activity": {"Operation history", "Inventory refreshed", "sanitized failure"},
	} {
		t.Run(tab, func(t *testing.T) {
			body := renderPhase30Page(t, data, WorkspaceView{Route: "site-detail", DetailID: 7, Tab: "wordpress", WordPressTab: tab, WordPress: &workspace, CSRFToken: "csrf"})
			for _, want := range wants {
				if !strings.Contains(body, want) {
					t.Fatalf("%s workspace missing %q:\n%s", tab, want, body)
				}
			}
			if strings.Contains(body, secret) || strings.Contains(body, "database_password") || strings.Contains(body, "admin-secret") {
				t.Fatalf("%s workspace exposed a secret", tab)
			}
		})
	}
}

func TestWordPressWorkspaceRendersSafeUninstallDangerZone(t *testing.T) {
	data := wordpressRenderData()
	workspace := controlwordpress.Workspace{Policy: wordpressPolicy(), Available: true,
		Instance: &controlwordpress.Instance{
			ID: 9, SiteID: 7, SubscriptionID: 20, DatabaseID: 41, DatabaseManaged: true,
			InstalledVersion: "7.1", DesiredState: "present", ObservedState: "healthy", ConvergenceStatus: "in_sync",
		}}
	body := renderPhase30Page(t, data, WorkspaceView{Route: "site-detail", DetailID: 7, Tab: "wordpress", WordPress: &workspace, CSRFToken: "csrf"})
	for _, want := range []string{
		"Detach from Toolkit", "Uninstall WordPress", `id="wordpress-uninstall-dialog"`,
		`name="create_backup" value="true" checked`, `name="delete_database" value="true"`,
		`name="confirm_domain"`, "owned.test", "preserves the domain",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("uninstall workspace missing %q:\n%s", want, body)
		}
	}
}

func TestWordPressWorkspaceRendersRemovedTombstoneAndReinstall(t *testing.T) {
	data := wordpressRenderData()
	workspace := controlwordpress.Workspace{Policy: wordpressPolicy(), Available: true,
		Instance: &controlwordpress.Instance{
			ID: 9, SiteID: 7, SubscriptionID: 20, DesiredState: "absent", ObservedState: "removed",
			DesiredRevision: 5, AppliedRevision: 5, ConvergenceStatus: "in_sync",
		},
		Operations: []controlwordpress.Operation{{
			ID: 14, Kind: types.WordPressActionUninstall, Status: "succeeded", BackupID: 51,
			Result: types.WordPressOperationResult{Action: types.WordPressActionUninstall, Removal: &types.WordPressRemovalResult{
				FilesRemoved: true, DatabasePreserved: true, BackupID: 51,
			}},
		}},
	}
	body := renderPhase30Page(t, data, WorkspaceView{Route: "site-detail", DetailID: 7, Tab: "wordpress", WordPress: &workspace, CSRFToken: "csrf"})
	for _, want := range []string{"WordPress removed", "Database preserved", "Recovery backup 51", "Install WordPress again", `id="wordpress-install-dialog"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("removed workspace missing %q:\n%s", want, body)
		}
	}
}

func TestWordPressWorkspaceAssetsAreResponsiveAndProgressive(t *testing.T) {
	css := string(appCSS)
	for _, want := range []string{".np-wordpress-summary", ".np-wordpress-commandbar", ".np-wordpress-checks", ".np-wordpress-findings", ".np-wordpress-removal-summary"} {
		if !strings.Contains(css, want) {
			t.Fatalf("compiled WordPress workspace CSS missing %q", want)
		}
	}
	for _, want := range []string{
		".np-wordpress-commandbar button{min-height:44px",
		".np-domain-commandbar>a,.np-routed-page-head>a{min-height:44px",
	} {
		if !strings.Contains(css, want) {
			t.Fatalf("compiled mobile domain CSS missing %q", want)
		}
	}
	javascript := string(appJS)
	for _, want := range []string{"data-np-generate-password", "data-np-copy-password", "crypto.getRandomValues", "data-np-wordpress-uninstall", "data-np-uninstall-backup", "data-np-uninstall-database"} {
		if !strings.Contains(javascript, want) {
			t.Fatalf("WordPress password workflow JavaScript missing %q", want)
		}
	}
}
