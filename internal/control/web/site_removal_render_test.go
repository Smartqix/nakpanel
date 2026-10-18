package web

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestSiteRemovalContextualPrimaryAndChildActions(t *testing.T) {
	for _, primary := range []bool{true, false} {
		var html bytes.Buffer
		if err := siteRemovalActions(dashboard.Site{ID: 7, ParentSiteID: 1, Domain: "child.test"}, primary, WorkspaceView{SupportCustomerID: 88}).Render(context.Background(), &html); err != nil {
			t.Fatal(err)
		}
		if primary {
			if !strings.Contains(html.String(), "Primary website") || strings.Contains(html.String(), "data-np-removal-open") {
				t.Fatal(html.String())
			}
		} else if !strings.Contains(html.String(), "Remove subdomain") || !strings.Contains(html.String(), "/support/customers/88/sites/7/removal") {
			t.Fatal(html.String())
		}
	}
}
func TestSiteRemovalPreviewChildrenAndDefaultCheckboxes(t *testing.T) {
	p := types.SiteRemovalPreview{SiteID: 7, Domain: "addon.test", Kind: "website", Allowed: true, RequiresHostnameConfirmation: true, Snapshot: types.SiteRemovalSnapshot{Sites: []types.SiteRemovalSite{{SiteID: 7, Domain: "addon.test"}, {SiteID: 8, Domain: "child.addon.test"}}, Databases: []types.SiteRemovalDatabase{{ID: 9, Name: "safe_db", DeletionEligible: true}, {ID: 10, Name: "shared_db", IneligibleReason: "Shared principal"}}}}
	var html bytes.Buffer
	if err := SiteRemovalPreviewContent(WorkspaceView{}, SiteRemovalView{Preview: &p}).Render(context.Background(), &html); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"child.addon.test", "include_children", "acknowledge_permanent", "confirm_domain", "Databases and backups are kept by default", "shared_db will be kept", "Will be removed", "Will be kept", "np-domain-removal-impact"} {
		if !strings.Contains(strings.ReplaceAll(html.String(), "</strong>", ""), want) {
			t.Fatal("missing", want)
		}
	}
	if strings.Contains(html.String(), " checked") || strings.Contains(html.String(), `name="delete_database_ids" value="10"`) {
		t.Fatal("unsafe removal defaults")
	}
}

func TestSiteRemovalPreviewListsNamedImpactWithoutSecretBindings(t *testing.T) {
	p := types.SiteRemovalPreview{SiteID: 7, Domain: "addon.test", Allowed: true, Snapshot: types.SiteRemovalSnapshot{Sites: []types.SiteRemovalSite{{SiteID: 7, Domain: "addon.test"}}, Resources: []types.SiteRemovalResource{{Kind: "mailbox", Name: "hello@addon.test"}, {Kind: "task", Name: "Nightly cleanup"}, {Kind: "php_environment", Name: "PRIVATE_SECRET_NAME"}}}}
	var html bytes.Buffer
	SiteRemovalPreviewContent(WorkspaceView{}, SiteRemovalView{Preview: &p}).Render(context.Background(), &html)
	if !strings.Contains(html.String(), "hello@addon.test") || !strings.Contains(html.String(), "Nightly cleanup") || strings.Contains(html.String(), "PRIVATE_SECRET_NAME") {
		t.Fatal("incomplete or unsafe impact details")
	}
}

func TestSiteRemovalPageAndDialogHaveDistinctAccessibleHeadings(t *testing.T) {
	p := types.SiteRemovalPreview{SiteID: 7, Domain: "addon.test", Allowed: true}
	var html bytes.Buffer
	model := SiteRemovalView{Preview: &p}
	SiteRemovalPreviewContent(WorkspaceView{Route: "site-removal"}, model).Render(context.Background(), &html)
	SiteRemovalPreviewContent(WorkspaceView{}, model).Render(context.Background(), &html)
	ids := regexp.MustCompile(`<h2 id="([^"]+)"`).FindAllStringSubmatch(html.String(), -1)
	if len(ids) != 2 || ids[0][1] == ids[1][1] {
		t.Fatal("dialog label points to the background page heading", ids)
	}
}

func TestSiteRemovalProgressDoesNotClaimUnfinishedSharedOrSQLStages(t *testing.T) {
	op := types.SiteRemovalOperation{State: "failed", Stage: types.RemovalShared, Checkpoints: []string{"stop_services", "remove_hosting", "reconcile_shared"}}
	if removalStageViews(op)[3].Complete {
		t.Fatal("failed access/mail convergence was shown completed")
	}
	op.Stage = types.RemovalFinalize
	op.Checkpoints = append(op.Checkpoints, "surviving-access", "surviving-mail", "finalize")
	if removalStageViews(op)[4].Complete {
		t.Fatal("rolled-back SQL completion was shown completed")
	}
}
func TestSiteRemovalRetainedBackupDownloadAndExplicitReplacement(t *testing.T) {
	backup := dashboard.Backup{ID: 9, SubscriptionID: 20, TargetName: "addon.test", Status: "active", ArchivePath: "fixture"}
	var html bytes.Buffer
	sites := []dashboard.Site{{ID: 8, SubscriptionID: 20, Domain: "addon.test", Status: "active", DesiredStatus: "active"}}
	if err := backupRecoveryActions(backup, sites, WorkspaceView{SupportCustomerID: 88}).Render(context.Background(), &html); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/support/customers/88/backups/9/download", `name="target_site_id"`, "Select the replacement website", "Restore to replacement"} {
		if !strings.Contains(html.String(), want) {
			t.Fatal("missing", want)
		}
	}
	sites[0].RemovalState = "removing"
	html.Reset()
	backupRecoveryActions(backup, sites, WorkspaceView{}).Render(context.Background(), &html)
	if strings.Contains(html.String(), `name="target_site_id"`) {
		t.Fatal("removing replacement available")
	}
}
