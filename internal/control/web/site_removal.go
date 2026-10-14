package web

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

type SiteRemovalView struct {
	Preview              *types.SiteRemovalPreview
	Operation            *types.SiteRemovalOperation
	Approval             string
	RequestID            string
	Error                string
	ConfirmDomain        string
	AcknowledgePermanent bool
	IncludeChildren      bool
	Redirect             string
}

func removalHeadingID(view WorkspaceView) string {
	if view.Route == "site-removal" || view.Route == "site-removal-progress" {
		return "np-site-removal-page-title"
	}
	return "np-site-removal-title"
}

type RemovalStageView struct {
	Key, Label string
	Complete   bool
}

type removalImpactGroup struct {
	Title string
	Items []string
}

func removalImpactGroups(p types.SiteRemovalPreview) []removalImpactGroup {
	definitions := []struct {
		title string
		kinds []string
	}{
		{"PHP, WordPress and deployments", []string{"php_application", "php_worker", "php_deployment", "wordpress", "git", "git_deployment"}},
		{"Applications, tasks and access", []string{"application", "application_generation", "task", "staging", "ftp", "sftp_identity", "protected_directory"}},
		{"Mail and webmail", []string{"mail_domain", "mailbox", "mail_alias", "webmail"}},
		{"DNS and statistics", []string{"dns_zone", "dns_record", "statistics"}},
	}
	captions := map[string]string{"php_application": "PHP application", "php_worker": "PHP worker", "php_deployment": "PHP release", "wordpress": "WordPress installation", "git": "Git repository", "git_deployment": "Git deployment", "application": "Container", "application_generation": "Container generation", "task": "Scheduled task", "staging": "Staging operation", "ftp": "FTPS account", "sftp_identity": "SFTP key", "protected_directory": "Protected directory", "mail_domain": "Mail domain", "mailbox": "Mailbox", "mail_alias": "Mail alias", "webmail": "Webmail host", "dns_zone": "DNS zone", "dns_record": "DNS record", "statistics": "Statistics report"}
	out := []removalImpactGroup{}
	for _, definition := range definitions {
		group := removalImpactGroup{Title: definition.title}
		for _, resource := range p.Snapshot.Resources {
			if !slices.Contains(definition.kinds, resource.Kind) {
				continue
			}
			label := captions[resource.Kind] + " " + resource.Name
			if resource.Name == "" {
				label = captions[resource.Kind] + " #" + strconv.FormatInt(resource.ID, 10)
			}
			group.Items = append(group.Items, label)
		}
		if len(group.Items) > 0 {
			out = append(out, group)
		}
	}
	return out
}

func mapSiteKind(site dashboard.Site) string {
	if site.ParentSiteID > 0 {
		return "subdomain"
	}
	return "website"
}
func removalStageIcon(complete bool) string {
	if complete {
		return "shield-check"
	}
	return "activity"
}
func isPrimarySite(site dashboard.Site, subscriptions []types.SubscriptionSummary) bool {
	for _, sub := range subscriptions {
		if sub.ID == site.SubscriptionID {
			return sub.PrimarySiteID == site.ID
		}
	}
	return false
}

func retainedBackupTarget(backup dashboard.Backup, sites []dashboard.Site) (dashboard.Site, bool) {
	for _, site := range sites {
		if site.SubscriptionID == backup.SubscriptionID && site.Domain == backup.TargetName && site.Status == "active" && site.DesiredStatus == "active" && !removalBusy(site) {
			return site, true
		}
	}
	return dashboard.Site{}, false
}
func removalStageViews(op types.SiteRemovalOperation) []RemovalStageView {
	stages := []RemovalStageView{{"waiting", "Waiting for current work", false}, {string(types.RemovalStopServices), "Stop domain services", false}, {string(types.RemovalHosting), "Remove hosting and files", false}, {string(types.RemovalShared), "Update DNS, mail and access", false}, {string(types.RemovalFinalize), "Finalize records", false}}
	for i := range stages {
		stages[i].Complete = op.State == "completed" || slices.Contains(op.Checkpoints, stages[i].Key)
		if stages[i].Key == string(types.RemovalShared) {
			stages[i].Complete = op.State == "completed" || stages[i].Complete && slices.Contains(op.Checkpoints, "surviving-access") && slices.Contains(op.Checkpoints, "surviving-mail")
		}
		if stages[i].Key == string(types.RemovalFinalize) {
			stages[i].Complete = op.State == "completed"
		}
		if i == 0 && len(op.Checkpoints) > 0 {
			stages[i].Complete = true
		}
	}
	return stages
}
func removalLabel(kind string) string {
	if kind == "subdomain" {
		return "Remove subdomain"
	}
	return "Remove website"
}
func removalResourceCount(p types.SiteRemovalPreview, kinds ...string) int {
	count := 0
	for _, r := range p.Snapshot.Resources {
		if slices.Contains(kinds, r.Kind) {
			count++
		}
	}
	return count
}
func removalKeptDatabaseCount(op types.SiteRemovalOperation) int {
	return len(op.Snapshot.Databases) - len(op.DeleteDatabaseIDs)
}
func removalCompletionMessage(op types.SiteRemovalOperation) string {
	return fmt.Sprintf("%s was removed. %d databases and %d backups were kept under the subscription.", op.Domain, removalKeptDatabaseCount(op), len(op.Snapshot.Backups))
}
func removalBusy(site dashboard.Site) bool {
	return site.RemovalState != "" && site.RemovalState != "none"
}
func removalActionPath(site dashboard.Site, view WorkspaceView) string {
	return workspacePath(view, "/sites/"+strconv.FormatInt(site.ID, 10)+"/removal")
}
