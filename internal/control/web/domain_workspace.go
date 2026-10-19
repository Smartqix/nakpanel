package web

import (
	"fmt"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

func domainWorkspaceClass(view WorkspaceView) string {
	if view.Route == "site-detail" && view.Tab == "mail" {
		return "np-app np-routed np-domains np-mail-page"
	}
	switch view.Route {
	case "sites", "site-new", "site-detail", "site-files", "site-file-edit", "site-setup", "site-removal", "site-removal-progress":
		return "np-app np-routed np-domains"
	default:
		return "np-app np-routed"
	}
}

func domainCanAddChild(site dashboard.Site, subscription types.SubscriptionSummary, actions DashboardActions) bool {
	return actions.CanCreateSite && !removalBusy(site) && subscription.Status == "active" &&
		site.Status == "active" && site.DesiredStatus == "active" && site.ParentSiteID == 0
}

func domainKind(site dashboard.Site, subscription types.SubscriptionSummary) string {
	if site.ParentSiteID > 0 {
		return "Subdomain"
	}
	if site.ID == subscription.PrimarySiteID {
		return "Primary domain"
	}
	return "Add-on domain"
}

func domainTLSLabel(site dashboard.Site) string {
	if site.TLSStatus == "active" {
		if site.TLSExpiresAt.Valid && !site.TLSExpiresAt.Time.After(time.Now()) {
			return "Expired"
		}
		if site.TLSExpiresAt.Valid && time.Until(site.TLSExpiresAt.Time) <= certificateExpiryWindow {
			return "Expires soon"
		}
		return "Secured"
	}
	switch site.TLSStatus {
	case "pending", "provisioning", "issuing":
		return "Issuing"
	case "failed":
		return "Needs attention"
	default:
		return "Not secured"
	}
}

func domainTLSTone(site dashboard.Site) string {
	switch domainTLSLabel(site) {
	case "Secured":
		return "success"
	case "Expired":
		return "danger"
	default:
		return "warning"
	}
}

func domainStateTone(state string) string {
	switch state {
	case "active", "in_sync", "configured":
		return "success"
	case "failed", "expired":
		return "danger"
	default:
		return "warning"
	}
}

func domainDNSLabel(site dashboard.Site, phase dashboard.Phase6Data) string {
	state := domainDNSStateForSite(phase, site)
	if site.ParentSiteID > 0 {
		zone, found := dnsZoneForSiteWorkspace(phase.DNSZones, phase.DNSRecords, site)
		state = subdomainDNSState(site, zone, found, phase.DNSRecords)
	}
	switch state {
	case "active", "in_sync":
		return "Configured"
	case "external":
		return "External"
	case "pending":
		return "Applying"
	case "failed":
		return "Needs attention"
	default:
		return "Not configured"
	}
}

func domainInventorySummary(sites []dashboard.Site) string {
	domains, children := 0, 0
	for _, site := range sites {
		if site.ParentSiteID > 0 {
			children++
		} else {
			domains++
		}
	}
	return fmt.Sprintf("%d %s and %d %s", domains, pluralDomain(domains, "domain"), children, pluralDomain(children, "subdomain"))
}

func pluralDomain(count int, noun string) string {
	if count == 1 {
		return noun
	}
	return noun + "s"
}

func domainToolURL(siteID int64, tool string, view WorkspaceView) string {
	base := workspacePath(view, "/sites/"+formatJobID(siteID))
	switch tool {
	case "overview", "hosting", "php", "mail", "dns", "ssl", "databases", "backups":
		return base + "?tab=" + tool
	case "files":
		return fileBasePath(view, siteID)
	default:
		return base + "/" + tool
	}
}

func domainCustomerName(subscription types.SubscriptionSummary) string {
	for _, value := range []string{subscription.CustomerName, subscription.CustomerCompany, subscription.CustomerEmail} {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return "Not configured"
}
