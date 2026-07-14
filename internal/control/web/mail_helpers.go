package web

import (
	"fmt"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

func mailWorkspaceSubscriptions(items []types.SubscriptionSummary, selected int64) []types.SubscriptionSummary {
	if selected <= 0 {
		return items
	}
	for _, item := range items {
		if item.ID == selected {
			return []types.SubscriptionSummary{item}
		}
	}
	return []types.SubscriptionSummary{}
}

func subscriptionMailEnabled(subscription types.SubscriptionSummary, data dashboard.SubscriptionServicesData) bool {
	if account, ok := accountForSubscription(data.Accounts, subscription.ID); ok {
		return account.EffectivePolicy.Permissions.Mail && account.EffectivePolicy.Mail.Enabled && account.EffectivePolicy.Resources.MaxMailboxes != 0
	}
	return subscription.MaxMailboxes != 0
}

func subscriptionWebmailEnabled(subscription types.SubscriptionSummary, data dashboard.SubscriptionServicesData) bool {
	if account, ok := accountForSubscription(data.Accounts, subscription.ID); ok {
		return account.EffectivePolicy.Permissions.Mail && account.EffectivePolicy.Mail.Enabled && account.EffectivePolicy.Mail.Webmail
	}
	return subscription.MaxMailboxes != 0 && subscription.ServicePresets.Mail.WebmailEnabled
}

func mailDomainsForWorkspace(items []dashboard.MailDomain, subscriptionID, selectedDomain int64) []dashboard.MailDomain {
	var out []dashboard.MailDomain
	for _, item := range items {
		if item.SubscriptionID == subscriptionID && (selectedDomain == 0 || item.ID == selectedDomain) {
			out = append(out, item)
		}
	}
	return out
}

func mailboxesForWorkspace(items []dashboard.Mailbox, domains []dashboard.MailDomain) []dashboard.Mailbox {
	visible := make(map[int64]bool, len(domains))
	for _, domain := range domains {
		visible[domain.ID] = true
	}
	var out []dashboard.Mailbox
	for _, item := range items {
		if visible[item.MailDomainID] {
			out = append(out, item)
		}
	}
	return out
}

func mailAliasesForWorkspace(items []dashboard.MailAlias, domains []dashboard.MailDomain) []dashboard.MailAlias {
	visible := make(map[int64]bool, len(domains))
	for _, domain := range domains {
		visible[domain.ID] = true
	}
	var out []dashboard.MailAlias
	for _, item := range items {
		if visible[item.MailDomainID] {
			out = append(out, item)
		}
	}
	return out
}

func mailWorkspaceSummary(data dashboard.Data, subscriptions []types.SubscriptionSummary, selectedDomain int64) types.MailWorkspaceSummary {
	var summary types.MailWorkspaceSummary
	for _, subscription := range subscriptions {
		domains := mailDomainsForWorkspace(data.SubscriptionServices.MailDomains, subscription.ID, selectedDomain)
		summary.Domains += len(domains)
		for _, domain := range domains {
			if domain.Enabled && domain.Status == "in_sync" {
				summary.ActiveDomains++
			}
			if domain.Status == "failed" || domain.LastError != "" {
				summary.FailedResources++
			}
		}
		summary.Mailboxes += len(mailboxesForWorkspace(data.SubscriptionServices.Mailboxes, domains))
		summary.Aliases += len(mailAliasesForWorkspace(data.SubscriptionServices.MailAliases, domains))
	}
	return summary
}

func siteForMailDomain(sites []dashboard.Site, domain dashboard.MailDomain) (dashboard.Site, bool) {
	for _, item := range sites {
		if (domain.SiteID > 0 && item.ID == domain.SiteID) || strings.EqualFold(item.Domain, domain.Domain) {
			return item, true
		}
	}
	return dashboard.Site{}, false
}

func mailDomainForSite(domains []dashboard.MailDomain, site dashboard.Site) (dashboard.MailDomain, bool) {
	for _, domain := range domains {
		if domain.SiteID == site.ID || (domain.SiteID == 0 && domain.SubscriptionID == site.SubscriptionID && strings.EqualFold(domain.Domain, site.Domain)) {
			return domain, true
		}
	}
	return dashboard.MailDomain{}, false
}

func webmailForSite(items []dashboard.WebmailHost, siteID int64) (dashboard.WebmailHost, bool) {
	for _, item := range items {
		if item.SiteID == siteID {
			return item, true
		}
	}
	return dashboard.WebmailHost{}, false
}

func mailDialogID(kind string, subscriptionID, resourceID int64) string {
	if resourceID > 0 {
		return fmt.Sprintf("mail-%s-%d-%d", kind, subscriptionID, resourceID)
	}
	return fmt.Sprintf("mail-%s-%d", kind, subscriptionID)
}

func mailLocalPart(address string) string {
	local, _, found := strings.Cut(address, "@")
	if !found {
		return address
	}
	return local
}

func mailDomainForMailbox(domains []dashboard.MailDomain, mailbox dashboard.Mailbox) string {
	for _, domain := range domains {
		if domain.ID == mailbox.MailDomainID {
			return domain.Domain
		}
	}
	return ""
}

func mailQuotaUsage(mailboxes []dashboard.Mailbox, limit int) string {
	if limit < 0 {
		return fmt.Sprintf("%d / unlimited", len(mailboxes))
	}
	return fmt.Sprintf("%d / %d", len(mailboxes), limit)
}

func mailDomainOptionLabel(domain dashboard.MailDomain) string {
	if domain.Status == "failed" {
		return domain.Domain + " (failed)"
	}
	return domain.Domain
}

func mailSubscriptionGate(subscription types.SubscriptionSummary) string {
	if subscription.Status != "active" {
		return "This subscription is " + subscription.Status + ". Activate it before managing mail."
	}
	if subscription.MaxMailboxes == 0 {
		return "Mail is disabled by this subscription's entitlement snapshot (0 mailboxes)."
	}
	return "Mail is disabled by the subscription policy."
}

func mailFailureCardClass(failures int) string {
	if failures > 0 {
		return "np-mail-summary-alert"
	}
	return ""
}

func mailWebmailStatus(host dashboard.WebmailHost, found bool) string {
	if !found {
		return "Not configured"
	}
	if host.Status == "" {
		return "Pending"
	}
	return host.Status
}

func mailWebmailAction(found bool) string {
	if found {
		return "Reconfigure webmail"
	}
	return "Enable webmail"
}

func mailEnabledStatus(enabled bool) string {
	if enabled {
		return "active"
	}
	return "suspended"
}

func mailDomainDialogTitle(id int64) string {
	if id > 0 {
		return "Mail domain settings"
	}
	return "Add mail domain"
}

func mailboxDialogKind(id int64) string {
	if id > 0 {
		return "mailbox-edit"
	}
	return "mailbox"
}

func mailboxDialogResourceID(id, domainID int64) int64 {
	if id > 0 {
		return id
	}
	return domainID
}

func mailboxDialogTitle(id int64) string {
	if id > 0 {
		return "Edit mailbox"
	}
	return "Create mailbox"
}

func mailboxPasswordHint(id int64) string {
	if id > 0 {
		return "leave blank to keep the current password"
	}
	return "at least 12 characters"
}

func mailboxSubmitLabel(id int64) string {
	if id > 0 {
		return "Save mailbox"
	}
	return "Create mailbox"
}

func formatMailboxQuotaInput(quotaMB int) string {
	if quotaMB == 0 {
		return "-1"
	}
	return fmt.Sprintf("%d", quotaMB)
}

func aliasDialogKind(id int64) string {
	if id > 0 {
		return "alias-edit"
	}
	return "alias"
}

func aliasDialogResourceID(id, domainID int64) int64 {
	if id > 0 {
		return id
	}
	return domainID
}

func aliasDialogTitle(id int64) string {
	if id > 0 {
		return "Edit alias"
	}
	return "Create alias"
}

func mailRelayStatus(settings types.MailSettingsView) string {
	if settings.SmarthostHost == "" {
		return "Direct delivery"
	}
	if settings.SmarthostConfigured {
		return settings.SmarthostHost + " (configured)"
	}
	return settings.SmarthostHost
}

func mailAlerts(items []types.UsageAlert, subscriptions []types.SubscriptionSummary) []types.UsageAlert {
	visible := make(map[int64]bool, len(subscriptions))
	for _, subscription := range subscriptions {
		visible[subscription.ID] = true
	}
	var out []types.UsageAlert
	for _, item := range items {
		kind := strings.ToLower(item.Kind)
		if visible[item.SubscriptionID] && (strings.Contains(kind, "mail") || strings.Contains(kind, "smtp")) {
			out = append(out, item)
		}
	}
	return out
}
