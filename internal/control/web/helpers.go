package web

import (
	"database/sql"
	"fmt"
	"math"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

type DashboardActions struct {
	CanCreateSite       bool
	CanCreateDatabase   bool
	CanIssueCertificate bool
	CanRetryJob         bool
	CanUsePhase6        bool
	CanManageQuotas     bool
	CanUseFileManager   bool
}

type WorkspaceView struct {
	Route                string
	Title                string
	DetailID             int64
	SelectedSubscription int64
	SelectedMailDomain   int64
	CSRFToken            string
	SupportCustomerID    int64
	SupportCustomerName  string
	PlanType             string
	PlanTab              string
	SearchQuery          string
	StatusFilter         string
	ProviderFilter       string
	CloneFrom            int64
	Tab                  string
	FileManager          *FileManagerView
	FileEditor           *FileEditorView
	MailSettings         types.MailSettingsView
	MailSettingsError    string
}

type FileManagerView struct {
	SiteID         int64
	Domain         string
	Username       string
	Path           string
	Entries        []types.FileEntry
	Directories    []types.FileEntry
	Total          int
	Page           int
	PerPage        int
	Query          string
	Sort           string
	Order          string
	UploadMaxBytes int64
	Error          string
}

type FileEditorView struct {
	SiteID  int64
	Domain  string
	Path    string
	Name    string
	Content string
	SHA256  string
	Mode    uint32
}

func databasesForSite(items []dashboard.Database, siteID int64) []dashboard.Database {
	result := make([]dashboard.Database, 0)
	for _, item := range items {
		if item.SiteID == siteID {
			result = append(result, item)
		}
	}
	return result
}

func backupsForSite(items []dashboard.Backup, siteID int64) []dashboard.Backup {
	result := make([]dashboard.Backup, 0)
	for _, item := range items {
		if item.SiteID == siteID {
			result = append(result, item)
		}
	}
	return result
}

func dnsZoneForSite(items []dashboard.DNSZone, siteID int64) (dashboard.DNSZone, bool) {
	for _, item := range items {
		if item.SiteID == siteID {
			return item, true
		}
	}
	return dashboard.DNSZone{}, false
}

func dnsRecordsForZone(items []types.DNSRecord, zoneID int64) []types.DNSRecord {
	result := make([]types.DNSRecord, 0)
	for _, item := range items {
		if item.ZoneID == zoneID {
			result = append(result, item)
		}
	}
	return result
}

func subscriptionForSite(items []types.SubscriptionSummary, site dashboard.Site) (types.SubscriptionSummary, bool) {
	return subscriptionByID(items, site.SubscriptionID)
}

func domainTabActive(current, candidate string) string {
	if current == candidate {
		return "is-active"
	}
	return ""
}

func phpVersions(allowlist string) []string {
	var result []string
	for _, item := range strings.Split(allowlist, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result = append(result, item)
		}
	}
	if len(result) == 0 {
		return []string{"8.3", "8.2"}
	}
	return result
}

func routeTitle(route string) string {
	switch route {
	case "dashboard":
		return "Home"
	case "sites", "site-detail", "site-files", "site-file-edit":
		return "Websites & Domains"
	case "databases":
		return "Databases"
	case "backups":
		return "Backups"
	case "dns":
		return "DNS"
	case "certificates":
		return "SSL/TLS Certificates"
	case "mail":
		return "Mail"
	case "activity":
		return "Activity"
	case "customers", "customer-detail":
		return "Customers"
	case "subscriptions", "subscription-detail", "subscription-new":
		return "Subscriptions"
	case "service-plans", "plan-detail", "plan-new", "addon-detail", "addon-new", "reseller-plan-new", "reseller-plan-detail":
		return "Service Plans"
	case "tools-settings":
		return "Tools & Settings"
	case "resellers", "reseller-detail":
		return "Resellers"
	case "reseller-plans":
		return "Reseller Plans"
	case "my-resources":
		return "My Resources"
	default:
		return "Nakpanel"
	}
}

func routeActive(route string, candidates ...string) string {
	for _, candidate := range candidates {
		if route == candidate {
			return "is-active"
		}
	}
	return ""
}

func planListType(view WorkspaceView) string {
	switch view.PlanType {
	case "addon", "reseller":
		return view.PlanType
	default:
		return "hosting"
	}
}

func planTypeClass(current, candidate string) string {
	if current == candidate {
		return "is-active"
	}
	return ""
}

func planEditorTab(view WorkspaceView) string {
	switch view.PlanTab {
	case "permissions", "hosting", "php", "mail", "dns", "performance", "logs", "applications":
		return view.PlanTab
	default:
		return "resources"
	}
}

func planTabClass(view WorkspaceView, tab string) string {
	if planEditorTab(view) == tab {
		return "is-active"
	}
	return ""
}

func planTabURL(view WorkspaceView, tab string) string {
	base := "/service-plans/new"
	switch view.Route {
	case "plan-detail":
		base = "/service-plans/" + strconv.FormatInt(view.DetailID, 10)
	case "addon-new":
		base = "/service-plans/addons/new"
	case "addon-detail":
		base = "/service-plans/addons/" + strconv.FormatInt(view.DetailID, 10)
	case "reseller-plan-new":
		base = "/service-plans/resellers/new"
	case "reseller-plan-detail":
		base = "/service-plans/resellers/" + strconv.FormatInt(view.DetailID, 10)
	}
	return base + "?tab=" + tab
}

func planEditorDefault(capabilities types.RuntimeCapabilities) controlquota.Plan {
	phpVersion := ""
	phpVersions := []string{}
	if len(capabilities.PHPVersions) > 0 {
		phpVersion = capabilities.PHPVersions[0]
		phpVersions = append(phpVersions, phpVersion)
	}
	return controlquota.Plan{Name: "", DiskMB: 5120, MaxSites: 1, MaxDatabases: 2, BandwidthMB: 102400,
		MaxMailboxes: 0, BackupRetentionDays: 7, PHPAllowlist: phpVersion, DefaultPHPVersion: phpVersion,
		PHPFPMMaxChildren: 3, PHPMemoryMB: 128, SiteDiskQuotaMB: 5120, MaxBackups: 7,
		BackupStorageMB: 5120, IsActive: true, OverusePolicy: types.PlanOveruseBlock,
		DiskWarningPercent: 80, TrafficWarningPercent: 80, MaxSubdomains: 0,
		MaxDomainAliases: 0, MaxFTPAccounts: 0, ValidityDays: -1, HostingEnabled: true,
		AllowDNS: true, AllowTLS: true, AllowBackups: true,
		Presets: types.PlanServicePresets{SchemaVersion: 1,
			Hosting: types.HostingPreset{WebServer: "nginx", PreferredDomain: "none", DefaultPHPVersion: phpVersion, AllowedPHPVersions: phpVersions},
			PHP:     types.PHPPreset{MaxExecutionSeconds: 30, MaxInputSeconds: 60, PostMaxMB: 128, UploadMaxMB: 128, FPMMaxRequests: 500, LogErrors: true},
			DNS:     types.DNSPreset{Mode: "primary", DefaultTTL: 3600}, Logs: types.LogsPreset{RotationEnabled: true, RetentionDays: 14}}}
}

func planForCreate(plans []controlquota.Plan, view WorkspaceView, capabilities types.RuntimeCapabilities) controlquota.Plan {
	if view.CloneFrom > 0 {
		if source, ok := planByID(plans, view.CloneFrom); ok {
			source.ID = 0
			source.Name += " Copy"
			source.IsActive = false
			source.Revision = 0
			return source
		}
	}
	return planEditorDefault(capabilities)
}

func addonEditorDefault() controlquota.Plan {
	return controlquota.Plan{IsActive: true, OverusePolicy: types.PlanOveruseBlock,
		DiskWarningPercent: 80, TrafficWarningPercent: 80,
		Presets: types.PlanServicePresets{SchemaVersion: 1}}
}

func planEditorLimitDisplayValue(value int, unit string) string {
	if value < 0 {
		return "0"
	}
	if unit == "MB" {
		switch planEditorLimitUnit(value) {
		case "TB":
			return strconv.Itoa(value / (1024 * 1024))
		case "GB":
			return strconv.Itoa(value / 1024)
		}
	}
	return strconv.Itoa(value)
}

func planEditorLimitUnit(value int) string {
	if value > 0 && value%(1024*1024) == 0 {
		return "TB"
	}
	if value > 0 && value%1024 == 0 {
		return "GB"
	}
	return "MB"
}

func planMatchesFilter(plan controlquota.Plan, view WorkspaceView) bool {
	if view.StatusFilter == "active" && !plan.IsActive || view.StatusFilter == "inactive" && plan.IsActive {
		return false
	}
	if view.ProviderFilter == "admin" && plan.ResellerID != 0 {
		return false
	}
	if view.ProviderFilter != "" && view.ProviderFilter != "admin" && view.ProviderFilter != strconv.FormatInt(plan.ResellerID, 10) {
		return false
	}
	query := strings.ToLower(strings.TrimSpace(view.SearchQuery))
	return query == "" || strings.Contains(strings.ToLower(plan.Name+" "+plan.Description), query)
}

func addonMatchesFilter(addon types.AddonPlan, view WorkspaceView) bool {
	if view.StatusFilter == "active" && !addon.IsActive || view.StatusFilter == "inactive" && addon.IsActive {
		return false
	}
	if view.ProviderFilter == "admin" && addon.ResellerID != 0 {
		return false
	}
	if view.ProviderFilter != "" && view.ProviderFilter != "admin" && view.ProviderFilter != strconv.FormatInt(addon.ResellerID, 10) {
		return false
	}
	query := strings.ToLower(strings.TrimSpace(view.SearchQuery))
	return query == "" || strings.Contains(strings.ToLower(addon.Name+" "+addon.Description), query)
}

func resellerPlanMatchesFilter(plan types.ResellerPlan, view WorkspaceView) bool {
	if view.StatusFilter == "active" && !plan.IsActive || view.StatusFilter == "inactive" && plan.IsActive {
		return false
	}
	if view.ProviderFilter != "" && view.ProviderFilter != "admin" {
		return false
	}
	query := strings.ToLower(strings.TrimSpace(view.SearchQuery))
	return query == "" || strings.Contains(strings.ToLower(plan.Name+" "+plan.Description), query)
}

func formatPlanPrice(value sql.NullInt64) string {
	if !value.Valid {
		return "Not set"
	}
	return fmt.Sprintf("$%.2f", float64(value.Int64)/100)
}

func planProvider(plan controlquota.Plan, resellers []types.Reseller) string {
	if plan.ResellerID == 0 {
		return "Administrator"
	}
	for _, reseller := range resellers {
		if reseller.ID == plan.ResellerID {
			if reseller.Company != "" {
				return reseller.Company
			}
			return reseller.DisplayName
		}
	}
	return "Reseller"
}

func planSubscriptionStats(planID int64, subscriptions []types.SubscriptionSummary) (int, int) {
	total, pending := 0, 0
	for _, subscription := range subscriptions {
		if subscription.PlanID != planID {
			continue
		}
		total++
		if subscription.SyncStatus != "" && subscription.SyncStatus != "in_sync" {
			pending++
		}
	}
	return total, pending
}

func planSubscriptionCount(planID int64, subscriptions []types.SubscriptionSummary) int {
	total, _ := planSubscriptionStats(planID, subscriptions)
	return total
}

func planSyncLabel(planID int64, subscriptions []types.SubscriptionSummary) string {
	_, pending := planSubscriptionStats(planID, subscriptions)
	if pending > 0 {
		return strconv.Itoa(pending) + " pending"
	}
	return "In sync"
}

func addonByID(items []types.AddonPlan, id int64) (types.AddonPlan, bool) {
	for _, item := range items {
		if item.ID == id {
			return item, true
		}
	}
	return types.AddonPlan{}, false
}

func addonProvider(addon types.AddonPlan, resellers []types.Reseller) string {
	return planProvider(controlquota.Plan{ResellerID: addon.ResellerID}, resellers)
}

func addonAsPlan(addon types.AddonPlan) controlquota.Plan {
	e := addon.Entitlements
	return controlquota.Plan{ID: addon.ID, Name: addon.Name, Description: addon.Description, DiskMB: e.DiskMB,
		MaxSites: e.MaxSites, MaxDatabases: e.MaxDatabases, BandwidthMB: e.BandwidthMB,
		MaxMailboxes: e.MaxMailboxes, AllowSSH: e.AllowSSH, AllowDNS: e.AllowDNS,
		BackupRetentionDays: e.BackupRetentionDays, PHPAllowlist: e.PHPAllowlist,
		PHPFPMMaxChildren: e.PHPFPMMaxChildren, PHPMemoryMB: e.PHPMemoryMB,
		SiteDiskQuotaMB: e.SiteDiskQuotaMB, MaxBackups: e.MaxBackups, BackupStorageMB: e.BackupStorageMB,
		MaxSubdomains: e.MaxSubdomains, MaxDomainAliases: e.MaxDomainAliases, MaxFTPAccounts: e.MaxFTPAccounts,
		AllowTLS: e.AllowTLS, AllowBackups: e.AllowBackups, AllowPHPSettings: e.AllowPHPSettings,
		Presets: e.ServicePresets, IsActive: addon.IsActive, Revision: addon.Revision,
		OverusePolicy: types.PlanOveruseBlock, DiskWarningPercent: 80, TrafficWarningPercent: 80,
		ValidityDays: -1, DefaultPHPVersion: e.DefaultPHPVersion}
}

func containsCSV(value, wanted string) bool {
	for _, item := range strings.Split(value, ",") {
		if strings.TrimSpace(item) == wanted {
			return true
		}
	}
	return false
}

func planEditorTitle(plan controlquota.Plan, addon bool) string {
	if plan.ID > 0 {
		return plan.Name
	}
	if addon {
		return "Add an Add-on"
	}
	return "Add a Plan"
}

func planEditorNameLabel(addon bool) string {
	if addon {
		return "Add-on name"
	}
	return "Plan name"
}

func planEditorDescription(plan controlquota.Plan, addon bool) string {
	if addon {
		return "Extend a subscription with additional resources and permissions."
	}
	if plan.ID > 0 {
		return "Edit the plan revision and synchronize eligible subscriptions."
	}
	return "Create a reusable hosting entitlement for new subscriptions."
}

func planEditorAction(addon bool) string {
	if addon {
		return "/addons"
	}
	return "/plans"
}

func planListBackURL(addon bool) string {
	if addon {
		return "/service-plans?type=addon"
	}
	return "/service-plans?type=hosting"
}

func planEditorSubmitLabel(plan controlquota.Plan, addon bool) string {
	if plan.ID == 0 {
		if addon {
			return "Create Add-on"
		}
		return "Create Plan"
	}
	if addon {
		return "Update Add-on"
	}
	return "Update & Sync"
}

func planEditorSaveTitle(plan controlquota.Plan, addon bool) string {
	if plan.ID == 0 {
		return "Create new revision source"
	}
	if addon {
		return "Save add-on revision"
	}
	return "Save and synchronize"
}

func planEditorSaveHint(plan controlquota.Plan, addon bool) string {
	if plan.ID == 0 {
		return "Limits are validated against provider capacity before saving."
	}
	if addon {
		return "Subscriptions using this add-on are queued for synchronization."
	}
	return "Locked and custom subscriptions are not changed."
}

func planPHPVersions(plan controlquota.Plan, capabilities types.RuntimeCapabilities) []string {
	seen := make(map[string]bool)
	var out []string
	for _, version := range capabilities.PHPVersions {
		if version = strings.TrimSpace(version); version != "" && !seen[version] {
			seen[version] = true
			out = append(out, version)
		}
	}
	for _, version := range strings.Split(plan.PHPAllowlist, ",") {
		if version = strings.TrimSpace(version); version != "" && !seen[version] {
			seen[version] = true
			out = append(out, version)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func stringInSlice(items []string, wanted string) bool {
	for _, item := range items {
		if item == wanted {
			return true
		}
	}
	return false
}

func subscriptionPHPVersions(items []types.SubscriptionSummary) []string {
	seen := make(map[string]bool)
	var out []string
	for _, item := range items {
		for _, version := range strings.Split(item.PHPAllowlist, ",") {
			if version = strings.TrimSpace(version); version != "" && !seen[version] {
				seen[version] = true
				out = append(out, version)
			}
		}
	}
	if len(out) == 0 {
		out = append(out, "8.3")
	}
	return out
}

func customSubscriptionPHPVersions(subscription types.SubscriptionSummary, capabilities types.RuntimeCapabilities) []string {
	return planPHPVersions(controlquota.Plan{PHPAllowlist: subscription.PHPAllowlist}, capabilities)
}

func ariaCurrent(active string) string {
	if active != "" {
		return "page"
	}
	return "false"
}

func customerByID(customers []types.Customer, id int64) (types.Customer, bool) {
	for _, customer := range customers {
		if customer.ID == id {
			return customer, true
		}
	}
	return types.Customer{}, false
}

func subscriptionByID(subscriptions []types.SubscriptionSummary, id int64) (types.SubscriptionSummary, bool) {
	for _, subscription := range subscriptions {
		if subscription.ID == id {
			return subscription, true
		}
	}
	return types.SubscriptionSummary{}, false
}

func siteByID(sites []dashboard.Site, id int64) (dashboard.Site, bool) {
	for _, item := range sites {
		if item.ID == id {
			return item, true
		}
	}
	return dashboard.Site{}, false
}

func planByID(plans []controlquota.Plan, id int64) (controlquota.Plan, bool) {
	for _, item := range plans {
		if item.ID == id {
			return item, true
		}
	}
	return controlquota.Plan{}, false
}

func resellerByID(items []types.Reseller, id int64) (types.Reseller, bool) {
	for _, item := range items {
		if item.ID == id {
			return item, true
		}
	}
	return types.Reseller{}, false
}
func customersForReseller(items []types.Customer, id int64) []types.Customer {
	var out []types.Customer
	for _, item := range items {
		if item.ResellerID == id {
			out = append(out, item)
		}
	}
	return out
}
func plansForReseller(items []controlquota.Plan, id int64) []controlquota.Plan {
	var out []controlquota.Plan
	for _, item := range items {
		if item.ResellerID == id {
			out = append(out, item)
		}
	}
	return out
}
func subscriptionsForReseller(items []types.SubscriptionSummary, id int64) []types.SubscriptionSummary {
	var out []types.SubscriptionSummary
	for _, item := range items {
		if item.ResellerID == id {
			out = append(out, item)
		}
	}
	return out
}
func addonsForProvider(items []types.AddonPlan, resellerID int64) []types.AddonPlan {
	result := make([]types.AddonPlan, 0, len(items))
	for _, item := range items {
		if item.ResellerID == resellerID && item.IsActive {
			result = append(result, item)
		}
	}
	return result
}
func providerName(customer types.Customer, resellers []types.Reseller) string {
	if customer.ResellerID == 0 {
		return "Administrator"
	}
	if r, ok := resellerByID(resellers, customer.ResellerID); ok {
		if r.DisplayName != "" {
			return r.DisplayName
		}
		return r.Email
	}
	return "Reseller"
}
func resellerPlanByName(items []types.ResellerPlan, name string) (types.ResellerPlan, bool) {
	for _, item := range items {
		if item.Name == name {
			return item, true
		}
	}
	return types.ResellerPlan{}, false
}

func resellerPlanByID(items []types.ResellerPlan, id int64) (types.ResellerPlan, bool) {
	for _, item := range items {
		if item.ID == id {
			return item, true
		}
	}
	return types.ResellerPlan{}, false
}

func resellerPlanDefault() types.ResellerPlan {
	return types.ResellerPlan{MaxCustomers: 10, MaxSubscriptions: 20, DiskMB: 102400,
		MaxSites: 20, MaxSubdomains: 40, MaxDomainAliases: 20, MaxDatabases: 40,
		BandwidthMB: 1024000, MaxMailboxes: 0, MaxFTPAccounts: 20, MaxBackups: 20,
		BackupStorageMB: 102400, AllowCustomPlans: true, AllowDNS: true, AllowTLS: true,
		AllowBackups: true, IsActive: true}
}

func resellerPlanEditorTitle(plan types.ResellerPlan) string {
	if plan.ID > 0 {
		return plan.Name
	}
	return "Add Reseller Plan"
}

func resellerPlanEditorSaveTitle(plan types.ResellerPlan) string {
	if plan.ID > 0 {
		return "Update reseller allocation"
	}
	return "Create reseller plan"
}

func resellerPlanEditorSubmitLabel(plan types.ResellerPlan) string {
	if plan.ID > 0 {
		return "Update Plan"
	}
	return "Create Plan"
}
func yesNo(value bool) string {
	if value {
		return "Yes"
	}
	return "No"
}
func planActiveStatus(value bool) string {
	if value {
		return "active"
	}
	return "inactive"
}
func formatProviderID(id int64) string {
	if id == 0 {
		return "Administrator"
	}
	return "Reseller #" + strconv.FormatInt(id, 10)
}

func subscriptionsForCustomer(items []types.SubscriptionSummary, customerID int64) []types.SubscriptionSummary {
	if customerID == 0 {
		return items
	}
	result := make([]types.SubscriptionSummary, 0)
	for _, item := range items {
		if item.CustomerID == customerID {
			result = append(result, item)
		}
	}
	return result
}

func sitesForCustomer(items []dashboard.Site, customerID int64) []dashboard.Site {
	if customerID == 0 {
		return items
	}
	result := make([]dashboard.Site, 0)
	for _, item := range items {
		if item.CustomerID == customerID {
			result = append(result, item)
		}
	}
	return result
}

func databasesForCustomer(items []dashboard.Database, customerID int64) []dashboard.Database {
	if customerID == 0 {
		return items
	}
	result := make([]dashboard.Database, 0)
	for _, item := range items {
		if item.CustomerID == customerID {
			result = append(result, item)
		}
	}
	return result
}

func selectedSubscription(items []types.SubscriptionSummary, selected int64) []types.SubscriptionSummary {
	if selected == 0 {
		return items
	}
	result := make([]types.SubscriptionSummary, 0, 1)
	for _, item := range items {
		if item.ID == selected {
			result = append(result, item)
		}
	}
	return result
}

func sitesForSubscription(items []dashboard.Site, subscriptionID int64) []dashboard.Site {
	if subscriptionID == 0 {
		return items
	}
	result := make([]dashboard.Site, 0)
	for _, item := range items {
		if item.SubscriptionID == subscriptionID {
			result = append(result, item)
		}
	}
	return result
}

func accountForSubscription(items []types.SubscriptionSystemAccount, subscriptionID int64) (types.SubscriptionSystemAccount, bool) {
	for _, item := range items {
		if item.SubscriptionID == subscriptionID {
			return item, true
		}
	}
	return types.SubscriptionSystemAccount{}, false
}

func sftpForSubscription(items []dashboard.SFTPIdentity, subscriptionID int64) []dashboard.SFTPIdentity {
	var out []dashboard.SFTPIdentity
	for _, item := range items {
		if item.SubscriptionID == subscriptionID {
			out = append(out, item)
		}
	}
	return out
}

func tasksForSubscription(items []dashboard.ScheduledTask, subscriptionID int64) []dashboard.ScheduledTask {
	var out []dashboard.ScheduledTask
	for _, item := range items {
		if item.SubscriptionID == subscriptionID {
			out = append(out, item)
		}
	}
	return out
}

func mailForSubscription(items []dashboard.MailDomain, subscriptionID int64) []dashboard.MailDomain {
	var out []dashboard.MailDomain
	for _, item := range items {
		if item.SubscriptionID == subscriptionID {
			out = append(out, item)
		}
	}
	return out
}

func mailboxesForSubscription(items []dashboard.Mailbox, subscriptionID int64) []dashboard.Mailbox {
	var out []dashboard.Mailbox
	for _, item := range items {
		if item.SubscriptionID == subscriptionID {
			out = append(out, item)
		}
	}
	return out
}

func mailAliasesForSubscription(items []dashboard.MailAlias, subscriptionID int64) []dashboard.MailAlias {
	var out []dashboard.MailAlias
	for _, item := range items {
		if item.SubscriptionID == subscriptionID {
			out = append(out, item)
		}
	}
	return out
}

func formatMailboxQuota(quotaMB int) string {
	if quotaMB <= 0 {
		return "Unlimited"
	}
	return fmt.Sprintf("%d MB", quotaMB)
}

func applicationsForSubscription(items []dashboard.Application, subscriptionID int64) []dashboard.Application {
	var out []dashboard.Application
	for _, item := range items {
		if item.SubscriptionID == subscriptionID {
			out = append(out, item)
		}
	}
	return out
}

func subscriptionTabPath(view WorkspaceView, subscriptionID int64, tab string) templ.SafeURL {
	return templ.SafeURL(workspacePath(view, "/subscriptions/"+formatJobID(subscriptionID)) + "?tab=" + tab)
}

func subscriptionTabClass(active, tab string) string {
	if active == tab {
		return "active"
	}
	return ""
}

func databasesForSubscription(items []dashboard.Database, subscriptionID int64) []dashboard.Database {
	if subscriptionID == 0 {
		return items
	}
	result := make([]dashboard.Database, 0)
	for _, item := range items {
		if item.SubscriptionID == subscriptionID {
			result = append(result, item)
		}
	}
	return result
}

func csrfField(token string) string { return token }

func workspacePath(view WorkspaceView, path string) string {
	if view.SupportCustomerID > 0 {
		if strings.HasPrefix(path, "/sites/") || strings.HasPrefix(path, "/subscriptions/") {
			return "/support/customers/" + strconv.FormatInt(view.SupportCustomerID, 10) + path
		}
		page := strings.TrimPrefix(path, "/")
		if strings.Contains(page, "/") {
			page = strings.Split(page, "/")[0]
		}
		if page == "" {
			page = "dashboard"
		}
		return "/support/customers/" + strconv.FormatInt(view.SupportCustomerID, 10) + "/" + page
	}
	return path
}

type fileCrumb struct{ Label, Path string }

func fileBasePath(view WorkspaceView, siteID int64) string {
	return workspacePath(view, "/sites/"+strconv.FormatInt(siteID, 10)+"/files")
}

func fileManagerPath(view WorkspaceView, siteID int64, rel string) string {
	base := fileBasePath(view, siteID)
	if strings.Trim(rel, "/") == "" {
		return base
	}
	return base + "?path=" + url.QueryEscape(strings.Trim(rel, "/"))
}

func fileActionPath(view WorkspaceView, siteID int64, action string, rel string) string {
	base := fileBasePath(view, siteID) + "/" + action
	if strings.Trim(rel, "/") == "" {
		return base
	}
	return base + "?path=" + url.QueryEscape(strings.Trim(rel, "/"))
}

func fileEntryPath(view WorkspaceView, siteID int64, action, rel string) string {
	return fileBasePath(view, siteID) + "/" + action + "?path=" + url.QueryEscape(rel)
}

func fileParent(rel string) string {
	rel = strings.Trim(rel, "/")
	if rel == "" {
		return ""
	}
	parent := path.Dir(rel)
	if parent == "." {
		return ""
	}
	return parent
}

func fileCrumbs(rel string) []fileCrumb {
	result := []fileCrumb{{Label: "public_html", Path: ""}}
	current := ""
	for _, part := range strings.Split(strings.Trim(rel, "/"), "/") {
		if part == "" {
			continue
		}
		current = path.Join(current, part)
		result = append(result, fileCrumb{Label: part, Path: current})
	}
	return result
}

func fileMode(mode uint32) string { return fmt.Sprintf("%04o", mode) }

func fileKindIcon(entry types.FileEntry) string {
	if entry.Kind == types.FileKindDirectory {
		return "folder"
	}
	if entry.Archive {
		return "file-archive"
	}
	switch strings.ToLower(path.Ext(entry.Name)) {
	case ".php", ".js", ".css", ".html", ".htm", ".json", ".xml", ".sh", ".sql", ".yaml", ".yml":
		return "file-code"
	default:
		return "file"
	}
}

func filePageCount(total, perPage int) int {
	if perPage <= 0 {
		return 1
	}
	pages := (total + perPage - 1) / perPage
	if pages < 1 {
		return 1
	}
	return pages
}

func filePagePath(view WorkspaceView, data *FileManagerView, pageNumber int) string {
	values := url.Values{}
	if data.Path != "" {
		values.Set("path", data.Path)
	}
	if data.Query != "" {
		values.Set("q", data.Query)
	}
	if data.Sort != "" {
		values.Set("sort", data.Sort)
	}
	if data.Order != "" {
		values.Set("order", data.Order)
	}
	values.Set("page", strconv.Itoa(pageNumber))
	return fileBasePath(view, data.SiteID) + "?" + values.Encode()
}

func fileSortPath(view WorkspaceView, data *FileManagerView, field string) string {
	values := url.Values{}
	if data.Path != "" {
		values.Set("path", data.Path)
	}
	if data.Query != "" {
		values.Set("q", data.Query)
	}
	current := strings.ToLower(strings.TrimSpace(data.Sort))
	if current == "" {
		current = "name"
	}
	values.Set("sort", field)
	if current == field && !strings.EqualFold(data.Order, "desc") {
		values.Set("order", "desc")
	} else {
		values.Set("order", "asc")
	}
	return fileBasePath(view, data.SiteID) + "?" + values.Encode()
}

func fileSortClass(data *FileManagerView, field string) string {
	current := strings.ToLower(strings.TrimSpace(data.Sort))
	if current == "" {
		current = "name"
	}
	className := "np-file-sort"
	if current == field {
		className += " is-active"
		if strings.EqualFold(data.Order, "desc") {
			className += " is-desc"
		} else {
			className += " is-asc"
		}
	}
	return className
}

func uploadLimitLabel(bytes int64) string { return formatBytes(bytes) }

func fileEmptyTitle(query string) string {
	if strings.TrimSpace(query) != "" {
		return "No matching files"
	}
	return "This folder is empty"
}

func fileEmptyCopy(query string) string {
	if strings.TrimSpace(query) != "" {
		return "Try another filename or open a different folder."
	}
	return "Upload content or create the first file or folder."
}

func canOpenSubscriptionDetails(view WorkspaceView) bool { return view.SupportCustomerID == 0 }

func subscriptionUsagePath(id int64, details bool, view WorkspaceView) string {
	if details {
		return "/subscriptions/" + strconv.FormatInt(id, 10)
	}
	return withSubscription(workspacePath(view, "/dashboard"), id)
}

func withSubscription(path string, subscriptionID int64) string {
	if subscriptionID <= 0 {
		return path
	}
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	return path + separator + "subscription_id=" + strconv.FormatInt(subscriptionID, 10)
}

func backupPhase6(data dashboard.Phase6Data) dashboard.Phase6Data {
	return dashboard.Phase6Data{Backups: data.Backups, Restores: data.Restores}
}

func retryActions(user auth.SessionUser) DashboardActions {
	return DashboardActions{CanRetryJob: user.Role == auth.RoleAdmin}
}

type usageMeterData struct {
	Percent string
	Class   string
}

func formatTLSStatus(site dashboard.Site) string {
	status := site.TLSStatus
	if status == "" {
		status = "none"
	}
	if site.TLSIssuer != "" {
		status += " / " + site.TLSIssuer
	}
	if site.TLSExpiresAt.Valid {
		status += " / expires " + site.TLSExpiresAt.Time.UTC().Format("2006-01-02")
	}
	return status
}

func formatTLSState(site dashboard.Site) string {
	if site.TLSStatus == "" {
		return "none"
	}
	return site.TLSStatus
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format("2006-01-02 15:04")
}

func formatUnix(value int64) string {
	if value <= 0 {
		return ""
	}
	return time.Unix(value, 0).UTC().Format("2006-01-02 15:04")
}

func formatNullableTime(value dashboard.NullableTime) string {
	if !value.Valid {
		return ""
	}
	return formatTime(value.Time)
}

func formatAttempts(job dashboard.Job) string {
	return fmt.Sprintf("%d / %d", job.Attempt, job.MaxAttempts)
}

func formatBytes(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	}
	units := []string{"KB", "MB", "GB", "TB"}
	value := float64(size)
	for _, unit := range units {
		value /= 1024
		if value < 1024 || unit == units[len(units)-1] {
			if value < 10 {
				return fmt.Sprintf("%.1f %s", value, unit)
			}
			return fmt.Sprintf("%.0f %s", value, unit)
		}
	}
	return fmt.Sprintf("%d B", size)
}

func formatEnabled(value bool) string {
	if value {
		return "Enabled"
	}
	return "Disabled"
}

func joinStrings(values []string) string { return strings.Join(values, ",") }

func policyForSite(items []dashboard.SitePolicy, siteID int64) (types.HostingPolicy, bool) {
	for _, item := range items {
		if item.SiteID == siteID {
			return item.EffectivePolicy, true
		}
	}
	return types.HostingPolicy{}, false
}

func statusPillClass(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "active", "completed", "ok", "healthy":
		return "ok"
	case "pending", "queued", "scheduled":
		return "pend"
	case "running", "provisioning", "restoring":
		return "run"
	case "failed", "discarded", "error":
		return "fail"
	default:
		return "susp"
	}
}

func usageMeter(used int, allowed int, hasLimits bool) usageMeterData {
	if !hasLimits {
		return usageMeterData{Percent: "0", Class: "none"}
	}
	if allowed < 0 {
		if used <= 0 {
			return usageMeterData{Percent: "0"}
		}
		percent := used + 1
		if percent > 100 {
			percent = 100
		}
		return usageMeterData{Percent: strconv.Itoa(percent)}
	}
	if allowed == 0 {
		return usageMeterData{Percent: "100", Class: "full"}
	}
	percent := int(math.Ceil((float64(used) / float64(allowed)) * 100))
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	class := ""
	if percent >= 100 {
		class = "full"
	} else if percent >= 80 {
		class = "hot"
	}
	return usageMeterData{Percent: strconv.Itoa(percent), Class: class}
}

func diskUsageMeter(summary controlquota.Summary) usageMeterData {
	usedMB := bytesToRoundedMB(summary.Usage.BackupStorageBytes)
	return usageMeter(usedMB, summary.Limits.StorageMB, summary.HasQuota)
}

func activeClass(active bool) string {
	if active {
		return "is-active"
	}
	return ""
}

func formatBadgeCount(value int) string {
	if value <= 0 {
		return ""
	}
	if value > 99 {
		return "99+"
	}
	return strconv.Itoa(value)
}

func initialWorkspaceTitle(title string, role auth.Role) string {
	if role == auth.RoleAdmin {
		return "Subscriptions"
	}
	return title
}

func userInitials(user auth.SessionUser) string {
	if user.Role == auth.RoleAdmin {
		return "RA"
	}
	prefix := strings.TrimSpace(strings.Split(user.Email, "@")[0])
	prefix = strings.ReplaceAll(prefix, ".", " ")
	fields := strings.Fields(prefix)
	if len(fields) >= 2 {
		return strings.ToUpper(string([]rune(fields[0])[0]) + string([]rune(fields[1])[0]))
	}
	runes := []rune(prefix)
	if len(runes) == 0 {
		return "NA"
	}
	if len(runes) == 1 {
		return strings.ToUpper(string(runes[0]))
	}
	return strings.ToUpper(string(runes[:2]))
}

func formatCapacityGB(valueMB int) string {
	return formatGBFromMB(valueMB)
}

func formatCapacityCommitment(committedMB int, capacityMB int) string {
	if committedMB < 0 {
		return "unlimited"
	}
	if capacityMB <= 0 {
		return fmt.Sprintf("%s / 0 GB", formatGBFromMB(committedMB))
	}
	percent := int(math.Round((float64(committedMB) / float64(capacityMB)) * 100))
	return fmt.Sprintf("%s / %s (%d%%)", formatGBFromMB(committedMB), formatGBFromMB(capacityMB), percent)
}

func capacityMeterWidth(committedMB int, capacityMB int) string {
	if committedMB <= 0 {
		return "0"
	}
	if capacityMB <= 0 {
		return "100"
	}
	percent := int(math.Round((float64(committedMB) / float64(capacityMB)) * 100))
	if percent < 1 {
		percent = 1
	}
	if percent > 100 {
		percent = 100
	}
	return strconv.Itoa(percent)
}

func formatUsedDiskGB(quotas []controlquota.Summary) string {
	var usedBytes int64
	for _, quota := range quotas {
		usedBytes += quota.Usage.BackupStorageBytes
	}
	return formatGBFromMB(bytesToRoundedMB(usedBytes))
}

func oversellActiveClass(current string, candidate string) string {
	if strings.EqualFold(current, candidate) {
		return "is-active"
	}
	return ""
}

func oversellPolicyCopy(policy string) string {
	if policy == controlquota.OversellPolicyCap {
		return "assignment is blocked when committed finite disk exceeds capacity."
	}
	return "assignment allowed past capacity; a warning string is returned. Most customers never fill quota."
}

func committedExceedsCapacity(committedMB int, capacityMB int) bool {
	return capacityMB > 0 && committedMB > capacityMB
}

func displayCustomerName(summary controlquota.Summary) string {
	local := strings.TrimSpace(strings.Split(summary.Email, "@")[0])
	if local == "" {
		return "Customer"
	}
	parts := strings.FieldsFunc(local, func(r rune) bool {
		return r == '.' || r == '_' || r == '-' || r == '+'
	})
	for i, part := range parts {
		if part == "" {
			continue
		}
		runes := []rune(strings.ToLower(part))
		runes[0] = []rune(strings.ToUpper(string(runes[0])))[0]
		parts[i] = string(runes)
	}
	if len(parts) == 0 {
		return "Customer"
	}
	return strings.Join(parts, " ")
}

func planPillClass(planName string) string {
	switch strings.ToLower(strings.TrimSpace(planName)) {
	case "business":
		return "np-plan-pill-business"
	case "pro":
		return "np-plan-pill-pro"
	case "starter":
		return "np-plan-pill-starter"
	default:
		return "np-plan-pill-muted"
	}
}

func siteLimitLabel(summary controlquota.Summary) string {
	if summary.HasQuota && summary.Limits.MaxSites >= 0 && summary.Usage.Sites >= summary.Limits.MaxSites {
		return "full"
	}
	return "sites"
}

func formatQuotaCompactCount(used int, allowed int, hasQuota bool) string {
	if !hasQuota {
		return "no plan"
	}
	if allowed < 0 {
		return fmt.Sprintf("%d/unlimited", used)
	}
	return fmt.Sprintf("%d/%d", used, allowed)
}

func formatQuotaCompactStorage(summary controlquota.Summary) string {
	used := formatGBFromMB(bytesToRoundedMB(summary.Usage.BackupStorageBytes))
	if !summary.HasQuota {
		return used + "/no plan"
	}
	if summary.Limits.StorageMB < 0 {
		return used + "/unlimited"
	}
	return fmt.Sprintf("%s/%s", used, formatGBFromMB(summary.Limits.StorageMB))
}

func subscriptionStatusLabel(summary controlquota.Summary) string {
	if summary.HasQuota {
		return "Active"
	}
	return "No plan"
}

func subscriptionStatusClass(summary controlquota.Summary) string {
	if summary.HasQuota {
		return "np-status-pill-active"
	}
	return "np-status-pill-muted"
}

func bytesToRoundedMB(value int64) int {
	usedMB := int(value / (1024 * 1024))
	if value > 0 && value%(1024*1024) != 0 {
		usedMB++
	}
	return usedMB
}

func formatGBFromMB(valueMB int) string {
	if valueMB < 0 {
		return "unlimited"
	}
	gb := float64(valueMB) / 1024
	if math.Abs(gb-math.Round(gb)) < 0.05 {
		return fmt.Sprintf("%.0f GB", math.Round(gb))
	}
	if gb > 0 && gb < 0.1 {
		return "0.1 GB"
	}
	return fmt.Sprintf("%.1f GB", gb)
}

func customerGateData(summary controlquota.Summary) map[string]string {
	return map[string]string{
		"user-id":         formatQuotaUserID(summary.UserID),
		"subscription-id": formatQuotaUserID(summary.SubscriptionID),
		"email":           summary.Email,
		"plan-name":       formatSummaryPlanName(summary),
		"has-quota":       formatBool(summary.HasQuota),
		"max-sites":       strconv.Itoa(summary.Limits.MaxSites),
		"sites-used":      strconv.Itoa(summary.Usage.Sites),
		"storage-mb":      strconv.Itoa(summary.Limits.StorageMB),
	}
}

func formatQuotaCount(used int, allowed int, hasQuota bool) string {
	if !hasQuota {
		return fmt.Sprintf("%d / no active subscription", used)
	}
	if allowed < 0 {
		return fmt.Sprintf("%d / unlimited", used)
	}
	return fmt.Sprintf("%d / %d", used, allowed)
}

func formatQuotaStorage(usedBytes int64, allowedMB int, hasQuota bool) string {
	usedMB := usedBytes / (1024 * 1024)
	if usedBytes > 0 && usedBytes%(1024*1024) != 0 {
		usedMB++
	}
	if !hasQuota {
		return fmt.Sprintf("%d MB / no active subscription", usedMB)
	}
	if allowedMB < 0 {
		return fmt.Sprintf("%d MB / unlimited", usedMB)
	}
	return fmt.Sprintf("%d MB / %d MB", usedMB, allowedMB)
}

func formatQuotaLimitMB(allowedMB int, hasQuota bool) string {
	if !hasQuota {
		return "no active subscription"
	}
	if allowedMB < 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d MB", allowedMB)
}

func formatQuotaPHP(summary controlquota.Summary) string {
	if !summary.HasQuota {
		return "no active subscription"
	}
	children := formatPHPChildrenLimit(summary.Limits.PHPFPMMaxChildren)
	memory := formatPHPMemoryLimit(summary.Limits.PHPMemoryMB)
	if children == "agent default" && memory == "agent default" {
		return "agent defaults"
	}
	return fmt.Sprintf("%s / %s", children, memory)
}

func formatPHPChildrenLimit(value int) string {
	if value < 0 {
		return "agent default"
	}
	return fmt.Sprintf("%d children", value)
}

func formatPHPMemoryLimit(value int) string {
	if value < 0 {
		return "agent default"
	}
	return fmt.Sprintf("%d MB", value)
}

func formatQuotaUserID(id int64) string {
	return fmt.Sprintf("%d", id)
}

func subscriptionCustomerID(summary controlquota.Summary, subscriptions []types.SubscriptionSummary) int64 {
	if summary.SubscriptionID > 0 {
		for _, subscription := range subscriptions {
			if subscription.ID == summary.SubscriptionID && subscription.CustomerID > 0 {
				return subscription.CustomerID
			}
		}
	}
	if summary.UserID > 0 {
		for _, subscription := range subscriptions {
			if subscription.CustomerUserID == summary.UserID && subscription.CustomerID > 0 {
				return subscription.CustomerID
			}
		}
	}
	if summary.Limits.CustomerID > 0 {
		return summary.Limits.CustomerID
	}
	if summary.Usage.CustomerID > 0 {
		return summary.Usage.CustomerID
	}
	return summary.UserID
}

func formatBool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func formatPlanID(id int64) string {
	return fmt.Sprintf("%d", id)
}

func formatPlanLimit(value int) string {
	if value < 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d", value)
}

func formatPlanLimitMB(value int) string {
	if value < 0 {
		return "unlimited"
	}
	const mbPerGB = 1024
	const mbPerTB = mbPerGB * 1024
	if value > 0 && value%mbPerTB == 0 {
		return fmt.Sprintf("%d TB", value/mbPerTB)
	}
	if value > 0 && value%mbPerGB == 0 {
		return fmt.Sprintf("%d GB", value/mbPerGB)
	}
	return fmt.Sprintf("%d MB", value)
}

func formatPlanLimitFormValue(value int) string {
	return fmt.Sprintf("%d", value)
}

func formatPlanPriceCents(value sql.NullInt64) string {
	if !value.Valid {
		return ""
	}
	return fmt.Sprintf("%d", value.Int64)
}

func formatPlanStatus(plan controlquota.Plan) string {
	if plan.IsActive {
		return "active"
	}
	return "inactive"
}

func oppositePlanStatus(plan controlquota.Plan) string {
	if plan.IsActive {
		return "false"
	}
	return "true"
}

func planStatusAction(plan controlquota.Plan) string {
	if plan.IsActive {
		return "Deactivate plan"
	}
	return "Activate plan"
}

func oppositeCustomerStatus(customer types.Customer) string {
	if customer.Status == "active" {
		return "suspended"
	}
	return "active"
}

func customerStatusAction(customer types.Customer) string {
	if customer.Status == "active" {
		return "Suspend"
	}
	return "Activate"
}

func isSiteRetryNotice(notice string) bool { return strings.Contains(notice, "first website") }

func formatPlanBool(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func formatPlanPHP(plan controlquota.Plan) string {
	children := formatPHPChildrenLimit(plan.PHPFPMMaxChildren)
	memory := formatPHPMemoryLimit(plan.PHPMemoryMB)
	if children == "agent default" && memory == "agent default" {
		return "agent defaults"
	}
	return fmt.Sprintf("%s / %s", children, memory)
}

func settingsPrimaryPlan(plans []controlquota.Plan) (controlquota.Plan, bool) {
	for _, plan := range plans {
		if plan.IsActive {
			return plan, true
		}
	}
	if len(plans) > 0 {
		return plans[0], true
	}
	return controlquota.Plan{}, false
}

func settingsDefaultPHPVersion(plans []controlquota.Plan) string {
	allowlist := settingsPHPAllowlist(plans)
	for _, candidate := range strings.Split(allowlist, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate != "" {
			return candidate
		}
	}
	return "agent default"
}

func settingsPHPAllowlist(plans []controlquota.Plan) string {
	if plan, ok := settingsPrimaryPlan(plans); ok && strings.TrimSpace(plan.PHPAllowlist) != "" {
		return strings.TrimSpace(plan.PHPAllowlist)
	}
	return "8.3,8.2"
}

func settingsPHPFPM(plans []controlquota.Plan) string {
	if plan, ok := settingsPrimaryPlan(plans); ok {
		return formatPlanPHP(plan)
	}
	return "agent defaults"
}

func settingsBackupRetention(plans []controlquota.Plan) string {
	if plan, ok := settingsPrimaryPlan(plans); ok {
		if plan.BackupRetentionDays < 0 {
			return "unlimited"
		}
		return fmt.Sprintf("%d days", plan.BackupRetentionDays)
	}
	return "30 days"
}

func settingsBackupLimits(plans []controlquota.Plan) string {
	if plan, ok := settingsPrimaryPlan(plans); ok {
		return fmt.Sprintf("%s backups / %s", formatPlanLimit(plan.MaxBackups), formatPlanLimitMB(plan.BackupStorageMB))
	}
	return "plan defaults"
}

func settingsSSHAccess(plans []controlquota.Plan) string {
	if plan, ok := settingsPrimaryPlan(plans); ok && plan.AllowSSH {
		return "allowed by active plan"
	}
	return "disabled by default"
}

func settingsPlannedStatus() string {
	return "Privileged agent op pending"
}

func formatCommittedDisk(value int) string {
	if value < 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d MB", value)
}

func formatSettingsCapacity(value int) string {
	return fmt.Sprintf("%d", value)
}

func formatSummaryPlanName(summary controlquota.Summary) string {
	if !summary.HasQuota || summary.PlanName == "" {
		return "No active subscription"
	}
	return summary.PlanName
}

func displayCustomer(customer types.Customer) string {
	if strings.TrimSpace(customer.DisplayName) != "" {
		return customer.DisplayName
	}
	if strings.TrimSpace(customer.Company) != "" {
		return customer.Company
	}
	return customer.Email
}

func customerStatusClass(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "active":
		return "np-status-pill-active"
	case "suspended":
		return "np-status-pill-pending"
	default:
		return "np-status-pill-failed"
	}
}

func customerLoginMode(customer types.Customer) string {
	if customer.LoginUserID > 0 {
		return "login enabled"
	}
	return "contact only"
}

func countCustomerSubscriptions(customerID int64, subscriptions []types.SubscriptionSummary) int {
	count := 0
	for _, subscription := range subscriptions {
		if subscription.CustomerID == customerID {
			count++
		}
	}
	return count
}

func subscriptionSelectLabel(subscription types.SubscriptionSummary) string {
	name := strings.TrimSpace(subscription.SubscriptionName)
	if name == "" {
		name = "Subscription " + formatQuotaUserID(subscription.ID)
	}
	owner := strings.TrimSpace(subscription.CustomerName)
	if owner == "" {
		owner = subscription.CustomerEmail
	}
	return fmt.Sprintf("%s - %s (%s)", owner, name, subscription.PlanName)
}

func formatReconcileSites(run dashboard.ReconciliationRun) string {
	return fmt.Sprintf("%d / %d", run.SitesOK, run.SitesTotal)
}

func formatJobID(id int64) string {
	return fmt.Sprintf("%d", id)
}

func canRetryJob(job dashboard.Job, actions DashboardActions) bool {
	return actions.CanRetryJob && job.State == "discarded"
}

func canRestoreBackup(backup dashboard.Backup) bool {
	return backup.ID > 0 && backup.Status == "active" && backup.ArchivePath != ""
}

func roleLabel(role auth.Role) string {
	switch role {
	case auth.RoleAdmin:
		return "Admin"
	case auth.RoleReseller:
		return "Reseller"
	case auth.RoleClient:
		return "Client"
	default:
		return "User"
	}
}

func roleScope(role auth.Role) string {
	switch role {
	case auth.RoleReseller:
		return "Customer portfolio"
	case auth.RoleClient:
		return "Hosting account"
	default:
		return "Account"
	}
}

func errorMessages(messages ...string) []string {
	visible := make([]string, 0, len(messages))
	for _, message := range messages {
		if message != "" {
			visible = append(visible, message)
		}
	}
	return visible
}
