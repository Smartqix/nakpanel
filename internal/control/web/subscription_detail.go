package web

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
)

// limitRow is one "used against a limit" line. The same struct backs
// the compact rail on every tab and the full table on the Resources tab, so the
// two can never disagree about a figure or a severity.
type limitRow struct {
	Group       string
	Label       string
	Used        string
	Limit       string
	Note        string
	Tone        string
	Percent     string
	HasBar      bool
	Enforcement string
	Severity    int
}

const (
	limitToneOK   = ""
	limitToneFull = "warn"
	limitToneOver = "over"
)

func limitRowClass(row limitRow) string {
	switch row.Tone {
	case limitToneOver:
		return "np-usage-row is-over"
	case limitToneFull:
		return "np-usage-row is-full"
	default:
		return "np-usage-row"
	}
}

func limitBarClass(row limitRow) string {
	switch row.Tone {
	case limitToneOver:
		return "np-usage-bar is-over"
	case limitToneFull:
		return "np-usage-bar is-full"
	default:
		return "np-usage-bar"
	}
}

func limitRowMeterLabel(row limitRow) string {
	if row.Note != "" {
		return fmt.Sprintf("%s: %s of %s, %s", row.Label, row.Used, row.Limit, row.Note)
	}
	return fmt.Sprintf("%s: %s of %s", row.Label, row.Used, row.Limit)
}

// countLimitRow builds a row for a counted resource. A limit of zero means the
// plan grants none of it, which must not render as a full red bar: there is no
// denominator, so there is no bar.
func countLimitRow(group, label, field string, used, allowed int, unitNoun string) limitRow {
	row := limitRow{
		Group:       group,
		Label:       label,
		Used:        strconv.Itoa(used),
		Enforcement: planEnforcementLabel(field),
	}
	switch {
	case allowed < 0:
		row.Limit = "Unlimited"
		row.Note = "No limit, so no bar"
	case allowed == 0:
		row.Used = "—"
		row.Limit = "0"
		row.Note = "Not allowed by this plan"
		if used > 0 {
			row.Used = strconv.Itoa(used)
			row.Tone = limitToneOver
			row.Severity = 3
			row.Note = fmt.Sprintf("%d held although the plan allows none", used)
			row.HasBar = true
			row.Percent = "100"
		}
	default:
		row.Limit = strconv.Itoa(allowed)
		row.HasBar = true
		row.Percent = strconv.Itoa(percentOf(used, allowed))
		switch {
		case used > allowed:
			row.Tone = limitToneOver
			row.Severity = 3
			row.Note = fmt.Sprintf("%d over the %s allowance", used-allowed, unitNoun)
		case used == allowed:
			row.Tone = limitToneFull
			row.Severity = 2
			row.Note = "Allowance reached"
		case percentOf(used, allowed) >= 80:
			row.Tone = limitToneFull
			row.Severity = 1
			row.Note = fmt.Sprintf("%d left", allowed-used)
		}
	}
	return row
}

func percentOf(used, allowed int) int {
	if allowed <= 0 {
		return 0
	}
	percent := used * 100 / allowed
	if percent < 0 {
		return 0
	}
	if percent > 100 {
		return 100
	}
	return percent
}

// subscriptionLimitRows is every limit the plan carries, in reading order.
func subscriptionLimitRows(subscription types.SubscriptionSummary, data dashboard.Data) []limitRow {
	return []limitRow{
		countLimitRow("Hosting", "Domains", "max_sites", subscription.DomainsUsed, subscription.MaxSites, "domain"),
		countLimitRow("Hosting", "Subdomains", "max_subdomains", subscription.SubdomainsUsed, subscription.MaxSubdomains, "subdomain"),
		countLimitRow("Hosting", "Domain aliases", "max_domain_aliases", 0, subscription.MaxDomainAliases, "alias"),
		countLimitRow("Hosting", "Databases", "max_databases", subscription.DatabasesUsed, subscription.MaxDatabases, "database"),
		subscriptionMeasuredLimitRow(subscription, data, false),
		subscriptionMeasuredLimitRow(subscription, data, true),
		countLimitRow("Storage", "Backups", "max_backups", subscription.BackupsUsed, subscription.MaxBackups, "backup"),
		byteLimitRow("Storage", "Backup storage", "backup_storage_mb", subscription.BackupBytesUsed, subscription.BackupStorageMB),
		countLimitRow("Mail and access", "Mailboxes", "max_mailboxes", subscriptionMailboxesUsed(subscription, data), subscriptionMailboxLimit(subscription, data.SubscriptionServices.Accounts), "mailbox"),
		countLimitRow("Mail and access", "FTP accounts", "max_ftp_accounts", subscriptionFTPUsed(subscription, data), subscriptionFTPLimit(subscription, data.SubscriptionServices.Accounts), "account"),
	}
}

// subscriptionRailLimits is the short list the properties rail shows on every tab:
// anything in trouble first, then the four an operator always wants.
func subscriptionRailLimits(subscription types.SubscriptionSummary, data dashboard.Data) []limitRow {
	all := subscriptionLimitRows(subscription, data)
	keep := map[string]bool{"Domains": true, "Databases": true, "Backups": true, "Disk": true, "Monthly traffic": true}
	rows := make([]limitRow, 0, len(all))
	for _, row := range all {
		// A row with neither a bar nor a problem has nothing to say in the
		// compact rail; the full table on Resources still lists it.
		if row.Severity > 0 || (keep[row.Label] && row.HasBar) {
			rows = append(rows, row)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Severity > rows[j].Severity })
	if len(rows) > 6 {
		rows = rows[:6]
	}
	return rows
}

// subscriptionBreaches are the rows that put the subscription outside its plan.
func subscriptionBreaches(subscription types.SubscriptionSummary, data dashboard.Data) []limitRow {
	rows := make([]limitRow, 0, 4)
	for _, row := range subscriptionLimitRows(subscription, data) {
		if row.Tone == limitToneOver {
			rows = append(rows, row)
		}
	}
	return rows
}

func subscriptionBreachSentence(rows []limitRow) string {
	parts := make([]string, 0, len(rows))
	for _, row := range rows {
		parts = append(parts, fmt.Sprintf("%s %s against a limit of %s", strings.ToLower(row.Label), row.Used, row.Limit))
	}
	return joinWithAnd(parts)
}

func joinWithAnd(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	case 2:
		return parts[0] + " and " + parts[1]
	default:
		return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
	}
}

func subscriptionMailboxesUsed(subscription types.SubscriptionSummary, data dashboard.Data) int {
	count := 0
	for _, item := range data.SubscriptionServices.Mailboxes {
		if item.SubscriptionID == subscription.ID {
			count++
		}
	}
	return count
}

func subscriptionFTPUsed(subscription types.SubscriptionSummary, data dashboard.Data) int {
	return len(ftpForSubscription(data.SubscriptionServices.FTP, subscription.ID))
}

// subscriptionAccessObjects is the badge beside the Account Access tab: scoped
// identities plus the primary FTPS account, which is what that tab holds.
func subscriptionAccessObjects(subscription types.SubscriptionSummary, data dashboard.Data) int {
	return len(sftpForSubscription(data.SubscriptionServices.SFTP, subscription.ID)) + len(subscriptionPrimaryFTP(data.SubscriptionServices.FTP, subscription.ID))
}

func subscriptionBackupsForID(items []dashboard.Backup, subscriptionID int64) []dashboard.Backup {
	rows := make([]dashboard.Backup, 0)
	for _, item := range items {
		if item.SubscriptionID == subscriptionID {
			rows = append(rows, item)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].CreatedAt.After(rows[j].CreatedAt) })
	return rows
}

// subscriptionBackupBeyondPlan marks the oldest backups that exceed the limit,
// so the table can say which rows are the ones over it.
func subscriptionBackupBeyondPlan(items []dashboard.Backup, allowed int) map[int64]bool {
	beyond := make(map[int64]bool)
	if allowed < 0 || len(items) <= allowed {
		return beyond
	}
	for _, item := range items[allowed:] {
		beyond[item.ID] = true
	}
	return beyond
}

func subscriptionBackupBytes(items []dashboard.Backup) int64 {
	var total int64
	for _, item := range items {
		total += item.SizeBytes
	}
	return total
}

func subscriptionAuditEvents(data dashboard.Data, subscriptionID int64, limit int) []types.AuditEvent {
	rows := make([]types.AuditEvent, 0)
	for _, item := range data.AuditEvents {
		if item.SubscriptionID == subscriptionID {
			rows = append(rows, item)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].CreatedAt.After(rows[j].CreatedAt) })
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

// auditActionLabel turns a recorded action key into something an operator reads.
func auditActionLabel(action string) string {
	switch action {
	case "subscription.created":
		return "Subscription created"
	case "subscription.status_changed":
		return "Plan or status changed"
	case "subscription.synced":
		return "Synchronized with the plan"
	case "subscription.mode_changed":
		return "Entitlement source changed"
	case "subscription.policy_updated":
		return "Hosting policy applied"
	case "subscription.addons_saved":
		return "Add-ons applied"
	case "valkey.saved":
		return "Cache configuration applied"
	case "valkey.flushed":
		return "Cache flushed"
	case "site.created":
		return "Website added"
	case "site.deleted":
		return "Website removed"
	case "backup.created":
		return "Backup taken"
	case "backup.restored":
		return "Backup restored"
	case "sftp.created", "sftp.saved":
		return "SFTP identity added"
	case "ftp.created", "ftp.saved":
		return "FTPS account created or reset"
	case "scheduled_task.created":
		return "Scheduled task added"
	}
	trimmed := strings.ReplaceAll(strings.ReplaceAll(action, ".", " "), "_", " ")
	if trimmed == "" {
		return "Change recorded"
	}
	return strings.ToUpper(trimmed[:1]) + trimmed[1:]
}

func auditActionTone(action string) string {
	switch {
	case strings.Contains(action, "deleted"), strings.Contains(action, "failed"), strings.Contains(action, "flushed"):
		return "fail"
	case strings.Contains(action, "created"), strings.Contains(action, "synced"), strings.Contains(action, "restored"):
		return "ok"
	default:
		return "run"
	}
}

func auditActor(event types.AuditEvent) string {
	if strings.TrimSpace(event.ActorEmail) != "" {
		return event.ActorEmail
	}
	if event.ActorUserID > 0 {
		return "User #" + strconv.FormatInt(event.ActorUserID, 10)
	}
	return "system"
}

// subscriptionSyncModeLabel names the three entitlement sources in words rather
// than echoing the stored token.
func subscriptionSyncModeLabel(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "custom":
		return "Custom snapshot"
	case "locked":
		return "Locked"
	default:
		return "Follows the plan"
	}
}

func subscriptionSyncModeDetail(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "custom":
		return "Its own saved limits. Plan edits never reach it."
	case "locked":
		return "Keeps today's values. Plan edits are held until it is released."
	default:
		return "Plan edits reach this subscription automatically."
	}
}

func subscriptionSyncStatusWord(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "in_sync", "ok", "synced":
		return "In sync"
	case "pending", "queued":
		return "Waiting to apply"
	case "running":
		return "Applying"
	case "failed", "error":
		return "Failed to apply"
	case "":
		return "Not recorded"
	default:
		return displayState(status)
	}
}

func subscriptionComplianceRaw(subscription types.SubscriptionSummary) string {
	if subscription.ComplianceStatus == "" {
		return string(types.SubscriptionComplianceUnknown)
	}
	return string(subscription.ComplianceStatus)
}

func subscriptionComplianceWord(subscription types.SubscriptionSummary) string {
	switch subscription.ComplianceStatus {
	case types.SubscriptionComplianceCompliant:
		return "Within plan"
	case types.SubscriptionComplianceOverLimit:
		return "Over limit"
	case types.SubscriptionComplianceCapabilityBlocked:
		return "Capability blocked"
	default:
		return "Not checked"
	}
}

func subscriptionComplianceTone(subscription types.SubscriptionSummary) string {
	switch subscription.ComplianceStatus {
	case types.SubscriptionComplianceCompliant:
		return "ok"
	case types.SubscriptionComplianceOverLimit, types.SubscriptionComplianceCapabilityBlocked:
		return "fail"
	default:
		return "susp"
	}
}

func subscriptionStatusWord(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "active":
		return "Active"
	case "suspended":
		return "Suspended"
	case "cancelled", "canceled":
		return "Cancelled"
	case "":
		return "Unknown"
	default:
		return displayState(status)
	}
}

// accountStateWord describes a convergence state in words. The raw token stays
// on the element as a data attribute for anything that needs to match on it.
func accountStateWord(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "present", "enabled", "active":
		return "Present and enabled"
	case "absent", "removed":
		return "Removed"
	case "disabled":
		return "Present but disabled"
	case "":
		return "Not recorded"
	default:
		return displayState(state)
	}
}

func accountShellWord(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "jailed", "restricted":
		return "Jailed"
	case "full", "shell":
		return "Full shell"
	case "none", "nologin", "disabled":
		return "No shell"
	case "":
		return "Not recorded"
	default:
		return displayState(mode)
	}
}

func accountShellDetail(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "jailed", "restricted":
		return "SFTP and scheduled tasks only"
	case "full", "shell":
		return "Interactive login is permitted"
	case "none", "nologin", "disabled":
		return "No interactive or file access"
	default:
		return ""
	}
}

func accountSettled(account types.SubscriptionSystemAccount) bool {
	return account.LastError == "" && strings.EqualFold(strings.TrimSpace(account.DesiredState), strings.TrimSpace(account.AppliedState))
}

func displayState(value string) string {
	trimmed := strings.TrimSpace(strings.ReplaceAll(value, "_", " "))
	if trimmed == "" {
		return ""
	}
	return strings.ToUpper(trimmed[:1]) + trimmed[1:]
}

// valkeyStateWord reads the convergence status rather than comparing the
// desired and applied states: those two use different vocabularies ("enabled"
// against "running"), so a settled instance never compares equal.
func valkeyStateWord(instance types.ValkeyInstance) string {
	if instance.LastError != "" {
		return "Failed"
	}
	switch strings.ToLower(strings.TrimSpace(instance.ConvergenceStatus)) {
	case "in_sync", "ok", "ready":
		if strings.EqualFold(instance.DesiredState, "enabled") {
			return "Running"
		}
		return "Stopped"
	case "":
		return "Not recorded"
	default:
		return "Applying"
	}
}

func subscriptionMailAllowed(subscription types.SubscriptionSummary, accounts []types.SubscriptionSystemAccount) bool {
	account, found := accountForSubscription(accounts, subscription.ID)
	return found && account.EffectivePolicy.Permissions.Mail && account.EffectivePolicy.Mail.Enabled && account.EffectivePolicy.Resources.MaxMailboxes != 0
}

func subscriptionMailboxLimit(subscription types.SubscriptionSummary, accounts []types.SubscriptionSystemAccount) int {
	if account, found := accountForSubscription(accounts, subscription.ID); found {
		return account.EffectivePolicy.Resources.MaxMailboxes
	}
	return subscription.MaxMailboxes
}

func subscriptionFTPLimit(subscription types.SubscriptionSummary, accounts []types.SubscriptionSystemAccount) int {
	if account, found := accountForSubscription(accounts, subscription.ID); found {
		return account.EffectivePolicy.Resources.MaxFTPAccounts
	}
	return subscription.MaxFTPAccounts
}

func subscriptionFTPSBlocked(accounts []types.SubscriptionSystemAccount, subscriptionID int64) bool {
	account, found := accountForSubscription(accounts, subscriptionID)
	if !found {
		return true
	}
	return !account.EffectivePolicy.Permissions.FTPS || !account.EffectivePolicy.Access.FTPSEnabled
}

func subscriptionSFTPBlocked(accounts []types.SubscriptionSystemAccount, subscriptionID int64) bool {
	account, found := accountForSubscription(accounts, subscriptionID)
	if !found {
		return true
	}
	return !account.EffectivePolicy.Permissions.SFTP
}

func subscriptionTasksBlocked(accounts []types.SubscriptionSystemAccount, subscriptionID int64) bool {
	account, found := accountForSubscription(accounts, subscriptionID)
	if !found {
		return true
	}
	return !account.EffectivePolicy.Permissions.ScheduledTasks
}

func subscriptionApplicationsBlocked(accounts []types.SubscriptionSystemAccount, subscriptionID int64) bool {
	account, found := accountForSubscription(accounts, subscriptionID)
	if !found {
		return true
	}
	return !account.EffectivePolicy.Permissions.Applications
}

func subscriptionApplicationLimit(accounts []types.SubscriptionSystemAccount, subscriptionID int64) int {
	if account, found := accountForSubscription(accounts, subscriptionID); found {
		return account.EffectivePolicy.Resources.MaxApplications
	}
	return 0
}

// formatDateLabel renders a calendar day an operator can read at a glance.
func formatDateLabel(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format("2 Jan 2006")
}

// formatStampLabel renders a day and time without the year, for recent events.
func formatStampLabel(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format("2 Jan, 15:04")
}

// formatRelativeLabel renders how long ago something happened. It is always
// paired with an exact timestamp, never used on its own.
func formatRelativeLabel(value time.Time) string {
	return relativeTo(value, time.Now().UTC())
}

func relativeTo(value, now time.Time) string {
	if value.IsZero() {
		return ""
	}
	delta := now.Sub(value.UTC())
	if delta < 0 {
		delta = -delta
		switch {
		case delta < time.Minute:
			return "in a moment"
		case delta < time.Hour:
			return fmt.Sprintf("in %dm", int(delta.Minutes()))
		case delta < 24*time.Hour:
			return fmt.Sprintf("in %dh %dm", int(delta.Hours()), int(delta.Minutes())%60)
		default:
			return fmt.Sprintf("in %d days", int(delta.Hours())/24)
		}
	}
	switch {
	case delta < time.Minute:
		return "just now"
	case delta < time.Hour:
		return fmt.Sprintf("%d minutes ago", int(delta.Minutes()))
	case delta < 24*time.Hour:
		if int(delta.Hours()) == 1 {
			return "an hour ago"
		}
		return fmt.Sprintf("%d hours ago", int(delta.Hours()))
	case delta < 48*time.Hour:
		return "yesterday"
	case delta < 30*24*time.Hour:
		return fmt.Sprintf("%d days ago", int(delta.Hours())/24)
	default:
		return formatDateLabel(value)
	}
}

func subscriptionProviderLabel(subscription types.SubscriptionSummary) string {
	return formatProviderID(subscription.ResellerID)
}

func siteBackupCount(items []dashboard.Backup, siteID int64) int {
	return len(backupsForSite(items, siteID))
}

func siteDiskLabel(data dashboard.Data, siteID int64) string {
	if usage, ok := usageForSite(data.SubscriptionServices.SiteUsage, siteID); ok && usage.DocumentRootBytes > 0 {
		return formatBytes(usage.DocumentRootBytes)
	}
	return ""
}

func subscriptionModeClass(mode, target string) string {
	selected := mode == target
	if target == "synced" && mode != "locked" && mode != "custom" {
		selected = true
	}
	if selected {
		return "np-mode-choice is-selected"
	}
	return "np-mode-choice"
}

func limitTableRowClass(row limitRow) string {
	if row.Tone == limitToneOver {
		return "np-limit-over"
	}
	return ""
}

func backupRowClass(beyond bool) string {
	if beyond {
		return "np-limit-over"
	}
	return ""
}

func enabledTone(enabled bool) string {
	if enabled {
		return "ok"
	}
	return "susp"
}

func siteDomain(sites []dashboard.Site, siteID int64) string {
	for _, site := range sites {
		if site.ID == siteID {
			return site.Domain
		}
	}
	return ""
}

func subscriptionPrimaryFTP(items []types.FTPAccount, subscriptionID int64) []types.FTPAccount {
	rows := make([]types.FTPAccount, 0, 1)
	for _, item := range items {
		if item.SubscriptionID == subscriptionID && item.SiteID == 0 {
			rows = append(rows, item)
		}
	}
	return rows
}

func valkeyStateTone(instance types.ValkeyInstance) string {
	switch valkeyStateWord(instance) {
	case "Failed":
		return "fail"
	case "Running":
		return "ok"
	case "Applying":
		return "run"
	default:
		return "susp"
	}
}

func credentialWord(set bool) string {
	if set {
		return "Set"
	}
	return "Not set"
}

func formatSeconds(value int) string {
	if value <= 0 {
		return "No timeout"
	}
	return strconv.Itoa(value) + "s"
}

func formatPercent(value int) string {
	if value <= 0 {
		return "Unlimited"
	}
	return strconv.Itoa(value) + "%"
}

// byteLimitRow measures a resource whose usage is counted in bytes against a
// plan limit expressed in megabytes. Reporting 100 bytes as "0 MB" loses the
// only fact the row carries.
func byteLimitRow(group, label, field string, usedBytes int64, allowedMB int) limitRow {
	row := limitRow{
		Group:       group,
		Label:       label,
		Used:        formatBytes(usedBytes),
		Enforcement: planEnforcementLabel(field),
	}
	switch {
	case allowedMB < 0:
		row.Limit = "Unlimited"
		row.Note = "No limit, so no bar"
	case allowedMB == 0:
		row.Limit = "0"
		row.Note = "Not allowed by this plan"
	default:
		allowedBytes := int64(allowedMB) * 1024 * 1024
		row.Limit = formatPlanLimitMB(allowedMB)
		row.HasBar = true
		percent := int(usedBytes * 100 / allowedBytes)
		if percent > 100 {
			percent = 100
		}
		if percent < 0 {
			percent = 0
		}
		row.Percent = strconv.Itoa(percent)
		switch {
		case usedBytes > allowedBytes:
			row.Tone = limitToneOver
			row.Severity = 3
			row.Note = formatBytes(usedBytes-allowedBytes) + " over the limit"
		case percent >= 80:
			row.Tone = limitToneFull
			row.Severity = 1
			row.Note = formatBytes(allowedBytes-usedBytes) + " left"
		}
	}
	return row
}

func subscriptionDiskUsedBytes(subscription types.SubscriptionSummary, data dashboard.Data) int64 {
	if usage, found := subscriptionCollectedUsage(subscription, data); found {
		return usage.DiskBytes
	}
	return 0
}

func subscriptionTrafficUsedBytes(subscription types.SubscriptionSummary, data dashboard.Data) int64 {
	if usage, found := subscriptionCollectedUsage(subscription, data); found {
		return usage.TrafficBytes
	}
	return 0
}

func subscriptionCollectedUsage(subscription types.SubscriptionSummary, data dashboard.Data) (types.SubscriptionUsage, bool) {
	for _, usage := range data.SubscriptionUsage {
		if usage.SubscriptionID == subscription.ID {
			return usage, true
		}
	}
	return types.SubscriptionUsage{}, false
}

func subscriptionMeasuredLimitRow(subscription types.SubscriptionSummary, data dashboard.Data, traffic bool) limitRow {
	label, field, limit := "Disk", "disk_mb", subscription.DiskMB
	used := subscriptionDiskUsedBytes(subscription, data)
	if traffic {
		label, field, limit = "Monthly traffic", "bandwidth_mb", subscription.BandwidthMB
		used = subscriptionTrafficUsedBytes(subscription, data)
	}
	row := byteLimitRow("Storage", label, field, used, limit)
	usage, found := subscriptionCollectedUsage(subscription, data)
	if !found || usage.CollectedAt.IsZero() {
		row.Used, row.Note, row.HasBar = "Not measured", "Awaiting a complete usage scan", false
		row.Tone, row.Severity = "", 0
	} else if !usage.Complete {
		row.Note, row.HasBar = "Last recorded usage · collection incomplete", false
		row.Tone, row.Severity = "", 0
	}
	return row
}
