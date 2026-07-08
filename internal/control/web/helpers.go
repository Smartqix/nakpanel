package web

import (
	"database/sql"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

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
	return fmt.Sprintf("%d B", size)
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
