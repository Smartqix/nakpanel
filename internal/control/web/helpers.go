package web

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
)

type DashboardActions struct {
	CanCreateSite       bool
	CanCreateDatabase   bool
	CanIssueCertificate bool
	CanRetryJob         bool
	CanUsePhase6        bool
	CanManageQuotas     bool
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
