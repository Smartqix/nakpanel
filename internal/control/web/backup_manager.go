package web

import (
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	"github.com/nakroteck/nakpanel/internal/types"
	"sort"
)

type BackupRemovalView struct {
	Preview  types.BackupRemovalPreview
	Approval string
}

func backupRemovable(status string) bool {
	return status == "active" || status == "failed" || status == "delete_failed"
}
func backupStatusLabel(status string) string {
	if status == "active" {
		return "Ready"
	}
	if status == "deleting" {
		return "Removing"
	}
	if status == "delete_failed" {
		return "Removal failed"
	}
	return status
}
func backupDomains(backups []dashboard.Backup) []string {
	seen := map[string]bool{}
	var domains []string
	for _, b := range backups {
		if !seen[b.TargetName] {
			domains = append(domains, b.TargetName)
			seen[b.TargetName] = true
		}
	}
	sort.Strings(domains)
	return domains
}

func backupRestores(restores []dashboard.RestoreRun, backups []dashboard.Backup) []dashboard.RestoreRun {
	ids := map[int64]bool{}
	for _, b := range backups {
		ids[b.ID] = true
	}
	var result []dashboard.RestoreRun
	for _, run := range restores {
		if ids[run.BackupID] {
			result = append(result, run)
		}
	}
	return result
}
