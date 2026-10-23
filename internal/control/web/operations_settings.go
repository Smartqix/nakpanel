package web

import (
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/operations"
)

type OperationIssueDetails struct {
	operations.Issue
	SettingsURL         string `json:"settings_url,omitempty"`
	SettingsLabel       string `json:"settings_label,omitempty"`
	SettingsUnavailable string `json:"settings_unavailable,omitempty"`
}

// DescribeOperationIssue consumes an already-authorized, current issue read.
// Destinations are fixed application routes; their GET handlers recheck access.
func DescribeOperationIssue(actor auth.SessionUser, issue operations.Issue) OperationIssueDetails {
	d := OperationIssueDetails{Issue: issue}
	if !issue.ResourceAvailable || !issue.Resource.Valid() {
		d.SettingsUnavailable = "This resource has been removed. Its settings are unavailable."
		return d
	}
	subject := strings.SplitN(issue.Condition, ":", 2)[0]
	switch issue.Resource.Kind {
	case operations.ResourceSite:
		tool, label := "overview", "website"
		switch issue.Kind {
		case "backup":
			tool, label = "backups", "backup"
		case "tls":
			tool, label = "ssl", "SSL/TLS"
		case "hosting":
			tool, label = "hosting", "hosting"
		case "mail":
			tool, label = "mail", "mail"
		case "dns":
			tool, label = "dns", "DNS"
		case "operation_failed":
			switch subject {
			case "run_scheduled_task":
				tool, label = "scheduled-tasks", "scheduled task"
			case "create_database":
				tool, label = "databases", "database"
			case "restore_backup":
				tool, label = "backups", "backup"
			case "deploy_php_release", "rollback_php_release":
				tool, label = "applications", "application"
			case "wordpress_operation":
				tool, label = "wordpress", "WordPress"
			case "run_staging_operation":
				tool, label = "staging", "staging"
			case "mail_import":
				tool, label = "mail-imports", "mail import"
			}
		}
		if tool == "mail-imports" {
			d.SettingsURL = "/sites/" + formatJobID(issue.Resource.ID) + "?tab=mail-imports"
		} else {
			d.SettingsURL = domainToolURL(issue.Resource.ID, tool, WorkspaceView{})
		}
		d.SettingsLabel = "Open " + label + " settings"
	case operations.ResourceSubscription:
		tab := "overview"
		switch issue.Kind {
		case "backup":
			tab = "backups"
		case "mail":
			tab = "mail"
		}
		if subject == "run_scheduled_task" {
			tab = "tasks"
		}
		d.SettingsURL = "/subscriptions/" + formatJobID(issue.Resource.ID) + "?tab=" + tab
		d.SettingsLabel = "Open subscription settings"
	case operations.ResourceCustomer:
		if actor.Role != auth.RoleClient {
			d.SettingsURL = "/customers/" + formatJobID(issue.Resource.ID)
			d.SettingsLabel = "Open customer settings"
		}
	case operations.ResourceUser:
		d.SettingsURL = "/activity?tab=preferences"
		d.SettingsLabel = "Open notification preferences"
	case operations.ResourceServer:
		if actor.Role == auth.RoleAdmin {
			tool := ""
			switch issue.Kind {
			case "mail":
				tool = "/mail"
			case "dns":
				tool = "/dns"
			case "backup":
				tool = "/backups"
			}
			switch subject {
			case "server_backup":
				tool = "/backups"
			case "system_control_service":
				tool = "/services"
			case "system_apply_updates":
				tool = "/server"
			}
			d.SettingsURL = "/tools-settings" + tool
			d.SettingsLabel = "Open server settings"
		}
	}
	if d.SettingsURL == "" {
		d.SettingsUnavailable = "Ask your provider to change these settings. They are unavailable in your current role."
	}
	return d
}
