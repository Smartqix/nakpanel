package web

import (
	"fmt"
	"time"

	"github.com/nakroteck/nakpanel/internal/control/operations"
)

func notificationTimeLabel(created, now time.Time) string {
	if created.IsZero() {
		return "Unknown time"
	}
	age := now.Sub(created)
	if age < time.Minute {
		return "Just now"
	}
	if age < time.Hour {
		return fmt.Sprintf("%d min ago", int(age/time.Minute))
	}
	if age < 24*time.Hour {
		return fmt.Sprintf("%d hr ago", int(age/time.Hour))
	}
	return created.UTC().Format("2 Jan 2006")
}

func notificationContext(n operations.Notification) string {
	if n.Target != "" {
		return n.Target
	}
	return "Workspace"
}

func notificationIcon(n operations.Notification) string {
	if n.Kind == "login_new_device" || n.Kind == "login_failed_burst" {
		return "shield"
	}
	if n.Severity == "critical" || n.Severity == "warning" {
		return "triangle-alert"
	}
	return "bell"
}

func notificationRowClass(n operations.Notification) string {
	if n.ReadAt == nil {
		return "np-notification-row np-notification-unread"
	}
	return "np-notification-row"
}

func notificationNow(p operations.Page) time.Time {
	if !p.CheckedAt.IsZero() {
		return p.CheckedAt
	}
	return time.Now().UTC()
}

func notificationScopeLabel(v WorkspaceView) string {
	if v.SelectedSubscription > 0 {
		return "Selected subscription"
	}
	if v.SupportCustomerID > 0 {
		return "Selected customer"
	}
	return "All resources in your workspace"
}

func notificationCountLabel(count int) string {
	if count > 0 {
		return fmt.Sprintf("%d unread", count)
	}
	return "All read"
}
