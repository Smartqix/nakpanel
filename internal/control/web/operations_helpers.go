package web

import (
	"net/url"
	"strconv"
	"strings"
)

func operationsTabLabel(s string) string {
	return map[string]string{"issues": "Issues", "tasks": "Tasks", "history": "History", "inbox": "Notifications", "preferences": "Preferences"}[s]
}
func operationsCurrent(a, b string) string {
	if a == b {
		return "page"
	}
	return "false"
}
func operationsActive(a, b string) string {
	if a == b {
		return "np-active"
	}
	return ""
}
func operationsScope(v WorkspaceView) string {
	q := url.Values{}
	if v.SelectedSubscription > 0 {
		q.Set("resource_kind", "subscription")
		q.Set("resource_id", strconv.FormatInt(v.SelectedSubscription, 10))
	} else if v.SupportCustomerID > 0 {
		q.Set("resource_kind", "customer")
		q.Set("resource_id", strconv.FormatInt(v.SupportCustomerID, 10))
	}
	return q.Encode()
}
func operationsPath(v WorkspaceView, tab string) string {
	path := workspacePath(v, "/activity")
	q := url.Values{"tab": []string{tab}}
	if v.SelectedSubscription > 0 {
		q.Set("subscription_id", strconv.FormatInt(v.SelectedSubscription, 10))
	}
	return path + "?" + q.Encode()
}
func operationsStateLabel(s string) string {
	if v := map[string]string{"queued": "Queued", "running": "Running", "waiting_retry": "Waiting to retry", "succeeded": "Succeeded", "failed": "Failed", "cancelled": "Cancelled", "open": "Open", "acknowledged": "Acknowledged", "checking": "Checking", "resolved": "Verified recovery"}[s]; v != "" {
		return v
	}
	return s
}
func operationsEventLabel(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, ".", " · "), "_", " ")
}
func operationsIssueTone(s string) string {
	if s == "critical" {
		return "fail"
	}
	return "pend"
}
