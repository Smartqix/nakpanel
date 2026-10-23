package types

import "time"

const OpInspectSiteReadiness = "inspect_site_readiness"

type InspectSiteReadinessReq struct {
	SiteID         int64  `json:"site_id"`
	SubscriptionID int64  `json:"subscription_id"`
	Username       string `json:"username"`
	Domain         string `json:"domain"`
	PHPVersion     string `json:"php_version"`
}
type ReadinessCheck struct {
	Code   string `json:"code"`
	Passed bool   `json:"passed"`
}
type SiteReadinessResult struct {
	Ready     bool             `json:"ready"`
	Checks    []ReadinessCheck `json:"checks"`
	CheckedAt time.Time        `json:"checked_at"`
}
