package types

const OpSiteServiceDependencies = "site_service_dependencies"

type SiteIdentity struct {
	SiteID         int64  `json:"site_id,omitempty"`
	SubscriptionID int64  `json:"subscription_id,omitempty"`
	Username       string `json:"username,omitempty"`
	Domain         string `json:"domain"`
}
