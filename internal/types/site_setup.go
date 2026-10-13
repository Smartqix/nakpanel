package types

import "time"

type SiteSetupStep struct {
	Code  string `json:"code"`
	Label string `json:"label"`
	State string `json:"state"`
}

type SiteSetupStatus struct {
	Kind           string          `json:"kind"`
	SSLRequested   bool            `json:"ssl_requested"`
	CanRetrySSL    bool            `json:"-"`
	SiteID         int64           `json:"site_id"`
	ParentID       int64           `json:"parent_id"`
	ParentDomain   string          `json:"-"`
	CustomerID     int64           `json:"-"`
	SubscriptionID int64           `json:"-"`
	Domain         string          `json:"domain"`
	State          string          `json:"state"`
	Message        string          `json:"message"`
	Steps          []SiteSetupStep `json:"steps"`
	StartedAt      time.Time       `json:"-"`
}
