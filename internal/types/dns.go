package types

import "time"

type DNSSOASettings struct {
	PrimaryNameserver  string `json:"primary_nameserver"`
	ResponsibleMailbox string `json:"responsible_mailbox"`
	SerialFormat       string `json:"serial_format"`
	DefaultTTL         int    `json:"default_ttl"`
	RefreshSeconds     int    `json:"refresh_seconds"`
	RetrySeconds       int    `json:"retry_seconds"`
	ExpireSeconds      int    `json:"expire_seconds"`
	MinimumTTL         int    `json:"minimum_ttl"`
}

type DNSTemplateRecord struct {
	ID            int64  `json:"id,omitempty"`
	StableKey     string `json:"stable_key"`
	Scope         string `json:"scope"`
	HostTemplate  string `json:"host_template"`
	Type          string `json:"type"`
	ValueTemplate string `json:"value_template"`
	Priority      int    `json:"priority,omitempty"`
	Weight        int    `json:"weight,omitempty"`
	Port          int    `json:"port,omitempty"`
	TTL           int    `json:"ttl"`
}

type DNSTemplateRevision struct {
	ID                 int64               `json:"id"`
	Revision           int64               `json:"revision"`
	SOA                DNSSOASettings      `json:"soa"`
	ZoneStatus         string              `json:"zone_status"`
	SubdomainPolicy    string              `json:"subdomain_policy"`
	TransferCIDRs      []string            `json:"transfer_cidrs"`
	Records            []DNSTemplateRecord `json:"records"`
	CreatedBy          int64               `json:"created_by,omitempty"`
	CreatedAt          time.Time           `json:"created_at"`
	OptimisticRevision int64               `json:"optimistic_revision"`
}

type DNSZoneView struct {
	ID                int64          `json:"id"`
	SiteID            int64          `json:"site_id"`
	ParentZoneID      int64          `json:"parent_zone_id,omitempty"`
	Domain            string         `json:"domain"`
	Address           string         `json:"address"`
	IPv6Address       string         `json:"ipv6_address,omitempty"`
	Mode              string         `json:"mode"`
	UpstreamPrimaries []string       `json:"upstream_primaries"`
	TransferCIDRs     []string       `json:"transfer_cidrs"`
	SOA               DNSSOASettings `json:"soa"`
	TemplateRevision  int64          `json:"template_revision,omitempty"`
	TemplateStatus    string         `json:"template_status"`
	DesiredRevision   int64          `json:"desired_revision"`
	AppliedRevision   int64          `json:"applied_revision"`
	Status            string         `json:"status"`
	LastError         string         `json:"last_error,omitempty"`
	Records           []DNSRecord    `json:"records"`
}

type DNSSyncItem struct {
	ID            int64  `json:"id"`
	ZoneID        int64  `json:"zone_id"`
	OwnerSiteID   int64  `json:"owner_site_id,omitempty"`
	Domain        string `json:"domain"`
	Outcome       string `json:"outcome"`
	AddedCount    int    `json:"added_count"`
	UpdatedCount  int    `json:"updated_count"`
	RemovedCount  int    `json:"removed_count"`
	OverrideCount int    `json:"override_count"`
	ConflictCount int    `json:"conflict_count"`
	Detail        string `json:"detail,omitempty"`
}

type DNSSyncRun struct {
	ID                    int64         `json:"id"`
	TemplateRevision      int64         `json:"template_revision"`
	Scope                 string        `json:"scope"`
	Status                string        `json:"status"`
	PreviewToken          string        `json:"preview_token,omitempty"`
	ExpectedStateRevision int64         `json:"expected_state_revision"`
	TotalZones            int           `json:"total_zones"`
	ChangedZones          int           `json:"changed_zones"`
	FailedZones           int           `json:"failed_zones"`
	LastError             string        `json:"last_error,omitempty"`
	CreatedAt             time.Time     `json:"created_at"`
	CompletedAt           *time.Time    `json:"completed_at,omitempty"`
	Items                 []DNSSyncItem `json:"items,omitempty"`
}

type DNSTemplateView struct {
	Template   DNSTemplateRevision `json:"template"`
	RecentRuns []DNSSyncRun        `json:"recent_runs"`
	Preview    *DNSSyncRun         `json:"preview,omitempty"`
}

type DNSTemplateSettingsInput struct {
	ExpectedRevision int64          `json:"expected_revision"`
	SOA              DNSSOASettings `json:"soa"`
	ZoneStatus       string         `json:"zone_status"`
	SubdomainPolicy  string         `json:"subdomain_policy"`
	TransferCIDRs    []string       `json:"transfer_cidrs"`
}

type DNSZoneModeInput struct {
	Mode              string   `json:"mode"`
	UpstreamPrimaries []string `json:"upstream_primaries"`
	ExpectedRevision  int64    `json:"expected_revision"`
}
