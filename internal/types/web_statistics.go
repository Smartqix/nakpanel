package types

import "time"

const (
	OpGenerateWebStatistics = "generate_web_statistics"
	OpReadWebStatistics     = "read_web_statistics"
	OpWebStatisticsStatus   = "web_statistics_status"
)

// No paths or command arguments cross this privileged boundary.
type WebStatisticsRequest struct {
	SiteID           int64  `json:"site_id"`
	Domain           string `json:"domain"`
	Username         string `json:"username"`
	Generation       int64  `json:"generation"`
	RetainGeneration int64  `json:"retain_generation,omitempty"`
	RetentionDays    int    `json:"retention_days"`
	AnonymizeIP      bool   `json:"anonymize_ip"`
}

type WebStatisticsSummary struct {
	Requests    int64     `json:"requests"`
	Visitors    int64     `json:"visitors"`
	Bandwidth   int64     `json:"bandwidth"`
	Errors      int64     `json:"errors"`
	GeneratedAt time.Time `json:"generated_at"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
}

type WebStatisticsResult struct {
	Summary WebStatisticsSummary `json:"summary"`
	HTML    []byte               `json:"html,omitempty"`
}

type WebStatisticsStatus struct {
	Available bool   `json:"available"`
	Version   string `json:"version"`
}
