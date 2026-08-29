package types

import "time"

const (
	OpQueryMailQueue       = "query_mail_queue"
	OpInspectQueuedMail    = "inspect_queued_mail"
	MailQueueStateQueued   = "queued"
	MailQueueStateDeferred = "deferred"
)

// MailQueueQueryReq is deliberately metadata-only. Message bodies and
// arbitrary Stalwart query expressions are never accepted from the panel.
type MailQueueQueryReq struct {
	State           string `json:"state,omitempty"`
	SenderDomain    string `json:"sender_domain,omitempty"`
	RecipientDomain string `json:"recipient_domain,omitempty"`
	OlderThanMins   int    `json:"older_than_minutes,omitempty"`
	Limit           int    `json:"limit"`
}

type InspectQueuedMailReq struct {
	MessageID string `json:"message_id"`
}

type MailQueueMessage struct {
	ID         string            `json:"id"`
	ReturnPath string            `json:"return_path"`
	State      string            `json:"state"`
	Domains    []MailQueueDomain `json:"domains,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	SizeBytes  int64             `json:"size_bytes"`
}

type MailQueueDomain struct {
	Name       string               `json:"name"`
	Status     string               `json:"status"`
	Recipients []MailQueueRecipient `json:"recipients,omitempty"`
	RetryCount int                  `json:"retry_count"`
	NextRetry  *time.Time           `json:"next_retry,omitempty"`
	ExpiresAt  *time.Time           `json:"expires_at,omitempty"`
}

type MailQueueRecipient struct {
	Address string `json:"address"`
	Status  string `json:"status"`
}

type MailQueueQueryResult struct {
	Messages  []MailQueueMessage `json:"messages"`
	Total     int                `json:"total"`
	Truncated bool               `json:"truncated"`
	CheckedAt time.Time          `json:"checked_at"`
}
