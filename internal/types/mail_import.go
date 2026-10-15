package types

import "time"

// Credentials are input-only; durable imports reference encrypted secrets.
type MailImportRequest struct {
	MailboxID      int64  `json:"mailbox_id"`
	SourceKind     string `json:"source_kind"`
	SourceHost     string `json:"source_host,omitempty"`
	SourcePort     int    `json:"source_port,omitempty"`
	SourceUser     string `json:"source_user,omitempty"`
	StagingID      string `json:"staging_id,omitempty"`
	SourceSecretID string `json:"-"`
	TargetSecretID string `json:"-"`
	SourcePassword string `json:"-"`
	TargetPassword string `json:"-"`
}

type MailImportPreview struct {
	ID        string            `json:"id"`
	Request   MailImportRequest `json:"request"`
	ExpiresAt time.Time         `json:"expires_at"`
}

type MailImport struct {
	ID             string    `json:"id"`
	MailboxID      int64     `json:"mailbox_id"`
	SubscriptionID int64     `json:"subscription_id"`
	State          string    `json:"state"`
	Revision       int64     `json:"revision"`
	Discovered     int64     `json:"discovered"`
	Copied         int64     `json:"copied"`
	Verified       int64     `json:"verified"`
	Failed         int64     `json:"failed"`
	Uncertain      int64     `json:"uncertain"`
	LastError      string    `json:"last_error,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}
