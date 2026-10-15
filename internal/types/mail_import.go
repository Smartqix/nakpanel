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
	ManifestSHA256 string `json:"manifest_sha256,omitempty"`
	SourceSecretID string `json:"-"`
	TargetSecretID string `json:"-"`
	SourcePassword string `json:"-"`
	TargetPassword string `json:"-"`
}

type MailImportPreview struct {
	ID        string             `json:"id"`
	Request   MailImportRequest  `json:"request"`
	ExpiresAt time.Time          `json:"expires_at"`
	Folders   []MailImportFolder `json:"folders"`
}
type MailImportFolder struct {
	ID       int64  `json:"id"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	Messages int64  `json:"messages"`
	Bytes    int64  `json:"bytes"`
	Approved bool   `json:"approved"`
}
type MailImportMapping struct {
	FolderID int64
	Target   string
	Include  bool
}
type MailImportMailbox struct {
	ID      int64  `json:"id"`
	Address string `json:"address"`
	Active  bool   `json:"active"`
}
type MailImportWorkspace struct {
	SiteID         int64               `json:"site_id"`
	SubscriptionID int64               `json:"subscription_id"`
	Domain         string              `json:"domain"`
	Mailboxes      []MailImportMailbox `json:"mailboxes"`
	Imports        []MailImport        `json:"imports"`
	Selected       *MailImport         `json:"selected,omitempty"`
	Folders        []MailImportFolder  `json:"folders"`
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
	Excluded       int64     `json:"excluded"`
	LastError      string    `json:"last_error,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

const (
	OpStageMaildir       = "stage_maildir"
	OpInspectMaildir     = "inspect_maildir"
	OpReadMaildirMessage = "read_maildir_message"
)

type StageMaildirReq struct {
	SubscriptionID int64  `json:"subscription_id"`
	UploadID       string `json:"upload_id"`
}
type StageMaildirResult struct {
	StagingID      string `json:"staging_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Messages       int    `json:"messages"`
}
type InspectMaildirReq struct {
	SubscriptionID int64  `json:"subscription_id"`
	StagingID      string `json:"staging_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Offset         int    `json:"offset"`
	Limit          int    `json:"limit"`
}
type MaildirMessage struct {
	Key          string    `json:"key"`
	Folder       string    `json:"folder"`
	SHA256       string    `json:"sha256"`
	Size         int64     `json:"size"`
	InternalDate time.Time `json:"internal_date"`
	Flags        []string  `json:"flags"`
}
type InspectMaildirResult struct {
	Messages       []MaildirMessage `json:"messages"`
	Total          int              `json:"total"`
	NextOffset     int              `json:"next_offset"`
	ManifestSHA256 string           `json:"manifest_sha256"`
}
type ReadMaildirMessageReq struct {
	SubscriptionID int64  `json:"subscription_id"`
	StagingID      string `json:"staging_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Key            string `json:"key"`
	Offset         int64  `json:"offset"`
	Limit          int    `json:"limit"`
}
type ReadMaildirMessageResult struct {
	Data   []byte `json:"data"`
	EOF    bool   `json:"eof"`
	SHA256 string `json:"sha256"`
}
