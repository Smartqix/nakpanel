package types

import "encoding/json"

// Server-level backup ops. Requests carry decrypted destination credentials
// and the archive key: the agent never loads the panel keyring, and the
// Unix socket transport is already peer-UID gated (the same trust model as
// create_database's password field).
const (
	OpCreateServerBackup    = "create_server_backup"
	OpVerifyServerBackup    = "verify_server_backup"
	OpPruneServerBackups    = "prune_server_backups"
	OpTestBackupDestination = "test_backup_destination"
)

// BackupDestinationSpec identifies a destination with its non-secret settings
// JSON and decrypted credential payload.
type BackupDestinationSpec struct {
	Kind       string          `json:"kind"`
	Settings   json.RawMessage `json:"settings"`
	Credential []byte          `json:"credential,omitempty"`
}

type CreateServerBackupReq struct {
	Destination     BackupDestinationSpec `json:"destination"`
	ArchiveKey      []byte                `json:"archive_key"`
	ArchiveName     string                `json:"archive_name"`
	IncludeMailData bool                  `json:"include_mail_data"`
	TenantDatabases []string              `json:"tenant_databases,omitempty"`
	SystemUsers     []string              `json:"system_users,omitempty"`
	PanelVersion    string                `json:"panel_version,omitempty"`
	GooseVersion    int64                 `json:"goose_version,omitempty"`
	OperationID     string                `json:"operation_id,omitempty"`
}

type CreateServerBackupResult struct {
	ArchiveName      string `json:"archive_name"`
	SizeBytes        int64  `json:"size_bytes"`
	SHA256           string `json:"sha256"`
	KeyFingerprint   string `json:"key_fingerprint"`
	Entries          int    `json:"entries"`
	StalwartPausedMS int64  `json:"stalwart_paused_ms"`
	DurationMS       int64  `json:"duration_ms"`
}

type VerifyServerBackupReq struct {
	Destination    BackupDestinationSpec `json:"destination"`
	ArchiveKey     []byte                `json:"archive_key"`
	ArchiveName    string                `json:"archive_name"`
	ExpectedSHA256 string                `json:"expected_sha256,omitempty"`
}

type VerifyServerBackupResult struct {
	Entries         int   `json:"entries"`
	Bytes           int64 `json:"bytes"`
	PgRestoreListOK bool  `json:"pg_restore_list_ok"`
	DurationMS      int64 `json:"duration_ms"`
}

type PruneServerBackupsReq struct {
	Destination BackupDestinationSpec `json:"destination"`
	Delete      []string              `json:"delete,omitempty"`
}

type PruneServerBackupsResult struct {
	Deleted []string `json:"deleted,omitempty"`
	Remote  []string `json:"remote,omitempty"`
}

type TestBackupDestinationReq struct {
	Destination BackupDestinationSpec `json:"destination"`
}

type TestBackupDestinationResult struct {
	OK              bool   `json:"ok"`
	ObservedHostKey string `json:"observed_host_key,omitempty"`
	Detail          string `json:"detail,omitempty"`
}
