package types

const OpReadBackupChunk = "read_backup_chunk"

type ReadBackupChunkReq struct {
	BackupID       int64  `json:"backup_id"`
	SubscriptionID int64  `json:"subscription_id"`
	Domain         string `json:"domain"`
	ArchivePath    string `json:"archive_path"`
	SHA256         string `json:"sha256"`
	Offset         int64  `json:"offset"`
	Limit          int    `json:"limit"`
}
type ReadBackupChunkResult struct {
	SHA256   string `json:"checksum_sha256"`
	BackupID int64  `json:"backup_id"`
	Offset   int64  `json:"offset"`
	Size     int64  `json:"size"`
	Data     []byte `json:"data"`
}
