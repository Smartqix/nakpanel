package provision

import (
	"context"
	"database/sql"
	"errors"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

type BackupChunkReader interface {
	ReadBackupChunk(context.Context, types.ReadBackupChunkReq) (types.ReadBackupChunkResult, error)
}

func WithBackupChunkReader(reader BackupChunkReader) ManagerOption {
	return func(m *Manager) { m.backupReader = reader }
}
func (m *Manager) ReadBackupFor(ctx context.Context, actor auth.SessionUser, backupID, offset int64, limit int) (types.ReadBackupChunkResult, error) {
	var result types.ReadBackupChunkResult
	if err := m.canManageBackup(ctx, actor, backupID); err != nil {
		return result, err
	}
	repository, ok := m.phase6Repo.(interface {
		BackupDownloadRequest(context.Context, int64) (types.ReadBackupChunkReq, error)
	})
	if !ok || m.backupReader == nil {
		return result, errors.New("backup download is not configured")
	}
	req, err := repository.BackupDownloadRequest(ctx, backupID)
	if err != nil {
		return result, err
	}
	req.Offset = offset
	req.Limit = limit
	result, err = m.backupReader.ReadBackupChunk(ctx, req)
	if err == nil {
		result.SHA256 = req.SHA256
	}
	return result, err
}
func (r *SQLPhase6Repository) BackupDownloadRequest(ctx context.Context, id int64) (types.ReadBackupChunkReq, error) {
	var req types.ReadBackupChunkReq
	err := r.db.QueryRowContext(ctx, `SELECT id,subscription_id,target_name,archive_path,checksum_sha256 FROM backups WHERE id=$1 AND status='active' AND archive_path<>'' AND checksum_sha256<>''`, id).Scan(&req.BackupID, &req.SubscriptionID, &req.Domain, &req.ArchivePath, &req.SHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return req, ErrForbidden
	}
	return req, err
}
