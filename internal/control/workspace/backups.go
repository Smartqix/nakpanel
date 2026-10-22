package workspace

import (
	"context"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
)

func (s *Store) SubscriptionIDForBackup(ctx context.Context, id int64) (int64, error) {
	var subscriptionID int64
	err := s.db.QueryRowContext(ctx, `SELECT subscription_id FROM backups WHERE id=$1`, id).Scan(&subscriptionID)
	return subscriptionID, err
}

func (s *Store) SubscriptionBackups(ctx context.Context, actor auth.SessionUser, id int64, page int) ([]dashboard.Backup, bool, error) {
	allowed, err := s.CanManageSubscription(ctx, actor, id)
	if err != nil {
		return nil, false, err
	}
	if !allowed {
		return nil, false, ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,target_name,status,archive_path,size_bytes,last_error,created_at,COALESCE(site_id,0),subscription_id FROM backups WHERE subscription_id=$1 ORDER BY created_at DESC,id DESC LIMIT 51 OFFSET $2`, id, page*50)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var result []dashboard.Backup
	for rows.Next() {
		var b dashboard.Backup
		if err = rows.Scan(&b.ID, &b.TargetName, &b.Status, &b.ArchivePath, &b.SizeBytes, &b.LastError, &b.CreatedAt, &b.SiteID, &b.SubscriptionID); err != nil {
			return nil, false, err
		}
		result = append(result, b)
	}
	if err = rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(result) > 50
	if more {
		result = result[:50]
	}
	return result, more, nil
}
