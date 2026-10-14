package provision

import (
	"context"
	"database/sql"
	"errors"
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"time"
)

type SiteRemovalAccessPolicy interface {
	CanRemoveSite(context.Context, auth.SessionUser, int64) (bool, error)
	CanRemoveSiteTx(context.Context, *sql.Tx, auth.SessionUser, int64) (bool, error)
	CanManageSubscription(context.Context, auth.SessionUser, int64) (bool, error)
}
type SiteRemovalUsageReader interface {
	CollectUsage(context.Context, types.CollectUsageReq) (types.CollectUsageResult, error)
}
type SiteRemovalOptions struct {
	PanelHostname string
	Now           func() time.Time
	Usage         SiteRemovalUsageReader
}
type SiteRemovalService struct {
	db      *sql.DB
	river   *river.Client[*sql.Tx]
	access  SiteRemovalAccessPolicy
	options SiteRemovalOptions
}

func NewSiteRemovalService(db *sql.DB, client *river.Client[*sql.Tx], access SiteRemovalAccessPolicy, opts SiteRemovalOptions) *SiteRemovalService {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &SiteRemovalService{db: db, river: client, access: access, options: opts}
}
func WithSiteRemovalService(service *SiteRemovalService) ManagerOption {
	return func(manager *Manager) { manager.siteRemoval = service }
}
func (m *Manager) PreviewSiteRemoval(ctx context.Context, actor auth.SessionUser, siteID int64) (types.SiteRemovalPreview, error) {
	if m.siteRemoval == nil {
		return types.SiteRemovalPreview{}, errors.New("website removal is not configured")
	}
	return m.siteRemoval.PreviewSiteRemoval(ctx, actor, siteID)
}
func (s *SiteRemovalService) authorizeSite(ctx context.Context, actor auth.SessionUser, siteID int64) error {
	if s == nil || s.db == nil || s.access == nil {
		return errors.New("website removal is not configured")
	}
	allowed, err := s.access.CanRemoveSite(ctx, actor, siteID)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrForbidden
	}
	return nil
}
