package provision

import (
	"context"
	"errors"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

func (m *Manager) PlanSynchronization(ctx context.Context, actor auth.SessionUser, planID int64) (types.PlanSynchronization, error) {
	if actor.Role != auth.RoleAdmin && actor.Role != auth.RoleReseller {
		return types.PlanSynchronization{}, ErrForbidden
	}
	if err := m.canManagePlan(ctx, actor, planID); err != nil {
		return types.PlanSynchronization{}, err
	}
	reader, ok := m.quotaAdmin.(interface {
		PlanSynchronization(context.Context, int64) (types.PlanSynchronization, error)
	})
	if !ok {
		return types.PlanSynchronization{}, errors.New("plan synchronization is not configured")
	}
	return reader.PlanSynchronization(ctx, planID)
}
