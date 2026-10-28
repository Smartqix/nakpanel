package provision

import (
	"context"
	"errors"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
)

func (m *Manager) DeletePlan(ctx context.Context, actor auth.SessionUser, planID int64) error {
	if (actor.Role != auth.RoleAdmin && actor.Role != auth.RoleReseller) || planID <= 0 {
		return ErrForbidden
	}
	if m.quotaAdmin == nil {
		return errors.New("plan management is not configured")
	}
	if err := m.canManagePlan(ctx, actor, planID); err != nil {
		return err
	}
	resellerID := int64(0)
	if actor.Role == auth.RoleReseller {
		scope, err := m.quotaAdmin.ProviderScopeForUser(ctx, actor)
		if err != nil {
			return err
		}
		if scope.ResellerID <= 0 {
			return ErrForbidden
		}
		resellerID = scope.ResellerID
	}
	err := m.quotaAdmin.DeletePlan(ctx, planID, resellerID, actor.Role == auth.RoleAdmin)
	if errors.Is(err, controlquota.ErrProviderScope) {
		return ErrForbidden
	}
	return err
}
