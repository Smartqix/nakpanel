package provision

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

type planPHPVersionsStore interface {
	GetPlan(context.Context, int64) (controlquota.Plan, error)
	PreviewPlanPHPVersions(context.Context, controlquota.PlanPHPVersionsCommand) (controlquota.PlanPHPVersionsPreview, error)
	UpdatePlanPHPVersions(context.Context, controlquota.PlanPHPVersionsCommand) (controlquota.PlanPHPVersionsResult, error)
}

func (m *Manager) planPHPCommand(ctx context.Context, actor auth.SessionUser, id int64, input controlquota.PlanPHPVersionsInput) (planPHPVersionsStore, controlquota.PlanPHPVersionsCommand, []types.PlanCapabilityIssue, error, error) {
	cmd := controlquota.PlanPHPVersionsCommand{PlanID: id, Actor: actor}
	if actor.Role != auth.RoleAdmin && actor.Role != auth.RoleReseller {
		return nil, cmd, nil, nil, ErrForbidden
	}
	if id <= 0 {
		return nil, cmd, nil, nil, &controlquota.PlanPHPRejectedError{Cause: errors.New("positive plan id is required")}
	}
	if err := m.canManagePlan(ctx, actor, id); err != nil {
		return nil, cmd, nil, nil, err
	}
	store, ok := m.quotaAdmin.(planPHPVersionsStore)
	if !ok {
		return nil, cmd, nil, nil, errors.New("PHP plan maintenance is not configured")
	}
	var err error
	cmd.Input, err = controlquota.NormalizePlanPHPVersions(input)
	if err != nil {
		return nil, cmd, nil, nil, err
	}
	plan, err := store.GetPlan(ctx, id)
	if err != nil {
		return nil, cmd, nil, nil, err
	}
	if plan.Revision != input.ExpectedRevision {
		return nil, cmd, nil, nil, &controlquota.PlanPHPConflictError{Code: "stale_revision", PlanID: id, ExpectedRevision: input.ExpectedRevision, CurrentRevision: plan.Revision}
	}
	cmd.Scope = types.ProviderScope{ActorUserID: actor.ID, Role: string(actor.Role)}
	if actor.Role == auth.RoleReseller {
		cmd.Scope, err = m.quotaAdmin.ProviderScopeForUser(ctx, actor)
		if err != nil {
			return nil, cmd, nil, nil, err
		}
		if cmd.Scope.ResellerID <= 0 || cmd.Scope.ResellerID != plan.ResellerID {
			return nil, cmd, nil, nil, ErrForbidden
		}
	}
	if m.capabilities == nil {
		return store, cmd, nil, &controlquota.PlanPHPReadinessError{Cause: errors.New("runtime capability reader is not configured")}, nil
	}
	capabilities, err := m.capabilities.RuntimeCapabilities(ctx)
	if err != nil {
		return store, cmd, nil, &controlquota.PlanPHPReadinessError{Cause: err}, nil
	}
	cmd.ReadyPHPVersions = controlquota.ReadyPHPVersions(capabilities)
	var readiness error
	if len(cmd.ReadyPHPVersions) == 0 {
		readiness = &controlquota.PlanPHPReadinessError{Cause: errors.New("empty authoritative runtime inventory")}
	} else {
		available := make(map[string]bool, len(cmd.ReadyPHPVersions))
		for _, version := range cmd.ReadyPHPVersions {
			available[version] = true
		}
		var missing []string
		for _, version := range cmd.Input.PHPVersions {
			if !available[version] {
				missing = append(missing, version)
			}
		}
		if len(missing) > 0 {
			readiness = &controlquota.PlanPHPReadinessError{UnreadyVersions: missing}
		}
	}
	candidate := plan
	candidate.PHPAllowlist = strings.Join(cmd.Input.PHPVersions, ",")
	candidate.DefaultPHPVersion = cmd.Input.DefaultPHPVersion
	candidate.HostingPolicy = controlquota.EffectivePlanHostingPolicy(candidate)
	candidate.HostingPolicy.PHP.AllowedVersions = cmd.Input.PHPVersions
	candidate.HostingPolicy.PHP.DefaultVersion = cmd.Input.DefaultPHPVersion
	issues := validatePlanReadinessWithCapabilities(candidate, capabilities)
	if plan.LifecycleStatus != types.PlanLifecycleActive {
		for i := range issues {
			issues[i].Blocking = false
		}
	}
	return store, cmd, issues, readiness, nil
}

func (m *Manager) PreviewPlanPHPVersions(ctx context.Context, actor auth.SessionUser, id int64, input controlquota.PlanPHPVersionsInput) (controlquota.PlanPHPVersionsPreview, error) {
	store, cmd, issues, readiness, err := m.planPHPCommand(ctx, actor, id, input)
	if err != nil {
		return controlquota.PlanPHPVersionsPreview{}, err
	}
	view, err := store.PreviewPlanPHPVersions(ctx, cmd)
	if err != nil {
		return view, err
	}
	view.Preview.CapabilityIssues = append(view.Preview.CapabilityIssues, issues...)
	for _, issue := range issues {
		if issue.Blocking {
			view.Preview.Allowed = false
			view.Preview.BlockingReasons = append(view.Preview.BlockingReasons, issue.Message)
		}
	}
	if readiness != nil {
		view.Preview.Allowed = false
		if len(view.Blockers) == 0 {
			view.Blockers = append(view.Blockers, controlquota.PlanPHPBlocker{Code: "php_version_unready", Message: readiness.Error()})
		}
	}
	return view, nil
}

func (m *Manager) UpdatePlanPHPVersions(ctx context.Context, actor auth.SessionUser, id int64, input controlquota.PlanPHPVersionsInput) (controlquota.PlanPHPVersionsResult, error) {
	store, cmd, issues, readiness, err := m.planPHPCommand(ctx, actor, id, input)
	if err != nil {
		return controlquota.PlanPHPVersionsResult{}, err
	}
	if readiness != nil {
		return controlquota.PlanPHPVersionsResult{}, readiness
	}
	if message := blockingCapabilityMessage(issues); message != "" {
		return controlquota.PlanPHPVersionsResult{}, &controlquota.PlanPHPRejectedError{Cause: fmt.Errorf("cannot update plan: %s", message)}
	}
	return store.UpdatePlanPHPVersions(ctx, cmd)
}
