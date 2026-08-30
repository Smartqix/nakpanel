package rpc

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

type fakePHPApplicationProvisioner struct {
	deploys    []types.DeployPHPReleaseReq
	rollbacks  []types.RollbackPHPReleaseReq
	reconciles []types.ReconcilePHPApplicationReq
	workers    []types.ReconcilePHPWorkersReq
}

func (f *fakePHPApplicationProvisioner) DeployPHPRelease(_ context.Context, req types.DeployPHPReleaseReq) (types.DeployPHPReleaseResult, error) {
	f.deploys = append(f.deploys, req)
	return types.DeployPHPReleaseResult{DeploymentID: req.Deployment.ID, ResolvedRevision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Changed: true}, nil
}

func (f *fakePHPApplicationProvisioner) RollbackPHPRelease(_ context.Context, req types.RollbackPHPReleaseReq) (types.RollbackPHPReleaseResult, error) {
	f.rollbacks = append(f.rollbacks, req)
	return types.RollbackPHPReleaseResult{DeploymentID: req.DeploymentID, ActiveDeploymentID: req.TargetDeployment.ID, Changed: true}, nil
}

func (f *fakePHPApplicationProvisioner) ReconcilePHPApplication(_ context.Context, req types.ReconcilePHPApplicationReq) (types.ReconcilePHPApplicationResult, error) {
	f.reconciles = append(f.reconciles, req)
	return types.ReconcilePHPApplicationResult{ApplicationID: req.Application.ApplicationID, ObservedState: "healthy"}, nil
}

func (f *fakePHPApplicationProvisioner) ReconcilePHPWorkers(_ context.Context, req types.ReconcilePHPWorkersReq) (types.ReconcilePHPWorkersResult, error) {
	f.workers = append(f.workers, req)
	return types.ReconcilePHPWorkersResult{ApplicationID: req.Application.ApplicationID}, nil
}

func TestDispatchPHPApplicationOperationsAreEnumeratedAndStrict(t *testing.T) {
	provisioner := &fakePHPApplicationProvisioner{}
	dispatcher := NewDispatcher(nil, Options{PHPApplications: provisioner})
	application := types.PHPApplicationSpec{ApplicationID: 8}
	tests := []struct {
		op      string
		payload any
		calls   func() int
	}{
		{types.OpDeployPHPRelease, types.DeployPHPReleaseReq{Application: application, Deployment: types.PHPDeployment{ID: 11}}, func() int { return len(provisioner.deploys) }},
		{types.OpRollbackPHPRelease, types.RollbackPHPReleaseReq{Application: application, DeploymentID: 12, TargetDeployment: types.PHPDeployment{ID: 11}}, func() int { return len(provisioner.rollbacks) }},
		{types.OpReconcilePHPApplication, types.ReconcilePHPApplicationReq{Application: application}, func() int { return len(provisioner.reconciles) }},
		{types.OpReconcilePHPWorkers, types.ReconcilePHPWorkersReq{Application: application}, func() int { return len(provisioner.workers) }},
	}
	for _, test := range tests {
		data, err := json.Marshal(test.payload)
		if err != nil {
			t.Fatal(err)
		}
		response := dispatcher.Dispatch(context.Background(), types.Request{Op: test.op, ID: test.op, Data: data})
		if !response.OK || test.calls() != 1 {
			t.Fatalf("dispatch %s = %+v, calls=%d", test.op, response, test.calls())
		}
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		raw["command"] = "sh -c id"
		bad, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		response = dispatcher.Dispatch(context.Background(), types.Request{Op: test.op, ID: test.op + "-bad", Data: bad})
		if response.OK || test.calls() != 1 {
			t.Fatalf("strict dispatch %s = %+v, calls=%d", test.op, response, test.calls())
		}
	}
}
