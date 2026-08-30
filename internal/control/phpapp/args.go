package phpapp

import (
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

var activeJobStates = []rivertype.JobState{
	rivertype.JobStateAvailable,
	rivertype.JobStatePending,
	rivertype.JobStateRetryable,
	rivertype.JobStateRunning,
	rivertype.JobStateScheduled,
}

type DeployPHPReleaseArgs struct {
	ApplicationID   int64 `json:"application_id" river:"unique"`
	DeploymentID    int64 `json:"deployment_id" river:"unique"`
	DesiredRevision int64 `json:"desired_revision" river:"unique"`
}

func (DeployPHPReleaseArgs) Kind() string { return "deploy_php_release" }
func (DeployPHPReleaseArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: "heavy", MaxAttempts: 5, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: activeJobStates}}
}

type RollbackPHPReleaseArgs struct {
	ApplicationID      int64 `json:"application_id" river:"unique"`
	DeploymentID       int64 `json:"deployment_id" river:"unique"`
	TargetDeploymentID int64 `json:"target_deployment_id" river:"unique"`
	DesiredRevision    int64 `json:"desired_revision" river:"unique"`
}

func (RollbackPHPReleaseArgs) Kind() string { return "rollback_php_release" }
func (RollbackPHPReleaseArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: "heavy", MaxAttempts: 5, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: activeJobStates}}
}

type ReconcilePHPApplicationArgs struct {
	ApplicationID   int64 `json:"application_id" river:"unique"`
	DesiredRevision int64 `json:"desired_revision" river:"unique"`
}

func (ReconcilePHPApplicationArgs) Kind() string { return "reconcile_php_application" }
func (ReconcilePHPApplicationArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: "heavy", MaxAttempts: 5, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: activeJobStates}}
}

type ReconcilePHPWorkersArgs struct {
	ApplicationID   int64 `json:"application_id" river:"unique"`
	DesiredRevision int64 `json:"desired_revision" river:"unique"`
}

func (ReconcilePHPWorkersArgs) Kind() string { return "reconcile_php_workers" }
func (ReconcilePHPWorkersArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: "heavy", MaxAttempts: 5, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: activeJobStates}}
}

type SweepPHPApplicationsArgs struct{}

func (SweepPHPApplicationsArgs) Kind() string { return "sweep_php_applications" }
func (SweepPHPApplicationsArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: activeJobStates}}
}

type SweepPHPRuntimesArgs struct{}

func (SweepPHPRuntimesArgs) Kind() string { return "sweep_php_runtimes" }
func (SweepPHPRuntimesArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: activeJobStates}}
}
