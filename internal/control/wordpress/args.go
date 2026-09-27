package wordpress

import (
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

var activeJobStates = []rivertype.JobState{
	rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
	rivertype.JobStateRunning, rivertype.JobStateScheduled,
}

type OperationArgs struct {
	InstanceID      int64 `json:"instance_id" river:"unique"`
	OperationID     int64 `json:"operation_id" river:"unique"`
	DesiredRevision int64 `json:"desired_revision" river:"unique"`
}

func (OperationArgs) Kind() string { return "wordpress_operation" }
func (OperationArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: "heavy", MaxAttempts: 5, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: activeJobStates}}
}

type CleanupRemovalArgs struct {
	InstanceID      int64 `json:"instance_id" river:"unique"`
	OperationID     int64 `json:"operation_id" river:"unique"`
	DesiredRevision int64 `json:"desired_revision" river:"unique"`
}

func (CleanupRemovalArgs) Kind() string { return "cleanup_wordpress_removal" }
func (CleanupRemovalArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: "heavy", MaxAttempts: 10, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: activeJobStates}}
}

type SweepArgs struct{}

func (SweepArgs) Kind() string { return "sweep_wordpress" }
func (SweepArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: activeJobStates}}
}
