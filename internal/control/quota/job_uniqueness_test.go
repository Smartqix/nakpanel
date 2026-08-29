package quota

import (
	"errors"
	"slices"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

func TestMutationConvergenceCanQueueSuccessorWhileRunning(t *testing.T) {
	for name, states := range map[string][]rivertype.JobState{
		"subscription": (ConvergeSubscriptionArgs{}).InsertOpts().UniqueOpts.ByState,
		"plan":         (SyncPlanArgs{}).InsertOpts().UniqueOpts.ByState,
		"add-on":       (SyncAddonArgs{}).InsertOpts().UniqueOpts.ByState,
		"application":  (ConvergeApplicationArgs{}).InsertOpts().UniqueOpts.ByState,
	} {
		if !slices.Contains(states, rivertype.JobStateRunning) {
			t.Fatalf("%s mutation job omits River's required running state", name)
		}
		if !slices.Contains(states, rivertype.JobStatePending) || !slices.Contains(states, rivertype.JobStateRetryable) {
			t.Fatalf("%s mutation job does not deduplicate queued successors", name)
		}
	}

	firstSubscription := NewConvergeSubscriptionArgs(42)
	secondSubscription := NewConvergeSubscriptionArgs(42)
	if firstSubscription.Revision == secondSubscription.Revision {
		t.Fatal("subscription mutations share a revision")
	}
	firstPlan := NewSyncPlanArgs(42)
	secondPlan := NewSyncPlanArgs(42)
	if firstPlan.Revision == secondPlan.Revision {
		t.Fatal("plan mutations share a revision")
	}
	firstAddon := NewSyncAddonArgs(42)
	secondAddon := NewSyncAddonArgs(42)
	if firstAddon.Revision == secondAddon.Revision {
		t.Fatal("add-on mutations share a revision")
	}
	firstApplication := ConvergeApplicationArgs{ApplicationID: 7, Revision: 1, SubscriptionRevision: 10}
	secondApplication := ConvergeApplicationArgs{ApplicationID: 7, Revision: 1, SubscriptionRevision: 11}
	if firstApplication.Revision == secondApplication.Revision {
		if firstApplication.SubscriptionRevision == secondApplication.SubscriptionRevision {
			t.Fatal("application policy mutations share a subscription revision")
		}
	}
}

func TestObservationJobSkipsAnAlreadyAppliedApplicationRevision(t *testing.T) {
	if !applicationObservationJobAlreadyConverged(8, 8, "in_sync") {
		t.Fatal("an already applied observation revision should be skipped")
	}
	for _, test := range []struct {
		desired, applied int64
		status           string
	}{
		{desired: 8, applied: 7, status: "in_sync"},
		{desired: 8, applied: 8, status: "pending"},
		{desired: 0, applied: 0, status: "in_sync"},
	} {
		if applicationObservationJobAlreadyConverged(test.desired, test.applied, test.status) {
			t.Fatalf("unexpected skip for desired=%d applied=%d status=%s", test.desired, test.applied, test.status)
		}
	}
}

func TestFailedApplicationGenerationIsTerminalForCurrentJob(t *testing.T) {
	cause := errors.New("candidate failed readiness")
	err := terminalApplicationConvergenceError(cause)
	var cancelErr *river.JobCancelError
	if !errors.As(err, &cancelErr) {
		t.Fatalf("application convergence error = %T, want JobCancelError", err)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("application convergence error does not retain cause: %v", err)
	}
}

func TestStoppedApplicationGenerationRetainsManagedEndpoint(t *testing.T) {
	request := types.EnsureApplicationReq{
		Endpoint: types.ApplicationEndpointSpec{HostPort: 20017},
	}
	if got := applicationGenerationEndpointPort(request, types.DeployApplicationGenerationResult{}); got != 20017 {
		t.Fatalf("stopped generation endpoint = %d, want 20017", got)
	}
	result := types.DeployApplicationGenerationResult{
		ApplicationObservedState: types.ApplicationObservedState{EndpointPort: 25017},
	}
	if got := applicationGenerationEndpointPort(request, result); got != 25017 {
		t.Fatalf("healthy generation endpoint = %d, want 25017", got)
	}
}

func TestScheduledTaskJobUniquenessIncludesDeferredJobs(t *testing.T) {
	states := (RunScheduledTaskArgs{}).InsertOpts().UniqueOpts.ByState
	for _, state := range []rivertype.JobState{
		rivertype.JobStateAvailable,
		rivertype.JobStatePending,
		rivertype.JobStateRetryable,
		rivertype.JobStateRunning,
		rivertype.JobStateScheduled,
	} {
		if !slices.Contains(states, state) {
			t.Fatalf("RunScheduledTaskArgs ByState = %#v, missing %s", states, state)
		}
	}
}

func TestEffectiveApplicationStateHonorsInheritedSuspension(t *testing.T) {
	tests := []struct {
		account, desired string
		permitted        bool
		want             string
	}{
		{account: "active", desired: "running", permitted: true, want: "running"},
		{account: "active", desired: "stopped", permitted: true, want: "stopped"},
		{account: "suspended", desired: "running", permitted: true, want: "stopped"},
		{account: "active", desired: "running", permitted: false, want: "stopped"},
	}
	for _, test := range tests {
		if got := effectiveApplicationState(test.account, test.desired, test.permitted); got != test.want {
			t.Fatalf("effectiveApplicationState(%q, %q, %t) = %q, want %q", test.account, test.desired, test.permitted, got, test.want)
		}
	}
}

func TestRevokedToolkitPermissionsConvergeServicesOff(t *testing.T) {
	var policy types.HostingPolicy
	if effectiveFTPSAccountEnabled(true, policy) {
		t.Fatal("revoked FTPS permission left an account enabled")
	}
	if got := effectiveValkeyState("active", "enabled", policy); got != "disabled" {
		t.Fatalf("revoked Valkey state = %q, want disabled", got)
	}
	policy.Permissions.FTPS = true
	policy.Access.FTPSEnabled = true
	policy.Permissions.Valkey = true
	policy.Valkey.Enabled = true
	if !effectiveFTPSAccountEnabled(true, policy) {
		t.Fatal("permitted active FTPS account was disabled")
	}
	if got := effectiveValkeyState("suspended", "enabled", policy); got != "suspended" {
		t.Fatalf("inherited Valkey suspension = %q, want suspended", got)
	}
}
