package phpapp

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/riverqueue/river/rivertype"
)

func TestPHPApplicationJobsCarryOnlyRevisionFencedIdentifiers(t *testing.T) {
	tests := []struct {
		name string
		args any
	}{
		{"deploy", DeployPHPReleaseArgs{ApplicationID: 7, DeploymentID: 11, DesiredRevision: 13}},
		{"rollback", RollbackPHPReleaseArgs{ApplicationID: 7, DeploymentID: 12, TargetDeploymentID: 11, DesiredRevision: 14}},
		{"application reconcile", ReconcilePHPApplicationArgs{ApplicationID: 7, DesiredRevision: 15}},
		{"worker reconcile", ReconcilePHPWorkersArgs{ApplicationID: 7, DesiredRevision: 16}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload, err := json.Marshal(test.args)
			if err != nil {
				t.Fatal(err)
			}
			encoded := strings.ToLower(string(payload))
			for _, forbidden := range []string{"secret", "password", "environment", "repository_url", "path", "socket", "command"} {
				if strings.Contains(encoded, forbidden) {
					t.Fatalf("job JSON contains forbidden field %q: %s", forbidden, payload)
				}
			}
		})
	}
}

func TestPHPApplicationMutationJobsDeduplicateAllActiveStates(t *testing.T) {
	states := []rivertype.JobState{
		rivertype.JobStateAvailable,
		rivertype.JobStatePending,
		rivertype.JobStateRetryable,
		rivertype.JobStateRunning,
		rivertype.JobStateScheduled,
	}
	for name, options := range map[string][]rivertype.JobState{
		"deploy":      (DeployPHPReleaseArgs{}).InsertOpts().UniqueOpts.ByState,
		"rollback":    (RollbackPHPReleaseArgs{}).InsertOpts().UniqueOpts.ByState,
		"application": (ReconcilePHPApplicationArgs{}).InsertOpts().UniqueOpts.ByState,
		"workers":     (ReconcilePHPWorkersArgs{}).InsertOpts().UniqueOpts.ByState,
	} {
		for _, state := range states {
			if !slices.Contains(options, state) {
				t.Fatalf("%s job omits active state %s: %#v", name, state, options)
			}
		}
	}
}
