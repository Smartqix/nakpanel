package operationsdb

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Missing CI configuration must fail the suite instead of quietly skipping
// the production-schema regressions. Local opt-in fixtures may still skip.
func TestMissingDatabaseCannotSilentlySkipCIRegressions(t *testing.T) {
	for _, ci := range []string{"true", "false"} {
		t.Run(ci, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestOperationsFixtureConfigurationProbe$", "-test.v")
			cmd.Env = append(os.Environ(), "NAKPANEL_OPERATIONS_FIXTURE_PROBE=1", "NAKPANEL_OPERATIONS_TEST_DSN=", "GITHUB_ACTIONS="+ci)
			output, err := cmd.CombinedOutput()
			if ci == "true" {
				if err == nil || !strings.Contains(string(output), "CI requires NAKPANEL_OPERATIONS_TEST_DSN") {
					t.Fatalf("missing CI database was not rejected: %v\n%s", err, output)
				}
			} else if err != nil || !strings.Contains(string(output), "SKIP") {
				t.Fatalf("local opt-in fixture no longer skips without configuration: %v\n%s", err, output)
			}
		})
	}
}

func TestOperationsFixtureConfigurationProbe(t *testing.T) {
	if os.Getenv("NAKPANEL_OPERATIONS_FIXTURE_PROBE") != "1" {
		return
	}
	New(t)
}
