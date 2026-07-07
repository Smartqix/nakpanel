package multipass_test

import (
	"os"
	"strings"
	"testing"
)

func TestPhase6RecoveryVerifierCoversDiscardedJobRetry(t *testing.T) {
	const path = "phase6-recovery-verify.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("%s is not executable; mode is %v", path, info.Mode())
	}

	script := string(data)
	for _, want := range []string{
		"${NAKPANEL_MULTIPASS_VM:-nakpanel-phase6-recovery}",
		"phase5-ui-verify.sh",
		"phase6-retry.test",
		"state::text",
		"did not complete before forced retry scenario",
		"state = 'discarded'",
		"phase6 synthetic failure",
		"previous_max_attempts",
		"action=\"/jobs/retry\"",
		"name=\\\"job_id\\\" value=\\\"${job_id}\\\"",
		"Retry job",
		"/jobs/retry",
		"max_attempts",
		"above ${previous_max_attempts}",
		"Retry queued. Refresh in a moment to see the updated status.",
		"Client dashboard",
		"client job retry returned HTTP",
		"Phase 6 recovery verification passed",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("%s missing required verifier coverage %q", path, want)
		}
	}
}
