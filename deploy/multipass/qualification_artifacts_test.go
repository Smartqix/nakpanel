package multipass

import (
	"os/exec"
	"testing"
)

func TestQualificationArtifactsAuthenticateAfterTmpIsCleared(t *testing.T) {
	if out, err := exec.Command("python3", "qualification_artifacts_test.py", "-q").CombinedOutput(); err != nil {
		t.Fatalf("durable artifact/probe policy: %s %v", out, err)
	}
}
