package multipass

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestQualificationHostBashAdmission(t *testing.T) {
	for _, path := range []string{"common.sh", "qualification-artifacts.sh", "common_bash_guard_test.py"} {
		if _, err := os.ReadFile(path); err != nil {
			t.Fatal(err)
		}
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-I", "-B", "common_bash_guard_test.py", "--bash5", bash, "-v")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("qualification host Bash admission: %v\n%s", err, output)
	}
}
