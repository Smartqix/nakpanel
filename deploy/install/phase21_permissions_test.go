package install

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestPhase21SharedNginxPermissions(t *testing.T) {
	for _, path := range []string{"phase21-25-install.sh", "phase21_permissions_test.py"} {
		if _, err := os.ReadFile(path); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-I", "-B", "phase21_permissions_test.py", "-v")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Phase21 shared nginx traversal: %v\n%s", err, output)
	}
}
