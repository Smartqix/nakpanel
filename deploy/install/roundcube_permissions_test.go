package install

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestRoundcubePublicProgramPermissions(t *testing.T) {
	for _, path := range []string{"roundcube.sh", "archive_policy.py", "roundcube_permissions_test.py"} {
		if _, err := os.ReadFile(path); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-I", "-B", "roundcube_permissions_test.py", "-v")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Roundcube public program traversal: %v\n%s", err, output)
	}
}
