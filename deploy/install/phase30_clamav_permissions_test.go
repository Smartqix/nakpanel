package install

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestPhase30ClamAVDefinitionsRemainReadableToTenantScanners(t *testing.T) {
	for _, path := range []string{"phase30-install.sh", "phase30_clamav_permissions_test.py"} {
		if _, err := os.ReadFile(path); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "phase30_clamav_permissions_test.py", "-v")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ClamAV public signature permissions: %v\n%s", err, output)
	}
}
