package multipass

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestSurySameVersionMaintenanceRecoveryBehavior(t *testing.T) {
	// Read non-Go sources through the Go test process so the test cache observes
	// changes to the executable qualification code and its Python behavior suite.
	for _, path := range []string{"sury-maintenance-verify.sh", "sury-maintenance-drill.py", "sury_maintenance_test.py", "sury_maintenance_test.go"} {
		if _, err := os.ReadFile(path); err != nil {
			t.Fatalf("read maintenance qualification source %s: %v", path, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "sury_maintenance_test.py", "-v")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("Surý same-version maintenance recovery behavior: %v\n%s", err, output)
	}
}
