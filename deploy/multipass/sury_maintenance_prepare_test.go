package multipass

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestSuryMaintenancePortablePreparation(t *testing.T) {
	for _, path := range []string{"sury-maintenance-prepare.py", "sury_maintenance_prepare_test.py", "sury-maintenance-drill.py", "../../.github/workflows/ubuntu-hosted-qualification.yml", "../systemd/nakpanel.service"} {
		if _, err := os.ReadFile(path); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "sury_maintenance_prepare_test.py", "-v")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("portable Surý preparation: %v\n%s", err, output)
	}
}
