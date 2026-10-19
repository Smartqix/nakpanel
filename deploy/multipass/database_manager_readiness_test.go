package multipass

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestDatabaseManagerOptInReadiness(t *testing.T) {
	for _, path := range []string{
		"database_manager_readiness_test.py", "internal-tools-verify.sh", "sury-maintenance-drill.py",
		"../install/database-manager-install.sh", "../database-manager/nginx.conf", "../database-manager/php-fpm.conf",
		"../database-manager/health.php", "../database-manager/prepend.php", "../database-manager/adapter.php",
		"../systemd/nakpanel-database-manager-http.service", "../systemd/nakpanel-database-manager.service.tmpl",
	} {
		if _, err := os.ReadFile(path); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "-B", "database_manager_readiness_test.py", "-v")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("database manager opt-in readiness: %v\n%s", err, output)
	}
}
