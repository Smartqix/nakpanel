package backup

import (
	"strings"
	"testing"
)

func TestRestoreRecoveryEnumeratesManagedPHPUnits(t *testing.T) {
	joined := strings.Join(instanceUnitPatterns(), "\n")
	for _, want := range []string{"nakpanel-php-fpm@*.service", "nakpanel-php-worker@*.service", "nakpanel-php-app-*.slice"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("server restore unit patterns omit %q: %s", want, joined)
		}
	}
}

func TestRestoreStartsOnlyDesiredActiveManagedPHPUnits(t *testing.T) {
	for _, unit := range []string{"nakpanel-php-fpm@17.service", "nakpanel-php-worker@51.service", "nakpanel-php-app-31.slice"} {
		if shouldStartRestoredInstanceUnit(unit) {
			t.Fatalf("%s activation must be left to application reconciliation", unit)
		}
	}
}
