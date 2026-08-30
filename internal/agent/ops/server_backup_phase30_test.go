package ops

import (
	"strings"
	"testing"
)

func TestServerBackupPatternsRetainManagedPHPUnits(t *testing.T) {
	joined := strings.Join(nakpanelUnitPatterns(), "\n")
	for _, want := range []string{"nakpanel-php-fpm@*.service", "nakpanel-php-worker@*.service", "nakpanel-php-app-*.slice"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("server backup unit patterns omit %q: %s", want, joined)
		}
	}
}
