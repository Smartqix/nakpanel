package backup

import (
	"context"
	"errors"
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
	enabled := func(_ context.Context, name string, args ...string) error {
		if name != "systemctl" || len(args) != 2 || args[0] != "is-enabled" || args[1] != "nakpanel-php-worker@51.service" {
			t.Fatalf("unexpected enabled probe: %s %v", name, args)
		}
		return nil
	}
	start, err := shouldStartRestoredInstanceUnit(context.Background(), "nakpanel-php-worker@51.service", enabled)
	if err != nil || !start {
		t.Fatalf("enabled worker start = %v, %v; want true, nil", start, err)
	}

	disabled := func(context.Context, string, ...string) error { return errors.New("disabled") }
	start, err = shouldStartRestoredInstanceUnit(context.Background(), "nakpanel-php-worker@52.service", disabled)
	if err != nil || start {
		t.Fatalf("disabled worker start = %v, %v; want false, nil", start, err)
	}

	for _, unit := range []string{"nakpanel-php-fpm@17.service", "nakpanel-php-app-31.slice"} {
		start, err = shouldStartRestoredInstanceUnit(context.Background(), unit, func(context.Context, string, ...string) error {
			t.Fatalf("%s activation must be left to application reconciliation", unit)
			return nil
		})
		if err != nil || start {
			t.Fatalf("%s start = %v, %v; want false, nil", unit, start, err)
		}
	}
}
