package main

import (
	"github.com/nakroteck/nakpanel/internal/backup"
	"testing"
)

func TestRestoreModeRequiresExplicitForwardGate(t *testing.T) {
	for _, tc := range []struct {
		mode                      backup.RestoreMode
		experimental, skip, check bool
		reject                    bool
	}{
		{mode: backup.RestoreSamePlatform},
		{mode: backup.RestoreForwardMigration, reject: true},
		{mode: backup.RestoreForwardMigration, check: true},
		{mode: backup.RestoreForwardMigration, experimental: true},
		{mode: backup.RestoreForwardMigration, experimental: true, skip: true, reject: true},
		{mode: "bogus", reject: true},
	} {
		if err := validateRestoreMode(tc.mode, tc.experimental, tc.skip, tc.check); (err != nil) != tc.reject {
			t.Fatalf("%+v err=%v", tc, err)
		}
	}
}
