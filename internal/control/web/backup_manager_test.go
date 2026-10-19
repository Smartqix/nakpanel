package web

import (
	"github.com/nakroteck/nakpanel/internal/control/auth"
	"strings"
	"testing"
)

func TestSubscriptionBackupManagerHasFocusedActionsAndNoCrampedRail(t *testing.T) {
	html := renderSubscriptionDetail(t, auth.RoleAdmin, "backups")
	for _, marker := range []string{"data-np-backup-manager", "Back Up Now", "Remove selected", "Search backups", "Filter backup domain", "Existing recovery points are kept until you select and confirm removal."} {
		if !strings.Contains(html, marker) {
			t.Errorf("missing backup workflow %q", marker)
		}
	}
	if strings.Contains(html, `class="np-detail-rail"`) || strings.Contains(html, "<span>Add Domain</span>") {
		t.Error("backup task is crowded by unrelated sidebar or primary action")
	}
}

func TestBackupManagerStatusTones(t *testing.T) {
	for status,want:=range map[string]string{"active":"ok","deleting":"run","delete_failed":"fail","pending":"pend"} {
		if got:=statusPillClass(backupStatusLabel(status));got!=want {t.Errorf("%s: %s != %s",status,got,want)}
	}
}
