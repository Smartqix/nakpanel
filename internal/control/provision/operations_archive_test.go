package provision

import (
	"context"
	"github.com/nakroteck/nakpanel/internal/control/operations"
	"github.com/nakroteck/nakpanel/internal/types"
	"strings"
	"testing"
	"time"
)

func TestBackupRecoveryVerifiesManualAndDisabledSchedules(t *testing.T) {
	for _, schedule := range []string{"manual", "disabled", "daily"} {
		t.Run(schedule, func(t *testing.T) {
			completed := time.Now().UTC()
			agent := &operationsProbeAgent{checksum: strings.Repeat("a", 64), size: 4096}
			m := &OperationsManager{agent: agent}
			in := operationIntent{SiteID: 51, SubscriptionID: 42, Domain: "studio.example", Hash: "current", Policy: types.HostingPolicy{Permissions: types.HostingPermissionPolicy{Backups: true}, Backups: types.HostingBackupPolicy{Enabled: true, Schedule: schedule}}, Archive: operationArchive{ID: 9, Path: "/managed/current.tar.gz", Checksum: agent.checksum, Size: agent.size, CompletedAt: &completed}}
			receipt, err := m.probeOperation(context.Background(), operations.Issue{Kind: "backup"}, in)
			if err != nil || receipt.Source != "archive_checksum" || agent.last.BackupID != 9 {
				t.Fatalf("current manual archive never verified: %#v %v", receipt, err)
			}
			if schedule == "manual" || schedule == "disabled" {
				if _, err = m.probeOperation(context.Background(), operations.Issue{Kind: "backup", ObservedAt: completed.Add(time.Minute)}, in); err == nil {
					t.Fatal("archive preceding this failure established manual recovery")
				}
			}
			agent.fail = true
			if _, err = m.probeOperation(context.Background(), operations.Issue{Kind: "backup"}, in); err == nil {
				t.Fatal("failed checksum inspection established recovery")
			}
		})
	}
}
