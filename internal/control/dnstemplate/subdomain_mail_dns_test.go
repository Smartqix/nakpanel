package dnstemplate

import (
	"context"
	"testing"

	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestSubdomainMailDNSModeChangesQueueReadinessRecheck(t *testing.T) {
	for _, mode := range []string{"authoritative mode", "separate child zone"} {
		t.Run(mode, func(t *testing.T) {
			db, manager := dnsFixture(t)
			parent := removaldb.Site(t, db, 1, "parent.test", nil)
			child := removaldb.Site(t, db, 1, "child.parent.test", parent)
			if _, err := db.Exec(`UPDATE sites SET dns_zone_mode='parent' WHERE id=$1`, child); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO dns_zones(owner_user_id,site_id,domain,address,serial,status,template_revision) VALUES(1,$1,'parent.test','192.0.2.1',1,'active',1)`, parent); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO mail_domains(subscription_id,site_id,domain,enabled,convergence_status) VALUES(1,$1,'child.parent.test',true,'in_sync')`, child); err != nil {
				t.Fatal(err)
			}
			var err error
			if mode == "authoritative mode" {
				err = manager.SetZoneMode(context.Background(), parent, types.DNSZoneModeInput{Mode: "disabled", ExpectedRevision: 1})
			} else {
				err = manager.SetSubdomainZoneMode(context.Background(), child, 1, "separate")
			}
			if err != nil {
				t.Fatal(err)
			}
			var jobs int
			var status string
			if err := db.QueryRow(`SELECT count(*) FROM river_job WHERE kind='configure_mail'`).Scan(&jobs); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(`SELECT convergence_status FROM mail_domains WHERE site_id=$1`, child).Scan(&status); err != nil {
				t.Fatal(err)
			}
			if jobs != 1 || status != "pending" {
				t.Fatalf("DNS mode change left stale readiness: jobs=%d status=%s", jobs, status)
			}
		})
	}
}
