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

func TestSubdomainMailDNSTemplateApplyQueuesReadinessRecheck(t *testing.T) {
	db, manager := dnsFixture(t)
	ctx := context.Background()
	parent := removaldb.Site(t, db, 1, "template-parent.test", nil)
	child := removaldb.Site(t, db, 1, "child.template-parent.test", parent)
	if _, err := db.Exec(`UPDATE sites SET dns_zone_mode='separate',dns_template_adoption_completed=true WHERE id=$1`, child); err != nil {
		t.Fatal(err)
	}
	var parentZone, childZone int64
	if err := db.QueryRow(`INSERT INTO dns_zones(owner_user_id,site_id,domain,address,serial,status,template_revision) VALUES(1,$1,'template-parent.test','192.0.2.1',1,'active',1) RETURNING id`, parent).Scan(&parentZone); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`INSERT INTO dns_zones(owner_user_id,site_id,parent_zone_id,domain,address,serial,status,template_revision) VALUES(1,$1,$2,'child.template-parent.test','192.0.2.1',1,'active',1) RETURNING id`, child, parentZone).Scan(&childZone); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,ttl,origin,template_record_key,template_revision) VALUES($1,$2,'child','NS','oldns.provider.test',3600,'custom',NULL,NULL),($3,$4,'@','NS','oldns.provider.test',3600,'template','phase2-ns',1)`, parentZone, parent, childZone, child); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO mail_domains(subscription_id,site_id,domain,enabled,convergence_status) VALUES(1,$1,'child.template-parent.test',true,'in_sync')`, child); err != nil {
		t.Fatal(err)
	}
	template, err := manager.activeTemplate(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.UpsertTemplateRecord(ctx, 1, 0, template.OptimisticRevision, types.DNSTemplateRecord{StableKey: "phase2-ns", Scope: "all", HostTemplate: "@", Type: "NS", ValueTemplate: "newns.provider.test", TTL: 3600}); err != nil {
		t.Fatal(err)
	}
	preview, err := manager.ApplyZone(ctx, 1, child)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ApplyPreview(ctx, 1, preview.ID, preview.PreviewToken, "APPLY DNS TEMPLATE"); err != nil {
		t.Fatal(err)
	}
	if err := manager.applyRun(ctx, preview.ID); err != nil {
		t.Fatal(err)
	}
	var childNS, parentNS string
	if err := db.QueryRow(`SELECT value FROM dns_records WHERE zone_id=$1 AND host='@' AND record_type='NS'`, childZone).Scan(&childNS); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT value FROM dns_records WHERE zone_id=$1 AND host='child' AND record_type='NS'`, parentZone).Scan(&parentNS); err != nil {
		t.Fatal(err)
	}
	if childNS != "newns.provider.test" || parentNS != "oldns.provider.test" {
		t.Fatalf("fixture did not change only child NS: child=%s parent=%s", childNS, parentNS)
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
		t.Fatalf("template apply left stale mail readiness: jobs=%d status=%s", jobs, status)
	}
}
