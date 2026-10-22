package provision

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/testutil/removaldb"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

type childMailDNSFixture struct {
	db                           *sql.DB
	worker                       *ConfigureMailWorker
	parent, child, sibling, zone int64
	domain                       mailDomainRow
}

func newChildMailDNSFixture(t *testing.T) childMailDNSFixture {
	t.Helper()
	db, repository, parent, zone := serviceDNSFixture(t, "parent-mail.test")
	child := removaldb.Site(t, db, 1, "child.parent-mail.test", parent)
	sibling := removaldb.Site(t, db, 1, "sibling.parent-mail.test", parent)
	if _, err := db.Exec(`UPDATE sites SET dns_zone_mode='parent' WHERE id IN ($1,$2)`, child, sibling); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,priority,ttl,origin) VALUES
($1,$2,'@','MX','mail.parent-mail.test',10,3600,'system'),
($1,$2,'@','TXT','v=spf1 mx ~all',NULL,3600,'system'),
($1,$2,'_dmarc','TXT','v=DMARC1; p=reject',NULL,3600,'system'),
($1,$3,'sibling','MX','mail.sibling.parent-mail.test',10,3600,'system'),
($1,$3,'nak1._domainkey.sibling','TXT','v=DKIM1; p=sibling',NULL,3600,'system')`, zone, parent, sibling); err != nil {
		t.Fatal(err)
	}
	worker := NewConfigureMailWorker(db, nil)
	worker.phase6 = repository
	return childMailDNSFixture{db, worker, parent, child, sibling, zone, mailDomainRow{SiteID: child, Domain: "child.parent-mail.test", Enabled: true, DKIM: true, DMARCPolicy: "none"}}
}

func (f childMailDNSFixture) records(t *testing.T, condition string) string {
	t.Helper()
	var result string
	if err := f.db.QueryRow(`SELECT COALESCE(string_agg(row_to_json(r)::text,',' ORDER BY id),'') FROM dns_records r WHERE zone_id=$1 AND `+condition, f.zone).Scan(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestSubdomainMailDNSRejectsConflictsWithoutMutation(t *testing.T) {
	for _, test := range []struct{ name, host, kind, value string }{
		{"apex CNAME", "child", "CNAME", "external.test"},
		{"mail CNAME", "mail.child", "CNAME", "external.test"},
		{"DKIM CNAME", "nak1._domainkey.child", "CNAME", "key.external.test"},
		{"DMARC CNAME", "_dmarc.child", "CNAME", "policy.external.test"},
		{"active mail hostname", "@", "MX", "child.parent-mail.test"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newChildMailDNSFixture(t)
			if _, err := f.db.Exec(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,priority,ttl,origin) VALUES($1,$2,$3,$4,$5,CASE WHEN $4='MX' THEN 10 ELSE NULL END,300,'custom')`, f.zone, f.parent, test.host, test.kind, test.value); err != nil {
				t.Fatal(err)
			}
			before := f.records(t, "true")
			err := f.worker.reconcileZoneRecords(context.Background(), f.domain, mailZoneRecords(f.domain, "v=DKIM1; p=child"))
			if err == nil || !strings.Contains(err.Error(), "DNS conflict") {
				t.Errorf("expected an actionable DNS conflict, got %v", err)
			}
			if after := f.records(t, "true"); after != before {
				t.Fatal("conflict changed DNS records")
			}
		})
	}
}

func TestSubdomainMailDNSReconciliationIsScopedAndIdempotent(t *testing.T) {
	f := newChildMailDNSFixture(t)
	canaries := f.records(t, "owner_site_id<>"+strconv.FormatInt(f.child, 10))
	desired := mailZoneRecords(f.domain, "v=DKIM1; p=child")
	for run := 0; run < 2; run++ {
		if err := f.worker.reconcileZoneRecords(context.Background(), f.domain, desired); err != nil {
			t.Fatal(err)
		}
		if desired[0].Host != "@" {
			t.Fatal("reconciliation mutated its desired record input")
		}
	}
	before := f.records(t, "true")
	var revision, jobs int
	if err := f.db.QueryRow(`SELECT desired_revision FROM dns_zones WHERE id=$1`, f.zone).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRow(`SELECT count(*) FROM river_job WHERE kind='configure_dns_zone'`).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if err := f.worker.reconcileZoneRecords(context.Background(), f.domain, mailZoneRecords(f.domain, "v=DKIM1; p=child")); err != nil {
		t.Fatal(err)
	}
	var currentRevision, currentJobs int
	if err := f.db.QueryRow(`SELECT desired_revision FROM dns_zones WHERE id=$1`, f.zone).Scan(&currentRevision); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRow(`SELECT count(*) FROM river_job WHERE kind='configure_dns_zone'`).Scan(&currentJobs); err != nil {
		t.Fatal(err)
	}
	if f.records(t, "true") != before || revision != currentRevision || jobs != currentJobs {
		t.Fatal("unchanged reconciliation rewrote records or queued another DNS apply")
	}
	if f.records(t, "owner_site_id<>"+strconv.FormatInt(f.child, 10)) != canaries {
		t.Fatal("child changed parent or sibling DNS")
	}
	if _, err := f.db.Exec(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,priority,ttl,origin) VALUES($1,$2,'child','MX','mx.external.test',10,300,'custom'),($1,$2,'child','TXT','v=spf1 include:external.test -all',NULL,300,'custom')`, f.zone, f.child); err != nil {
		t.Fatal(err)
	}
	custom := f.records(t, "origin='custom'")
	for _, records := range [][]types.DNSRecord{mailZoneRecords(f.domain, "v=DKIM1; p=new-key"), nil, nil} {
		if err := f.worker.reconcileZoneRecords(context.Background(), f.domain, records); err != nil {
			t.Fatal(err)
		}
		if f.records(t, "origin='custom'") != custom || f.records(t, "owner_site_id<>"+strconv.FormatInt(f.child, 10)) != canaries {
			t.Fatal("reconcile/disable removed custom, parent or sibling records")
		}
	}
}

type childMailDNSAgent struct {
	failure     string
	malformed   bool
	missingDKIM bool
	omitDomain  string
}

func (a childMailDNSAgent) ConfigureMail(_ context.Context, req types.ConfigureMailReq) (types.Response, error) {
	if a.failure != "" {
		return types.Response{}, errors.New(a.failure)
	}
	if a.malformed {
		return types.Response{OK: true, Data: json.RawMessage(`{`)}, nil
	}
	result := types.ConfigureMailResult{}
	if a.missingDKIM {
		data, _ := json.Marshal(result)
		return types.Response{OK: true, Data: data}, nil
	}
	for _, domain := range req.Domains {
		if domain.Domain == a.omitDomain {
			continue
		}
		result.DKIM = append(result.DKIM, types.MailDomainDKIM{MailDomainID: domain.MailDomainID, Domain: domain.Domain, Selector: "nak1", Record: "v=DKIM1; p=public-child-key"})
	}
	data, _ := json.Marshal(result)
	return types.Response{OK: true, Data: data}, nil
}

func TestSubdomainMailDNSWorkerReportsActionAndFailure(t *testing.T) {
	for _, name := range []string{"custom routing", "protected routing", "external DNS", "separate missing delegation", "separate wrong delegation", "separate delegated", "parent delegated", "agent failure", "malformed acknowledgement", "missing DKIM failure", "CNAME failure"} {
		t.Run(name, func(t *testing.T) {
			f := newChildMailDNSFixture(t)
			var domainID int64
			if err := f.db.QueryRow(`INSERT INTO mail_domains(subscription_id,site_id,domain,enabled,dkim_enabled,dmarc_policy,convergence_status) VALUES(1,$1,$2,true,true,'none','in_sync') RETURNING id`, f.child, f.domain.Domain).Scan(&domainID); err != nil {
				t.Fatal(err)
			}
			agent := childMailDNSAgent{}
			wantNote := ""
			switch name {
			case "custom routing", "protected routing":
				_, err := f.db.Exec(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,priority,ttl,origin) VALUES($1,$2,'child','MX','mx.external.test',10,300,'custom'),($1,$2,'child','TXT','v=spf1 include:external.test -all',NULL,300,'custom')`, f.zone, f.child)
				if err != nil {
					t.Fatal(err)
				}
				if name == "protected routing" {
					if _, err := f.db.Exec(`UPDATE dns_records SET origin='system',owner_site_id=$2 WHERE zone_id=$1 AND host='child'`, f.zone, f.parent); err != nil {
						t.Fatal(err)
					}
				}
				wantNote = "Custom DNS"
			case "external DNS":
				if _, err := f.db.Exec(`UPDATE dns_zones SET mode='disabled' WHERE id=$1`, f.zone); err != nil {
					t.Fatal(err)
				}
				wantNote = "External DNS"
			case "parent delegated":
				if _, err := f.db.Exec(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,ttl,origin) VALUES($1,$2,'child','NS','ns.external.test',300,'custom')`, f.zone, f.child); err != nil {
					t.Fatal(err)
				}
				wantNote = "delegat"
			case "separate missing delegation", "separate wrong delegation", "separate delegated":
				if _, err := f.db.Exec(`UPDATE sites SET dns_zone_mode='separate' WHERE id=$1`, f.child); err != nil {
					t.Fatal(err)
				}
				var zone int64
				if err := f.db.QueryRow(`INSERT INTO dns_zones(owner_user_id,site_id,parent_zone_id,domain,address,serial,status,template_revision) VALUES(1,$1,$2,$3,'192.0.2.1',1,'active',1) RETURNING id`, f.child, f.zone, f.domain.Domain).Scan(&zone); err != nil {
					t.Fatal(err)
				}
				if _, err := f.db.Exec(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,ttl,origin) VALUES($1,$2,'@','NS','ns.parent-mail.test',300,'custom')`, zone, f.child); err != nil {
					t.Fatal(err)
				}
				if name != "separate missing delegation" {
					ns := "ns.parent-mail.test"
					if name == "separate wrong delegation" {
						ns = "ns.external.test"
					}
					if _, err := f.db.Exec(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,ttl,origin) VALUES($1,$2,'child','NS',$3,300,'custom')`, f.zone, f.parent, ns); err != nil {
						t.Fatal(err)
					}
				}
				if name != "separate delegated" {
					wantNote = "delegat"
				}
			case "agent failure":
				agent.failure = "mail agent refused configuration"
			case "malformed acknowledgement":
				agent.malformed = true
			case "missing DKIM failure":
				agent.missingDKIM = true
			case "CNAME failure":
				if _, err := f.db.Exec(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,ttl,origin) VALUES($1,$2,'child','CNAME','external.test',300,'custom')`, f.zone, f.child); err != nil {
					t.Fatal(err)
				}
			}
			before := f.records(t, "true")
			canaries := f.records(t, "owner_site_id<>"+strconv.FormatInt(f.child, 10))
			f.worker.agent = agent
			err := f.worker.Work(context.Background(), &river.Job[controlquota.ConfigureMailArgs]{Args: controlquota.NewConfigureMailArgs()})
			var status, note string
			if queryErr := f.db.QueryRow(`SELECT convergence_status,last_error FROM mail_domains WHERE id=$1`, domainID).Scan(&status, &note); queryErr != nil {
				t.Fatal(queryErr)
			}
			failed := strings.Contains(name, "failure") || name == "malformed acknowledgement"
			if failed {
				if err == nil || status != "failed" || note == "" {
					t.Fatalf("failed convergence was hidden: status=%s note=%q err=%v", status, note, err)
				}
			} else if err != nil || status != "in_sync" || (wantNote != "" && !strings.Contains(note, wantNote)) || (wantNote == "" && note != "") {
				t.Fatalf("readiness status=%s note=%q err=%v", status, note, err)
			}
			if name == "external DNS" {
				for _, required := range []string{"child.parent-mail.test", "mail.child.parent-mail.test", "v=spf1 mx ~all", "nak1._domainkey", "public-child-key", "_dmarc"} {
					if !strings.Contains(note, required) {
						t.Errorf("external guidance missing %q", required)
					}
				}
			}
			if f.records(t, "owner_site_id<>"+strconv.FormatInt(f.child, 10)) != canaries {
				t.Fatal("worker changed parent or sibling DNS")
			}
			if name == "parent delegated" || failed {
				if f.records(t, "true") != before {
					t.Fatal("blocked convergence changed DNS")
				}
			}
		})
	}
}

func TestSubdomainMailDNSEditsQueueReadinessRecheck(t *testing.T) {
	f := newChildMailDNSFixture(t)
	if _, err := f.db.Exec(`INSERT INTO mail_domains(subscription_id,site_id,domain,enabled,convergence_status) VALUES(1,$1,$2,true,'in_sync')`, f.child, f.domain.Domain); err != nil {
		t.Fatal(err)
	}
	repository := f.worker.phase6
	if err := repository.UpsertDNSRecord(context.Background(), f.child, types.DNSRecord{Host: "@", Type: "MX", Value: "mx.external.test", Priority: 10, TTL: 300}); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := f.db.QueryRow(`SELECT id FROM dns_records WHERE zone_id=$1 AND host='child' AND origin='custom'`, f.zone).Scan(&id); err != nil {
		t.Fatal(err)
	}
	for pass := 1; pass <= 2; pass++ {
		var jobs int
		var status string
		if err := f.db.QueryRow(`SELECT count(*) FROM river_job WHERE kind='configure_mail'`).Scan(&jobs); err != nil {
			t.Fatal(err)
		}
		if err := f.db.QueryRow(`SELECT convergence_status FROM mail_domains WHERE site_id=$1`, f.child).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if jobs != pass || status != "pending" {
			t.Errorf("DNS edit left stale mail readiness: jobs=%d status=%s", jobs, status)
		}
		if pass == 1 {
			if _, err := f.db.Exec(`UPDATE mail_domains SET convergence_status='in_sync' WHERE site_id=$1`, f.child); err != nil {
				t.Fatal(err)
			}
			if err := repository.DeleteDNSRecord(context.Background(), f.child, id); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestSubdomainMailDNSAllowsUnusedServiceLabel(t *testing.T) {
	domain := mailDomainRow{SiteID: 2, Domain: "mail.example.test", Enabled: true, DMARCPolicy: "none"}
	desired := scopedMailRecords(domain, "example.test", "192.0.2.1", mailZoneRecords(domain, ""))
	if err := mailDNSConflicts(domain, "example.test", []types.DNSRecord{{OwnerSiteID: 1, Host: "@", Type: "A", Value: "192.0.2.1"}}, desired); err != nil {
		t.Fatalf("unused mail label was banned: %v", err)
	}
}

func TestSubdomainMailDNSFailureDoesNotBlockOtherDomains(t *testing.T) {
	for _, failure := range []string{"CNAME", "missing DKIM"} {
		t.Run(failure, func(t *testing.T) {
			f := newChildMailDNSFixture(t)
			later := removaldb.Site(t, f.db, 1, "zulu.parent-mail.test", f.parent)
			if _, err := f.db.Exec(`UPDATE sites SET dns_zone_mode='parent' WHERE id=$1`, later); err != nil {
				t.Fatal(err)
			}
			if _, err := f.db.Exec(`INSERT INTO mail_domains(subscription_id,site_id,domain,enabled,dkim_enabled,dmarc_policy) VALUES(1,$1,$2,true,true,'none'),(1,$3,'zulu.parent-mail.test',true,true,'none')`, f.child, f.domain.Domain, later); err != nil {
				t.Fatal(err)
			}
			foreign := removaldb.Site(t, f.db, 2, "zzz.foreign.test", nil)
			var foreignZone int64
			if err := f.db.QueryRow(`INSERT INTO dns_zones(owner_user_id,site_id,domain,address,serial,status,template_revision) VALUES(1,$1,'zzz.foreign.test','192.0.2.1',1,'active',1) RETURNING id`, foreign).Scan(&foreignZone); err != nil {
				t.Fatal(err)
			}
			if _, err := f.db.Exec(`INSERT INTO mail_domains(subscription_id,site_id,domain,enabled,dkim_enabled,dmarc_policy) VALUES(1,$1,'parent-mail.test',true,true,'none'),(2,$2,'zzz.foreign.test',true,true,'none')`, f.parent, foreign); err != nil {
				t.Fatal(err)
			}
			agent := childMailDNSAgent{}
			if failure == "CNAME" {
				if _, err := f.db.Exec(`INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,ttl,origin) VALUES($1,$2,'child','CNAME','external.test',300,'custom')`, f.zone, f.child); err != nil {
					t.Fatal(err)
				}
			} else {
				agent.omitDomain = f.domain.Domain
			}
			f.worker.agent = agent
			if err := f.worker.Work(context.Background(), &river.Job[controlquota.ConfigureMailArgs]{Args: controlquota.NewConfigureMailArgs()}); err == nil {
				t.Fatal("child failure was swallowed")
			}
			for _, healthy := range []struct{ site, zone int64 }{{f.parent, f.zone}, {later, f.zone}, {foreign, foreignZone}} {
				var status string
				var effective bool
				var records int
				if err := f.db.QueryRow(`SELECT convergence_status,effective_enabled FROM mail_domains WHERE site_id=$1`, healthy.site).Scan(&status, &effective); err != nil {
					t.Fatal(err)
				}
				if err := f.db.QueryRow(`SELECT count(*) FROM dns_records WHERE zone_id=$1 AND owner_site_id=$2`, healthy.zone, healthy.site).Scan(&records); err != nil {
					t.Fatal(err)
				}
				if status != "in_sync" || !effective || records != 5 {
					t.Errorf("early child failure blocked domain %d: status=%s effective=%t records=%d", healthy.site, status, effective, records)
				}
			}

		})
	}
}
