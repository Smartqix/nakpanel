package provision

import (
	"context"
	"database/sql"
	"strings"

	"github.com/nakroteck/nakpanel/internal/types"
)

type DNSServiceState struct {
	FTPS    bool
	Webmail bool
}

// DNSServiceDefaults describes configured endpoints, not permissions to create
// them. Nameserver addresses are emitted only inside their authoritative zone.
func DNSServiceDefaults(domain, address, prefix string, records []types.DNSRecord, ftps, webmail bool) []types.DNSRecord {
	var desired []types.DNSRecord
	add := func(host, key string) {
		if prefix != "" {
			host += "." + prefix
		}
		desired = append(desired, types.DNSRecord{Host: host, Type: "A", Value: address, TTL: 3600, Origin: "system", TemplateRecordKey: "service-" + key})
	}
	if ftps {
		add("ftp", "ftp")
	}
	if webmail {
		add("webmail", "webmail")
	}
	if prefix == "" {
		seen := map[string]bool{}
		for _, record := range records {
			if record.Host != "@" || record.Type != "NS" {
				continue
			}
			name := strings.TrimSuffix(strings.ToLower(record.Value), ".")
			host := strings.TrimSuffix(name, "."+strings.ToLower(domain))
			if host == name || host == "" || seen[host] {
				continue
			}
			seen[host] = true
			add(host, "nameserver-"+host)
		}
	}
	return desired
}

// PlanServiceDNSRecords never mutates a customer/template-owned RRset. A
// conflicting custom answer suppresses the local default instead of mixing
// local and external routing. Identical records retain their IDs and TTLs.
func PlanServiceDNSRecords(current, desired []types.DNSRecord, owns func(types.DNSRecord) bool) (add []types.DNSRecord, remove []int64, preserved int) {
	var allowed []types.DNSRecord
	for _, wanted := range desired {
		blocked := false
		for _, record := range current {
			if owns(record) || !strings.EqualFold(record.Host, wanted.Host) {
				continue
			}
			if serviceDNSConflict(record, wanted) {
				blocked = true
				preserved++
				break
			}
		}
		if !blocked {
			allowed = append(allowed, wanted)
		}
	}
	for _, record := range current {
		if !owns(record) {
			continue
		}
		found := false
		for _, wanted := range allowed {
			if mailRecordSetsEqual([]types.DNSRecord{record}, []types.DNSRecord{wanted}) {
				found = true
				break
			}
		}
		if !found {
			remove = append(remove, record.ID)
		}
	}
	for _, wanted := range allowed {
		found := false
		for _, record := range current {
			if owns(record) && mailRecordSetsEqual([]types.DNSRecord{record}, []types.DNSRecord{wanted}) {
				found = true
				break
			}
		}
		if !found {
			add = append(add, wanted)
		}
	}
	return
}

func serviceDNSConflict(record, wanted types.DNSRecord) bool {
	if record.Type == "CNAME" || wanted.Type == "CNAME" {
		return true
	}
	if record.Type != wanted.Type {
		return false
	}
	if record.Type != "TXT" {
		return true
	}
	if strings.EqualFold(record.Host, "_dmarc") || strings.HasPrefix(strings.ToLower(record.Host), "_dmarc.") {
		return true
	}
	for _, prefix := range []string{"v=spf1", "v=dmarc1"} {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(record.Value)), prefix) && strings.HasPrefix(strings.ToLower(strings.TrimSpace(wanted.Value)), prefix) {
			return true
		}
	}
	return strings.Contains(strings.ToLower(record.Host), "_domainkey") || record.Value == wanted.Value
}

func IsEndpointDNSRecord(record types.DNSRecord) bool {
	return record.Origin == "system" && (strings.HasPrefix(record.TemplateRecordKey, "service-") ||
		(record.Type == "A" && (record.Host == "ns1" || record.Host == "webmail" || record.Host == "ftp")))
}

type dnsServiceQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func LoadDNSServiceFlags(ctx context.Context, q dnsServiceQuerier, siteID int64) (ftps, webmail bool, err error) {
	err = q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ftp_accounts ftp JOIN sites site ON site.subscription_id=ftp.subscription_id
WHERE site.id=$1 AND (ftp.site_id IS NULL OR ftp.site_id=site.id) AND ftp.enabled AND ftp.convergence_status='in_sync'),
EXISTS(SELECT 1 FROM webmail_hosts WHERE site_id=$1 AND status='active')`, siteID).Scan(&ftps, &webmail)
	return
}

func loadDNSRecordsTx(ctx context.Context, tx *sql.Tx, zoneID int64) ([]types.DNSRecord, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,COALESCE(owner_site_id,0),host,record_type,value,COALESCE(priority,0),ttl,origin,COALESCE(template_record_key,'') FROM dns_records WHERE zone_id=$1 ORDER BY id`, zoneID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []types.DNSRecord
	for rows.Next() {
		var r types.DNSRecord
		if err = rows.Scan(&r.ID, &r.OwnerSiteID, &r.Host, &r.Type, &r.Value, &r.Priority, &r.TTL, &r.Origin, &r.TemplateRecordKey); err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}

func insertServiceDNSRecordsTx(ctx context.Context, tx *sql.Tx, zoneID, siteID int64, add []types.DNSRecord, remove []int64) error {
	for _, id := range remove {
		if _, err := tx.ExecContext(ctx, `DELETE FROM dns_records WHERE id=$1 AND zone_id=$2 AND origin='system'`, id, zoneID); err != nil {
			return err
		}
	}
	for _, r := range add {
		if _, err := tx.ExecContext(ctx, `INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,priority,ttl,origin,template_record_key)
VALUES($1,$2,$3,$4,$5,$6,$7,'system',$8) ON CONFLICT DO NOTHING`, zoneID, siteID, r.Host, r.Type, r.Value, nullableDNSPriority(r), r.TTL, nullableDNSKey(r.TemplateRecordKey)); err != nil {
			return err
		}
	}
	return nil
}

func nullableDNSKey(key string) any {
	if key == "" {
		return nil
	}
	return key
}
