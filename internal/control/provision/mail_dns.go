package provision

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/lib/pq"
	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

func scopedMailRecords(domain mailDomainRow, zoneDomain, address string, desired []types.DNSRecord) []types.DNSRecord {
	records := append([]types.DNSRecord(nil), desired...)
	prefix := strings.TrimSuffix(domain.Domain, "."+zoneDomain)
	for i := range records {
		if zoneDomain != domain.Domain {
			if records[i].Host == "@" {
				records[i].Host = prefix
			} else {
				records[i].Host += "." + prefix
			}
		}
		if records[i].Type == "A" && records[i].Value == "" {
			records[i].Value = address
		}
	}
	return records
}

func mailDNSConflicts(domain mailDomainRow, zoneDomain string, current, desired []types.DNSRecord) error {
	for _, record := range current {
		if (record.Type == "MX" || record.Type == "NS") && record.OwnerSiteID != domain.SiteID && strings.EqualFold(strings.TrimSuffix(record.Value, "."), domain.Domain) {
			return fmt.Errorf("DNS conflict: %s is an active %s service hostname; choose a separate hosted name", domain.Domain, record.Type)
		}
		hostname := record.Host + "." + zoneDomain
		if record.Host == "@" {
			hostname = zoneDomain
		}
		if strings.HasPrefix(record.TemplateRecordKey, "service-") && strings.EqualFold(hostname, domain.Domain) {
			return fmt.Errorf("DNS conflict: %s is an active service hostname", domain.Domain)
		}
		for _, wanted := range desired {
			if record.Type == "CNAME" && strings.EqualFold(record.Host, wanted.Host) {
				return fmt.Errorf("DNS conflict: %s already has a CNAME; preserve or explicitly replace it before enabling local mail", record.Host)
			}
		}
	}
	return nil
}

func mailDNSDelegated(records []types.DNSRecord, host string) bool {
	for _, record := range records {
		if record.Type == "NS" && strings.EqualFold(record.Host, host) {
			return true
		}
	}
	return false
}

// Public record values are included in the existing convergence notice so an
// external DNS owner can publish the real generated DKIM key as well as routing.
func mailDNSRequirements(domain mailDomainRow, desired []types.DNSRecord) string {
	lines := []string{"Required local mail records:"}
	for _, record := range desired {
		name := domain.Domain
		if record.Host != "@" {
			name = record.Host + "." + domain.Domain
		}
		value := record.Value
		if record.Type == "A" && value == "" {
			value = "your mail server's public IPv4 address"
		}
		if record.Type == "MX" {
			value = fmt.Sprintf("%d %s", record.Priority, value)
		}
		lines = append(lines, name+" "+record.Type+" "+value)
	}
	return strings.Join(lines, "\n")
}

// mailDNSNotice describes configuration that local zone application cannot
// establish. Zone apply progress itself is read live by the Mail workspace.
func (w *ConfigureMailWorker) mailDNSNotice(ctx context.Context, domain mailDomainRow, desired []types.DNSRecord) (string, error) {
	var zoneID int64
	var zoneDomain, address string
	err := w.db.QueryRowContext(ctx, `SELECT zone.id,zone.domain,zone.address FROM sites site
LEFT JOIN sites parent ON parent.id=site.parent_site_id
JOIN dns_zones zone ON zone.site_id=CASE WHEN site.dns_zone_mode='parent' AND parent.id IS NOT NULL THEN parent.id ELSE site.id END
WHERE site.id=$1 AND site.domain=$2 AND zone.mode='primary'`, domain.SiteID, domain.Domain).Scan(&zoneID, &zoneDomain, &address)
	if err == sql.ErrNoRows {
		return "External DNS action required: publish these records with your authoritative DNS provider.\n" + mailDNSRequirements(domain, desired), nil
	}
	if err != nil {
		return "", err
	}
	tx, err := w.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	current, err := loadDNSRecordsTx(ctx, tx, zoneID)
	if err != nil {
		return "", err
	}
	scoped := scopedMailRecords(domain, zoneDomain, address, desired)
	if zoneDomain != domain.Domain && mailDNSDelegated(current, strings.TrimSuffix(domain.Domain, "."+zoneDomain)) {
		return "External DNS action required: this child is delegated by NS records; publish mail records at the delegated DNS provider or explicitly select and delegate a separate local child zone.\n" + mailDNSRequirements(domain, desired), nil
	}
	for _, record := range current {
		protected := record.Origin != "system" || (record.OwnerSiteID != domain.SiteID && record.OwnerSiteID != 0) || IsEndpointDNSRecord(record)
		for _, wanted := range scoped {
			if protected && strings.EqualFold(record.Host, wanted.Host) && serviceDNSConflict(record, wanted) && (record.Value != wanted.Value || record.Priority != wanted.Priority) {
				return "Custom DNS requires action: existing routing or authentication records were preserved. Confirm external routing, or explicitly replace the conflicting records to use local mail.\n" + mailDNSRequirements(domain, desired), nil
			}
		}
	}
	var parentID sql.NullInt64
	var mode string
	if err := tx.QueryRowContext(ctx, `SELECT parent_site_id,dns_zone_mode FROM sites WHERE id=$1`, domain.SiteID).Scan(&parentID, &mode); err != nil {
		return "", err
	}
	if parentID.Valid && mode == "separate" {
		var parentZone int64
		var parentDomain string
		err := tx.QueryRowContext(ctx, `SELECT id,domain FROM dns_zones WHERE site_id=$1 AND mode='primary'`, parentID.Int64).Scan(&parentZone, &parentDomain)
		if err == sql.ErrNoRows {
			return "External DNS delegation action required: delegate " + domain.Domain + " to the NS records of its separate local zone at the authoritative parent DNS provider.", nil
		}
		if err != nil {
			return "", err
		}
		parentRecords, err := loadDNSRecordsTx(ctx, tx, parentZone)
		if err != nil {
			return "", err
		}
		expected, delegated := map[string]bool{}, map[string]bool{}
		for _, record := range current {
			if record.Host == "@" && record.Type == "NS" {
				expected[strings.ToLower(strings.TrimSuffix(record.Value, "."))] = true
			}
		}
		label := strings.TrimSuffix(domain.Domain, "."+parentDomain)
		for _, record := range parentRecords {
			if record.Host == label && record.Type == "NS" {
				delegated[strings.ToLower(strings.TrimSuffix(record.Value, "."))] = true
			}
		}
		matches := len(expected) > 0 && len(expected) == len(delegated)
		for name := range expected {
			matches = matches && delegated[name]
		}
		if !matches {
			return "DNS delegation action required: the parent NS delegation for " + domain.Domain + " must match the NS records at the apex of its separate child zone. Parent records were preserved.", nil
		}
	}
	return "", nil
}

func (w *ConfigureMailWorker) markMailFailure(ctx context.Context, domains []mailDomainRow, cause error) error {
	for _, domain := range domains {
		if _, err := w.db.ExecContext(ctx, `UPDATE mail_domains domain SET convergence_status='failed',last_error=$2,updated_at=now()
WHERE id=$1 AND `+mailDomainIntentVersionSQL+`=$3`, domain.ID, cause.Error(), domain.IntentVersion); err != nil {
			return fmt.Errorf("%w; record mail failure: %v", cause, err)
		}
	}
	return cause
}

// EnqueueMailDNSRecheckTx handles a user DNS edit that can change routing or delegation without changing the
// mail-domain settings. Recheck those domains in the same transaction; the mail
// worker's own DNS reconciliation deliberately does not queue another mail job.
func (r *SQLPhase6Repository) EnqueueMailDNSRecheckTx(ctx context.Context, tx *sql.Tx, zoneIDs ...int64) error {
	result, err := tx.ExecContext(ctx, `UPDATE mail_domains domain SET convergence_status='pending',last_error='',updated_at=now()
WHERE enabled AND NOT delete_requested AND EXISTS (
 SELECT 1 FROM sites site JOIN dns_zones zone ON zone.id=ANY($1::bigint[])
 WHERE site.id=domain.site_id AND (site.id=zone.site_id OR site.parent_site_id=zone.site_id)
)`, pq.Array(zoneIDs))
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count > 0 {
		_, err = r.river.InsertTx(ctx, tx, controlquota.NewConfigureMailArgs(), nil)
	}
	return err
}
