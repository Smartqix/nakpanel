package provision

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/nakroteck/nakpanel/internal/types"
)

// missingSubdomainAddressRecords never replaces a record a user or another
// site controls. Identical existing answers already satisfy the requirement.
func missingSubdomainAddressRecords(existing []types.DNSRecord, label, address, ipv6 string) ([]types.DNSRecord, error) {
	if ip := net.ParseIP(address); ip == nil || ip.To4() == nil {
		return nil, errors.New("the parent DNS zone has no valid server IPv4 address")
	}
	wanted := []types.DNSRecord{{Host: label, Type: "A", Value: address, TTL: 3600}}
	if ipv6 != "" {
		if ip := net.ParseIP(ipv6); ip == nil || ip.To4() != nil {
			return nil, errors.New("the parent DNS zone has no valid server IPv6 address")
		}
		wanted = append(wanted, types.DNSRecord{Host: label, Type: "AAAA", Value: ipv6, TTL: 3600})
	}
	missing := make([]types.DNSRecord, 0, len(wanted))
	for _, desired := range wanted {
		found := false
		for _, record := range existing {
			if record.Host != label {
				continue
			}
			if record.Type == "CNAME" {
				return nil, fmt.Errorf("DNS conflict: %s already has a CNAME record", label)
			}
			if record.Type == desired.Type {
				if !strings.EqualFold(record.Value, desired.Value) {
					return nil, fmt.Errorf("DNS conflict: %s already has a different %s record", label, desired.Type)
				}
				found = true
			}
		}
		if !found {
			missing = append(missing, desired)
		}
	}
	if ipv6 == "" {
		for _, record := range existing {
			if record.Host == label && record.Type == "AAAA" {
				return nil, fmt.Errorf("DNS conflict: %s has an IPv6 address but this server does not", label)
			}
		}
	}
	return missing, nil
}

// AutoConfigureSubdomainDNS adds an address under an authoritative parent
// zone only after the child site is active. External or secondary DNS remains
// the provider's responsibility.
func (r *SQLPhase6Repository) AutoConfigureSubdomainDNS(ctx context.Context, siteID int64) error {
	if r.db == nil || r.river == nil {
		return errors.New("subdomain DNS repository is not configured")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin subdomain DNS transaction: %w", err)
	}
	defer tx.Rollback()
	var parentID sql.NullInt64
	var mode, domain string
	if err := tx.QueryRowContext(ctx, `SELECT parent_site_id,dns_zone_mode,domain
FROM sites WHERE id=$1 AND status='active' FOR UPDATE`, siteID).
		Scan(&parentID, &mode, &domain); err != nil {
		return fmt.Errorf("load active subdomain: %w", err)
	}
	if !parentID.Valid || mode != "parent" {
		return nil
	}
	var zoneID, previousSerial, desiredRevision int64
	var parentDomain, zoneMode, address, ipv6, serialFormat string
	err = tx.QueryRowContext(ctx, `SELECT zone.id,zone.domain,zone.mode,zone.address,zone.ipv6_address,
zone.serial,zone.desired_revision,COALESCE(zone.soa_override->>'serial_format',revision.serial_format,'unix')
FROM dns_zones zone LEFT JOIN dns_template_revisions revision ON revision.revision=zone.template_revision
WHERE zone.site_id=$1 FOR UPDATE OF zone`, parentID.Int64).
		Scan(&zoneID, &parentDomain, &zoneMode, &address, &ipv6, &previousSerial, &desiredRevision, &serialFormat)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load parent DNS zone: %w", err)
	}
	if zoneMode != "primary" {
		return nil
	}
	label := strings.TrimSuffix(domain, "."+parentDomain)
	if label == domain || label == "" || strings.Contains(label, ".") {
		return errors.New("subdomain does not belong to its parent DNS zone")
	}
	rows, err := tx.QueryContext(ctx, `SELECT host,record_type,value FROM dns_records
WHERE zone_id=$1 AND host=$2 AND record_type IN ('A','AAAA','CNAME') FOR UPDATE`, zoneID, label)
	if err != nil {
		return fmt.Errorf("load subdomain DNS records: %w", err)
	}
	var existing []types.DNSRecord
	for rows.Next() {
		var record types.DNSRecord
		if err := rows.Scan(&record.Host, &record.Type, &record.Value); err != nil {
			rows.Close()
			return err
		}
		existing = append(existing, record)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	missing, err := missingSubdomainAddressRecords(existing, label, address, ipv6)
	if err != nil {
		return err
	}
	if len(missing) == 0 {
		return nil
	}
	for _, record := range missing {
		if _, err := tx.ExecContext(ctx, `INSERT INTO dns_records(zone_id,owner_site_id,host,record_type,value,ttl,origin)
VALUES($1,$2,$3,$4,$5,$6,'system') ON CONFLICT DO NOTHING`, zoneID, siteID,
			record.Host, record.Type, record.Value, record.TTL); err != nil {
			return fmt.Errorf("insert subdomain DNS record: %w", err)
		}
	}
	serial, err := nextProvisionDNSSerial(r.now().UTC(), previousSerial, serialFormat)
	if err != nil {
		return err
	}
	desiredRevision++
	if _, err := tx.ExecContext(ctx, `UPDATE dns_zones SET serial=$2,desired_revision=$3,status='pending',
last_error='',updated_at=now() WHERE id=$1`, zoneID, serial, desiredRevision); err != nil {
		return err
	}
	if _, err := r.river.InsertTx(ctx, tx, ConfigureDNSZoneArgs{ZoneID: zoneID, DesiredRevision: desiredRevision}, nil); err != nil {
		return fmt.Errorf("enqueue parent DNS zone: %w", err)
	}
	return tx.Commit()
}
