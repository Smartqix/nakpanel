package provision

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/nakroteck/nakpanel/internal/types"
)

// ReconcileSiteDNS updates only configured service endpoints in an existing
// primary zone. It never creates a zone for externally hosted DNS.
func (r *SQLPhase6Repository) ReconcileSiteDNS(ctx context.Context, siteID int64) error {
	if r.river == nil {
		return errors.New("DNS service queue is not configured")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var zoneID int64
	var siteDomain, domain, address, mode string
	err = tx.QueryRowContext(ctx, `SELECT zone.id,site.domain,zone.domain,zone.address,zone.mode
FROM sites site LEFT JOIN sites parent ON parent.id=site.parent_site_id
JOIN dns_zones zone ON zone.site_id=CASE WHEN site.dns_zone_mode='parent' AND parent.id IS NOT NULL THEN parent.id ELSE site.id END
WHERE site.id=$1 AND site.removal_state='none' FOR UPDATE OF zone`, siteID).Scan(&zoneID, &siteDomain, &domain, &address, &mode)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if mode != "primary" {
		return nil
	}
	prefix := ""
	if siteDomain != domain {
		prefix = strings.TrimSuffix(siteDomain, "."+domain)
		if prefix == siteDomain {
			return errors.New("service domain is outside its DNS zone")
		}
	}
	current, err := loadDNSRecordsTx(ctx, tx, zoneID)
	if err != nil {
		return err
	}
	ftps, webmail, err := LoadDNSServiceFlags(ctx, tx, siteID)
	if err != nil {
		return err
	}
	desired := DNSServiceDefaults(domain, address, prefix, current, ftps, webmail)
	for i := len(desired) - 1; i >= 0; i-- {
		baseHost := strings.TrimSuffix(desired[i].Host, "."+prefix)
		var suppressed bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM dns_template_deletions WHERE zone_id=$1 AND owner_site_id=$2 AND template_record_key=$3)`, zoneID, siteID, baseHost+"-a").Scan(&suppressed); err != nil {
			return err
		}
		if suppressed {
			desired = append(desired[:i], desired[i+1:]...)
		}
	}
	add, remove, _ := PlanServiceDNSRecords(current, desired, func(record types.DNSRecord) bool {
		return (record.OwnerSiteID == siteID || record.OwnerSiteID == 0) && IsEndpointDNSRecord(record)
	})
	if len(add)+len(remove) == 0 {
		return tx.Commit()
	}
	if err = insertServiceDNSRecordsTx(ctx, tx, zoneID, siteID, add, remove); err != nil {
		return err
	}
	return r.enqueueDNSZoneTx(ctx, tx, zoneID, false)
}

func (r *SQLPhase6Repository) ReconcileSubscriptionDNS(ctx context.Context, subscriptionID int64) error {
	rows, err := r.db.QueryContext(ctx, `SELECT id FROM sites WHERE subscription_id=$1 AND removal_state='none' ORDER BY id`, subscriptionID)
	if err != nil {
		return err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, id := range ids {
		if err = r.ReconcileSiteDNS(ctx, id); err != nil {
			return err
		}
	}
	return nil
}
