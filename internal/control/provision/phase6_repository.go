package provision

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

type SQLPhase6Repository struct {
	db    *sql.DB
	river *river.Client[*sql.Tx]
	now   func() time.Time
}

var controlDNSOwnerRE = regexp.MustCompile(`^(@|[A-Za-z0-9_](?:[A-Za-z0-9._-]*[A-Za-z0-9_-])?)$`)

func normalizeDNSRecord(domain string, record types.DNSRecord) (types.DNSRecord, error) {
	record.Host = strings.ToLower(strings.TrimSpace(record.Host))
	if record.Host == "" {
		record.Host = "@"
	}
	record.Type = strings.ToUpper(strings.TrimSpace(record.Type))
	record.Value = strings.TrimSpace(record.Value)
	if strings.ContainsAny(record.Host, "\r\n\x00 \t") || strings.ContainsAny(record.Value, "\r\n\x00") {
		return record, errors.New("DNS records cannot contain whitespace or control-character injection")
	}
	if record.TTL == 0 {
		record.TTL = 3600
	}
	if record.TTL < 60 || record.TTL > 86400 {
		return record, errors.New("DNS TTL must be between 60 and 86400")
	}
	if len(record.Host) > 253 || !controlDNSOwnerRE.MatchString(record.Host) || !validControlDNSOwnerLabels(record.Host) {
		return record, errors.New("DNS host is invalid")
	}
	if record.Host != "@" && !strings.Contains(record.Host, "_") {
		if err := site.ValidateDomain(record.Host + "." + domain); err != nil {
			return record, fmt.Errorf("invalid DNS host: %w", err)
		}
	}
	switch record.Type {
	case "A":
		ip := net.ParseIP(record.Value)
		if ip == nil || ip.To4() == nil {
			return record, errors.New("A record requires an IPv4 address")
		}
		record.Priority = 0
		record.Weight = 0
		record.Port = 0
	case "AAAA":
		ip := net.ParseIP(record.Value)
		if ip == nil || ip.To4() != nil {
			return record, errors.New("AAAA record requires an IPv6 address")
		}
		record.Priority = 0
		record.Weight = 0
		record.Port = 0
	case "CNAME":
		if record.Host == "@" {
			return record, errors.New("a CNAME record cannot be created at the zone apex")
		}
		record.Value = canonicalDNSRecordTarget(record.Value)
		if err := site.ValidateDomain(record.Value); err != nil {
			return record, errors.New("CNAME requires a fully qualified domain")
		}
		record.Priority = 0
		record.Weight = 0
		record.Port = 0
	case "MX":
		record.Value = canonicalDNSRecordTarget(record.Value)
		if err := site.ValidateDomain(record.Value); err != nil {
			return record, errors.New("MX requires a fully qualified domain")
		}
		if record.Priority < 0 || record.Priority > 65535 {
			return record, errors.New("MX priority is invalid")
		}
		record.Weight = 0
		record.Port = 0
	case "NS":
		record.Value = canonicalDNSRecordTarget(record.Value)
		if err := site.ValidateDomain(record.Value); err != nil {
			return record, errors.New("NS requires a fully qualified domain")
		}
		record.Priority = 0
		record.Weight = 0
		record.Port = 0
	case "SRV":
		if !validControlSRVOwner(record.Host) {
			return record, errors.New("SRV host must use the _service._protocol form")
		}
		record.Value = canonicalDNSRecordTarget(record.Value)
		if err := site.ValidateDomain(record.Value); err != nil {
			return record, errors.New("SRV requires a fully qualified target")
		}
		if record.Priority < 0 || record.Priority > 65535 || record.Weight < 0 || record.Weight > 65535 || record.Port < 1 || record.Port > 65535 {
			return record, errors.New("SRV priority, weight, or port is invalid")
		}
	case "CAA":
		match := regexp.MustCompile(`^([0-9]{1,3})\s+(issue|issuewild|iodef)\s+"[^"\r\n]+"$`).FindStringSubmatch(record.Value)
		if len(match) != 2 {
			return record, errors.New(`CAA value must be: flags tag "value"`)
		}
		flags, _ := strconv.Atoi(match[1])
		if flags > 255 {
			return record, errors.New("CAA flags must be between 0 and 255")
		}
		record.Priority = 0
		record.Weight = 0
		record.Port = 0
	case "DS":
		match := regexp.MustCompile(`^([0-9]{1,5})\s+([0-9]{1,3})\s+([124])\s+([A-Fa-f0-9]+)$`).FindStringSubmatch(record.Value)
		if len(match) != 5 {
			return record, errors.New("DS value must contain key-tag algorithm digest-type digest")
		}
		keyTag, _ := strconv.Atoi(match[1])
		algorithm, _ := strconv.Atoi(match[2])
		if keyTag > 65535 || algorithm < 1 || algorithm > 255 {
			return record, errors.New("DS key tag or algorithm is invalid")
		}
		digestType, _ := strconv.Atoi(match[3])
		if want := map[int]int{1: 40, 2: 64, 4: 96}[digestType]; len(match[4]) != want {
			return record, errors.New("DS digest length does not match its digest type")
		}
		record.Priority = 0
		record.Weight = 0
		record.Port = 0
	case "TXT":
		if record.Value == "" || len(record.Value) > 4096 {
			return record, errors.New("TXT value must contain 1 to 4096 characters")
		}
		record.Priority = 0
		record.Weight = 0
		record.Port = 0
	default:
		return record, fmt.Errorf("unsupported DNS record type %q", record.Type)
	}
	return record, nil
}

func canonicalDNSRecordTarget(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func validControlSRVOwner(host string) bool {
	labels := strings.Split(strings.ToLower(strings.TrimSpace(host)), ".")
	return len(labels) >= 2 && len(labels[0]) > 1 && len(labels[1]) > 1 &&
		strings.HasPrefix(labels[0], "_") && strings.HasPrefix(labels[1], "_")
}

func validControlDNSOwnerLabels(host string) bool {
	if host == "@" {
		return true
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

func (r *SQLPhase6Repository) UpsertDNSRecord(ctx context.Context, siteID int64, record types.DNSRecord) error {
	if r.db == nil || r.river == nil {
		return errors.New("DNS record repository is not configured")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var zoneID, zoneOwnerSiteID int64
	var domain, siteDomain string
	if err = tx.QueryRowContext(ctx, `SELECT zone.id,zone.site_id,zone.domain,site.domain
FROM sites site
LEFT JOIN sites parent ON parent.id=site.parent_site_id
JOIN dns_zones zone ON zone.site_id=CASE
    WHEN site.dns_zone_mode='parent' AND parent.id IS NOT NULL THEN parent.id ELSE site.id END
WHERE site.id=$1 FOR UPDATE OF zone`, siteID).Scan(&zoneID, &zoneOwnerSiteID, &domain, &siteDomain); err != nil {
		return err
	}
	record, err = normalizeDNSRecord(domain, record)
	if err != nil {
		return err
	}
	if siteDomain != domain {
		label := strings.TrimSuffix(siteDomain, "."+domain)
		if label == siteDomain || label == "" {
			return errors.New("site is not inside its selected parent DNS zone")
		}
		if record.Host == "@" {
			record.Host = label
		} else {
			record.Host += "." + label
		}
	}
	if err := ensureDNSRecordCompatibility(ctx, tx, zoneID, record); err != nil {
		return err
	}
	if record.ID > 0 {
		res, execErr := tx.ExecContext(ctx, `UPDATE dns_records SET host=$4,record_type=$5,value=$6,
priority=$7,weight=$8,port=$9,ttl=$10,
locally_modified=CASE WHEN origin='template' THEN true ELSE locally_modified END,updated_at=now()
WHERE id=$1 AND zone_id=$2 AND origin<>'system' AND (owner_site_id=$3 OR $3=$11)`,
			record.ID, zoneID, siteID, record.Host, record.Type, record.Value,
			nullableDNSPriority(record), nullableDNSWeight(record), nullableDNSPort(record), record.TTL, zoneOwnerSiteID)
		if execErr != nil {
			return execErr
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
	} else {
		if _, err = tx.ExecContext(ctx, `INSERT INTO dns_records(
zone_id,owner_site_id,host,record_type,value,priority,weight,port,ttl,origin
) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'custom')`,
			zoneID, siteID, record.Host, record.Type, record.Value, nullableDNSPriority(record),
			nullableDNSWeight(record), nullableDNSPort(record), record.TTL); err != nil {
			return err
		}
	}
	return r.enqueueDNSZoneTx(ctx, tx, zoneID)
}

func (r *SQLPhase6Repository) DeleteDNSRecord(ctx context.Context, siteID, recordID int64) error {
	if r.db == nil || r.river == nil {
		return errors.New("DNS record repository is not configured")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var zoneID, zoneOwnerSiteID int64
	if err = tx.QueryRowContext(ctx, `SELECT zone.id,zone.site_id
FROM sites site
LEFT JOIN sites parent ON parent.id=site.parent_site_id
JOIN dns_zones zone ON zone.site_id=CASE
    WHEN site.dns_zone_mode='parent' AND parent.id IS NOT NULL THEN parent.id ELSE site.id END
WHERE site.id=$1 FOR UPDATE OF zone`, siteID).Scan(&zoneID, &zoneOwnerSiteID); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM dns_records
WHERE id=$1 AND zone_id=$2 AND origin<>'system' AND (owner_site_id=$3 OR $3=$4)`,
		recordID, zoneID, siteID, zoneOwnerSiteID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return r.enqueueDNSZoneTx(ctx, tx, zoneID)
}

func nullableDNSPriority(record types.DNSRecord) any {
	if record.Type == "MX" || record.Type == "SRV" {
		return record.Priority
	}
	return nil
}

func nullableDNSWeight(record types.DNSRecord) any {
	if record.Type == "SRV" {
		return record.Weight
	}
	return nil
}

func nullableDNSPort(record types.DNSRecord) any {
	if record.Type == "SRV" {
		return record.Port
	}
	return nil
}

func ensureDNSRecordCompatibility(ctx context.Context, tx *sql.Tx, zoneID int64, record types.DNSRecord) error {
	var count int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM dns_records
WHERE zone_id=$1 AND lower(host)=lower($2) AND id<>$3
  AND (record_type='CNAME' OR $4='CNAME')`,
		zoneID, record.Host, record.ID, record.Type).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return errors.New("a CNAME cannot coexist with another record at the same host")
	}
	return nil
}

func (r *SQLPhase6Repository) enqueueDNSZoneTx(ctx context.Context, tx *sql.Tx, zoneID int64, markCustomized ...bool) error {
	var previousSerial, desiredRevision int64
	var serialFormat string
	if err := tx.QueryRowContext(ctx, `SELECT zone.serial,zone.desired_revision,
COALESCE(zone.soa_override->>'serial_format',revision.serial_format)
FROM dns_zones zone
JOIN dns_template_revisions revision ON revision.revision=zone.template_revision
WHERE zone.id=$1`, zoneID).Scan(&previousSerial, &desiredRevision, &serialFormat); err != nil {
		return err
	}
	serial, err := nextProvisionDNSSerial(r.now().UTC(), previousSerial, serialFormat)
	if err != nil {
		return err
	}
	desiredRevision++
	customized := true
	if len(markCustomized) > 0 {
		customized = markCustomized[0]
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dns_zones SET serial=$2,desired_revision=$3,status='pending',
template_status=CASE WHEN $4 AND template_revision IS NOT NULL THEN 'customized' ELSE template_status END,
last_error='',updated_at=now() WHERE id=$1`, zoneID, serial, desiredRevision, customized); err != nil {
		return err
	}
	if _, err := r.river.InsertTx(ctx, tx, ConfigureDNSZoneArgs{ZoneID: zoneID, DesiredRevision: desiredRevision}, nil); err != nil {
		return err
	}
	return tx.Commit()
}

func nextProvisionDNSSerial(now time.Time, previous int64, format string) (int64, error) {
	var serial int64
	if format == "date-counter" {
		base, _ := strconv.ParseInt(now.Format("20060102")+"00", 10, 64)
		if previous >= base && previous < base+99 {
			serial = previous + 1
		} else if previous >= base+99 && previous < base+100 {
			return 0, errors.New("the DNS serial date counter is exhausted for today")
		} else if previous > base {
			serial = previous + 1
		} else {
			serial = base
		}
	} else {
		serial = now.Unix()
		if serial <= previous {
			serial = previous + 1
		}
	}
	if serial < 1 || serial > int64(^uint32(0)) {
		return 0, errors.New("the next DNS serial exceeds the RFC 1982 32-bit range")
	}
	return serial, nil
}

func NewSQLPhase6Repository(db *sql.DB, riverClient *river.Client[*sql.Tx]) *SQLPhase6Repository {
	return &SQLPhase6Repository{db: db, river: riverClient, now: time.Now}
}

func (r *SQLPhase6Repository) CreateBackup(ctx context.Context, ownerID int64, req types.CreateBackupReq) (int64, error) {
	if r.db == nil {
		return 0, errors.New("database is not configured")
	}
	if r.river == nil {
		return 0, errors.New("river client is not configured")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin backup transaction: %w", err)
	}
	defer tx.Rollback()

	var site phase6Site
	if req.SubscriptionID > 0 {
		if err := guardBackupIntentTx(ctx, tx, req.SubscriptionID, req.Domain); err != nil {
			return 0, fmt.Errorf("guard backup entitlement: %w", err)
		}
		site, err = selectActiveSubscriptionSiteForUpdate(ctx, tx, req.SubscriptionID, req.Domain)
	} else {
		site, err = selectActiveSiteForUpdate(ctx, tx, ownerID, req.Domain)
	}
	if err != nil {
		return 0, err
	}
	var databases []string
	if req.SubscriptionID > 0 {
		databases, err = selectActiveSubscriptionDatabases(ctx, tx, req.SubscriptionID)
	} else {
		databases, err = selectActiveOwnerDatabases(ctx, tx, ownerID)
	}
	if err != nil {
		return 0, err
	}
	var backupID int64
	if req.SubscriptionID > 0 {
		err = tx.QueryRowContext(ctx, `INSERT INTO backups (owner_user_id, customer_id, site_id, subscription_id, target_kind, target_name, status)
SELECT $1, s.customer_id, $2, s.id, 'site', $3, 'pending'
FROM subscriptions s
WHERE s.id = $4
  AND s.status = 'active'
RETURNING id`, ownerID, site.id, site.domain, req.SubscriptionID).Scan(&backupID)
	} else {
		err = tx.QueryRowContext(ctx, `INSERT INTO backups (owner_user_id, customer_id, site_id, subscription_id, target_kind, target_name, status)
VALUES ($1, (SELECT customer_id FROM subscriptions WHERE customer_user_id = $1 AND status = 'active' LIMIT 1), $2, (SELECT id FROM subscriptions WHERE customer_user_id = $1 AND status = 'active' LIMIT 1), 'site', $3, 'pending')
RETURNING id`, ownerID, site.id, site.domain).Scan(&backupID)
	}
	if err != nil {
		return 0, fmt.Errorf("insert backup intent: %w", err)
	}
	_, err = r.river.InsertTx(ctx, tx, CreateBackupArgs{
		BackupID:       backupID,
		SiteID:         site.id,
		SubscriptionID: req.SubscriptionID,
		Domain:         site.domain,
		Username:       site.username,
		Docroot:        site.documentRoot,
		Databases:      databases,
	}, nil)
	if err != nil {
		return 0, fmt.Errorf("enqueue create_backup job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit backup transaction: %w", err)
	}
	return backupID, nil
}

func (r *SQLPhase6Repository) ConfigureWebmail(ctx context.Context, ownerID int64, domain string) (int64, error) {
	if r.db == nil {
		return 0, errors.New("database is not configured")
	}
	if r.river == nil {
		return 0, errors.New("river client is not configured")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin webmail transaction: %w", err)
	}
	defer tx.Rollback()

	site, err := selectActiveSiteByDomainForUpdate(ctx, tx, domain)
	if err != nil {
		return 0, err
	}
	hostname := "webmail." + site.domain
	var id int64
	if err := tx.QueryRowContext(ctx, `INSERT INTO webmail_hosts (owner_user_id, site_id, hostname, status, last_error)
VALUES ($1, $2, $3, 'pending', '')
ON CONFLICT (hostname) DO UPDATE SET status = 'pending', last_error = '', updated_at = now()
RETURNING id`, ownerID, site.id, hostname).Scan(&id); err != nil {
		return 0, fmt.Errorf("upsert webmail intent: %w", err)
	}
	_, err = r.river.InsertTx(ctx, tx, ConfigureWebmailArgs{WebmailID: id, Domain: site.domain, Hostname: hostname}, nil)
	if err != nil {
		return 0, fmt.Errorf("enqueue configure_webmail job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit webmail transaction: %w", err)
	}
	return id, nil
}

func (r *SQLPhase6Repository) RestoreBackup(ctx context.Context, ownerID int64, backupID int64) (int64, error) {
	if backupID <= 0 {
		return 0, errors.New("backup id is required")
	}
	if r.db == nil {
		return 0, errors.New("database is not configured")
	}
	if r.river == nil {
		return 0, errors.New("river client is not configured")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin restore transaction: %w", err)
	}
	defer tx.Rollback()

	backup, err := selectRestorableBackupForUpdate(ctx, tx, backupID)
	if err != nil {
		return 0, err
	}
	databases, err := selectActiveSubscriptionDatabases(ctx, tx, backup.subscriptionID)
	if err != nil {
		return 0, err
	}
	var restoreID int64
	if err := tx.QueryRowContext(ctx, `INSERT INTO restore_runs (owner_user_id, backup_id, target_name, status)
VALUES ($1, $2, $3, 'pending')
RETURNING id`, ownerID, backupID, backup.domain).Scan(&restoreID); err != nil {
		return 0, fmt.Errorf("insert restore run: %w", err)
	}
	_, err = r.river.InsertTx(ctx, tx, RestoreBackupArgs{
		RestoreID:   restoreID,
		BackupID:    backupID,
		Domain:      backup.domain,
		Username:    backup.username,
		Docroot:     backup.documentRoot,
		ArchivePath: backup.archivePath,
		Databases:   databases,
	}, nil)
	if err != nil {
		return 0, fmt.Errorf("enqueue restore_backup job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit restore transaction: %w", err)
	}
	return restoreID, nil
}

func (r *SQLPhase6Repository) ConfigureDNS(ctx context.Context, ownerID int64, domain string, address string) (int64, error) {
	if ip := net.ParseIP(address); ip == nil || ip.To4() == nil {
		return 0, fmt.Errorf("invalid dns address %q", address)
	}
	if r.db == nil {
		return 0, errors.New("database is not configured")
	}
	if r.river == nil {
		return 0, errors.New("river client is not configured")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin dns transaction: %w", err)
	}
	defer tx.Rollback()

	site, err := selectActiveSiteByDomainForUpdate(ctx, tx, domain)
	if err != nil {
		return 0, err
	}
	var parentSiteID sql.NullInt64
	var siteZoneMode string
	if err := tx.QueryRowContext(ctx, `SELECT parent_site_id,dns_zone_mode FROM sites WHERE id=$1`, site.id).
		Scan(&parentSiteID, &siteZoneMode); err != nil {
		return 0, err
	}
	serial := r.now().UTC().Unix()
	var id int64
	ownerSiteID := site.id
	zoneDomain := site.domain
	subdomain := ""
	if siteZoneMode == "parent" && parentSiteID.Valid {
		var parentDomain string
		err := tx.QueryRowContext(ctx, `SELECT zone.id,zone.domain FROM dns_zones zone
JOIN sites parent ON parent.id=zone.site_id WHERE parent.id=$1 FOR UPDATE OF zone`,
			parentSiteID.Int64).Scan(&id, &parentDomain)
		if err == nil {
			zoneDomain = parentDomain
			subdomain = strings.TrimSuffix(site.domain, "."+parentDomain)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return 0, err
		} else {
			siteZoneMode = "separate"
			if _, err := tx.ExecContext(ctx, `UPDATE sites SET dns_zone_mode='separate' WHERE id=$1`, site.id); err != nil {
				return 0, err
			}
		}
	}
	if id == 0 {
		var templateRevision int64
		var templateID int64
		var templateZoneStatus string
		if err := tx.QueryRowContext(ctx, `SELECT revision.id,revision.revision,revision.zone_status
FROM dns_template_state state JOIN dns_template_revisions revision ON revision.id=state.active_revision_id`).
			Scan(&templateID, &templateRevision, &templateZoneStatus); err != nil {
			return 0, err
		}
		mode := "primary"
		if templateZoneStatus == "disabled" {
			mode = "disabled"
		}
		if err := tx.QueryRowContext(ctx, `INSERT INTO dns_zones(
owner_user_id,site_id,domain,address,serial,status,last_error,mode,template_revision,
template_status,desired_revision,applied_revision
) VALUES($1,$2,$3,$4,$5,'pending','',$6,$7,'pending',1,0)
ON CONFLICT (domain) DO UPDATE SET address=EXCLUDED.address,serial=EXCLUDED.serial,
status='pending',desired_revision=dns_zones.desired_revision+1,last_error='',updated_at=now()
RETURNING id`, ownerID, site.id, site.domain, address, serial, mode, templateRevision).Scan(&id); err != nil {
			return 0, fmt.Errorf("upsert dns intent: %w", err)
		}
		zoneDomain = site.domain
		if err := instantiateDNSTemplateTx(ctx, tx, id, ownerSiteID, templateID, templateRevision, zoneDomain, "", address, ""); err != nil {
			return 0, err
		}
		if err := ensureSystemDNSRecordsTx(ctx, tx, id, ownerSiteID, zoneDomain, address); err != nil {
			return 0, err
		}
	} else {
		var templateID, templateRevision int64
		if err := tx.QueryRowContext(ctx, `SELECT revision.id,revision.revision
FROM dns_template_state state JOIN dns_template_revisions revision ON revision.id=state.active_revision_id`).
			Scan(&templateID, &templateRevision); err != nil {
			return 0, err
		}
		if err := instantiateDNSTemplateTx(ctx, tx, id, ownerSiteID, templateID, templateRevision, zoneDomain, subdomain, address, ""); err != nil {
			return 0, err
		}
		if subdomain == "" {
			if err := ensureSystemDNSRecordsTx(ctx, tx, id, ownerSiteID, zoneDomain, address); err != nil {
				return 0, err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sites
SET dns_template_adoption_completed=true,updated_at=now() WHERE id=$1`, site.id); err != nil {
		return 0, err
	}
	if err := r.enqueueDNSZoneTx(ctx, tx, id, false); err != nil {
		return 0, fmt.Errorf("enqueue configure_dns_zone job: %w", err)
	}
	return id, nil
}

func ensureSystemDNSRecordsTx(ctx context.Context, tx *sql.Tx, zoneID, ownerSiteID int64, domain, address string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM dns_records
WHERE zone_id=$1 AND origin='system' AND (
    (host='@' AND record_type='NS') OR
    (host IN ('ns1','webmail') AND record_type='A')
)`, zoneID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO dns_records(
zone_id,owner_site_id,host,record_type,value,ttl,origin
) VALUES
($1,$2,'@','NS',$3,3600,'system'),
($1,$2,'ns1','A',$4,3600,'system'),
($1,$2,'webmail','A',$4,3600,'system')
ON CONFLICT DO NOTHING`, zoneID, ownerSiteID, "ns1."+domain, address)
	return err
}

func instantiateDNSTemplateTx(
	ctx context.Context,
	tx *sql.Tx,
	zoneID, ownerSiteID, templateID, templateRevision int64,
	domain, subdomain, address, ipv6 string,
) error {
	rows, err := tx.QueryContext(ctx, `SELECT stable_key,scope,host_template,record_type,value_template,
COALESCE(priority,0),COALESCE(weight,0),COALESCE(port,0),ttl
FROM dns_template_records WHERE revision_id=$1 ORDER BY id`, templateID)
	if err != nil {
		return err
	}
	type templateRecord struct {
		key, scope, host, recordType, value string
		priority, weight, port, ttl         int
	}
	var templateRecords []templateRecord
	for rows.Next() {
		var record templateRecord
		if err := rows.Scan(&record.key, &record.scope, &record.host, &record.recordType,
			&record.value, &record.priority, &record.weight, &record.port, &record.ttl); err != nil {
			rows.Close()
			return err
		}
		templateRecords = append(templateRecords, record)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	hostname := domain
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(NULLIF((
    SELECT payload->>'hostname' FROM server_inventory WHERE kind='server' AND resource_key='host'
),''),$1)`, domain).Scan(&hostname); err != nil {
		return err
	}
	for _, templateRecord := range templateRecords {
		key, scope, host, recordType, value := templateRecord.key, templateRecord.scope, templateRecord.host, templateRecord.recordType, templateRecord.value
		priority, weight, port, ttl := templateRecord.priority, templateRecord.weight, templateRecord.port, templateRecord.ttl
		if (scope == "root" && subdomain != "") || (scope == "subdomain" && subdomain == "") {
			continue
		}
		if strings.Contains(value, "<ipv6.") && ipv6 == "" {
			continue
		}
		replacements := map[string]string{
			"<domain>": domain, "<subdomain>": subdomain, "<hostname>": hostname,
		}
		for placeholder, replacement := range replacements {
			host = strings.ReplaceAll(host, placeholder, replacement)
			value = strings.ReplaceAll(value, placeholder, replacement)
		}
		host = regexp.MustCompile(`<ip\.[a-z0-9_-]+>`).ReplaceAllString(host, address)
		value = regexp.MustCompile(`<ip\.[a-z0-9_-]+>`).ReplaceAllString(value, address)
		host = regexp.MustCompile(`<ipv6\.[a-z0-9_-]+>`).ReplaceAllString(host, ipv6)
		value = regexp.MustCompile(`<ipv6\.[a-z0-9_-]+>`).ReplaceAllString(value, ipv6)
		if subdomain != "" {
			switch {
			case host == "@":
				host = subdomain
			case host != subdomain && !strings.HasSuffix(host, "."+subdomain):
				host += "." + subdomain
			}
		}
		record, err := normalizeDNSRecord(domain, types.DNSRecord{
			Host: host, Type: recordType, Value: value, Priority: priority,
			Weight: weight, Port: port, TTL: ttl,
		})
		if err != nil {
			return fmt.Errorf("expand DNS template record %s: %w", key, err)
		}
		if err := ensureDNSRecordCompatibility(ctx, tx, zoneID, record); err != nil {
			return fmt.Errorf("expand DNS template record %s: %w", key, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO dns_records(
zone_id,owner_site_id,host,record_type,value,priority,weight,port,ttl,origin,
template_record_key,template_revision,locally_modified
) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'template',$10,$11,false)
ON CONFLICT DO NOTHING`, zoneID, ownerSiteID, record.Host, record.Type, record.Value,
			nullableDNSPriority(record), nullableDNSWeight(record), nullableDNSPort(record),
			record.TTL, key, templateRevision); err != nil {
			return err
		}
	}
	return nil
}

func (r *SQLPhase6Repository) ReconcileSystem(ctx context.Context, ownerID int64) (int64, error) {
	if r.db == nil {
		return 0, errors.New("database is not configured")
	}
	if r.river == nil {
		return 0, errors.New("river client is not configured")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin reconciliation transaction: %w", err)
	}
	defer tx.Rollback()

	sites, err := selectReconcileSites(ctx, tx)
	if err != nil {
		return 0, err
	}
	databases, err := selectReconcileDatabases(ctx, tx)
	if err != nil {
		return 0, err
	}
	if err := lockReconcileSubscriptions(ctx, tx, sites, databases); err != nil {
		return 0, err
	}
	var runID int64
	if err := tx.QueryRowContext(ctx, `INSERT INTO reconciliation_runs (owner_user_id, status, sites_total)
VALUES ($1, 'pending', $2)
RETURNING id`, ownerID, len(sites)).Scan(&runID); err != nil {
		return 0, fmt.Errorf("insert reconciliation run: %w", err)
	}
	_, err = r.river.InsertTx(ctx, tx, ReconcileSystemArgs{RunID: runID, Sites: sites, Databases: databases}, nil)
	if err != nil {
		return 0, fmt.Errorf("enqueue reconcile_system job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit reconciliation transaction: %w", err)
	}
	return runID, nil
}

func (r *SQLPhase6Repository) ReconcileSite(ctx context.Context, ownerID int64, domain string) (int64, error) {
	if r.db == nil || r.river == nil {
		return 0, errors.New("site reconciliation repository is not configured")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	allSites, err := selectReconcileSites(ctx, tx)
	if err != nil {
		return 0, err
	}
	var selected []types.ReconcileSiteReq
	for _, candidate := range allSites {
		if candidate.Domain == domain {
			selected = append(selected, candidate)
			break
		}
	}
	if len(selected) == 0 {
		return 0, sql.ErrNoRows
	}
	if err = lockReconcileSubscriptions(ctx, tx, selected, nil); err != nil {
		return 0, err
	}
	var runID int64
	if err = tx.QueryRowContext(ctx, `INSERT INTO reconciliation_runs(owner_user_id,status,sites_total) VALUES($1,'pending',1) RETURNING id`, ownerID).Scan(&runID); err != nil {
		return 0, err
	}
	if _, err = r.river.InsertTx(ctx, tx, ReconcileSystemArgs{RunID: runID, ScopeKey: "site:" + domain, Sites: selected}, nil); err != nil {
		return 0, fmt.Errorf("enqueue site reconciliation: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return runID, nil
}

func lockReconcileSubscriptions(ctx context.Context, tx *sql.Tx, sites []types.ReconcileSiteReq, databases []types.ReconcileDatabaseReq) error {
	unique := make(map[int64]struct{}, len(sites)+len(databases))
	for _, item := range sites {
		if item.SubscriptionID > 0 {
			unique[item.SubscriptionID] = struct{}{}
		}
	}
	for _, item := range databases {
		if item.SubscriptionID > 0 {
			unique[item.SubscriptionID] = struct{}{}
		}
	}
	ids := make([]int64, 0, len(unique))
	for subscriptionID := range unique {
		ids = append(ids, subscriptionID)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, subscriptionID := range ids {
		if err := controlquota.LockSubscriptionMutationTx(ctx, tx, subscriptionID); err != nil {
			return fmt.Errorf("lock subscription %d for reconciliation: %w", subscriptionID, err)
		}
	}
	return nil
}

func (r *SQLPhase6Repository) CreateAdminerToken(ctx context.Context, ownerID int64) (types.AdminerSSO, error) {
	if r.db == nil {
		return types.AdminerSSO{}, errors.New("database is not configured")
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return types.AdminerSSO{}, fmt.Errorf("generate adminer token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	hash := sha256.Sum256([]byte(token))
	expiresAt := r.now().UTC().Add(10 * time.Minute)
	if _, err := r.db.ExecContext(ctx, `INSERT INTO adminer_tokens (owner_user_id, token_hash, expires_at)
VALUES ($1, $2, $3)`, ownerID, hex.EncodeToString(hash[:]), expiresAt); err != nil {
		return types.AdminerSSO{}, fmt.Errorf("insert adminer token: %w", err)
	}
	return types.AdminerSSO{Token: token, ExpiresAtUnix: expiresAt.Unix()}, nil
}

type phase6Site struct {
	id           int64
	username     string
	domain       string
	phpVersion   string
	documentRoot string
}

type restorableBackup struct {
	backupID       int64
	subscriptionID int64
	siteID         int64
	username       string
	domain         string
	archivePath    string
	documentRoot   string
}

func selectRestorableBackupForUpdate(ctx context.Context, tx *sql.Tx, backupID int64) (restorableBackup, error) {
	var backup restorableBackup
	if err := tx.QueryRowContext(ctx, `SELECT b.id, b.subscription_id, s.id, s.username, s.domain, b.archive_path, s.document_root
FROM backups b
JOIN sites s ON s.id = b.site_id
WHERE b.id = $1
  AND b.status = 'active'
  AND b.archive_path <> ''
  AND s.status = 'active'
FOR UPDATE`, backupID).Scan(&backup.backupID, &backup.subscriptionID, &backup.siteID, &backup.username, &backup.domain, &backup.archivePath, &backup.documentRoot); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return restorableBackup{}, fmt.Errorf("active backup %d was not found", backupID)
		}
		return restorableBackup{}, fmt.Errorf("select restorable backup: %w", err)
	}
	return backup, nil
}

func selectActiveSiteByDomainForUpdate(ctx context.Context, tx *sql.Tx, domain string) (phase6Site, error) {
	var site phase6Site
	if err := tx.QueryRowContext(ctx, `SELECT id, username, domain, php_version, document_root
FROM sites
WHERE domain=$1 AND status='active'
FOR UPDATE`, domain).Scan(&site.id, &site.username, &site.domain, &site.phpVersion, &site.documentRoot); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return phase6Site{}, fmt.Errorf("active site %q was not found", domain)
		}
		return phase6Site{}, fmt.Errorf("select active site: %w", err)
	}
	return site, nil
}

func selectActiveSiteForUpdate(ctx context.Context, tx *sql.Tx, ownerID int64, domain string) (phase6Site, error) {
	var site phase6Site
	if err := tx.QueryRowContext(ctx, `SELECT id, username, domain, php_version, document_root
FROM sites
WHERE (owner_user_id = $1 OR customer_id IN (SELECT id FROM customers WHERE login_user_id = $1))
  AND domain = $2 AND status = 'active'
FOR UPDATE`, ownerID, domain).Scan(&site.id, &site.username, &site.domain, &site.phpVersion, &site.documentRoot); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return phase6Site{}, fmt.Errorf("active site %q was not found", domain)
		}
		return phase6Site{}, fmt.Errorf("select active site: %w", err)
	}
	return site, nil
}

func selectActiveSubscriptionSiteForUpdate(ctx context.Context, tx *sql.Tx, subscriptionID int64, domain string) (phase6Site, error) {
	var site phase6Site
	if err := tx.QueryRowContext(ctx, `SELECT id, username, domain, php_version, document_root
FROM sites
WHERE subscription_id = $1 AND domain = $2 AND status = 'active'
FOR UPDATE`, subscriptionID, domain).Scan(&site.id, &site.username, &site.domain, &site.phpVersion, &site.documentRoot); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return phase6Site{}, fmt.Errorf("active site %q was not found for subscription %d", domain, subscriptionID)
		}
		return phase6Site{}, fmt.Errorf("select active subscription site: %w", err)
	}
	return site, nil
}

func selectActiveOwnerDatabases(ctx context.Context, tx *sql.Tx, ownerID int64) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT db_name FROM databases WHERE owner_user_id = $1 AND status = 'active' ORDER BY db_name`, ownerID)
	if err != nil {
		return nil, fmt.Errorf("select active databases: %w", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return names, nil
}

func selectActiveSubscriptionDatabases(ctx context.Context, tx *sql.Tx, subscriptionID int64) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT db_name FROM databases WHERE subscription_id = $1 AND status = 'active' ORDER BY db_name`, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("select active subscription databases: %w", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return names, nil
}

func selectReconcileSites(ctx context.Context, tx *sql.Tx) ([]types.ReconcileSiteReq, error) {
	rows, err := tx.QueryContext(ctx, `SELECT s.id,s.customer_id,s.subscription_id,s.username,s.domain,s.document_root,s.php_version,s.desired_php_version,
       COALESCE(w.status IN ('pending', 'active', 'failed'), false) AS enable_webmail,
       COALESCE(d.status IN ('pending', 'active', 'failed'), false) AS enable_dns,
	   COALESCE(d.id,0),COALESCE(d.serial,0),COALESCE(d.address, '') AS address,
	   CASE WHEN s.desired_status='active' AND customer.status='active' AND sub.status='active'
	     AND (customer.reseller_id IS NULL OR (reseller.status='active' AND reseller_sub.id IS NOT NULL)) THEN 'active' ELSE 'suspended' END,
	   CASE WHEN s.tls_status='active' THEN s.desired_https_redirect ELSE false END,
	   CASE WHEN s.tls_status='active' THEN s.tls_cert_path ELSE '' END,
	   CASE WHEN s.tls_status='active' THEN s.tls_key_path ELSE '' END
FROM sites s JOIN subscriptions sub ON sub.id=s.subscription_id JOIN customers customer ON customer.id=sub.customer_id
LEFT JOIN webmail_hosts w ON w.site_id = s.id
LEFT JOIN dns_zones d ON d.site_id = s.id
LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id
LEFT JOIN reseller_subscriptions reseller_sub ON reseller_sub.reseller_id=reseller.id AND reseller_sub.status='active'
ORDER BY s.domain`)
	if err != nil {
		return nil, fmt.Errorf("select reconcile sites: %w", err)
	}
	defer rows.Close()
	var sites []types.ReconcileSiteReq
	for rows.Next() {
		var site types.ReconcileSiteReq
		var documentRoot string
		if err := rows.Scan(&site.SiteID, &site.CustomerID, &site.SubscriptionID, &site.Username, &site.Domain, &documentRoot, &site.PHPVersion, &site.DesiredPHPVersion, &site.EnableWebmail, &site.EnableDNS, &site.DNSZoneID, &site.DNSSerial, &site.Address, &site.State, &site.HTTPSRedirect, &site.TLSCertPath, &site.TLSKeyPath); err != nil {
			return nil, err
		}
		site.SharedAccount = controlquota.IsSharedSiteDocumentRoot(site.Username, site.Domain, documentRoot)
		sites = append(sites, site)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range sites {
		sites[i].Limits, err = controlquota.EffectiveSiteResourceLimitsTx(ctx, tx, sites[i].SiteID)
		if err != nil {
			return nil, err
		}
		if sites[i].DNSZoneID > 0 {
			request, queryErr := LoadDNSZoneRequest(ctx, tx, sites[i].DNSZoneID)
			if queryErr != nil {
				return nil, queryErr
			}
			sites[i].DNSZone = &request
			sites[i].DNSRecords = request.Records
		}
	}
	return sites, nil
}

func selectReconcileDNSRecords(ctx context.Context, tx *sql.Tx, zoneID int64) ([]types.DNSRecord, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,zone_id,COALESCE(owner_site_id,0),host,record_type,value,
COALESCE(priority,0),COALESCE(weight,0),COALESCE(port,0),ttl,origin,
COALESCE(template_record_key,''),COALESCE(template_revision,0),locally_modified
FROM dns_records WHERE zone_id=$1 ORDER BY id`, zoneID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []types.DNSRecord
	for rows.Next() {
		var record types.DNSRecord
		if err := rows.Scan(&record.ID, &record.ZoneID, &record.OwnerSiteID, &record.Host,
			&record.Type, &record.Value, &record.Priority, &record.Weight, &record.Port,
			&record.TTL, &record.Origin, &record.TemplateRecordKey, &record.TemplateRevision,
			&record.LocallyModified); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func selectReconcileDatabases(ctx context.Context, tx *sql.Tx) ([]types.ReconcileDatabaseReq, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,customer_id,subscription_id,db_name FROM databases WHERE status='active' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var databases []types.ReconcileDatabaseReq
	for rows.Next() {
		var database types.ReconcileDatabaseReq
		if err := rows.Scan(&database.DatabaseID, &database.CustomerID, &database.SubscriptionID, &database.Name); err != nil {
			return nil, err
		}
		databases = append(databases, database)
	}
	return databases, rows.Err()
}

type SQLPhase6StatusStore struct {
	db *sql.DB
}

func NewSQLPhase6StatusStore(db *sql.DB) *SQLPhase6StatusStore {
	return &SQLPhase6StatusStore{db: db}
}

func (s *SQLPhase6StatusStore) RefreshReconcileIntent(ctx context.Context, args ReconcileSystemArgs) (ReconcileSystemArgs, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return args, err
	}
	defer tx.Rollback()

	sites, err := selectReconcileSites(ctx, tx)
	if err != nil {
		return args, err
	}
	databases, err := selectReconcileDatabases(ctx, tx)
	if err != nil {
		return args, err
	}
	sites, databases = retainCapturedReconcileIntent(args, sites, databases)
	if err := tx.Commit(); err != nil {
		return args, err
	}
	args.Sites = sites
	args.Databases = databases
	return args, nil
}

func retainCapturedReconcileIntent(args ReconcileSystemArgs, sites []types.ReconcileSiteReq, databases []types.ReconcileDatabaseReq) ([]types.ReconcileSiteReq, []types.ReconcileDatabaseReq) {
	requestedSites := make(map[int64]struct{}, len(args.Sites))
	for _, site := range args.Sites {
		requestedSites[site.SiteID] = struct{}{}
	}
	filteredSites := sites[:0]
	for _, site := range sites {
		if _, ok := requestedSites[site.SiteID]; ok {
			filteredSites = append(filteredSites, site)
		}
	}
	sites = filteredSites

	if strings.HasPrefix(args.ScopeKey, "site:") {
		databases = nil
	} else {
		requestedDatabases := make(map[int64]struct{}, len(args.Databases))
		for _, database := range args.Databases {
			requestedDatabases[database.DatabaseID] = struct{}{}
		}
		filteredDatabases := databases[:0]
		for _, database := range databases {
			if _, ok := requestedDatabases[database.DatabaseID]; ok {
				filteredDatabases = append(filteredDatabases, database)
			}
		}
		databases = filteredDatabases
	}
	return sites, databases
}

func (s *SQLPhase6StatusStore) MarkBackupActive(ctx context.Context, id int64, result types.CreateBackupResult) error {
	_, err := s.db.ExecContext(ctx, `UPDATE backups SET status = 'active', archive_path = $2, size_bytes = $3, checksum_sha256 = $4, last_error = '', updated_at = now() WHERE id = $1`, id, result.ArchivePath, result.SizeBytes, result.SHA256)
	return err
}

func (s *SQLPhase6StatusStore) MarkBackupFailed(ctx context.Context, id int64, message string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE backups SET status = 'failed', last_error = $2, updated_at = now() WHERE id = $1`, id, message)
	return err
}

func (s *SQLPhase6StatusStore) MarkRestoreActive(ctx context.Context, id int64, result types.RestoreBackupResult) error {
	_, err := s.db.ExecContext(ctx, `UPDATE restore_runs SET status = 'active', restored_at = now(), last_error = '', updated_at = now() WHERE id = $1`, id)
	return err
}

func (s *SQLPhase6StatusStore) MarkRestoreFailed(ctx context.Context, id int64, message string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE restore_runs SET status = 'failed', last_error = $2, updated_at = now() WHERE id = $1`, id, message)
	return err
}

func (s *SQLPhase6StatusStore) MarkWebmailActive(ctx context.Context, id int64, result types.ConfigureWebmailResult) error {
	_, err := s.db.ExecContext(ctx, `UPDATE webmail_hosts SET status = 'active', config_path = $2, last_error = '', updated_at = now() WHERE id = $1`, id, result.ConfigPath)
	return err
}

func (s *SQLPhase6StatusStore) MarkWebmailFailed(ctx context.Context, id int64, message string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE webmail_hosts SET status = 'failed', last_error = $2, updated_at = now() WHERE id = $1`, id, message)
	return err
}

func (s *SQLPhase6StatusStore) MarkDNSActive(ctx context.Context, id int64, result types.ConfigureDNSZoneResult) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE dns_zones SET status='active',zone_path=$2,serial=$3,
applied_revision=$4,template_status=CASE WHEN template_status='pending' THEN 'in_sync' ELSE template_status END,
last_error='',updated_at=now()
WHERE id=$1 AND ($4=0 OR desired_revision=$4)`, id, result.ZonePath, result.Serial, result.DesiredRevision)
	if err != nil {
		return err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return ErrDNSRevisionStale
	}
	if result.DesiredRevision > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE dns_template_sync_items
SET outcome='applied',updated_at=now()
WHERE zone_id=$1 AND desired_revision<=$2 AND outcome NOT IN ('applied','failed')`, id, result.DesiredRevision); err != nil {
			return err
		}
		if err := refreshDNSSyncRunsTx(ctx, tx, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLPhase6StatusStore) MarkDNSFailed(ctx context.Context, id int64, message string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE dns_zones SET status = 'failed', last_error = $2, updated_at = now() WHERE id = $1`, id, message)
	return err
}

var ErrDNSRevisionStale = errors.New("DNS zone changed while an older revision was applying")

func (s *SQLPhase6StatusStore) MarkDNSRevisionFailed(ctx context.Context, id, desiredRevision int64, message string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE dns_zones SET status='failed',template_status='failed',
last_error=$3,updated_at=now() WHERE id=$1 AND ($2=0 OR desired_revision=$2)`, id, desiredRevision, message)
	if err != nil {
		return err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return ErrDNSRevisionStale
	}
	if desiredRevision > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE dns_template_sync_items
SET outcome='failed',detail=$3,updated_at=now()
WHERE zone_id=$1 AND desired_revision<=$2 AND outcome NOT IN ('applied','failed')`, id, desiredRevision, message); err != nil {
			return err
		}
		if err := refreshDNSSyncRunsTx(ctx, tx, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func refreshDNSSyncRunsTx(ctx context.Context, tx *sql.Tx, zoneID int64) error {
	_, err := tx.ExecContext(ctx, `WITH affected AS (
    SELECT DISTINCT run_id FROM dns_template_sync_items WHERE zone_id=$1
), totals AS (
    SELECT item.run_id,
           count(*) FILTER (WHERE item.desired_revision IS NOT NULL AND item.outcome NOT IN ('applied','failed')) AS pending,
           count(*) FILTER (WHERE item.outcome='failed') AS failed
    FROM dns_template_sync_items item JOIN affected ON affected.run_id=item.run_id
    GROUP BY item.run_id
)
UPDATE dns_template_sync_runs run
SET status=CASE WHEN totals.pending>0 THEN 'running' WHEN totals.failed>0 THEN 'partial' ELSE 'active' END,
    failed_zones=totals.failed,
    completed_at=CASE WHEN totals.pending=0 THEN now() ELSE NULL END
FROM totals WHERE run.id=totals.run_id`, zoneID)
	return err
}

type dnsZoneQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func LoadDNSZoneRequest(ctx context.Context, queryer dnsZoneQueryer, id int64) (types.ConfigureDNSZoneReq, error) {
	var req types.ConfigureDNSZoneReq
	var primariesJSON, zoneCIDRsJSON, templateCIDRsJSON, overrideJSON string
	var hostname string
	var templateSOA types.DNSSOASettings
	err := queryer.QueryRowContext(ctx, `SELECT zone.id,zone.desired_revision,zone.domain,zone.address,
zone.ipv6_address,zone.serial,zone.mode,COALESCE(array_to_json(zone.upstream_primaries)::text,'[]'),
COALESCE(array_to_json(zone.transfer_cidrs)::text,'null'),COALESCE(zone.soa_override::text,'null'),
	revision.primary_nameserver,revision.responsible_mailbox,revision.serial_format,revision.default_ttl,
	revision.refresh_seconds,revision.retry_seconds,revision.expire_seconds,revision.minimum_ttl,
	COALESCE(array_to_json(revision.transfer_cidrs)::text,'[]'),
	COALESCE(NULLIF((SELECT payload->>'hostname' FROM server_inventory
	    WHERE kind='server' AND resource_key='host'),''),zone.domain)
	FROM dns_zones zone
	JOIN dns_template_revisions revision ON revision.revision=zone.template_revision
WHERE zone.id=$1`, id).Scan(
		&req.ZoneID, &req.DesiredRevision, &req.Domain, &req.Address, &req.IPv6Address,
		&req.Serial, &req.Mode, &primariesJSON, &zoneCIDRsJSON, &overrideJSON,
		&templateSOA.PrimaryNameserver, &templateSOA.ResponsibleMailbox, &templateSOA.SerialFormat,
		&templateSOA.DefaultTTL, &templateSOA.RefreshSeconds, &templateSOA.RetrySeconds,
		&templateSOA.ExpireSeconds, &templateSOA.MinimumTTL, &templateCIDRsJSON, &hostname)
	if err != nil {
		return req, err
	}
	_ = json.Unmarshal([]byte(primariesJSON), &req.UpstreamPrimaries)
	if zoneCIDRsJSON == "null" {
		_ = json.Unmarshal([]byte(templateCIDRsJSON), &req.TransferCIDRs)
	} else {
		_ = json.Unmarshal([]byte(zoneCIDRsJSON), &req.TransferCIDRs)
	}
	req.SOA = templateSOA
	if overrideJSON != "null" {
		if err := json.Unmarshal([]byte(overrideJSON), &req.SOA); err != nil {
			return req, err
		}
	}
	values := map[string]string{"<domain>": req.Domain, "<hostname>": hostname}
	for placeholder, value := range values {
		req.SOA.PrimaryNameserver = strings.ReplaceAll(req.SOA.PrimaryNameserver, placeholder, value)
		req.SOA.ResponsibleMailbox = strings.ReplaceAll(req.SOA.ResponsibleMailbox, placeholder, value)
	}
	rows, err := queryer.QueryContext(ctx, `SELECT id,zone_id,COALESCE(owner_site_id,0),host,record_type,value,
COALESCE(priority,0),COALESCE(weight,0),COALESCE(port,0),ttl,origin,
COALESCE(template_record_key,''),COALESCE(template_revision,0),locally_modified
FROM dns_records WHERE zone_id=$1 ORDER BY host,record_type,id`, id)
	if err != nil {
		return req, err
	}
	defer rows.Close()
	for rows.Next() {
		var record types.DNSRecord
		if err := rows.Scan(&record.ID, &record.ZoneID, &record.OwnerSiteID, &record.Host,
			&record.Type, &record.Value, &record.Priority, &record.Weight, &record.Port,
			&record.TTL, &record.Origin, &record.TemplateRecordKey, &record.TemplateRevision,
			&record.LocallyModified); err != nil {
			return req, err
		}
		req.Records = append(req.Records, record)
	}
	if err := rows.Err(); err != nil {
		return req, err
	}
	if req.Mode != "primary" {
		req.Records = nil
	}
	return req, nil
}

func (s *SQLPhase6StatusStore) DNSZoneRequest(ctx context.Context, id int64) (types.ConfigureDNSZoneReq, error) {
	return LoadDNSZoneRequest(ctx, s.db, id)
}

func (s *SQLPhase6StatusStore) MarkReconcileActive(ctx context.Context, id int64, result types.ReconcileSystemResult) error {
	_, err := s.db.ExecContext(ctx, `UPDATE reconciliation_runs SET status = 'active', sites_total = $2, sites_ok = $3, last_error = '', updated_at = now() WHERE id = $1`, id, result.SitesTotal, result.SitesOK)
	return err
}

func (s *SQLPhase6StatusStore) MarkReconcileFailed(ctx context.Context, id int64, message string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE reconciliation_runs SET status = 'failed', last_error = $2, updated_at = now() WHERE id = $1`, id, message)
	return err
}
