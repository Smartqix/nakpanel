package provision

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

// MailAgent is the slice of the agent client the mail worker needs.
type MailAgent interface {
	ConfigureMail(context.Context, types.ConfigureMailReq) (types.Response, error)
}

// ConfigureMailWorker reconciles the node's Stalwart instance with every
// mail_domains row and publishes each enabled domain's MX/SPF/DKIM/DMARC
// records through the existing dns_records → configure_dns_zone path. It is
// the worker behind quota.ConfigureMailArgs.
type ConfigureMailWorker struct {
	river.WorkerDefaults[controlquota.ConfigureMailArgs]
	db     *sql.DB
	agent  MailAgent
	phase6 *SQLPhase6Repository
}

func NewConfigureMailWorker(db *sql.DB, agent MailAgent) *ConfigureMailWorker {
	return &ConfigureMailWorker{db: db, agent: agent}
}

// SetRiverClient wires the phase6 repository used for DNS zone refreshes; it
// runs after the river client exists, mirroring the other workers.
func (w *ConfigureMailWorker) SetRiverClient(client *river.Client[*sql.Tx]) {
	w.phase6 = NewSQLPhase6Repository(w.db, client)
}

type mailDomainRow struct {
	ID              int64
	Domain          string
	Enabled         bool
	DeleteRequested bool
	DKIM            bool
	DMARCPolicy     string
}

func (w *ConfigureMailWorker) Work(ctx context.Context, _ *river.Job[controlquota.ConfigureMailArgs]) error {
	if w.db == nil || w.agent == nil || w.phase6 == nil {
		return errors.New("mail convergence is not configured")
	}
	settings, err := controlquota.ReadMailSettings(ctx, w.db)
	if err != nil {
		return err
	}
	rows, err := w.db.QueryContext(ctx, `SELECT id,domain,enabled,delete_requested,dkim_enabled,dmarc_policy FROM mail_domains ORDER BY domain`)
	if err != nil {
		return err
	}
	var domains []mailDomainRow
	for rows.Next() {
		var item mailDomainRow
		if err := rows.Scan(&item.ID, &item.Domain, &item.Enabled, &item.DeleteRequested, &item.DKIM, &item.DMARCPolicy); err != nil {
			rows.Close()
			return err
		}
		domains = append(domains, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(domains) == 0 && settings.SmarthostHost == "" {
		return nil
	}
	request := types.ConfigureMailReq{
		Hostname:          settings.MailHostname,
		OutboundRateLimit: settings.OutboundRateLimit,
	}
	for _, domain := range domains {
		if domain.Enabled && !domain.DeleteRequested {
			request.Domains = append(request.Domains, types.MailDomainConfig{
				MailDomainID: domain.ID, Domain: domain.Domain, DKIM: domain.DKIM,
			})
		}
	}
	if request.Hostname == "" {
		// Deterministic fallback: the first enabled domain hosts the EHLO name.
		names := make([]string, 0, len(request.Domains))
		for _, domain := range request.Domains {
			names = append(names, domain.Domain)
		}
		sort.Strings(names)
		if len(names) > 0 {
			request.Hostname = "mail." + names[0]
		} else if len(domains) > 0 {
			request.Hostname = "mail." + domains[0].Domain
		} else {
			return nil
		}
	}
	if settings.SmarthostHost != "" {
		request.Smarthost = &types.MailSmarthostConfig{
			Host: settings.SmarthostHost, Port: settings.SmarthostPort,
			Username: settings.SmarthostUsername, Password: settings.SmarthostPassword,
		}
	}
	response, err := w.agent.ConfigureMail(ctx, request)
	if err == nil && !response.OK {
		err = errors.New(response.Error)
	}
	if err != nil {
		_, markErr := w.db.ExecContext(ctx, `UPDATE mail_domains SET convergence_status='failed',last_error=$1,updated_at=now() WHERE convergence_status='pending'`, err.Error())
		return errors.Join(err, markErr)
	}
	var result types.ConfigureMailResult
	if err := json.Unmarshal(response.Data, &result); err != nil {
		return err
	}
	dkimRecords := make(map[string]string, len(result.DKIM))
	for _, item := range result.DKIM {
		dkimRecords[item.Domain] = item.Record
	}
	for _, domain := range domains {
		if domain.DeleteRequested {
			if err := w.reconcileZoneRecords(ctx, domain, nil); err != nil {
				return err
			}
			if _, err := w.db.ExecContext(ctx, `DELETE FROM mail_domains WHERE id=$1 AND delete_requested=true`, domain.ID); err != nil {
				return err
			}
			continue
		}
		var desired []types.DNSRecord
		if domain.Enabled {
			desired = mailZoneRecords(domain, dkimRecords[domain.Domain])
		}
		zoneNote := ""
		if err := w.reconcileZoneRecords(ctx, domain, desired); err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if domain.Enabled {
				zoneNote = "no managed DNS zone for this domain: publish MX, SPF, DKIM, and DMARC records externally"
			}
		}
		if _, err := w.db.ExecContext(ctx, `UPDATE mail_domains SET convergence_status='in_sync',last_error=$2,updated_at=now() WHERE id=$1`, domain.ID, zoneNote); err != nil {
			return err
		}
	}
	return nil
}

// mailZoneRecords is the managed record set mail ownership implies for a
// zone. Values are deterministic so reconciliation can compare literally.
func mailZoneRecords(domain mailDomainRow, dkimRecord string) []types.DNSRecord {
	records := []types.DNSRecord{
		{Host: "@", Type: "MX", Value: "mail." + domain.Domain, Priority: 10, TTL: 3600},
		{Host: "mail", Type: "A", Value: "", TTL: 3600}, // value filled from the zone address
		{Host: "@", Type: "TXT", Value: "v=spf1 mx ~all", TTL: 3600},
		{Host: "_dmarc", Type: "TXT", Value: fmt.Sprintf("v=DMARC1; p=%s; rua=mailto:postmaster@%s", domain.DMARCPolicy, domain.Domain), TTL: 3600},
	}
	if dkimRecord != "" {
		records = append(records, types.DNSRecord{Host: "nak1._domainkey", Type: "TXT", Value: dkimRecord, TTL: 3600})
	}
	return records
}

// reconcileZoneRecords makes the zone's managed mail records match desired
// (nil means remove them all). It only bumps the zone serial and re-renders
// when something actually changed, which keeps re-runs idempotent. Returns
// sql.ErrNoRows when the domain has no managed zone.
func (w *ConfigureMailWorker) reconcileZoneRecords(ctx context.Context, domain mailDomainRow, desired []types.DNSRecord) error {
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var zoneID, serial int64
	var address string
	if err = tx.QueryRowContext(ctx, `SELECT id,address,serial FROM dns_zones WHERE domain=$1 FOR UPDATE`, domain.Domain).Scan(&zoneID, &address, &serial); err != nil {
		return err
	}
	for i := range desired {
		if desired[i].Type == "A" && desired[i].Value == "" {
			desired[i].Value = address
		}
	}
	managedFilter := `zone_id=$1 AND ((record_type='MX' AND host='@') OR (record_type='A' AND host='mail')
OR (record_type='TXT' AND host='@' AND value LIKE 'v=spf1%') OR (record_type='TXT' AND host='_dmarc')
OR (record_type='TXT' AND host LIKE '%._domainkey'))`
	rows, err := tx.QueryContext(ctx, `SELECT host,record_type,value,COALESCE(priority,0),ttl FROM dns_records WHERE `+managedFilter+` ORDER BY host,record_type,value`, zoneID)
	if err != nil {
		return err
	}
	var current []types.DNSRecord
	for rows.Next() {
		var record types.DNSRecord
		if err := rows.Scan(&record.Host, &record.Type, &record.Value, &record.Priority, &record.TTL); err != nil {
			rows.Close()
			return err
		}
		current = append(current, record)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if mailRecordSetsEqual(current, desired) {
		return tx.Commit()
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM dns_records WHERE `+managedFilter, zoneID); err != nil {
		return err
	}
	for _, record := range desired {
		var priority any
		if record.Type == "MX" {
			priority = record.Priority
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO dns_records(zone_id,host,record_type,value,priority,ttl) VALUES($1,$2,$3,$4,$5,$6)`,
			zoneID, record.Host, record.Type, record.Value, priority, record.TTL); err != nil {
			return err
		}
	}
	// enqueueDNSZoneTx bumps the serial, snapshots all records into the job,
	// and commits the transaction.
	return w.phase6.enqueueDNSZoneTx(ctx, tx, zoneID, domain.Domain, address, serial)
}

func mailRecordSetsEqual(current, desired []types.DNSRecord) bool {
	if len(current) != len(desired) {
		return false
	}
	key := func(record types.DNSRecord) string {
		return strings.Join([]string{record.Host, record.Type, record.Value, fmt.Sprint(record.Priority), fmt.Sprint(record.TTL)}, "\x00")
	}
	seen := make(map[string]int, len(current))
	for _, record := range current {
		seen[key(record)]++
	}
	for _, record := range desired {
		if seen[key(record)] == 0 {
			return false
		}
		seen[key(record)]--
	}
	return true
}
