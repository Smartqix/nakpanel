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
	"github.com/nakroteck/nakpanel/internal/control/serveradmin"
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
	db      *sql.DB
	agent   MailAgent
	phase6  *SQLPhase6Repository
	secrets *serveradmin.Store
}

func NewConfigureMailWorker(db *sql.DB, agent MailAgent, secrets ...*serveradmin.Store) *ConfigureMailWorker {
	worker := &ConfigureMailWorker{db: db, agent: agent}
	if len(secrets) > 0 {
		worker.secrets = secrets[0]
	}
	return worker
}

// SetRiverClient wires the phase6 repository used for DNS zone refreshes; it
// runs after the river client exists, mirroring the other workers.
func (w *ConfigureMailWorker) SetRiverClient(client *river.Client[*sql.Tx]) {
	w.phase6 = NewSQLPhase6Repository(w.db, client)
}

type mailDomainRow struct {
	ID              int64
	SiteID          int64
	SubscriptionID  int64
	Domain          string
	Enabled         bool
	LifecycleActive bool
	DeleteRequested bool
	DKIM            bool
	DMARCPolicy     string
	IntentVersion   string
}

const mailDomainIntentVersionSQL = `jsonb_build_array(domain.subscription_id,domain.site_id,domain.domain,domain.enabled,domain.delete_requested,domain.dkim_enabled,domain.dmarc_policy,domain.updated_at AT TIME ZONE 'UTC')::text`

func (w *ConfigureMailWorker) Work(ctx context.Context, _ *river.Job[controlquota.ConfigureMailArgs]) error {
	if w.db == nil || w.agent == nil || w.phase6 == nil {
		return errors.New("mail convergence is not configured")
	}
	settings, err := controlquota.ReadMailSettings(ctx, w.db, w.secrets)
	if err != nil {
		return err
	}
	rows, err := w.db.QueryContext(ctx, `SELECT domain.id,domain.subscription_id,domain.domain,domain.enabled,
subscription.status='active' AND customer.status='active'
AND (customer.reseller_id IS NULL OR (
    reseller.status='active' AND EXISTS (
        SELECT 1 FROM reseller_subscriptions allocation
        WHERE allocation.reseller_id=customer.reseller_id AND allocation.status='active'
    )
)),
domain.delete_requested,domain.dkim_enabled,domain.dmarc_policy,`+mailDomainIntentVersionSQL+`,COALESCE(domain.site_id,(SELECT id FROM sites selected WHERE selected.domain=domain.domain AND selected.subscription_id=domain.subscription_id))
FROM mail_domains domain
JOIN subscriptions subscription ON subscription.id=domain.subscription_id
JOIN customers customer ON customer.id=subscription.customer_id
LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id
WHERE NOT EXISTS(SELECT 1 FROM sites selected WHERE selected.subscription_id=domain.subscription_id
 AND (selected.id=domain.site_id OR (domain.site_id IS NULL AND selected.domain=domain.domain)) AND selected.removal_state<>'none')
ORDER BY domain.domain`)
	if err != nil {
		return err
	}
	var domains []mailDomainRow
	for rows.Next() {
		var item mailDomainRow
		if err := rows.Scan(&item.ID, &item.SubscriptionID, &item.Domain, &item.Enabled, &item.LifecycleActive, &item.DeleteRequested, &item.DKIM, &item.DMARCPolicy, &item.IntentVersion, &item.SiteID); err != nil {
			rows.Close()
			return err
		}
		domains = append(domains, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	policyStore := controlquota.NewSQLStore(w.db)
	policyCache := make(map[int64]types.HostingPolicy)
	for index := range domains {
		policy, ok := policyCache[domains[index].SubscriptionID]
		if !ok {
			policy, err = policyStore.EffectiveSubscriptionPolicy(ctx, domains[index].SubscriptionID)
			if err != nil {
				_, disableErr := w.db.ExecContext(ctx, `UPDATE mail_domains
SET effective_enabled=false,convergence_status='failed',last_error=$2,updated_at=now()
WHERE subscription_id=$1`, domains[index].SubscriptionID, err.Error())
				return errors.Join(err, disableErr)
			}
			policyCache[domains[index].SubscriptionID] = policy
		}
		domains[index].Enabled = effectiveMailDomainEnabled(domains[index], policy)
	}
	for _, domain := range domains {
		if domain.Enabled && !domain.DeleteRequested {
			continue
		}
		if _, err = w.db.ExecContext(ctx, `UPDATE mail_domains domain
SET effective_enabled=false
WHERE id=$1 AND effective_enabled AND `+mailDomainIntentVersionSQL+`=$2`, domain.ID, domain.IntentVersion); err != nil {
			return err
		}
	}
	request := types.ConfigureMailReq{
		Hostname:          settings.MailHostname,
		OutboundRateLimit: settings.OutboundRateLimit,
	}
	for _, domain := range domains {
		if domain.Enabled && !domain.DeleteRequested {
			request.Domains = append(request.Domains, types.MailDomainConfig{
				SiteID: domain.SiteID, SubscriptionID: domain.SubscriptionID,
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
			// Keep the generated configuration authoritative even after the
			// final hosted domain is removed. Stalwart's SQL directory then
			// has no local recipients, and no stale per-domain signer remains.
			request.Hostname = "mail.localhost.localdomain"
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
			if err := w.reconcileZoneRecords(ctx, domain, nil); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if _, err := w.db.ExecContext(ctx, `DELETE FROM mail_domains domain WHERE id=$1 AND delete_requested=true AND `+mailDomainIntentVersionSQL+`=$2`, domain.ID, domain.IntentVersion); err != nil {
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
		update, err := w.db.ExecContext(ctx, `UPDATE mail_domains domain
SET effective_enabled=$2,convergence_status='in_sync',last_error=$3,updated_at=now()
WHERE id=$1 AND `+mailDomainIntentVersionSQL+`=$4`, domain.ID, domain.Enabled, zoneNote, domain.IntentVersion)
		if err != nil {
			return err
		}
		count, err := update.RowsAffected()
		if err != nil || count != 1 {
			return errors.New("mail intent changed during convergence")
		}
	}
	return nil
}

func effectiveMailDomainEnabled(domain mailDomainRow, policy types.HostingPolicy) bool {
	return domain.Enabled && domain.LifecycleActive && !domain.DeleteRequested &&
		policy.Permissions.Mail && policy.Mail.Enabled
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
	var zoneID, siteID int64
	var address, zoneDomain string
	if err = tx.QueryRowContext(ctx, `SELECT zone.id,site.id,zone.address,zone.domain
FROM sites site LEFT JOIN sites parent ON parent.id=site.parent_site_id
JOIN dns_zones zone ON zone.site_id=CASE WHEN site.dns_zone_mode='parent' AND parent.id IS NOT NULL THEN parent.id ELSE site.id END
WHERE site.domain=$1 AND ($2::bigint=0 OR site.id=$2) AND zone.mode='primary'
FOR UPDATE OF zone`, domain.Domain, domain.SiteID).Scan(&zoneID, &siteID, &address, &zoneDomain); err != nil {
		return err
	}
	prefix := ""
	if zoneDomain != domain.Domain {
		prefix = strings.TrimSuffix(domain.Domain, "."+zoneDomain)
		if prefix == domain.Domain {
			return errors.New("mail domain is outside its DNS zone")
		}
	}
	host := func(value string) string {
		if prefix == "" {
			return value
		}
		if value == "@" {
			return prefix
		}
		return value + "." + prefix
	}
	for i := range desired {
		desired[i].Host = host(desired[i].Host)
		if desired[i].Type == "A" && desired[i].Value == "" {
			desired[i].Value = address
		}
	}
	current, err := loadDNSRecordsTx(ctx, tx, zoneID)
	if err != nil {
		return err
	}
	add, remove, _ := PlanServiceDNSRecords(current, desired, func(record types.DNSRecord) bool {
		return record.Origin == "system" && (record.OwnerSiteID == siteID || record.OwnerSiteID == 0) && !IsEndpointDNSRecord(record) &&
			((record.Host == host("@") && record.Type == "MX") || (record.Host == host("mail") && record.Type == "A") ||
				(record.Type == "TXT" && ((record.Host == host("@") && strings.HasPrefix(strings.ToLower(record.Value), "v=spf1")) || record.Host == host("_dmarc") || record.Host == host("nak1._domainkey"))))
	})
	if len(add)+len(remove) == 0 {
		return tx.Commit()
	}
	if err = insertServiceDNSRecordsTx(ctx, tx, zoneID, siteID, add, remove); err != nil {
		return err
	}
	// enqueueDNSZoneTx bumps the desired revision and commits the transaction.
	return w.phase6.enqueueDNSZoneTx(ctx, tx, zoneID, false)
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
