package provision

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/types"
)

func (m *Manager) SiteSetupStatus(ctx context.Context, actor auth.SessionUser, siteID int64) (types.SiteSetupStatus, error) {
	reader, ok := m.siteRepo.(interface {
		ReadSiteSetup(context.Context, int64) (types.SiteSetupStatus, error)
	})
	if !ok {
		return types.SiteSetupStatus{}, errors.New("site setup status is unavailable")
	}
	setup, err := reader.ReadSiteSetup(ctx, siteID)
	if errors.Is(err, sql.ErrNoRows) {
		return setup, ErrForbidden
	}
	if err != nil {
		return setup, err
	}
	if setup.SiteID != siteID || setup.SubscriptionID <= 0 || (setup.ParentID > 0 && setup.ParentDomain == "") {
		return types.SiteSetupStatus{}, ErrForbidden
	}
	// The failed child cannot pass a mutation policy, but its owning root still can.
	if setup.ParentID > 0 {
		if err = m.canManageDomain(ctx, actor, setup.ParentDomain); err != nil {
			return types.SiteSetupStatus{}, err
		}
	}
	if err = m.canManageSubscription(ctx, actor, setup.SubscriptionID); err != nil {
		return types.SiteSetupStatus{}, err
	}
	return setup, nil
}

func (m *Manager) RetryCreationSSLFor(ctx context.Context, actor auth.SessionUser, siteID int64) (int64, error) {
	setup, err := m.SiteSetupStatus(ctx, actor, siteID)
	if err != nil {
		return 0, err
	}
	if !setup.CanRetrySSL {
		return 0, errors.New("SSL setup is not awaiting retry")
	}
	if err = m.canManageTLS(ctx, actor, setup.Domain); err != nil {
		return 0, err
	}
	repo, ok := m.siteRepo.(interface {
		RetryCreationSSL(context.Context, int64, string) (int64, error)
	})
	if !ok {
		return 0, errors.New("SSL setup retry is unavailable")
	}
	return repo.RetryCreationSSL(ctx, actor.ID, setup.Domain)
}

func (r *SQLSiteRepository) ReadSiteSetup(ctx context.Context, id int64) (types.SiteSetupStatus, error) {
	var result types.SiteSetupStatus
	var hosting, desired, settings, tls, mode, dns, job string
	var address, applied bool
	err := r.db.QueryRowContext(ctx, `SELECT site.id,COALESCE(site.parent_site_id,0),site.customer_id,site.subscription_id,site.domain,
site.status,site.desired_status,site.settings_status,site.tls_status,COALESCE(zone.mode,'external'),COALESCE(zone.status,''),
EXISTS(SELECT 1 FROM dns_records record WHERE record.zone_id=zone.id AND record.record_type='A'
 AND record.host=CASE WHEN site.domain=zone.domain THEN '@' ELSE left(site.domain,length(site.domain)-length(zone.domain)-1) END
 AND record.value=zone.address), COALESCE(zone.applied_revision>=zone.desired_revision,false),
COALESCE(create_job.state::text,''),COALESCE(create_job.created_at,site.created_at),COALESCE(parent.domain,'')
FROM sites site
LEFT JOIN sites parent ON parent.id=site.parent_site_id AND parent.subscription_id=site.subscription_id AND parent.customer_id=site.customer_id
LEFT JOIN dns_zones zone ON zone.site_id=CASE WHEN site.dns_zone_mode='parent' THEN site.parent_site_id ELSE site.id END
LEFT JOIN LATERAL (SELECT state,created_at FROM river_job WHERE kind='create_site' AND args->>'site_id'=site.id::text ORDER BY id DESC LIMIT 1) create_job ON true
WHERE site.id=$1`, id).Scan(&result.SiteID, &result.ParentID, &result.CustomerID, &result.SubscriptionID, &result.Domain, &hosting, &desired, &settings, &tls, &mode, &dns, &address, &applied, &job, &result.StartedAt, &result.ParentDomain)
	if err != nil {
		return result, err
	}
	result.Kind = "website"
	if result.ParentID > 0 {
		result.Kind = "subdomain"
	}
	result.State, result.Message = "pending", "Creating "+result.Kind+"."
	var desiredHTTPS, appliedHTTPS, integrated bool
	var certJob string
	if tls != "" && tls != "none" {
		err = r.db.QueryRowContext(ctx, `SELECT site.desired_https_redirect,site.https_redirect,
site.ssl_setup_requested,COALESCE(certificate.state::text,'')
FROM sites site LEFT JOIN LATERAL(SELECT args,state FROM river_job WHERE kind='issue_cert'
AND args->>'site_id'=site.id::text ORDER BY id DESC LIMIT 1) certificate ON true WHERE site.id=$1`, id).Scan(&desiredHTTPS, &appliedHTTPS, &integrated, &certJob)
		if err != nil {
			return result, err
		}
	}
	result.SSLRequested = integrated
	result.CanRetrySSL = integrated && (tls == "failed" || settings == "failed" || certJob == "discarded" || certJob == "cancelled" || (tls == "pending" && certJob == ""))
	hostingState := hosting
	if hosting == "active" && settings != "" && settings != "in_sync" && !(integrated && tls == "active") {
		hostingState = settings
	}
	dnsState := dns
	if mode != "primary" {
		dnsState = "external"
	} else if dns == "active" && !address {
		dnsState = "missing"
	} else if dns == "active" && !applied {
		dnsState = "pending"
	}
	if tls == "" || tls == "none" {
		tls = "not_requested"
	}
	result.Steps = []types.SiteSetupStep{{Code: "hosting", Label: "Hosting", State: hostingState}, {Code: "dns", Label: "DNS", State: dnsState}, {Code: "tls", Label: "SSL/TLS", State: tls}}
	httpsState := "pending"
	if settings == "failed" {
		httpsState = "failed"
	}
	if desiredHTTPS && appliedHTTPS && settings == "in_sync" {
		httpsState = "active"
	}
	if integrated {
		result.Steps = append(result.Steps, types.SiteSetupStep{Code: "https", Label: "HTTPS", State: httpsState})
	}
	switch {
	case desired != "active":
		result.State, result.Message = "failed", "The subdomain is suspended. Setup cannot complete."
	case hostingState == "failed":
		result.State, result.Message = "failed", "Hosting setup failed. Open the subdomain to review the error."
	case dnsState == "failed":
		result.State, result.Message = "failed", "DNS configuration failed. Open the subdomain's DNS settings to review it."
	case tls == "failed":
		result.State, result.Message = "failed", "The website was created, but SSL issuance failed. Open SSL/TLS to review it."
	case job == "retryable" || job == "discarded" || job == "cancelled":
		result.State, result.Message = "failed", "Subdomain setup needs attention. Review the provisioning job in Activity."
	case hostingState != "active" || job == "running" || job == "available" || job == "pending" || job == "scheduled":
	case integrated && httpsState == "failed":
		result.State, result.Message = "failed", "Certificate installed; HTTPS activation failed. Retry SSL setup to restore HTTPS."
	case integrated && tls != "active" && (certJob == "discarded" || certJob == "cancelled" || certJob == ""):
		result.State, result.Message = "failed", "Website created; SSL setup needs attention. Check DNS and retry SSL."
	case integrated && dnsState == "external" && tls == "active" && httpsState == "active":
		result.State, result.Message = "ready", fmt.Sprintf("%s created and secured.", map[string]string{"website": "Website", "subdomain": "Subdomain"}[result.Kind])
	case integrated && dnsState == "external":
		result.Message = "Hosting is ready. Waiting for public DNS, SSL and HTTPS activation."
	case dnsState == "external":
		result.State, result.Message = "attention", "Hosting is ready. DNS is managed elsewhere; configure the address record at your DNS provider."
	case dnsState == "missing":
		result.State, result.Message = "attention", "Hosting is ready, but the subdomain's DNS address record is missing."
	case dnsState != "active":
		result.Message = "Applying DNS configuration."
	case tls == "pending":
		result.Message = "Waiting for the SSL certificate."
	case integrated && httpsState != "active":
		result.Message = "Certificate installed. Enabling HTTPS."
	default:
		result.State = "ready"
		label := map[string]string{"website": "Website", "subdomain": "Subdomain"}[result.Kind]
		result.Message = label + " created successfully."
		if integrated {
			result.Message = label + " created and secured."
		}
	}
	return result, nil
}
