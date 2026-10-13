package provision

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/control/store"
	"github.com/nakroteck/nakpanel/internal/types"
	"github.com/riverqueue/river"
)

var ErrProvisionedSSLInactive = errors.New("website SSL setup is no longer allowed by its active subscription")

type ProvisionedCertificateState struct {
	Args             IssueCertArgs
	Ready, Installed bool
}
type ProvisioningCertificateSetup interface {
	PrepareProvisionedCertificate(context.Context, IssueCertArgs) (ProvisionedCertificateState, error)
	EnableProvisionedHTTPS(context.Context, int64) error
}
type SQLProvisioningCertificateSetup struct {
	db      *sql.DB
	river   *river.Client[*sql.Tx]
	queries *store.Queries
}

func NewSQLProvisioningCertificateSetup(db *sql.DB, client *river.Client[*sql.Tx]) *SQLProvisioningCertificateSetup {
	return &SQLProvisioningCertificateSetup{db: db, river: client, queries: store.New(db)}
}
func (s *SQLProvisioningCertificateSetup) SetRiverClient(client *river.Client[*sql.Tx]) {
	s.river = client
}

func (s *SQLProvisioningCertificateSetup) PrepareProvisionedCertificate(ctx context.Context, args IssueCertArgs) (ProvisionedCertificateState, error) {
	result := ProvisionedCertificateState{Args: args}
	site, err := s.queries.GetSite(ctx, args.SiteID)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrProvisionedSSLInactive
	}
	if err != nil {
		return result, err
	}
	if site.SubscriptionID != args.SubscriptionID || site.CustomerID != args.CustomerID || site.Domain != args.Domain || site.DesiredStatus != "active" {
		return result, ErrProvisionedSSLInactive
	}
	var active bool
	err = s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM subscriptions sub JOIN customers c ON c.id=sub.customer_id
 LEFT JOIN reseller_accounts reseller ON reseller.id=c.reseller_id
 LEFT JOIN reseller_subscriptions allocation ON allocation.reseller_id=reseller.id AND allocation.status='active'
 WHERE sub.id=$1 AND sub.customer_id=$2 AND sub.status='active' AND c.status='active'
 AND (c.reseller_id IS NULL OR (reseller.status='active' AND allocation.id IS NOT NULL)))`, site.SubscriptionID, site.CustomerID).Scan(&active)
	if err != nil {
		return result, err
	}
	if !active {
		return result, ErrProvisionedSSLInactive
	}
	policy, err := controlquota.NewSQLStore(s.db).EffectiveSitePolicy(ctx, site.ID)
	if err != nil {
		return result, err
	}
	if !policy.Permissions.TLS {
		return result, ErrProvisionedSSLInactive
	}
	result.Installed = site.TlsStatus == "active" && site.TlsIssuer == string(types.CertIssuerACME) && site.TlsExpiresAt.Valid && site.TlsExpiresAt.Time.After(time.Now()) && site.TlsCertPath != "" && site.TlsKeyPath != ""
	if site.TlsStatus == "active" && site.TlsIssuer == string(types.CertIssuerCustom) {
		return result, ErrProvisionedSSLInactive
	}
	setup, err := (&SQLSiteRepository{db: s.db}).ReadSiteSetup(ctx, site.ID)
	if err != nil {
		return result, err
	}
	for _, step := range setup.Steps {
		if step.Code == "hosting" && step.State != "active" && !(result.Installed && site.Status == "active") {
			if step.State == "failed" {
				return result, fmt.Errorf("%w: hosting failed before SSL setup", ErrProvisionedSSLInactive)
			}
			return result, nil
		}
		if step.Code == "dns" && step.State != "active" && step.State != "external" {
			if step.State == "failed" {
				return result, fmt.Errorf("%w: DNS configuration failed before SSL setup", ErrProvisionedSSLInactive)
			}
			return result, nil
		}
	}
	if policy.Permissions.DNS && (policy.DNS.Mode == "authoritative" || policy.DNS.Mode == "primary") {
		zoneSiteID := site.ID
		if setup.ParentID > 0 {
			zoneSiteID = setup.ParentID
		}
		var configured bool
		if err = s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM dns_zones WHERE site_id=$1)`, zoneSiteID).Scan(&configured); err != nil {
			return result, err
		}
		if !configured {
			return result, nil
		}
	}
	if site.Status != "active" {
		return result, nil
	}
	result.Args.Username = site.Username
	result.Args.PHPVersion = site.PhpVersion
	result.Args.SharedAccount = controlquota.IsSharedSiteDocumentRoot(site.Username, site.Domain, site.DocumentRoot)
	result.Args.Limits = controlquota.SiteResourceLimitsFromPolicy(policy)
	result.Ready = true
	return result, nil
}

func (s *SQLProvisioningCertificateSetup) EnableProvisionedHTTPS(ctx context.Context, siteID int64) error {
	if s.river == nil {
		return errors.New("HTTPS reconciliation queue is unavailable")
	}
	return controlquota.NewSQLStore(s.db, s.river).EnableSiteHTTPS(ctx, siteID)
}
