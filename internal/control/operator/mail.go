package operator

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/site"
	"github.com/nakroteck/nakpanel/internal/types"
)

type MailDomainStatus struct {
	ID             int64
	SubscriptionID int64
	Domain         string
	Enabled        bool
	DKIM           bool
	DMARCPolicy    string
	Status         string
	LastError      string
}

type Mailbox struct {
	ID      int64
	Address string
	QuotaMB int
	Enabled bool
}

type MailAlias struct {
	ID           int64
	Address      string
	Destinations string
}

// EnableMailDomain turns mail on for a hosted domain. When subscriptionID is
// zero it is resolved from the site that serves the domain.
func (s *Service) EnableMailDomain(ctx context.Context, domain string, subscriptionID int64, dkim bool, dmarcPolicy string) (int64, error) {
	domain = site.NormalizeDomain(domain)
	if subscriptionID == 0 {
		if err := s.db.QueryRowContext(ctx, `SELECT subscription_id FROM sites WHERE lower(domain)=lower($1)`, domain).Scan(&subscriptionID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return 0, fmt.Errorf("no site hosts %q; pass --subscription explicitly", domain)
			}
			return 0, err
		}
	}
	var existingID int64
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM mail_domains WHERE lower(domain)=lower($1) AND subscription_id=$2`, domain, subscriptionID).Scan(&existingID); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	actor, err := s.systemActor(ctx)
	if err != nil {
		return 0, err
	}
	id, err := s.manager.UpsertMailDomain(ctx, actor, subscriptionID, types.MailDomainInput{
		ID: existingID, Domain: domain, Enabled: true, DKIM: dkim, DMARCPolicy: dmarcPolicy,
	})
	if err != nil {
		return 0, err
	}
	return id, s.audit(ctx, "mail_domain.saved", "mail_domain", id, map[string]any{"domain": domain, "subscription_id": subscriptionID, "dkim": dkim, "dmarc_policy": dmarcPolicy})
}

func (s *Service) mailDomainForAddress(ctx context.Context, address string) (localPart string, domainID, subscriptionID int64, err error) {
	address = strings.ToLower(strings.TrimSpace(address))
	local, domain, ok := strings.Cut(address, "@")
	if !ok || local == "" || domain == "" {
		return "", 0, 0, fmt.Errorf("%q is not a mail address", address)
	}
	err = s.db.QueryRowContext(ctx, `SELECT id,subscription_id FROM mail_domains WHERE lower(domain)=lower($1) AND NOT delete_requested`, domain).Scan(&domainID, &subscriptionID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, 0, fmt.Errorf("mail is not enabled for domain %q (run: panelctl mail enable %s)", domain, domain)
	}
	return local, domainID, subscriptionID, err
}

// AddMailbox creates or updates a mailbox. When password is empty a random
// one is generated and returned so the operator can hand it to the user; it
// is never logged or audited.
func (s *Service) AddMailbox(ctx context.Context, address string, quotaMB int, password string) (int64, string, error) {
	local, domainID, subscriptionID, err := s.mailDomainForAddress(ctx, address)
	if err != nil {
		return 0, "", err
	}
	generated := ""
	if strings.TrimSpace(password) == "" {
		if generated, err = generatePassword(); err != nil {
			return 0, "", err
		}
		password = generated
	}
	var existingID int64
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM mailboxes WHERE mail_domain_id=$1 AND lower(local_part)=$2`, domainID, local).Scan(&existingID); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, "", err
	}
	actor, err := s.systemActor(ctx)
	if err != nil {
		return 0, "", err
	}
	id, err := s.manager.UpsertMailbox(ctx, actor, subscriptionID, types.MailboxInput{
		ID: existingID, MailDomainID: domainID, LocalPart: local, Password: password, QuotaMB: quotaMB, Enabled: true,
	})
	if err != nil {
		return 0, "", err
	}
	return id, generated, s.audit(ctx, "mailbox.saved", "mailbox", id, map[string]any{"address": strings.ToLower(address), "subscription_id": subscriptionID})
}

func (s *Service) DeleteMailbox(ctx context.Context, address string) error {
	local, domainID, subscriptionID, err := s.mailDomainForAddress(ctx, address)
	if err != nil {
		return err
	}
	var id int64
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM mailboxes WHERE mail_domain_id=$1 AND lower(local_part)=$2`, domainID, local).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("mailbox %q does not exist", strings.ToLower(address))
		}
		return err
	}
	actor, err := s.systemActor(ctx)
	if err != nil {
		return err
	}
	if err := s.manager.DeleteSubscriptionService(ctx, actor, subscriptionID, "mailbox", id); err != nil {
		return err
	}
	return s.audit(ctx, "mailbox.deleted", "mailbox", id, map[string]any{"address": strings.ToLower(address), "subscription_id": subscriptionID})
}

func (s *Service) AddMailAlias(ctx context.Context, address string, destinations []string) (int64, error) {
	local, domainID, subscriptionID, err := s.mailDomainForAddress(ctx, address)
	if err != nil {
		return 0, err
	}
	var existingID int64
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM mail_aliases WHERE mail_domain_id=$1 AND lower(local_part)=$2`, domainID, local).Scan(&existingID); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	actor, err := s.systemActor(ctx)
	if err != nil {
		return 0, err
	}
	id, err := s.manager.UpsertMailAlias(ctx, actor, subscriptionID, types.MailAliasInput{
		ID: existingID, MailDomainID: domainID, LocalPart: local, Destinations: destinations,
	})
	if err != nil {
		return 0, err
	}
	return id, s.audit(ctx, "mail_alias.saved", "mail_alias", id, map[string]any{"address": strings.ToLower(address), "subscription_id": subscriptionID})
}

func (s *Service) DeleteMailAlias(ctx context.Context, address string) error {
	local, domainID, subscriptionID, err := s.mailDomainForAddress(ctx, address)
	if err != nil {
		return err
	}
	var id int64
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM mail_aliases WHERE mail_domain_id=$1 AND lower(local_part)=$2`, domainID, local).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("alias %q does not exist", strings.ToLower(address))
		}
		return err
	}
	actor, err := s.systemActor(ctx)
	if err != nil {
		return err
	}
	if err := s.manager.DeleteSubscriptionService(ctx, actor, subscriptionID, "mail_alias", id); err != nil {
		return err
	}
	return s.audit(ctx, "mail_alias.deleted", "mail_alias", id, map[string]any{"address": strings.ToLower(address), "subscription_id": subscriptionID})
}

func (s *Service) MailDomainStatus(ctx context.Context, domain string) (MailDomainStatus, error) {
	var status MailDomainStatus
	err := s.db.QueryRowContext(ctx, `SELECT id,subscription_id,domain,enabled,dkim_enabled,dmarc_policy,convergence_status,last_error
FROM mail_domains WHERE lower(domain)=lower($1)`, site.NormalizeDomain(domain)).Scan(
		&status.ID, &status.SubscriptionID, &status.Domain, &status.Enabled,
		&status.DKIM, &status.DMARCPolicy, &status.Status, &status.LastError)
	return status, err
}

func (s *Service) ListMailboxes(ctx context.Context, domain string) ([]Mailbox, []MailAlias, error) {
	domain = site.NormalizeDomain(domain)
	rows, err := s.db.QueryContext(ctx, `SELECT mb.id,lower(mb.local_part)||'@'||md.domain,mb.quota_mb,mb.enabled
FROM mailboxes mb JOIN mail_domains md ON md.id=mb.mail_domain_id WHERE lower(md.domain)=lower($1) ORDER BY mb.local_part`, domain)
	if err != nil {
		return nil, nil, err
	}
	var mailboxes []Mailbox
	for rows.Next() {
		var item Mailbox
		if err := rows.Scan(&item.ID, &item.Address, &item.QuotaMB, &item.Enabled); err != nil {
			rows.Close()
			return nil, nil, err
		}
		mailboxes = append(mailboxes, item)
	}
	if err := rows.Close(); err != nil {
		return nil, nil, err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT alias.id,lower(alias.local_part)||'@'||md.domain,array_to_string(alias.destinations,', ')
FROM mail_aliases alias JOIN mail_domains md ON md.id=alias.mail_domain_id WHERE lower(md.domain)=lower($1) ORDER BY alias.local_part`, domain)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var aliases []MailAlias
	for rows.Next() {
		var item MailAlias
		if err := rows.Scan(&item.ID, &item.Address, &item.Destinations); err != nil {
			return nil, nil, err
		}
		aliases = append(aliases, item)
	}
	return mailboxes, aliases, rows.Err()
}

func (s *Service) MailSettings(ctx context.Context) (controlquota.MailSettings, error) {
	return controlquota.ReadMailSettings(ctx, s.db)
}

func (s *Service) UpdateMailSettings(ctx context.Context, mutate func(*controlquota.MailSettings)) (controlquota.MailSettings, error) {
	settings, err := controlquota.ReadMailSettings(ctx, s.db)
	if err != nil {
		return settings, err
	}
	mutate(&settings)
	if err := s.quota.UpdateMailSettings(ctx, settings); err != nil {
		return settings, err
	}
	return settings, s.audit(ctx, "mail_settings.updated", "mail_settings", 1, map[string]any{
		"hostname": settings.MailHostname, "smarthost": settings.SmarthostHost,
		"rate_limit": settings.OutboundRateLimit, "alert_threshold": settings.QueueAlertThreshold,
	})
}

func generatePassword() (string, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
