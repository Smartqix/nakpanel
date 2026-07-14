package workspace

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	"github.com/nakroteck/nakpanel/internal/control/dashboard"
	controlpolicy "github.com/nakroteck/nakpanel/internal/control/policy"
	"github.com/nakroteck/nakpanel/internal/types"
)

func (s *Store) ListSubscriptionServices(ctx context.Context, actor auth.SessionUser) (dashboard.SubscriptionServicesData, error) {
	if s == nil || s.db == nil {
		return dashboard.SubscriptionServicesData{}, errorsNewWorkspaceDB()
	}
	where, args, err := subscriptionScope(actor)
	if err != nil {
		return dashboard.SubscriptionServicesData{}, err
	}
	data := dashboard.SubscriptionServicesData{}
	accountRows, err := s.db.QueryContext(ctx, `SELECT account.id,account.subscription_id,account.username,account.home_path,COALESCE(account.linux_uid,0),account.shell_mode,account.desired_state,account.applied_state,account.convergence_status,account.last_error,account.migration_status,account.migration_error,e.hosting_policy,COALESCE(o.policy_patch,'{}'::jsonb)
FROM subscription_system_accounts account JOIN subscriptions sub ON sub.id=account.subscription_id JOIN customers customer ON customer.id=sub.customer_id
JOIN subscription_entitlements e ON e.subscription_id=sub.id LEFT JOIN subscription_policy_overrides o ON o.subscription_id=sub.id
LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id WHERE `+where+` ORDER BY account.id`, args...)
	if err != nil {
		return data, err
	}
	for accountRows.Next() {
		var item types.SubscriptionSystemAccount
		var baseRaw, patchRaw []byte
		if err := accountRows.Scan(&item.ID, &item.SubscriptionID, &item.Username, &item.HomePath, &item.LinuxUID, &item.ShellMode, &item.DesiredState, &item.AppliedState, &item.ConvergenceStatus, &item.LastError, &item.MigrationStatus, &item.MigrationError, &baseRaw, &patchRaw); err != nil {
			accountRows.Close()
			return data, err
		}
		var base types.HostingPolicy
		if err := json.Unmarshal(baseRaw, &base); err == nil {
			if resolved, resolveErr := controlpolicy.Resolve(base, patchRaw, nil); resolveErr == nil {
				item.EffectivePolicy = resolved
			}
		}
		data.Accounts = append(data.Accounts, item)
	}
	accountRows.Close()
	siteRows, err := s.db.QueryContext(ctx, `SELECT site.id,site.subscription_id,e.hosting_policy,COALESCE(subscription_override.policy_patch,'{}'::jsonb),COALESCE(site_override.policy_patch,'{}'::jsonb)
FROM sites site JOIN subscriptions sub ON sub.id=site.subscription_id JOIN customers customer ON customer.id=sub.customer_id
JOIN subscription_entitlements e ON e.subscription_id=sub.id
LEFT JOIN subscription_policy_overrides subscription_override ON subscription_override.subscription_id=sub.id
LEFT JOIN site_policy_overrides site_override ON site_override.site_id=site.id
LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id WHERE `+where+` ORDER BY site.id`, args...)
	if err != nil {
		return data, err
	}
	for siteRows.Next() {
		var item dashboard.SitePolicy
		var baseRaw, subscriptionPatch, sitePatch []byte
		if err := siteRows.Scan(&item.SiteID, &item.SubscriptionID, &baseRaw, &subscriptionPatch, &sitePatch); err != nil {
			siteRows.Close()
			return data, err
		}
		var base types.HostingPolicy
		if err := json.Unmarshal(baseRaw, &base); err != nil {
			siteRows.Close()
			return data, err
		}
		item.EffectivePolicy, err = controlpolicy.Resolve(base, subscriptionPatch, sitePatch)
		if err != nil {
			siteRows.Close()
			return data, err
		}
		data.SitePolicies = append(data.SitePolicies, item)
	}
	if err := siteRows.Close(); err != nil {
		return data, err
	}
	queries := []struct {
		query string
		scan  func(*sql.Rows) error
	}{
		{`SELECT item.id,item.subscription_id,item.name,item.relative_root,item.enabled FROM sftp_access_identities item JOIN subscriptions sub ON sub.id=item.subscription_id JOIN customers customer ON customer.id=sub.customer_id LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id WHERE ` + where + ` ORDER BY item.id`, func(rows *sql.Rows) error {
			var item dashboard.SFTPIdentity
			if err := rows.Scan(&item.ID, &item.SubscriptionID, &item.Name, &item.RelativeRoot, &item.Enabled); err != nil {
				return err
			}
			data.SFTP = append(data.SFTP, item)
			return nil
		}},
		{`SELECT item.id,item.subscription_id,COALESCE(item.site_id,0),item.name,item.schedule,item.command,item.working_directory,item.timeout_seconds,item.enabled,item.convergence_status,item.last_error FROM scheduled_tasks item JOIN subscriptions sub ON sub.id=item.subscription_id JOIN customers customer ON customer.id=sub.customer_id LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id WHERE ` + where + ` ORDER BY item.id`, func(rows *sql.Rows) error {
			var item dashboard.ScheduledTask
			if err := rows.Scan(&item.ID, &item.SubscriptionID, &item.SiteID, &item.Name, &item.Schedule, &item.Command, &item.WorkingDirectory, &item.TimeoutSeconds, &item.Enabled, &item.Status, &item.LastError); err != nil {
				return err
			}
			data.Tasks = append(data.Tasks, item)
			return nil
		}},
		{`SELECT item.id,item.subscription_id,COALESCE(item.site_id,0),item.domain,item.enabled,item.dkim_enabled,item.dmarc_policy,item.convergence_status,item.last_error FROM mail_domains item JOIN subscriptions sub ON sub.id=item.subscription_id JOIN customers customer ON customer.id=sub.customer_id LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id WHERE ` + where + ` ORDER BY item.id`, func(rows *sql.Rows) error {
			var item dashboard.MailDomain
			if err := rows.Scan(&item.ID, &item.SubscriptionID, &item.SiteID, &item.Domain, &item.Enabled, &item.DKIM, &item.DMARCPolicy, &item.Status, &item.LastError); err != nil {
				return err
			}
			data.MailDomains = append(data.MailDomains, item)
			return nil
		}},
		{`SELECT item.id,md.subscription_id,item.mail_domain_id,lower(item.local_part)||'@'||md.domain,item.quota_mb,item.enabled FROM mailboxes item JOIN mail_domains md ON md.id=item.mail_domain_id JOIN subscriptions sub ON sub.id=md.subscription_id JOIN customers customer ON customer.id=sub.customer_id LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id WHERE ` + where + ` ORDER BY item.id`, func(rows *sql.Rows) error {
			var item dashboard.Mailbox
			if err := rows.Scan(&item.ID, &item.SubscriptionID, &item.MailDomainID, &item.Address, &item.QuotaMB, &item.Enabled); err != nil {
				return err
			}
			data.Mailboxes = append(data.Mailboxes, item)
			return nil
		}},
		{`SELECT item.id,md.subscription_id,item.mail_domain_id,lower(item.local_part)||'@'||md.domain,array_to_string(item.destinations,', ') FROM mail_aliases item JOIN mail_domains md ON md.id=item.mail_domain_id JOIN subscriptions sub ON sub.id=md.subscription_id JOIN customers customer ON customer.id=sub.customer_id LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id WHERE ` + where + ` ORDER BY item.id`, func(rows *sql.Rows) error {
			var item dashboard.MailAlias
			if err := rows.Scan(&item.ID, &item.SubscriptionID, &item.MailDomainID, &item.Address, &item.Destinations); err != nil {
				return err
			}
			data.MailAliases = append(data.MailAliases, item)
			return nil
		}},
		{`SELECT item.id,site.subscription_id,item.site_id,site.domain,item.hostname,item.status,item.config_path,item.last_error,item.created_at FROM webmail_hosts item JOIN sites site ON site.id=item.site_id JOIN subscriptions sub ON sub.id=site.subscription_id JOIN customers customer ON customer.id=sub.customer_id LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id WHERE ` + where + ` ORDER BY item.id`, func(rows *sql.Rows) error {
			var item dashboard.WebmailHost
			if err := rows.Scan(&item.ID, &item.SubscriptionID, &item.SiteID, &item.Domain, &item.Hostname, &item.Status, &item.ConfigPath, &item.LastError, &item.CreatedAt); err != nil {
				return err
			}
			data.WebmailHosts = append(data.WebmailHosts, item)
			return nil
		}},
		{`SELECT item.id,item.subscription_id,COALESCE(item.site_id,0),item.name,item.runtime,item.image_ref,item.desired_state,item.applied_state,item.convergence_status,item.last_error FROM application_instances item JOIN subscriptions sub ON sub.id=item.subscription_id JOIN customers customer ON customer.id=sub.customer_id LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id WHERE ` + where + ` ORDER BY item.id`, func(rows *sql.Rows) error {
			var item dashboard.Application
			if err := rows.Scan(&item.ID, &item.SubscriptionID, &item.SiteID, &item.Name, &item.Runtime, &item.ImageRef, &item.DesiredState, &item.AppliedState, &item.Status, &item.LastError); err != nil {
				return err
			}
			data.Applications = append(data.Applications, item)
			return nil
		}},
	}
	for _, item := range queries {
		rows, err := s.db.QueryContext(ctx, item.query, args...)
		if err != nil {
			return data, err
		}
		for rows.Next() {
			if err := item.scan(rows); err != nil {
				rows.Close()
				return data, err
			}
		}
		if err := rows.Close(); err != nil {
			return data, err
		}
	}
	return data, nil
}

func subscriptionScope(actor auth.SessionUser) (string, []any, error) {
	switch actor.Role {
	case auth.RoleAdmin:
		return "TRUE", nil, nil
	case auth.RoleReseller:
		return "reseller.login_user_id=$1", []any{actor.ID}, nil
	case auth.RoleClient:
		return "customer.login_user_id=$1", []any{actor.ID}, nil
	default:
		return "", nil, fmt.Errorf("unsupported role %q", actor.Role)
	}
}

func errorsNewWorkspaceDB() error { return fmt.Errorf("workspace database is not configured") }
