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
		item.InheritedPolicy, err = controlpolicy.Resolve(base, subscriptionPatch, nil)
		if err != nil {
			siteRows.Close()
			return data, err
		}
		item.SiteOverride = append(json.RawMessage(nil), sitePatch...)
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
		{`SELECT item.id,item.subscription_id,COALESCE(item.site_id,0),item.name,item.schedule,item.command,item.working_directory,item.timeout_seconds,item.enabled,item.convergence_status,item.last_error,item.kind,item.url,item.script_path,item.timezone FROM scheduled_tasks item JOIN subscriptions sub ON sub.id=item.subscription_id JOIN customers customer ON customer.id=sub.customer_id LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id WHERE ` + where + ` ORDER BY item.id`, func(rows *sql.Rows) error {
			var item dashboard.ScheduledTask
			if err := rows.Scan(&item.ID, &item.SubscriptionID, &item.SiteID, &item.Name, &item.Schedule, &item.Command, &item.WorkingDirectory, &item.TimeoutSeconds, &item.Enabled, &item.Status, &item.LastError, &item.Kind, &item.URL, &item.Script, &item.Timezone); err != nil {
				return err
			}
			data.Tasks = append(data.Tasks, item)
			return nil
		}},
		{`SELECT item.id,item.subscription_id,COALESCE(item.site_id,0),item.name,CASE WHEN item.site_id IS NULL THEN 'Subscription root' ELSE COALESCE(site.domain,'Domain') END,item.enabled,item.convergence_status,item.last_error,item.created_at
FROM ftp_accounts item JOIN subscriptions sub ON sub.id=item.subscription_id JOIN customers customer ON customer.id=sub.customer_id
LEFT JOIN sites site ON site.id=item.site_id LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id WHERE ` + where + ` ORDER BY item.id`, func(rows *sql.Rows) error {
			var item types.FTPAccount
			if err := rows.Scan(&item.ID, &item.SubscriptionID, &item.SiteID, &item.Name, &item.HomeLabel, &item.Enabled, &item.ConvergenceStatus, &item.LastError, &item.CreatedAt); err != nil {
				return err
			}
			data.FTP = append(data.FTP, item)
			return nil
		}},
		{`SELECT item.id,item.site_id,item.mode,item.remote_url,item.branch,item.deploy_target,item.automatic,item.convergence_status,item.last_revision,item.last_error,item.known_host_key,item.deploy_public_key,item.webhook_secret_hash<>'',item.created_at
FROM git_repositories item JOIN sites site ON site.id=item.site_id JOIN subscriptions sub ON sub.id=site.subscription_id
JOIN customers customer ON customer.id=sub.customer_id LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id WHERE ` + where + ` ORDER BY item.id`, func(rows *sql.Rows) error {
			var item types.GitRepository
			if err := rows.Scan(&item.ID, &item.SiteID, &item.Mode, &item.RemoteURL, &item.Branch, &item.DeployTarget, &item.Automatic, &item.ConvergenceStatus, &item.LastRevision, &item.LastError, &item.KnownHostKey, &item.DeployPublicKey, &item.WebhookConfigured, &item.CreatedAt); err != nil {
				return err
			}
			data.Git = append(data.Git, item)
			return nil
		}},
		{`SELECT deployment.id,deployment.repository_id,deployment.revision,deployment.status,deployment.output,deployment.rollback_revision,deployment.created_at,deployment.finished_at
FROM git_deployments deployment JOIN git_repositories repository ON repository.id=deployment.repository_id
JOIN sites site ON site.id=repository.site_id JOIN subscriptions sub ON sub.id=site.subscription_id
JOIN customers customer ON customer.id=sub.customer_id LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id
WHERE ` + where + ` ORDER BY deployment.created_at DESC LIMIT 250`, func(rows *sql.Rows) error {
			var item types.GitDeployment
			var finished sql.NullTime
			if err := rows.Scan(&item.ID, &item.RepositoryID, &item.Revision, &item.Status, &item.Output, &item.RollbackRevision, &item.CreatedAt, &finished); err != nil {
				return err
			}
			if finished.Valid {
				item.FinishedAt = finished.Time
			}
			data.GitDeployments = append(data.GitDeployments, item)
			return nil
		}},
		{`SELECT item.id,item.site_id,item.relative_path,item.realm,item.username,item.enabled,item.created_at
FROM protected_directories item JOIN sites site ON site.id=item.site_id JOIN subscriptions sub ON sub.id=site.subscription_id
JOIN customers customer ON customer.id=sub.customer_id LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id
WHERE ` + where + ` ORDER BY item.site_id,item.relative_path`, func(rows *sql.Rows) error {
			var item types.ProtectedDirectory
			if err := rows.Scan(&item.ID, &item.SiteID, &item.Path, &item.Realm, &item.Username, &item.Enabled, &item.CreatedAt); err != nil {
				return err
			}
			data.ProtectedDirectories = append(data.ProtectedDirectories, item)
			return nil
		}},
		{`SELECT item.id,item.subscription_id,item.desired_state,item.applied_state,item.memory_mb,item.max_clients,
item.idle_timeout_seconds,item.cpu_percent,item.process_limit,item.socket_path,true,item.convergence_status,item.last_error,item.updated_at
FROM valkey_instances item JOIN subscriptions sub ON sub.id=item.subscription_id JOIN customers customer ON customer.id=sub.customer_id
LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id WHERE ` + where + ` ORDER BY item.id`, func(rows *sql.Rows) error {
			var item types.ValkeyInstance
			if err := rows.Scan(&item.ID, &item.SubscriptionID, &item.DesiredState, &item.AppliedState, &item.MemoryMB, &item.MaxClients,
				&item.IdleTimeoutSeconds, &item.CPUPercent, &item.ProcessLimit, &item.SocketPath, &item.CredentialSet,
				&item.ConvergenceStatus, &item.LastError, &item.UpdatedAt); err != nil {
				return err
			}
			data.Valkey = append(data.Valkey, item)
			return nil
		}},
		{`SELECT operation.id,operation.source_site_id,operation.target_site_id,source.domain,target.domain,
operation.direction,operation.include_database,operation.status,operation.snapshot_path,operation.copied_bytes,
operation.last_error,operation.created_at,operation.finished_at
FROM staging_operations operation
JOIN sites source ON source.id=operation.source_site_id
JOIN sites target ON target.id=operation.target_site_id
JOIN subscriptions sub ON sub.id=source.subscription_id
JOIN customers customer ON customer.id=sub.customer_id
LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id
WHERE ` + where + ` ORDER BY operation.created_at DESC LIMIT 250`, func(rows *sql.Rows) error {
			var item types.StagingOperation
			var finishedAt sql.NullTime
			if err := rows.Scan(&item.ID, &item.SourceSiteID, &item.TargetSiteID, &item.SourceDomain, &item.TargetDomain,
				&item.Direction, &item.IncludeDatabase, &item.Status, &item.SnapshotPath, &item.CopiedBytes,
				&item.LastError, &item.CreatedAt, &finishedAt); err != nil {
				return err
			}
			if finishedAt.Valid {
				item.FinishedAt = finishedAt.Time
			}
			data.Staging = append(data.Staging, item)
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
		{`SELECT item.id,item.subscription_id,COALESCE(item.site_id,0),item.name,item.runtime,item.image_ref,
item.desired_state,item.applied_state,item.convergence_status,item.last_error,item.route_mode,item.route_prefix,
item.container_port,item.endpoint_port,item.health_kind,item.health_path,item.active_generation,item.observed_state,
item.observed_message,item.observed_at
FROM application_instances item JOIN subscriptions sub ON sub.id=item.subscription_id
JOIN customers customer ON customer.id=sub.customer_id LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id
WHERE ` + where + ` ORDER BY item.id`, func(rows *sql.Rows) error {
			var item dashboard.Application
			var observedAt sql.NullTime
			if err := rows.Scan(&item.ID, &item.SubscriptionID, &item.SiteID, &item.Name, &item.Runtime,
				&item.ImageRef, &item.DesiredState, &item.AppliedState, &item.Status, &item.LastError,
				&item.RouteMode, &item.RoutePrefix, &item.ContainerPort, &item.EndpointPort, &item.HealthKind,
				&item.HealthPath, &item.ActiveRevision, &item.ObservedState, &item.ObservedMessage, &observedAt); err != nil {
				return err
			}
			if observedAt.Valid {
				item.ObservedAt = dashboard.NullableTime{Time: observedAt.Time, Valid: true}
			}
			data.Applications = append(data.Applications, item)
			return nil
		}},
		{`SELECT generation.id,generation.application_id,generation.desired_revision,generation.image_ref,
generation.endpoint_port,generation.unit_name,generation.container_name,generation.status,generation.health_message,
generation.started_at,generation.healthy_at,generation.created_at
FROM application_generations generation JOIN application_instances item ON item.id=generation.application_id
JOIN subscriptions sub ON sub.id=item.subscription_id JOIN customers customer ON customer.id=sub.customer_id
LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id
WHERE ` + where + ` ORDER BY generation.created_at DESC LIMIT 250`, func(rows *sql.Rows) error {
			var item types.ApplicationGeneration
			var startedAt, healthyAt sql.NullTime
			if err := rows.Scan(&item.ID, &item.ApplicationID, &item.DesiredRevision, &item.ImageRef, &item.EndpointPort,
				&item.UnitName, &item.ContainerName, &item.Status, &item.HealthMessage, &startedAt, &healthyAt,
				&item.CreatedAt); err != nil {
				return err
			}
			if startedAt.Valid {
				item.StartedAt = startedAt.Time
			}
			if healthyAt.Valid {
				item.HealthyAt = healthyAt.Time
			}
			data.ApplicationGenerations = append(data.ApplicationGenerations, item)
			return nil
		}},
		{`SELECT run.id,run.task_id,run.status,run.exit_code,run.output,
COALESCE(run.started_at,run.created_at),COALESCE(run.finished_at,run.created_at),
COALESCE(run.scheduled_for,run.created_at),run.created_at
FROM scheduled_task_runs run JOIN scheduled_tasks task ON task.id=run.task_id
JOIN subscriptions sub ON sub.id=task.subscription_id JOIN customers customer ON customer.id=sub.customer_id
LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id WHERE ` + where + ` ORDER BY run.created_at DESC LIMIT 250`, func(rows *sql.Rows) error {
			var item types.ScheduledTaskRun
			if err := rows.Scan(&item.ID, &item.TaskID, &item.Status, &item.ExitCode, &item.Output, &item.StartedAt, &item.FinishedAt, &item.ScheduledFor, &item.CreatedAt); err != nil {
				return err
			}
			data.TaskRuns = append(data.TaskRuns, item)
			return nil
		}},
		{`SELECT usage.site_id,usage.period_start,usage.document_root_bytes,usage.traffic_bytes,
usage.request_count,usage.error_count,usage.php_state,usage.collected_at,usage.last_error
FROM site_usage_current usage JOIN sites site ON site.id=usage.site_id
JOIN subscriptions sub ON sub.id=site.subscription_id JOIN customers customer ON customer.id=sub.customer_id
LEFT JOIN reseller_accounts reseller ON reseller.id=customer.reseller_id WHERE ` + where + ` ORDER BY usage.site_id`, func(rows *sql.Rows) error {
			item, err := scanSiteUsage(rows)
			if err != nil {
				return err
			}
			data.SiteUsage = append(data.SiteUsage, item)
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
	presetQuery := `SELECT preset.id,COALESCE(preset.reseller_id,0),preset.slug,preset.name,preset.runtime,preset.image_ref,preset.active,preset.created_at
FROM application_presets preset WHERE preset.reseller_id IS NULL ORDER BY preset.name`
	presetArgs := []any{}
	switch actor.Role {
	case auth.RoleReseller:
		presetQuery = `SELECT preset.id,COALESCE(preset.reseller_id,0),preset.slug,preset.name,preset.runtime,preset.image_ref,preset.active,preset.created_at
FROM application_presets preset
JOIN reseller_accounts reseller ON reseller.id=preset.reseller_id
WHERE reseller.login_user_id=$1 ORDER BY preset.name`
		presetArgs = append(presetArgs, actor.ID)
	case auth.RoleClient:
		presetQuery = `SELECT preset.id,COALESCE(preset.reseller_id,0),preset.slug,preset.name,preset.runtime,preset.image_ref,preset.active,preset.created_at
FROM application_presets preset
WHERE EXISTS (SELECT 1 FROM customers customer WHERE customer.login_user_id=$1
              AND customer.reseller_id IS NOT DISTINCT FROM preset.reseller_id)
ORDER BY preset.name`
		presetArgs = append(presetArgs, actor.ID)
	}
	presetRows, err := s.db.QueryContext(ctx, presetQuery, presetArgs...)
	if err != nil {
		return data, err
	}
	defer presetRows.Close()
	for presetRows.Next() {
		var item types.ApplicationPreset
		if err := presetRows.Scan(&item.ID, &item.ResellerID, &item.Slug, &item.Name, &item.Runtime, &item.ImageRef, &item.Active, &item.CreatedAt); err != nil {
			return data, err
		}
		data.ApplicationPresets = append(data.ApplicationPresets, item)
	}
	if err := presetRows.Err(); err != nil {
		return data, err
	}
	return data, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanSiteUsage(row rowScanner) (dashboard.SiteUsage, error) {
	var item dashboard.SiteUsage
	var collectedAt sql.NullTime
	if err := row.Scan(&item.SiteID, &item.PeriodStart, &item.DocumentRootBytes, &item.TrafficBytes,
		&item.RequestCount, &item.ErrorCount, &item.PHPState, &collectedAt, &item.LastError); err != nil {
		return dashboard.SiteUsage{}, err
	}
	item.CollectedAt = dashboard.NullableTime{Time: collectedAt.Time, Valid: collectedAt.Valid}
	return item, nil
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
