package quota

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlpolicy "github.com/nakroteck/nakpanel/internal/control/policy"
	"github.com/nakroteck/nakpanel/internal/types"
)

var (
	ErrResellerCapacity = errors.New("reseller capacity exceeded")
	ErrProviderScope    = errors.New("provider scoped object not found")
)

func (s *SQLStore) SetPlanStatuses(ctx context.Context, planIDs []int64, resellerID int64, unrestricted bool, active bool) error {
	return s.setProviderPlanStatuses(ctx, "plans", planIDs, resellerID, unrestricted, active)
}

func (s *SQLStore) SetAddonPlanStatuses(ctx context.Context, addonIDs []int64, resellerID int64, unrestricted bool, active bool) error {
	return s.setProviderPlanStatuses(ctx, "addon_plans", addonIDs, resellerID, unrestricted, active)
}

func (s *SQLStore) setProviderPlanStatuses(ctx context.Context, table string, ids []int64, resellerID int64, unrestricted bool, active bool) error {
	if s == nil || s.db == nil {
		return errors.New("plan database is not configured")
	}
	if len(ids) == 0 {
		return errors.New("at least one plan is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	seen := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		if id <= 0 {
			return errors.New("plan ids must be positive")
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		result, execErr := tx.ExecContext(ctx, `UPDATE `+table+` SET is_active=$2,updated_at=now()
WHERE id=$1 AND ($4 OR COALESCE(reseller_id,0)=$3)`, id, active, resellerID, unrestricted)
		if execErr != nil {
			return execErr
		}
		affected, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return rowsErr
		}
		if affected != 1 {
			return ErrProviderScope
		}
	}
	return tx.Commit()
}

func (s *SQLStore) SetResellerPlanStatuses(ctx context.Context, planIDs []int64, active bool) error {
	if s == nil || s.db == nil {
		return errors.New("plan database is not configured")
	}
	if len(planIDs) == 0 {
		return errors.New("at least one reseller plan is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	seen := make(map[int64]struct{}, len(planIDs))
	for _, id := range planIDs {
		if id <= 0 {
			return errors.New("reseller plan ids must be positive")
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		result, execErr := tx.ExecContext(ctx, `UPDATE reseller_plans SET is_active=$2,updated_at=now() WHERE id=$1`, id, active)
		if execErr != nil {
			return execErr
		}
		affected, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return rowsErr
		}
		if affected != 1 {
			return ErrProviderScope
		}
	}
	return tx.Commit()
}

func validateNewResellerCustomerTx(ctx context.Context, tx *sql.Tx, resellerID int64) error {
	var used, allowed int
	err := tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*)::int FROM customers WHERE reseller_id=$1),p.max_customers FROM reseller_accounts r JOIN reseller_subscriptions rs ON rs.reseller_id=r.id AND rs.status='active' JOIN reseller_plans p ON p.id=rs.reseller_plan_id WHERE r.id=$1 AND r.status='active' FOR UPDATE OF r,rs,p`, resellerID).Scan(&used, &allowed)
	if err != nil {
		return err
	}
	if allowed >= 0 && used >= allowed {
		return fmt.Errorf("%w: customers %d / %d", ErrResellerCapacity, used, allowed)
	}
	return nil
}

func validatePlanWithinResellerTx(ctx context.Context, tx *sql.Tx, p Plan) error {
	if p.ResellerID <= 0 {
		return nil
	}
	var rp types.ResellerPlan
	err := tx.QueryRowContext(ctx, `SELECT x.disk_mb,x.max_sites,x.max_subdomains,x.max_domain_aliases,x.max_databases,x.bandwidth_mb,x.max_mailboxes,x.max_ftp_accounts,x.max_backups,x.backup_storage_mb,x.allow_ssh,x.allow_dns,x.allow_tls,x.allow_backups,x.allow_php_settings FROM reseller_accounts r JOIN reseller_subscriptions rs ON rs.reseller_id=r.id AND rs.status='active' JOIN reseller_plans x ON x.id=rs.reseller_plan_id WHERE r.id=$1 FOR UPDATE OF r,rs,x`, p.ResellerID).Scan(&rp.DiskMB, &rp.MaxSites, &rp.MaxSubdomains, &rp.MaxDomainAliases, &rp.MaxDatabases, &rp.BandwidthMB, &rp.MaxMailboxes, &rp.MaxFTPAccounts, &rp.MaxBackups, &rp.BackupStorageMB, &rp.AllowSSH, &rp.AllowDNS, &rp.AllowTLS, &rp.AllowBackups, &rp.AllowPHPSettings)
	if err != nil {
		return err
	}
	checks := []struct {
		name          string
		want, allowed int
	}{{"disk", p.DiskMB, rp.DiskMB}, {"sites", p.MaxSites, rp.MaxSites}, {"subdomains", p.MaxSubdomains, rp.MaxSubdomains}, {"domain aliases", p.MaxDomainAliases, rp.MaxDomainAliases}, {"databases", p.MaxDatabases, rp.MaxDatabases}, {"bandwidth", p.BandwidthMB, rp.BandwidthMB}, {"mailboxes", p.MaxMailboxes, rp.MaxMailboxes}, {"FTP accounts", p.MaxFTPAccounts, rp.MaxFTPAccounts}, {"backups", p.MaxBackups, rp.MaxBackups}, {"backup storage", p.BackupStorageMB, rp.BackupStorageMB}}
	for _, c := range checks {
		if c.allowed >= 0 && (c.want < 0 || c.want > c.allowed) {
			return fmt.Errorf("%w: plan %s limit %d exceeds %d", ErrResellerCapacity, c.name, c.want, c.allowed)
		}
	}
	if p.AllowSSH && !rp.AllowSSH {
		return fmt.Errorf("%w: SSH permission is unavailable", ErrResellerCapacity)
	}
	if p.AllowDNS && !rp.AllowDNS {
		return fmt.Errorf("%w: DNS permission is unavailable", ErrResellerCapacity)
	}
	if p.AllowTLS && !rp.AllowTLS {
		return fmt.Errorf("%w: TLS permission is unavailable", ErrResellerCapacity)
	}
	if p.AllowBackups && !rp.AllowBackups {
		return fmt.Errorf("%w: backup permission is unavailable", ErrResellerCapacity)
	}
	if p.AllowPHPSettings && !rp.AllowPHPSettings {
		return fmt.Errorf("%w: PHP settings permission is unavailable", ErrResellerCapacity)
	}
	return nil
}

func validateCustomWithinResellerTx(ctx context.Context, tx *sql.Tx, resellerID int64, entitlements types.SubscriptionEntitlements) error {
	var allowed bool
	if err := tx.QueryRowContext(ctx, `SELECT p.allow_custom_plans FROM reseller_accounts r JOIN reseller_subscriptions rs ON rs.reseller_id=r.id AND rs.status='active' JOIN reseller_plans p ON p.id=rs.reseller_plan_id WHERE r.id=$1 FOR UPDATE OF r,rs,p`, resellerID).Scan(&allowed); err != nil {
		return err
	}
	if !allowed {
		return errors.New("reseller plan does not permit custom subscriptions")
	}
	plan := planFromEntitlements(entitlements)
	plan.ResellerID = resellerID
	return validatePlanWithinResellerTx(ctx, tx, plan)
}

func validateEntitlementsWithinResellerTx(ctx context.Context, tx *sql.Tx, resellerID int64, entitlements types.SubscriptionEntitlements) error {
	plan := planFromEntitlements(entitlements)
	plan.ResellerID = resellerID
	return validatePlanWithinResellerTx(ctx, tx, plan)
}

func ensureResellerActiveTx(ctx context.Context, tx *sql.Tx, resellerID int64) error {
	var status string
	err := tx.QueryRowContext(ctx, `SELECT r.status
FROM reseller_accounts r
JOIN reseller_subscriptions rs ON rs.reseller_id=r.id AND rs.status='active'
WHERE r.id=$1
FOR UPDATE OF r,rs`, resellerID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) || status != "active" {
		return errors.New("reseller is not active or has no active allocation")
	}
	return err
}

func ValidateEntitlements(e types.SubscriptionEntitlements) error {
	for name, value := range map[string]int{
		"disk_mb": e.DiskMB, "max_sites": e.MaxSites, "max_databases": e.MaxDatabases,
		"bandwidth_mb": e.BandwidthMB, "max_mailboxes": e.MaxMailboxes,
		"backup_retention_days": e.BackupRetentionDays, "php_fpm_max_children": e.PHPFPMMaxChildren,
		"php_memory_mb": e.PHPMemoryMB, "site_disk_quota_mb": e.SiteDiskQuotaMB,
		"max_backups": e.MaxBackups, "backup_storage_mb": e.BackupStorageMB,
		"max_subdomains": e.MaxSubdomains, "max_domain_aliases": e.MaxDomainAliases,
		"max_ftp_accounts": e.MaxFTPAccounts, "validity_days": e.ValidityDays,
	} {
		if value < -1 {
			return fmt.Errorf("%s cannot be less than -1", name)
		}
		if value > maxPlanLimit {
			return fmt.Errorf("%s exceeds the maximum supported value", name)
		}
	}
	switch e.OverusePolicy {
	case "", types.PlanOveruseBlock, types.PlanOveruseNormal, types.PlanOveruseNotify,
		types.PlanOveruseNotSuspend, types.PlanOveruseNotSuspendNotify:
	default:
		return fmt.Errorf("unsupported overuse policy %q", e.OverusePolicy)
	}
	if e.DiskWarningPercent != 0 && (e.DiskWarningPercent < 1 || e.DiskWarningPercent > 100) {
		return errors.New("disk warning percent must be between 1 and 100")
	}
	if e.TrafficWarningPercent != 0 && (e.TrafficWarningPercent < 1 || e.TrafficWarningPercent > 100) {
		return errors.New("traffic warning percent must be between 1 and 100")
	}
	if e.HostingEnabled {
		if strings.TrimSpace(e.DefaultPHPVersion) == "" {
			return errors.New("default PHP version is required when hosting is enabled")
		}
		if !csvContains(e.PHPAllowlist, e.DefaultPHPVersion) {
			return errors.New("default PHP version must be included in the PHP allowlist")
		}
	}
	if strings.TrimSpace(e.PlanName) == "" {
		e.PlanName = "Custom"
	}
	return nil
}

func ComposeEntitlements(base types.SubscriptionEntitlements, addons []types.AddonPlan) (types.SubscriptionEntitlements, error) {
	if err := ValidateEntitlements(base); err != nil {
		return types.SubscriptionEntitlements{}, err
	}
	result := base
	php := csvSet(base.PHPAllowlist)
	for _, addon := range addons {
		if err := ValidateEntitlements(addon.Entitlements); err != nil {
			return types.SubscriptionEntitlements{}, fmt.Errorf("add-on %q: %w", addon.Name, err)
		}
		add := addon.Entitlements
		for _, limit := range []struct {
			name    string
			current *int
			delta   int
		}{
			{"disk", &result.DiskMB, add.DiskMB},
			{"sites", &result.MaxSites, add.MaxSites},
			{"databases", &result.MaxDatabases, add.MaxDatabases},
			{"traffic", &result.BandwidthMB, add.BandwidthMB},
			{"mailboxes", &result.MaxMailboxes, add.MaxMailboxes},
			{"backups", &result.MaxBackups, add.MaxBackups},
			{"backup storage", &result.BackupStorageMB, add.BackupStorageMB},
			{"subdomains", &result.MaxSubdomains, add.MaxSubdomains},
			{"domain aliases", &result.MaxDomainAliases, add.MaxDomainAliases},
			{"FTP accounts", &result.MaxFTPAccounts, add.MaxFTPAccounts},
		} {
			combined, err := additiveLimit(*limit.current, limit.delta)
			if err != nil {
				return types.SubscriptionEntitlements{}, fmt.Errorf("add-on %q %s: %w", addon.Name, limit.name, err)
			}
			*limit.current = combined
		}
		result.BackupRetentionDays = highestLimit(result.BackupRetentionDays, add.BackupRetentionDays)
		result.PHPFPMMaxChildren = highestLimit(result.PHPFPMMaxChildren, add.PHPFPMMaxChildren)
		result.PHPMemoryMB = highestLimit(result.PHPMemoryMB, add.PHPMemoryMB)
		result.SiteDiskQuotaMB = highestLimit(result.SiteDiskQuotaMB, add.SiteDiskQuotaMB)
		result.AllowSSH = result.AllowSSH || add.AllowSSH
		result.AllowDNS = result.AllowDNS || add.AllowDNS
		result.AllowTLS = result.AllowTLS || add.AllowTLS
		result.AllowBackups = result.AllowBackups || add.AllowBackups
		result.AllowPHPSettings = result.AllowPHPSettings || add.AllowPHPSettings
		result.ServicePresets = composePresetIncrements(result.ServicePresets, add.ServicePresets)
		for version := range csvSet(add.PHPAllowlist) {
			php[version] = struct{}{}
		}
		if addon.Revision > result.SourceRevision {
			result.SourceRevision = addon.Revision
		}
	}
	result.PHPAllowlist = joinSet(php)
	result.ServicePresets.Hosting.AllowedPHPVersions = nil
	if result.PHPAllowlist != "" {
		result.ServicePresets.Hosting.AllowedPHPVersions = strings.Split(result.PHPAllowlist, ",")
	}
	result.HostingPolicy = mergeLegacyEntitlementsPolicy(result, base.HostingPolicy)
	return result, nil
}

func mergeLegacyEntitlementsPolicy(e types.SubscriptionEntitlements, previous types.HostingPolicy) types.HostingPolicy {
	resolved := controlpolicy.DefaultFromEntitlements(e)
	if previous.SchemaVersion != 1 {
		return resolved
	}
	resolved.Resources.CPUPercent = previous.Resources.CPUPercent
	resolved.Resources.MemoryMB = previous.Resources.MemoryMB
	resolved.Resources.IOReadMBPS = previous.Resources.IOReadMBPS
	resolved.Resources.IOWriteMBPS = previous.Resources.IOWriteMBPS
	resolved.Resources.MaxTasks = previous.Resources.MaxTasks
	resolved.Resources.MaxDatabaseUsers = previous.Resources.MaxDatabaseUsers
	resolved.Resources.MaxMailAliases = previous.Resources.MaxMailAliases
	resolved.Resources.MaxScheduledTasks = previous.Resources.MaxScheduledTasks
	resolved.Resources.MaxApplications = previous.Resources.MaxApplications
	resolved.Resources.ContainerStorageMB = previous.Resources.ContainerStorageMB
	resolved.Permissions.ScheduledTasks = previous.Permissions.ScheduledTasks
	resolved.Permissions.CGI = previous.Permissions.CGI
	resolved.Permissions.Applications = previous.Permissions.Applications
	resolved.Permissions.CustomOCIImages = previous.Permissions.CustomOCIImages
	resolved.Permissions.ApplicationEgress = previous.Permissions.ApplicationEgress
	resolved.Web.RequestRatePerSecond = previous.Web.RequestRatePerSecond
	resolved.Web.RequestBurst = previous.Web.RequestBurst
	resolved.Web.FastCGIMicrocache = previous.Web.FastCGIMicrocache
	resolved.PHP.ExecEnabled = previous.PHP.ExecEnabled
	resolved.Mail.MailboxQuotaMB = previous.Mail.MailboxQuotaMB
	resolved.Mail.Autoresponders = previous.Mail.Autoresponders
	resolved.Mail.CatchAll = previous.Mail.CatchAll
	resolved.DNS.DNSSEC = previous.DNS.DNSSEC
	resolved.Access = previous.Access
	resolved.Backups.Schedule = previous.Backups.Schedule
	resolved.Backups.RemoteTarget = previous.Backups.RemoteTarget
	resolved.Applications = previous.Applications
	resolved.Applications.CatalogEnabled = resolved.Applications.CatalogEnabled || e.ServicePresets.Applications.CatalogEnabled
	return resolved
}

func composePresetIncrements(base, add types.PlanServicePresets) types.PlanServicePresets {
	result := base
	result.SchemaVersion = maxInt(maxInt(result.SchemaVersion, add.SchemaVersion), 1)
	result.PHP.MaxExecutionSeconds = maxInt(result.PHP.MaxExecutionSeconds, add.PHP.MaxExecutionSeconds)
	result.PHP.MaxInputSeconds = maxInt(result.PHP.MaxInputSeconds, add.PHP.MaxInputSeconds)
	result.PHP.PostMaxMB = maxInt(result.PHP.PostMaxMB, add.PHP.PostMaxMB)
	result.PHP.UploadMaxMB = maxInt(result.PHP.UploadMaxMB, add.PHP.UploadMaxMB)
	result.PHP.FPMMaxRequests = maxInt(result.PHP.FPMMaxRequests, add.PHP.FPMMaxRequests)
	result.PHP.DisplayErrors = result.PHP.DisplayErrors || add.PHP.DisplayErrors
	result.PHP.LogErrors = result.PHP.LogErrors || add.PHP.LogErrors
	result.PHP.AllowURLFOpen = result.PHP.AllowURLFOpen || add.PHP.AllowURLFOpen
	result.Mail.WebmailEnabled = result.Mail.WebmailEnabled || add.Mail.WebmailEnabled
	result.Mail.SpamFilter = result.Mail.SpamFilter || add.Mail.SpamFilter
	result.Mail.DKIM = result.Mail.DKIM || add.Mail.DKIM
	if policy := strings.TrimSpace(add.Mail.DMARCPolicy); policy != "" && policy != "none" {
		result.Mail.DMARCPolicy = policy
	}
	result.DNS.DefaultTTL = maxInt(result.DNS.DefaultTTL, add.DNS.DefaultTTL)
	result.Performance.MaxConnections = maxInt(result.Performance.MaxConnections, add.Performance.MaxConnections)
	result.Performance.StaticFileCache = result.Performance.StaticFileCache || add.Performance.StaticFileCache
	result.Logs.RotationEnabled = result.Logs.RotationEnabled || add.Logs.RotationEnabled
	result.Logs.RetentionDays = maxInt(result.Logs.RetentionDays, add.Logs.RetentionDays)
	result.Logs.StatisticsEnabled = result.Logs.StatisticsEnabled || add.Logs.StatisticsEnabled
	result.Applications.CatalogEnabled = result.Applications.CatalogEnabled || add.Applications.CatalogEnabled
	applications := make(map[string]struct{})
	for _, name := range append(append([]string{}, result.Applications.Allowed...), add.Applications.Allowed...) {
		if name = strings.TrimSpace(name); name != "" {
			applications[name] = struct{}{}
		}
	}
	result.Applications.Allowed = make([]string, 0, len(applications))
	for name := range applications {
		result.Applications.Allowed = append(result.Applications.Allowed, name)
	}
	sort.Strings(result.Applications.Allowed)
	return result
}

func additiveLimit(current, delta int) (int, error) {
	if current < 0 || delta < 0 {
		return -1, nil
	}
	if current > maxPlanLimit-delta {
		return 0, errors.New("combined limit exceeds the maximum supported value")
	}
	return current + delta, nil
}

func highestLimit(current, candidate int) int {
	if current < 0 || candidate < 0 {
		return -1
	}
	if candidate > current {
		return candidate
	}
	return current
}

func csvSet(value string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out[item] = struct{}{}
		}
	}
	return out
}

func joinSet(values map[string]struct{}) string {
	items := make([]string, 0, len(values))
	for value := range values {
		items = append(items, value)
	}
	sort.Strings(items)
	return strings.Join(items, ",")
}

func planFromEntitlements(e types.SubscriptionEntitlements) Plan {
	name := strings.TrimSpace(e.PlanName)
	if name == "" {
		name = "Custom"
	}
	plan := Plan{ID: 0, Name: name, DiskMB: e.DiskMB, MaxSites: e.MaxSites,
		MaxDatabases: e.MaxDatabases, BandwidthMB: e.BandwidthMB, MaxMailboxes: e.MaxMailboxes,
		AllowSSH: e.AllowSSH, AllowDNS: e.AllowDNS, BackupRetentionDays: e.BackupRetentionDays,
		PHPAllowlist: e.PHPAllowlist, PHPFPMMaxChildren: e.PHPFPMMaxChildren,
		PHPMemoryMB: e.PHPMemoryMB, SiteDiskQuotaMB: e.SiteDiskQuotaMB,
		MaxBackups: e.MaxBackups, BackupStorageMB: e.BackupStorageMB, Revision: maxInt(e.SourceRevision, 1),
		OverusePolicy: e.OverusePolicy, DiskWarningPercent: e.DiskWarningPercent,
		TrafficWarningPercent: e.TrafficWarningPercent, MaxSubdomains: e.MaxSubdomains,
		MaxDomainAliases: e.MaxDomainAliases, MaxFTPAccounts: e.MaxFTPAccounts,
		ValidityDays: e.ValidityDays, HostingEnabled: e.HostingEnabled,
		DefaultPHPVersion: e.DefaultPHPVersion, AllowTLS: e.AllowTLS,
		AllowBackups: e.AllowBackups, AllowPHPSettings: e.AllowPHPSettings, Presets: e.ServicePresets, HostingPolicy: e.HostingPolicy}
	return normalizePlanDefaults(plan)
}

func entitlementsFromPlan(plan Plan) types.SubscriptionEntitlements {
	plan = normalizePlanDefaults(plan)
	e := types.SubscriptionEntitlements{PlanName: plan.Name, DiskMB: plan.DiskMB,
		MaxSites: plan.MaxSites, MaxDatabases: plan.MaxDatabases, BandwidthMB: plan.BandwidthMB,
		MaxMailboxes: plan.MaxMailboxes, AllowSSH: plan.AllowSSH, AllowDNS: plan.AllowDNS,
		BackupRetentionDays: plan.BackupRetentionDays, PHPAllowlist: plan.PHPAllowlist,
		PHPFPMMaxChildren: plan.PHPFPMMaxChildren, PHPMemoryMB: plan.PHPMemoryMB,
		SiteDiskQuotaMB: plan.SiteDiskQuotaMB, MaxBackups: plan.MaxBackups,
		BackupStorageMB: plan.BackupStorageMB, SourceRevision: maxInt(plan.Revision, 1),
		OverusePolicy: plan.OverusePolicy, DiskWarningPercent: plan.DiskWarningPercent,
		TrafficWarningPercent: plan.TrafficWarningPercent, MaxSubdomains: plan.MaxSubdomains,
		MaxDomainAliases: plan.MaxDomainAliases, MaxFTPAccounts: plan.MaxFTPAccounts,
		ValidityDays: plan.ValidityDays, HostingEnabled: plan.HostingEnabled,
		DefaultPHPVersion: plan.DefaultPHPVersion, AllowTLS: plan.AllowTLS,
		AllowBackups: plan.AllowBackups, AllowPHPSettings: plan.AllowPHPSettings,
		ServicePresets: plan.Presets, HostingPolicy: plan.HostingPolicy}
	if e.HostingPolicy.SchemaVersion == 0 {
		e.HostingPolicy = controlpolicy.DefaultFromEntitlements(e)
	}
	return e
}

func writePlanEntitlementsTx(ctx context.Context, tx *sql.Tx, subscriptionID int64, plan Plan) error {
	e := entitlementsFromPlan(plan)
	e.SubscriptionID = subscriptionID
	return writeSubscriptionEntitlementsTx(ctx, tx, e)
}

func writeSubscriptionEntitlementsTx(ctx context.Context, tx *sql.Tx, e types.SubscriptionEntitlements) error {
	if e.SubscriptionID <= 0 {
		return errors.New("subscription id is required")
	}
	if err := ValidateEntitlements(e); err != nil {
		return err
	}
	if strings.TrimSpace(e.PlanName) == "" {
		e.PlanName = "Custom"
	}
	if e.OverusePolicy == "" {
		e.OverusePolicy = types.PlanOveruseBlock
	}
	if e.DiskWarningPercent == 0 {
		e.DiskWarningPercent = 80
	}
	if e.TrafficWarningPercent == 0 {
		e.TrafficWarningPercent = 80
	}
	if e.ServicePresets.SchemaVersion <= 0 {
		e.ServicePresets.SchemaVersion = 1
	}
	presets, err := json.Marshal(e.ServicePresets)
	if err != nil {
		return fmt.Errorf("encode subscription service presets: %w", err)
	}
	policy := e.HostingPolicy
	if policy.SchemaVersion == 0 {
		policy = controlpolicy.DefaultFromEntitlements(e)
	}
	if err := controlpolicy.Validate(policy); err != nil {
		return fmt.Errorf("validate subscription hosting policy: %w", err)
	}
	hostingPolicy, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("encode subscription hosting policy: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO subscription_entitlements (
subscription_id, plan_name, disk_mb, max_sites, max_databases, bandwidth_mb, max_mailboxes,
allow_ssh, allow_dns, backup_retention_days, php_allowlist, php_fpm_max_children,
php_memory_mb, site_disk_quota_mb, max_backups, backup_storage_mb, source_revision,
overuse_policy,disk_warning_percent,traffic_warning_percent,max_subdomains,max_domain_aliases,
max_ftp_accounts,validity_days,hosting_enabled,default_php_version,allow_tls,allow_backups,
	allow_php_settings,service_presets,hosting_policy
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31)
ON CONFLICT (subscription_id) DO UPDATE SET
plan_name=EXCLUDED.plan_name, disk_mb=EXCLUDED.disk_mb, max_sites=EXCLUDED.max_sites,
max_databases=EXCLUDED.max_databases, bandwidth_mb=EXCLUDED.bandwidth_mb,
max_mailboxes=EXCLUDED.max_mailboxes, allow_ssh=EXCLUDED.allow_ssh, allow_dns=EXCLUDED.allow_dns,
backup_retention_days=EXCLUDED.backup_retention_days, php_allowlist=EXCLUDED.php_allowlist,
php_fpm_max_children=EXCLUDED.php_fpm_max_children, php_memory_mb=EXCLUDED.php_memory_mb,
site_disk_quota_mb=EXCLUDED.site_disk_quota_mb, max_backups=EXCLUDED.max_backups,
backup_storage_mb=EXCLUDED.backup_storage_mb, source_revision=EXCLUDED.source_revision,
overuse_policy=EXCLUDED.overuse_policy,disk_warning_percent=EXCLUDED.disk_warning_percent,
traffic_warning_percent=EXCLUDED.traffic_warning_percent,max_subdomains=EXCLUDED.max_subdomains,
max_domain_aliases=EXCLUDED.max_domain_aliases,max_ftp_accounts=EXCLUDED.max_ftp_accounts,
validity_days=EXCLUDED.validity_days,hosting_enabled=EXCLUDED.hosting_enabled,
default_php_version=EXCLUDED.default_php_version,allow_tls=EXCLUDED.allow_tls,
allow_backups=EXCLUDED.allow_backups,allow_php_settings=EXCLUDED.allow_php_settings,
	service_presets=EXCLUDED.service_presets,hosting_policy=EXCLUDED.hosting_policy,updated_at=now()`,
		e.SubscriptionID, e.PlanName, e.DiskMB, e.MaxSites, e.MaxDatabases, e.BandwidthMB,
		e.MaxMailboxes, e.AllowSSH, e.AllowDNS, e.BackupRetentionDays, e.PHPAllowlist,
		e.PHPFPMMaxChildren, e.PHPMemoryMB, e.SiteDiskQuotaMB, e.MaxBackups,
		e.BackupStorageMB, maxInt(e.SourceRevision, 1), e.OverusePolicy,
		e.DiskWarningPercent, e.TrafficWarningPercent, e.MaxSubdomains,
		e.MaxDomainAliases, e.MaxFTPAccounts, e.ValidityDays, e.HostingEnabled,
		e.DefaultPHPVersion, e.AllowTLS, e.AllowBackups, e.AllowPHPSettings, presets, hostingPolicy)
	return err
}

// ValidateProvisioningCapacityTx applies the same provider and server-capacity
// gates used by the panel while an external provisioning transaction is open.
func ValidateProvisioningCapacityTx(ctx context.Context, tx *sql.Tx, resellerID, subscriptionID int64) error {
	entitlements, err := readSubscriptionEntitlementsTx(ctx, tx, subscriptionID)
	if err != nil {
		return err
	}
	if resellerID > 0 {
		if err = ensureResellerActiveTx(ctx, tx, resellerID); err != nil {
			return err
		}
		if err = validateResellerCapacityTx(ctx, tx, resellerID, subscriptionID, entitlements); err != nil {
			return err
		}
	}
	_, err = subscriptionOversellWarningForSubscriptionTx(ctx, tx, subscriptionID, planFromEntitlements(entitlements), "active")
	return err
}

func readSubscriptionEntitlementsTx(ctx context.Context, tx *sql.Tx, subscriptionID int64) (types.SubscriptionEntitlements, error) {
	var e types.SubscriptionEntitlements
	var presets, hostingPolicy []byte
	err := tx.QueryRowContext(ctx, `SELECT subscription_id,plan_name,disk_mb,max_sites,max_databases,bandwidth_mb,max_mailboxes,allow_ssh,allow_dns,backup_retention_days,php_allowlist,php_fpm_max_children,php_memory_mb,site_disk_quota_mb,max_backups,backup_storage_mb,source_revision,overuse_policy,disk_warning_percent,traffic_warning_percent,max_subdomains,max_domain_aliases,max_ftp_accounts,validity_days,hosting_enabled,default_php_version,allow_tls,allow_backups,allow_php_settings,service_presets,hosting_policy FROM subscription_entitlements WHERE subscription_id=$1`, subscriptionID).Scan(
		&e.SubscriptionID, &e.PlanName, &e.DiskMB, &e.MaxSites, &e.MaxDatabases,
		&e.BandwidthMB, &e.MaxMailboxes, &e.AllowSSH, &e.AllowDNS,
		&e.BackupRetentionDays, &e.PHPAllowlist, &e.PHPFPMMaxChildren,
		&e.PHPMemoryMB, &e.SiteDiskQuotaMB, &e.MaxBackups, &e.BackupStorageMB,
		&e.SourceRevision, &e.OverusePolicy, &e.DiskWarningPercent, &e.TrafficWarningPercent,
		&e.MaxSubdomains, &e.MaxDomainAliases, &e.MaxFTPAccounts, &e.ValidityDays,
		&e.HostingEnabled, &e.DefaultPHPVersion, &e.AllowTLS, &e.AllowBackups,
		&e.AllowPHPSettings, &presets, &hostingPolicy,
	)
	if err == nil {
		err = json.Unmarshal(presets, &e.ServicePresets)
	}
	if err == nil {
		err = json.Unmarshal(hostingPolicy, &e.HostingPolicy)
	}
	return e, err
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (s *SQLStore) ProviderScopeForUser(ctx context.Context, user auth.SessionUser) (types.ProviderScope, error) {
	scope := types.ProviderScope{ActorUserID: user.ID, Role: string(user.Role)}
	if user.Role != auth.RoleReseller {
		return scope, nil
	}
	err := s.db.QueryRowContext(ctx, `SELECT id FROM reseller_accounts WHERE login_user_id=$1 AND status='active'`, user.ID).Scan(&scope.ResellerID)
	if errors.Is(err, sql.ErrNoRows) {
		return types.ProviderScope{}, ErrNoActiveSubscription
	}
	return scope, err
}

func (s *SQLStore) ListResellers(ctx context.Context) ([]types.Reseller, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT r.id,r.login_user_id,r.email,r.display_name,r.company,r.status,r.notes,
COALESCE(p.name,''),r.created_at,r.updated_at FROM reseller_accounts r
LEFT JOIN reseller_subscriptions rs ON rs.reseller_id=r.id AND rs.status='active'
LEFT JOIN reseller_plans p ON p.id=rs.reseller_plan_id ORDER BY r.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Reseller
	for rows.Next() {
		var item types.Reseller
		if err := rows.Scan(&item.ID, &item.LoginUserID, &item.Email, &item.DisplayName, &item.Company, &item.Status, &item.Notes, &item.PlanName, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListResellerPlans(ctx context.Context) ([]types.ResellerPlan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,description,max_customers,max_subscriptions,disk_mb,max_sites,max_subdomains,max_domain_aliases,max_databases,
bandwidth_mb,max_mailboxes,max_ftp_accounts,max_backups,backup_storage_mb,allow_custom_plans,allow_ssh,allow_dns,allow_tls,allow_backups,allow_php_settings,is_active,created_at,updated_at
FROM reseller_plans ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.ResellerPlan
	for rows.Next() {
		var p types.ResellerPlan
		if err := scanResellerPlan(rows, &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

type resellerPlanScanner interface {
	Scan(dest ...any) error
}

func scanResellerPlan(row resellerPlanScanner, p *types.ResellerPlan) error {
	return row.Scan(&p.ID, &p.Name, &p.Description, &p.MaxCustomers, &p.MaxSubscriptions, &p.DiskMB,
		&p.MaxSites, &p.MaxSubdomains, &p.MaxDomainAliases, &p.MaxDatabases, &p.BandwidthMB,
		&p.MaxMailboxes, &p.MaxFTPAccounts, &p.MaxBackups, &p.BackupStorageMB, &p.AllowCustomPlans,
		&p.AllowSSH, &p.AllowDNS, &p.AllowTLS, &p.AllowBackups, &p.AllowPHPSettings, &p.IsActive,
		&p.CreatedAt, &p.UpdatedAt)
}

func (s *SQLStore) ListResellerPlansForUser(ctx context.Context, userID int64) ([]types.ResellerPlan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT p.id,p.name,p.description,p.max_customers,p.max_subscriptions,p.disk_mb,p.max_sites,p.max_subdomains,p.max_domain_aliases,p.max_databases,p.bandwidth_mb,p.max_mailboxes,p.max_ftp_accounts,p.max_backups,p.backup_storage_mb,p.allow_custom_plans,p.allow_ssh,p.allow_dns,p.allow_tls,p.allow_backups,p.allow_php_settings,p.is_active,p.created_at,p.updated_at FROM reseller_accounts r JOIN reseller_subscriptions rs ON rs.reseller_id=r.id AND rs.status='active' JOIN reseller_plans p ON p.id=rs.reseller_plan_id WHERE r.login_user_id=$1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.ResellerPlan
	for rows.Next() {
		var p types.ResellerPlan
		if err := scanResellerPlan(rows, &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListResellersForUser(ctx context.Context, userID int64) ([]types.Reseller, error) {
	items, err := s.ListResellers(ctx)
	if err != nil {
		return nil, err
	}
	var out []types.Reseller
	for _, item := range items {
		if item.LoginUserID == userID {
			out = append(out, item)
		}
	}
	return out, nil
}

func (s *SQLStore) UpsertResellerPlan(ctx context.Context, p types.ResellerPlan) (types.ResellerPlan, error) {
	if strings.TrimSpace(p.Name) == "" {
		return types.ResellerPlan{}, errors.New("reseller plan name is required")
	}
	for _, v := range []int{p.MaxCustomers, p.MaxSubscriptions, p.DiskMB, p.MaxSites, p.MaxSubdomains, p.MaxDomainAliases, p.MaxDatabases, p.BandwidthMB, p.MaxMailboxes, p.MaxFTPAccounts, p.MaxBackups, p.BackupStorageMB} {
		if v < -1 {
			return types.ResellerPlan{}, errors.New("reseller plan limits cannot be less than -1")
		}
	}
	rowQuery := `INSERT INTO reseller_plans (name,description,max_customers,max_subscriptions,disk_mb,max_sites,max_subdomains,max_domain_aliases,max_databases,bandwidth_mb,max_mailboxes,max_ftp_accounts,max_backups,backup_storage_mb,allow_custom_plans,allow_ssh,allow_dns,allow_tls,allow_backups,allow_php_settings,is_active)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
RETURNING id,name,description,max_customers,max_subscriptions,disk_mb,max_sites,max_subdomains,max_domain_aliases,max_databases,bandwidth_mb,max_mailboxes,max_ftp_accounts,max_backups,backup_storage_mb,allow_custom_plans,allow_ssh,allow_dns,allow_tls,allow_backups,allow_php_settings,is_active,created_at,updated_at`
	args := []any{strings.TrimSpace(p.Name), strings.TrimSpace(p.Description), p.MaxCustomers, p.MaxSubscriptions, p.DiskMB, p.MaxSites, p.MaxSubdomains, p.MaxDomainAliases, p.MaxDatabases, p.BandwidthMB, p.MaxMailboxes, p.MaxFTPAccounts, p.MaxBackups, p.BackupStorageMB, p.AllowCustomPlans, p.AllowSSH, p.AllowDNS, p.AllowTLS, p.AllowBackups, p.AllowPHPSettings, p.IsActive}
	if p.ID > 0 {
		rowQuery = `UPDATE reseller_plans SET name=$2,description=$3,max_customers=$4,max_subscriptions=$5,disk_mb=$6,max_sites=$7,max_subdomains=$8,max_domain_aliases=$9,max_databases=$10,bandwidth_mb=$11,max_mailboxes=$12,max_ftp_accounts=$13,max_backups=$14,backup_storage_mb=$15,allow_custom_plans=$16,allow_ssh=$17,allow_dns=$18,allow_tls=$19,allow_backups=$20,allow_php_settings=$21,is_active=$22,updated_at=now() WHERE id=$1 RETURNING id,name,description,max_customers,max_subscriptions,disk_mb,max_sites,max_subdomains,max_domain_aliases,max_databases,bandwidth_mb,max_mailboxes,max_ftp_accounts,max_backups,backup_storage_mb,allow_custom_plans,allow_ssh,allow_dns,allow_tls,allow_backups,allow_php_settings,is_active,created_at,updated_at`
		args = append([]any{p.ID}, args...)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return types.ResellerPlan{}, err
	}
	defer tx.Rollback()
	var saved types.ResellerPlan
	if err = scanResellerPlan(tx.QueryRowContext(ctx, rowQuery, args...), &saved); err != nil {
		return types.ResellerPlan{}, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT reseller_id FROM reseller_subscriptions WHERE reseller_plan_id=$1 AND status='active' ORDER BY reseller_id`, saved.ID)
	if err != nil {
		return types.ResellerPlan{}, err
	}
	var resellerIDs []int64
	for rows.Next() {
		var resellerID int64
		if err = rows.Scan(&resellerID); err != nil {
			rows.Close()
			return types.ResellerPlan{}, err
		}
		resellerIDs = append(resellerIDs, resellerID)
	}
	if err = rows.Close(); err != nil {
		return types.ResellerPlan{}, err
	}
	for _, resellerID := range resellerIDs {
		if err = validateResellerCapacityTx(ctx, tx, resellerID, 0, types.SubscriptionEntitlements{}); err != nil {
			return types.ResellerPlan{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return types.ResellerPlan{}, err
	}
	return saved, nil
}

func (s *SQLStore) CreateReseller(ctx context.Context, req types.CreateCustomerReq, resellerPlanID int64) (types.Reseller, error) {
	if resellerPlanID <= 0 {
		return types.Reseller{}, errors.New("reseller plan id is required")
	}
	if strings.TrimSpace(req.Password) == "" {
		return types.Reseller{}, errors.New("reseller password is required")
	}
	email := normalizeEmail(req.Email)
	if email == "" {
		return types.Reseller{}, errors.New("reseller email is required")
	}
	hash, err := auth.HashPassword(req.Password, auth.DefaultPasswordParams)
	if err != nil {
		return types.Reseller{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return types.Reseller{}, err
	}
	defer tx.Rollback()
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT is_active FROM reseller_plans WHERE id=$1 FOR UPDATE`, resellerPlanID).Scan(&active); err != nil {
		return types.Reseller{}, err
	}
	if !active {
		return types.Reseller{}, errors.New("reseller plan is inactive")
	}
	var userID int64
	err = tx.QueryRowContext(ctx, `INSERT INTO users (email,password_hash,role) VALUES ($1,$2,'reseller') RETURNING id`, email, hash).Scan(&userID)
	if err != nil {
		return types.Reseller{}, err
	}
	display := strings.TrimSpace(req.DisplayName)
	if display == "" {
		display = email
	}
	var out types.Reseller
	err = tx.QueryRowContext(ctx, `INSERT INTO reseller_accounts (login_user_id,email,display_name,company,notes) VALUES ($1,$2,$3,$4,$5) RETURNING id,login_user_id,email,display_name,company,status,notes,created_at,updated_at`, userID, email, display, strings.TrimSpace(req.Company), strings.TrimSpace(req.Notes)).Scan(&out.ID, &out.LoginUserID, &out.Email, &out.DisplayName, &out.Company, &out.Status, &out.Notes, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		return types.Reseller{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO reseller_subscriptions (reseller_id,reseller_plan_id,status) VALUES ($1,$2,'active')`, out.ID, resellerPlanID); err != nil {
		return types.Reseller{}, err
	}
	err = tx.Commit()
	return out, err
}

func (s *SQLStore) SetResellerStatus(ctx context.Context, resellerID int64, status string) error {
	return s.SetResellerStatuses(ctx, []int64{resellerID}, status)
}

func (s *SQLStore) SetResellerStatuses(ctx context.Context, resellerIDs []int64, status string) error {
	if status != "active" && status != "suspended" {
		return fmt.Errorf("unsupported reseller status %q", status)
	}
	if len(resellerIDs) == 0 {
		return errors.New("at least one reseller id is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, resellerID := range resellerIDs {
		if resellerID <= 0 {
			return errors.New("reseller id is required")
		}
		res, execErr := tx.ExecContext(ctx, `UPDATE reseller_accounts SET status=$2,updated_at=now() WHERE id=$1`, resellerID, status)
		if execErr != nil {
			return execErr
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
		if status == "active" {
			if err = validateResellerSubscriptionsTx(ctx, tx, resellerID); err != nil {
				return err
			}
			if err = validateResellerCapacityTx(ctx, tx, resellerID, 0, types.SubscriptionEntitlements{}); err != nil {
				return err
			}
		}
		if err = s.enqueueResellerHostingStateTx(ctx, tx, resellerID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLStore) TransferCustomer(ctx context.Context, customerID, resellerID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if resellerID > 0 {
		if err := ensureResellerActiveTx(ctx, tx, resellerID); err != nil {
			return err
		}
	}
	res, err := tx.ExecContext(ctx, `UPDATE customers SET reseller_id=$2,updated_at=now() WHERE id=$1`, customerID, nullableInt64(resellerID))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	// Plans can be shared by several customers. A provider move therefore locks
	// every plan-backed snapshot, including suspended subscriptions, instead of
	// leaving future synchronization attached to the previous provider.
	_, err = tx.ExecContext(ctx, `UPDATE subscriptions SET sync_mode='locked',sync_status='in_sync',sync_error='',updated_at=now() WHERE customer_id=$1 AND sync_mode<>'custom'`, customerID)
	if err != nil {
		return err
	}
	if resellerID > 0 {
		if err := validateCustomerSubscriptionsForTransferTx(ctx, tx, customerID, resellerID); err != nil {
			return err
		}
		if err := validateResellerCapacityTx(ctx, tx, resellerID, 0, types.SubscriptionEntitlements{}); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func validateCustomerSubscriptionsForTransferTx(ctx context.Context, tx *sql.Tx, customerID, resellerID int64) error {
	rows, err := tx.QueryContext(ctx, `SELECT s.id,s.sync_mode FROM subscriptions s WHERE s.customer_id=$1 ORDER BY s.id FOR UPDATE`, customerID)
	if err != nil {
		return err
	}
	type subscriptionMode struct {
		id   int64
		mode string
	}
	var subscriptions []subscriptionMode
	for rows.Next() {
		var item subscriptionMode
		if err := rows.Scan(&item.id, &item.mode); err != nil {
			rows.Close()
			return err
		}
		subscriptions = append(subscriptions, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range subscriptions {
		entitlements, err := readSubscriptionEntitlementsTx(ctx, tx, item.id)
		if err != nil {
			return err
		}
		if item.mode == "custom" {
			err = validateCustomWithinResellerTx(ctx, tx, resellerID, entitlements)
		} else {
			err = validateEntitlementsWithinResellerTx(ctx, tx, resellerID, entitlements)
		}
		if err != nil {
			return fmt.Errorf("subscription %d cannot be transferred: %w", item.id, err)
		}
	}
	return nil
}

func validateResellerSubscriptionsTx(ctx context.Context, tx *sql.Tx, resellerID int64) error {
	rows, err := tx.QueryContext(ctx, `SELECT s.id,s.sync_mode FROM subscriptions s JOIN customers c ON c.id=s.customer_id WHERE c.reseller_id=$1 ORDER BY s.id FOR UPDATE OF s`, resellerID)
	if err != nil {
		return err
	}
	var ids []int64
	var modes []string
	for rows.Next() {
		var id int64
		var mode string
		if err := rows.Scan(&id, &mode); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
		modes = append(modes, mode)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for i, id := range ids {
		entitlements, err := readSubscriptionEntitlementsTx(ctx, tx, id)
		if err != nil {
			return err
		}
		if modes[i] == "custom" {
			err = validateCustomWithinResellerTx(ctx, tx, resellerID, entitlements)
		} else {
			err = validateEntitlementsWithinResellerTx(ctx, tx, resellerID, entitlements)
		}
		if err != nil {
			return fmt.Errorf("subscription %d exceeds reseller allocation: %w", id, err)
		}
	}
	return nil
}

func validateResellerCapacityTx(ctx context.Context, tx *sql.Tx, resellerID, excludeSubscriptionID int64, candidate types.SubscriptionEntitlements) error {
	var limits types.ResellerPlan
	err := tx.QueryRowContext(ctx, `SELECT p.max_customers,p.max_subscriptions,p.disk_mb,p.max_sites,p.max_subdomains,p.max_domain_aliases,p.max_databases,p.bandwidth_mb,p.max_mailboxes,p.max_ftp_accounts,p.max_backups,p.backup_storage_mb,p.allow_custom_plans,p.allow_ssh,p.allow_dns,p.allow_tls,p.allow_backups,p.allow_php_settings
FROM reseller_accounts r JOIN reseller_subscriptions rs ON rs.reseller_id=r.id AND rs.status='active' JOIN reseller_plans p ON p.id=rs.reseller_plan_id WHERE r.id=$1 FOR UPDATE OF r,rs,p`, resellerID).Scan(&limits.MaxCustomers, &limits.MaxSubscriptions, &limits.DiskMB, &limits.MaxSites, &limits.MaxSubdomains, &limits.MaxDomainAliases, &limits.MaxDatabases, &limits.BandwidthMB, &limits.MaxMailboxes, &limits.MaxFTPAccounts, &limits.MaxBackups, &limits.BackupStorageMB, &limits.AllowCustomPlans, &limits.AllowSSH, &limits.AllowDNS, &limits.AllowTLS, &limits.AllowBackups, &limits.AllowPHPSettings)
	if err != nil {
		return err
	}
	var customers, subs, disk, sites, subdomains, aliases, dbs, traffic, mail, ftp, backups, backupMB int
	var unlimitedDisk, unlimitedSites, unlimitedSubdomains, unlimitedAliases, unlimitedDB, unlimitedTraffic, unlimitedMail, unlimitedFTP, unlimitedBackups, unlimitedBackupMB bool
	err = tx.QueryRowContext(ctx, `SELECT COUNT(DISTINCT c.id)::int,COUNT(DISTINCT s.id)::int,
COALESCE(SUM(CASE WHEN e.disk_mb>=0 THEN e.disk_mb ELSE 0 END),0)::int,COALESCE(BOOL_OR(e.disk_mb<0),false),
COALESCE(SUM(CASE WHEN e.max_sites>=0 THEN e.max_sites ELSE 0 END),0)::int,COALESCE(BOOL_OR(e.max_sites<0),false),
COALESCE(SUM(CASE WHEN e.max_subdomains>=0 THEN e.max_subdomains ELSE 0 END),0)::int,COALESCE(BOOL_OR(e.max_subdomains<0),false),
COALESCE(SUM(CASE WHEN e.max_domain_aliases>=0 THEN e.max_domain_aliases ELSE 0 END),0)::int,COALESCE(BOOL_OR(e.max_domain_aliases<0),false),
COALESCE(SUM(CASE WHEN e.max_databases>=0 THEN e.max_databases ELSE 0 END),0)::int,COALESCE(BOOL_OR(e.max_databases<0),false),
COALESCE(SUM(CASE WHEN e.bandwidth_mb>=0 THEN e.bandwidth_mb ELSE 0 END),0)::int,COALESCE(BOOL_OR(e.bandwidth_mb<0),false),
COALESCE(SUM(CASE WHEN e.max_mailboxes>=0 THEN e.max_mailboxes ELSE 0 END),0)::int,COALESCE(BOOL_OR(e.max_mailboxes<0),false),
COALESCE(SUM(CASE WHEN e.max_ftp_accounts>=0 THEN e.max_ftp_accounts ELSE 0 END),0)::int,COALESCE(BOOL_OR(e.max_ftp_accounts<0),false),
COALESCE(SUM(CASE WHEN e.max_backups>=0 THEN e.max_backups ELSE 0 END),0)::int,COALESCE(BOOL_OR(e.max_backups<0),false),
COALESCE(SUM(CASE WHEN e.backup_storage_mb>=0 THEN e.backup_storage_mb ELSE 0 END),0)::int,COALESCE(BOOL_OR(e.backup_storage_mb<0),false)
FROM customers c LEFT JOIN subscriptions s ON s.customer_id=c.id AND s.status='active' AND ($2::bigint=0 OR s.id<>$2) LEFT JOIN subscription_entitlements e ON e.subscription_id=s.id WHERE c.reseller_id=$1`, resellerID, excludeSubscriptionID).Scan(&customers, &subs, &disk, &unlimitedDisk, &sites, &unlimitedSites, &subdomains, &unlimitedSubdomains, &aliases, &unlimitedAliases, &dbs, &unlimitedDB, &traffic, &unlimitedTraffic, &mail, &unlimitedMail, &ftp, &unlimitedFTP, &backups, &unlimitedBackups, &backupMB, &unlimitedBackupMB)
	if err != nil {
		return err
	}
	checks := []struct {
		name             string
		used, add, limit int
		unlimited        bool
	}{{"customers", customers, 0, limits.MaxCustomers, false}, {"subscriptions", subs, boolInt(candidate.PlanName != ""), limits.MaxSubscriptions, false}, {"disk", disk, candidate.DiskMB, limits.DiskMB, unlimitedDisk}, {"sites", sites, candidate.MaxSites, limits.MaxSites, unlimitedSites}, {"subdomains", subdomains, candidate.MaxSubdomains, limits.MaxSubdomains, unlimitedSubdomains}, {"domain aliases", aliases, candidate.MaxDomainAliases, limits.MaxDomainAliases, unlimitedAliases}, {"databases", dbs, candidate.MaxDatabases, limits.MaxDatabases, unlimitedDB}, {"traffic", traffic, candidate.BandwidthMB, limits.BandwidthMB, unlimitedTraffic}, {"mailboxes", mail, candidate.MaxMailboxes, limits.MaxMailboxes, unlimitedMail}, {"FTP accounts", ftp, candidate.MaxFTPAccounts, limits.MaxFTPAccounts, unlimitedFTP}, {"backups", backups, candidate.MaxBackups, limits.MaxBackups, unlimitedBackups}, {"backup storage", backupMB, candidate.BackupStorageMB, limits.BackupStorageMB, unlimitedBackupMB}}
	for _, c := range checks {
		if c.limit < 0 {
			continue
		}
		if c.unlimited || c.add < 0 || c.used+c.add > c.limit {
			return fmt.Errorf("%w: %s allocation exceeds %d", ErrResellerCapacity, c.name, c.limit)
		}
	}
	return nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (s *SQLStore) ListAddonPlans(ctx context.Context) ([]types.AddonPlan, error) {
	rows, err := s.db.QueryContext(ctx, addonPlanSelect+` ORDER BY a.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.AddonPlan
	for rows.Next() {
		item, err := scanAddonPlan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListAddonPlansForUser(ctx context.Context, userID int64) ([]types.AddonPlan, error) {
	rows, err := s.db.QueryContext(ctx, addonPlanSelect+` WHERE a.reseller_id=(SELECT id FROM reseller_accounts WHERE login_user_id=$1) ORDER BY a.id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.AddonPlan
	for rows.Next() {
		a, err := scanAddonPlan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertAddonPlan(ctx context.Context, addon types.AddonPlan) (types.AddonPlan, error) {
	if strings.TrimSpace(addon.Name) == "" {
		return types.AddonPlan{}, errors.New("add-on name is required")
	}
	if err := ValidateEntitlements(addon.Entitlements); err != nil {
		return types.AddonPlan{}, err
	}
	e := addon.Entitlements
	presets, err := json.Marshal(e.ServicePresets)
	if err != nil {
		return types.AddonPlan{}, err
	}
	query := `INSERT INTO addon_plans (reseller_id,name,description,disk_mb,max_sites,max_databases,bandwidth_mb,max_mailboxes,backup_retention_days,php_allowlist,php_fpm_max_children,php_memory_mb,site_disk_quota_mb,max_backups,backup_storage_mb,allow_ssh,allow_dns,is_active,max_subdomains,max_domain_aliases,max_ftp_accounts,allow_tls,allow_backups,allow_php_settings,service_presets)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25) RETURNING id`
	args := []any{nullableInt64(addon.ResellerID), strings.TrimSpace(addon.Name), strings.TrimSpace(addon.Description), e.DiskMB, e.MaxSites, e.MaxDatabases, e.BandwidthMB, e.MaxMailboxes, e.BackupRetentionDays, e.PHPAllowlist, e.PHPFPMMaxChildren, e.PHPMemoryMB, e.SiteDiskQuotaMB, e.MaxBackups, e.BackupStorageMB, e.AllowSSH, e.AllowDNS, addon.IsActive, e.MaxSubdomains, e.MaxDomainAliases, e.MaxFTPAccounts, e.AllowTLS, e.AllowBackups, e.AllowPHPSettings, presets}
	var id int64
	if addon.ID > 0 {
		query = `UPDATE addon_plans SET name=$3,description=$4,disk_mb=$5,max_sites=$6,max_databases=$7,bandwidth_mb=$8,max_mailboxes=$9,backup_retention_days=$10,php_allowlist=$11,php_fpm_max_children=$12,php_memory_mb=$13,site_disk_quota_mb=$14,max_backups=$15,backup_storage_mb=$16,allow_ssh=$17,allow_dns=$18,is_active=$19,max_subdomains=$20,max_domain_aliases=$21,max_ftp_accounts=$22,allow_tls=$23,allow_backups=$24,allow_php_settings=$25,service_presets=$26,revision=revision+1,updated_at=now() WHERE id=$1 AND reseller_id IS NOT DISTINCT FROM $2 RETURNING id`
		args = append([]any{addon.ID}, args...)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return types.AddonPlan{}, err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, query, args...).Scan(&id); err != nil {
		return types.AddonPlan{}, err
	}
	if addon.ID > 0 {
		if s.river != nil {
			if err = preflightAddonSyncTx(ctx, tx, id); err != nil {
				return types.AddonPlan{}, err
			}
			if _, err = tx.ExecContext(ctx, `UPDATE subscriptions s SET sync_status='pending',sync_error='',updated_at=now() FROM subscription_addons sa WHERE sa.subscription_id=s.id AND sa.addon_plan_id=$1 AND s.sync_mode='synced'`, id); err != nil {
				return types.AddonPlan{}, err
			}
			if _, err = s.river.InsertTx(ctx, tx, SyncAddonArgs{AddonID: id}, nil); err != nil {
				return types.AddonPlan{}, fmt.Errorf("enqueue add-on synchronization: %w", err)
			}
		} else {
			if err = syncAddonSubscriptionsTx(ctx, tx, id); err != nil {
				return types.AddonPlan{}, err
			}
			if err = enforceCommittedAllocationCapTx(ctx, tx); err != nil {
				return types.AddonPlan{}, err
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return types.AddonPlan{}, err
	}
	return s.getAddonPlan(ctx, id)
}

func preflightAddonSyncTx(ctx context.Context, tx *sql.Tx, addonID int64) error {
	if _, err := tx.ExecContext(ctx, `SAVEPOINT addon_sync_preflight`); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT s.id FROM subscriptions s JOIN subscription_addons sa ON sa.subscription_id=s.id WHERE sa.addon_plan_id=$1 AND s.sync_mode='synced' ORDER BY s.id`, addonID)
	var ids []int64
	if err == nil {
		for rows.Next() {
			var id int64
			if err = rows.Scan(&id); err != nil {
				break
			}
			ids = append(ids, id)
		}
		if closeErr := rows.Close(); err == nil {
			err = closeErr
		}
	}
	if err == nil {
		for _, id := range ids {
			if err = syncSubscriptionTx(ctx, tx, id, false); err != nil {
				break
			}
		}
	}
	if err == nil {
		err = enforceCommittedAllocationCapTx(ctx, tx)
	}
	if _, rollbackErr := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT addon_sync_preflight`); err == nil {
		err = rollbackErr
	}
	if _, releaseErr := tx.ExecContext(ctx, `RELEASE SAVEPOINT addon_sync_preflight`); err == nil {
		err = releaseErr
	}
	return err
}

func (s *SQLStore) getAddonPlan(ctx context.Context, id int64) (types.AddonPlan, error) {
	return scanAddonPlan(s.db.QueryRowContext(ctx, addonPlanSelect+` WHERE a.id=$1`, id))
}

const addonPlanSelect = `SELECT a.id,COALESCE(a.reseller_id,0),a.name,a.description,a.disk_mb,a.max_sites,a.max_databases,a.bandwidth_mb,a.max_mailboxes,a.backup_retention_days,a.php_allowlist,a.php_fpm_max_children,a.php_memory_mb,a.site_disk_quota_mb,a.max_backups,a.backup_storage_mb,a.allow_ssh,a.allow_dns,a.is_active,a.revision,a.max_subdomains,a.max_domain_aliases,a.max_ftp_accounts,a.allow_tls,a.allow_backups,a.allow_php_settings,a.service_presets FROM addon_plans a`

type addonScanner interface{ Scan(...any) error }

func scanAddonPlan(row addonScanner) (types.AddonPlan, error) {
	var a types.AddonPlan
	e := &a.Entitlements
	var presets []byte
	err := row.Scan(&a.ID, &a.ResellerID, &a.Name, &a.Description, &e.DiskMB, &e.MaxSites, &e.MaxDatabases, &e.BandwidthMB, &e.MaxMailboxes, &e.BackupRetentionDays, &e.PHPAllowlist, &e.PHPFPMMaxChildren, &e.PHPMemoryMB, &e.SiteDiskQuotaMB, &e.MaxBackups, &e.BackupStorageMB, &e.AllowSSH, &e.AllowDNS, &a.IsActive, &a.Revision, &e.MaxSubdomains, &e.MaxDomainAliases, &e.MaxFTPAccounts, &e.AllowTLS, &e.AllowBackups, &e.AllowPHPSettings, &presets)
	if err == nil {
		err = json.Unmarshal(presets, &e.ServicePresets)
	}
	return a, err
}

func (s *SQLStore) SetSubscriptionAddons(ctx context.Context, subscriptionID int64, addonIDs []int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var mode string
	var resellerID int64
	if err = tx.QueryRowContext(ctx, `SELECT s.sync_mode,COALESCE(c.reseller_id,0) FROM subscriptions s JOIN customers c ON c.id=s.customer_id WHERE s.id=$1 FOR UPDATE OF s,c`, subscriptionID).Scan(&mode, &resellerID); err != nil {
		return err
	}
	if mode == "custom" && len(addonIDs) > 0 {
		return errors.New("custom subscriptions cannot use add-ons")
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM subscription_addons WHERE subscription_id=$1`, subscriptionID); err != nil {
		return err
	}
	seen := make(map[int64]struct{}, len(addonIDs))
	for _, id := range addonIDs {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		result, insertErr := tx.ExecContext(ctx, `INSERT INTO subscription_addons (subscription_id,addon_plan_id) SELECT $1,a.id FROM addon_plans a WHERE a.id=$2 AND a.is_active AND COALESCE(a.reseller_id,0)=$3`, subscriptionID, id, resellerID)
		if insertErr != nil {
			return insertErr
		}
		affected, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return rowsErr
		}
		if affected != 1 {
			return errors.New("add-on is inactive, missing, or belongs to another provider")
		}
	}
	if mode == "custom" {
		return tx.Commit()
	}
	if err = syncSubscriptionTx(ctx, tx, subscriptionID, true); err != nil {
		return err
	}
	if err = enforceCommittedAllocationCapTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) SyncSubscription(ctx context.Context, subscriptionID int64) error {
	return s.syncSubscriptionSnapshot(ctx, subscriptionID, true)
}

func (s *SQLStore) syncSubscriptionSnapshot(ctx context.Context, subscriptionID int64, force bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = syncSubscriptionTx(ctx, tx, subscriptionID, force); err != nil {
		return err
	}
	if err = enforceCommittedAllocationCapTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func loadSubscriptionAddonsTx(ctx context.Context, tx *sql.Tx, subscriptionID int64) ([]types.AddonPlan, error) {
	rows, err := tx.QueryContext(ctx, addonPlanSelect+` JOIN subscription_addons sa ON sa.addon_plan_id=a.id WHERE sa.subscription_id=$1 ORDER BY a.id`, subscriptionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var addons []types.AddonPlan
	for rows.Next() {
		addon, scanErr := scanAddonPlan(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		addons = append(addons, addon)
	}
	return addons, rows.Err()
}

func (s *SQLStore) SyncPlan(ctx context.Context, planID int64) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM subscriptions WHERE plan_id=$1 AND sync_mode='synced' ORDER BY id`, planID)
	if err != nil {
		return err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	var firstErr error
	for _, id := range ids {
		if err := s.syncSubscriptionSnapshot(ctx, id, false); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			if _, markErr := s.db.ExecContext(ctx, `UPDATE subscriptions SET sync_status='out_of_sync',sync_error=$2,updated_at=now() WHERE id=$1`, id, err.Error()); markErr != nil {
				return markErr
			}
			if _, auditErr := s.db.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,customer_id,subscription_id,action,target_type,target_id,metadata)
SELECT u.id,s.customer_id,s.id,'plan.sync_failed','subscription',s.id,jsonb_build_object('plan_id',$2::bigint,'error',$3::text)
				FROM subscriptions s CROSS JOIN LATERAL (SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1) u WHERE s.id=$1`, id, planID, err.Error()); auditErr != nil {
				return auditErr
			}
			if notifyErr := recordSubscriptionNotification(ctx, s.db, id, "sync_failed", "critical", "Service plan synchronization failed", "Nakpanel retained the previous valid entitlement snapshot. "+truncateError(err), fmt.Sprintf("sync:plan:%d:subscription:%d", planID, id)); notifyErr != nil {
				return notifyErr
			}
		}
	}
	return firstErr
}

func (s *SQLStore) SyncAddon(ctx context.Context, addonID int64) error {
	rows, err := s.db.QueryContext(ctx, `SELECT s.id FROM subscriptions s JOIN subscription_addons sa ON sa.subscription_id=s.id WHERE sa.addon_plan_id=$1 AND s.sync_mode='synced' ORDER BY s.id`, addonID)
	if err != nil {
		return err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	var firstErr error
	for _, id := range ids {
		if err := s.syncSubscriptionSnapshot(ctx, id, false); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			if _, markErr := s.db.ExecContext(ctx, `UPDATE subscriptions SET sync_status='out_of_sync',sync_error=$2,updated_at=now() WHERE id=$1`, id, err.Error()); markErr != nil {
				return markErr
			}
			if _, auditErr := s.db.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,customer_id,subscription_id,action,target_type,target_id,metadata)
SELECT u.id,s.customer_id,s.id,'addon.sync_failed','subscription',s.id,jsonb_build_object('addon_id',$2::bigint,'error',$3::text)
FROM subscriptions s CROSS JOIN LATERAL (SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1) u WHERE s.id=$1`, id, addonID, err.Error()); auditErr != nil {
				return auditErr
			}
			if notifyErr := recordSubscriptionNotification(ctx, s.db, id, "sync_failed", "critical", "Add-on synchronization failed", "Nakpanel retained the previous valid entitlement snapshot. "+truncateError(err), fmt.Sprintf("sync:addon:%d:subscription:%d", addonID, id)); notifyErr != nil {
				return notifyErr
			}
		}
	}
	return firstErr
}

func (s *SQLStore) SetSubscriptionMode(ctx context.Context, subscriptionID int64, mode string, custom types.SubscriptionEntitlements) error {
	if mode != "synced" && mode != "locked" && mode != "custom" {
		return fmt.Errorf("unsupported sync mode %q", mode)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var resellerID int64
	var status string
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(c.reseller_id,0),s.status FROM subscriptions s JOIN customers c ON c.id=s.customer_id WHERE s.id=$1 FOR UPDATE OF s,c`, subscriptionID).Scan(&resellerID, &status); err != nil {
		return err
	}
	if mode == "custom" {
		if err = ValidateEntitlements(custom); err != nil {
			return err
		}
		if strings.TrimSpace(custom.PlanName) == "" {
			custom.PlanName = "Custom"
		}
		if resellerID > 0 {
			if err = validateCustomWithinResellerTx(ctx, tx, resellerID, custom); err != nil {
				return err
			}
			if status == "active" {
				if err = validateResellerCapacityTx(ctx, tx, resellerID, subscriptionID, custom); err != nil {
					return err
				}
			}
		}
		custom.SubscriptionID = subscriptionID
		if _, err = tx.ExecContext(ctx, `DELETE FROM subscription_addons WHERE subscription_id=$1`, subscriptionID); err != nil {
			return err
		}
		if err = writeSubscriptionEntitlementsTx(ctx, tx, custom); err != nil {
			return err
		}
		var result sql.Result
		result, err = tx.ExecContext(ctx, `UPDATE subscriptions SET plan_id=NULL,sync_mode='custom',sync_status='in_sync',sync_error='',updated_at=now() WHERE id=$1`, subscriptionID)
		if err == nil {
			if affected, rowsErr := result.RowsAffected(); rowsErr != nil {
				err = rowsErr
			} else if affected == 0 {
				err = sql.ErrNoRows
			}
		}
	} else {
		var result sql.Result
		result, err = tx.ExecContext(ctx, `UPDATE subscriptions SET sync_mode=$2,updated_at=now() WHERE id=$1 AND plan_id IS NOT NULL`, subscriptionID, mode)
		if err == nil {
			if affected, rowsErr := result.RowsAffected(); rowsErr != nil {
				err = rowsErr
			} else if affected == 0 {
				err = errors.New("custom subscription has no base plan")
			}
		}
		if err == nil && mode == "synced" {
			err = syncSubscriptionTx(ctx, tx, subscriptionID, true)
		}
	}
	if err != nil {
		return err
	}
	if err = enforceCommittedAllocationCapTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func syncPlanSubscriptionsTx(ctx context.Context, tx *sql.Tx, planID int64) error {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM subscriptions WHERE plan_id=$1 AND sync_mode='synced' ORDER BY id`, planID)
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
	if err = rows.Close(); err != nil {
		return err
	}
	for _, id := range ids {
		if err = syncSubscriptionTx(ctx, tx, id, false); err != nil {
			if _, markErr := tx.ExecContext(ctx, `UPDATE subscriptions SET sync_status='out_of_sync',sync_error=$2,updated_at=now() WHERE id=$1`, id, err.Error()); markErr != nil {
				return markErr
			}
			if _, notifyErr := upsertNotificationTx(ctx, tx, id, "sync_failed", "critical", "Service plan synchronization failed", "Nakpanel retained the previous valid entitlement snapshot. "+truncateError(err), fmt.Sprintf("sync:plan:%d:subscription:%d", planID, id)); notifyErr != nil {
				return notifyErr
			}
		}
	}
	return nil
}

func syncAddonSubscriptionsTx(ctx context.Context, tx *sql.Tx, addonID int64) error {
	rows, err := tx.QueryContext(ctx, `SELECT s.id FROM subscriptions s JOIN subscription_addons sa ON sa.subscription_id=s.id WHERE sa.addon_plan_id=$1 AND s.sync_mode='synced' ORDER BY s.id`, addonID)
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
	if err = rows.Close(); err != nil {
		return err
	}
	for _, id := range ids {
		if err = syncSubscriptionTx(ctx, tx, id, false); err != nil {
			if _, markErr := tx.ExecContext(ctx, `UPDATE subscriptions SET sync_status='out_of_sync',sync_error=$2,updated_at=now() WHERE id=$1`, id, err.Error()); markErr != nil {
				return markErr
			}
			if _, notifyErr := upsertNotificationTx(ctx, tx, id, "sync_failed", "critical", "Add-on synchronization failed", "Nakpanel retained the previous valid entitlement snapshot. "+truncateError(err), fmt.Sprintf("sync:addon:%d:subscription:%d", addonID, id)); notifyErr != nil {
				return notifyErr
			}
		}
	}
	return nil
}

func syncSubscriptionTx(ctx context.Context, tx *sql.Tx, subscriptionID int64, force bool) error {
	var planID, customerID, resellerID int64
	var mode, status string
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(s.plan_id,0),s.customer_id,COALESCE(c.reseller_id,0),s.sync_mode,s.status FROM subscriptions s JOIN customers c ON c.id=s.customer_id WHERE s.id=$1 FOR UPDATE OF s,c`, subscriptionID).Scan(&planID, &customerID, &resellerID, &mode, &status)
	if err != nil {
		return err
	}
	if planID <= 0 {
		return errors.New("custom subscription has no base plan")
	}
	if !force && mode != "synced" {
		return nil
	}
	plan, err := selectPlanForUpdateTx(ctx, tx, planID)
	if err != nil {
		return err
	}
	if plan.ResellerID != resellerID {
		return errors.New("plan and subscription must belong to the same provider")
	}
	addons, err := loadSubscriptionAddonsTx(ctx, tx, subscriptionID)
	if err != nil {
		return err
	}
	for _, addon := range addons {
		if addon.ResellerID != resellerID {
			return errors.New("add-on and subscription must belong to the same provider")
		}
	}
	e, err := ComposeEntitlements(entitlementsFromPlan(plan), addons)
	if err != nil {
		return err
	}
	e.SubscriptionID = subscriptionID
	if resellerID > 0 && status == "active" {
		if err = validateResellerCapacityTx(ctx, tx, resellerID, subscriptionID, e); err != nil {
			return err
		}
	}
	if err = writeSubscriptionEntitlementsTx(ctx, tx, e); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE subscription_system_accounts SET convergence_status='pending',last_error='',updated_at=now() WHERE subscription_id=$1`, subscriptionID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE subscriptions SET sync_status='in_sync',plan_revision=$2,sync_error='',updated_at=now() WHERE id=$1`, subscriptionID, plan.Revision)
	return err
}
