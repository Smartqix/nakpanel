package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"slices"
	"strings"

	"github.com/nakroteck/nakpanel/internal/types"
)

type Scope string

const (
	ScopeSubscription Scope = "subscription"
	ScopeSite         Scope = "site"
)

var siteSections = map[string]struct{}{
	"schema_version": {}, "permissions": {}, "web": {}, "php": {}, "mail": {}, "dns": {}, "applications": {}, "valkey": {},
}

var phpVersionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)
var nginxFileListRE = regexp.MustCompile(`^[A-Za-z0-9._-]+(?: [A-Za-z0-9._-]+)*$`)
var relativeWebPathRE = regexp.MustCompile(`^/?[A-Za-z0-9._/-]*$`)

// Resolve applies inheritance-aware JSON patches and returns a fully typed,
// validated policy. A JSON null means inherit, so it never erases the parent.
func Resolve(base types.HostingPolicy, subscriptionPatch, sitePatch []byte) (types.HostingPolicy, error) {
	base = Upgrade(base)
	if err := Validate(base); err != nil {
		return types.HostingPolicy{}, fmt.Errorf("base policy: %w", err)
	}
	resolved, err := apply(base, subscriptionPatch, ScopeSubscription)
	if err != nil {
		return types.HostingPolicy{}, fmt.Errorf("subscription policy: %w", err)
	}
	resolved, err = apply(resolved, sitePatch, ScopeSite)
	if err != nil {
		return types.HostingPolicy{}, fmt.Errorf("site policy: %w", err)
	}
	return resolved, nil
}

func apply(base types.HostingPolicy, patch []byte, scope Scope) (types.HostingPolicy, error) {
	if len(bytes.TrimSpace(patch)) == 0 || bytes.Equal(bytes.TrimSpace(patch), []byte("{}")) {
		return base, nil
	}
	var patchValue map[string]any
	if err := decodeStrict(patch, &patchValue); err != nil {
		return types.HostingPolicy{}, err
	}
	if scope == ScopeSite {
		for section := range patchValue {
			if _, ok := siteSections[section]; !ok {
				return types.HostingPolicy{}, fmt.Errorf("%q cannot be overridden for a site", section)
			}
		}
		if permissions, ok := patchValue["permissions"].(map[string]any); ok {
			for permission := range permissions {
				if permission != "cgi" && permission != "php_settings" {
					return types.HostingPolicy{}, fmt.Errorf("permission %q cannot be overridden for a site", permission)
				}
			}
		}
	}
	baseJSON, err := json.Marshal(base)
	if err != nil {
		return types.HostingPolicy{}, err
	}
	var baseValue map[string]any
	if err := json.Unmarshal(baseJSON, &baseValue); err != nil {
		return types.HostingPolicy{}, err
	}
	merge(baseValue, patchValue)
	merged, err := json.Marshal(baseValue)
	if err != nil {
		return types.HostingPolicy{}, err
	}
	var result types.HostingPolicy
	if err := decodeStrict(merged, &result); err != nil {
		return types.HostingPolicy{}, err
	}
	if err := Validate(result); err != nil {
		return types.HostingPolicy{}, err
	}
	return result, nil
}

func merge(dst, patch map[string]any) {
	for key, value := range patch {
		if value == nil {
			continue
		}
		child, object := value.(map[string]any)
		if !object {
			dst[key] = value
			continue
		}
		current, ok := dst[key].(map[string]any)
		if !ok {
			current = make(map[string]any)
			dst[key] = current
		}
		merge(current, child)
	}
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("policy must contain one JSON value")
	}
	return nil
}

func Validate(p types.HostingPolicy) error {
	if p.SchemaVersion != 1 && p.SchemaVersion != 2 && p.SchemaVersion != 3 {
		return fmt.Errorf("unsupported schema version %d", p.SchemaVersion)
	}
	limits := map[string]int{
		"disk_mb": p.Resources.DiskMB, "traffic_mb": p.Resources.TrafficMB,
		"cpu_percent": p.Resources.CPUPercent, "memory_mb": p.Resources.MemoryMB,
		"io_read_mbps": p.Resources.IOReadMBPS, "io_write_mbps": p.Resources.IOWriteMBPS,
		"max_tasks": p.Resources.MaxTasks, "max_sites": p.Resources.MaxSites,
		"max_databases": p.Resources.MaxDatabases, "max_database_users": p.Resources.MaxDatabaseUsers,
		"max_mailboxes": p.Resources.MaxMailboxes, "max_mail_aliases": p.Resources.MaxMailAliases,
		"max_sftp_identities": p.Resources.MaxSFTPIdentities, "max_scheduled_tasks": p.Resources.MaxScheduledTasks,
		"max_backups": p.Resources.MaxBackups, "backup_storage_mb": p.Resources.BackupStorageMB,
		"max_applications": p.Resources.MaxApplications, "container_storage_mb": p.Resources.ContainerStorageMB,
		"max_ftp_accounts": p.Resources.MaxFTPAccounts, "valkey_memory_mb": p.Resources.ValkeyMemoryMB,
		"max_php_workers": p.Resources.MaxPHPWorkers, "max_php_releases": p.Resources.MaxPHPReleases,
		"fpm_max_children": p.PHP.FPMMaxChildren, "fpm_max_requests": p.PHP.FPMMaxRequests,
		"php_memory_limit_mb": p.PHP.MemoryLimitMB, "mailbox_quota_mb": p.Mail.MailboxQuotaMB,
		"backup_retention_days": p.Backups.RetentionDays, "opcache_memory_mb": p.PHP.OPcacheMemoryMB,
		"valkey_policy_memory_mb": p.Valkey.MemoryMB,
	}
	for name, value := range limits {
		if value < -1 {
			return fmt.Errorf("%s cannot be less than -1", name)
		}
	}
	for name, value := range map[string]int{
		"request_rate_per_second": p.Web.RequestRatePerSecond, "request_burst": p.Web.RequestBurst,
		"max_connections": p.Web.MaxConnections, "max_execution_seconds": p.PHP.MaxExecutionSeconds,
		"max_input_seconds": p.PHP.MaxInputSeconds, "post_max_mb": p.PHP.PostMaxMB,
		"upload_max_mb": p.PHP.UploadMaxMB, "dns_default_ttl": p.DNS.DefaultTTL,
		"ssh_idle_timeout_minutes": p.Access.SSHIdleTimeoutMins,
		"request_body_limit_mb":    p.Web.RequestBodyLimitMB, "cache_ttl_seconds": p.Web.CacheTTLSeconds,
		"rate_limit_per_second": p.Web.RateLimitPerSecond, "rate_limit_burst": p.Web.RateLimitBurst,
		"connect_timeout_seconds": p.Web.ConnectTimeoutSecs, "read_timeout_seconds": p.Web.ReadTimeoutSecs,
		"fpm_idle_timeout_seconds":          p.PHP.FPMIdleTimeoutSecs,
		"request_terminate_timeout_seconds": p.PHP.RequestTerminateSecs,
		"valkey_max_clients":                p.Valkey.MaxClients, "valkey_idle_timeout_seconds": p.Valkey.IdleTimeoutSeconds,
		"valkey_cpu_percent": p.Valkey.CPUPercent, "valkey_process_limit": p.Valkey.ProcessLimit,
	} {
		if value < 0 {
			return fmt.Errorf("%s cannot be negative", name)
		}
	}
	if p.PHP.DefaultVersion != "" && !slices.Contains(p.PHP.AllowedVersions, p.PHP.DefaultVersion) {
		return errors.New("default PHP version must be allowed")
	}
	for _, version := range p.PHP.AllowedVersions {
		if !phpVersionRE.MatchString(version) {
			return fmt.Errorf("unsupported PHP version %q", version)
		}
	}
	if p.PHP.FPMMode != "" && p.PHP.FPMMode != "ondemand" && p.PHP.FPMMode != "dynamic" && p.PHP.FPMMode != "static" {
		return fmt.Errorf("unsupported PHP-FPM mode %q", p.PHP.FPMMode)
	}
	if p.Web.SecurityHeaderPreset != "" && p.Web.SecurityHeaderPreset != "off" && p.Web.SecurityHeaderPreset != "balanced" && p.Web.SecurityHeaderPreset != "strict" {
		return fmt.Errorf("unsupported security header preset %q", p.Web.SecurityHeaderPreset)
	}
	for _, cidr := range p.Web.AllowedCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid access CIDR %q", cidr)
		}
	}
	if p.Web.IndexFiles != "" && !nginxFileListRE.MatchString(p.Web.IndexFiles) {
		return errors.New("index files must be a space-separated filename list")
	}
	for _, candidate := range []string{p.Web.ErrorDocument404, p.Web.ErrorDocument50X} {
		if candidate != "" && (!relativeWebPathRE.MatchString(candidate) || strings.Contains(candidate, "..")) {
			return fmt.Errorf("invalid custom error document %q", candidate)
		}
	}
	if p.Valkey.EvictionPolicy != "" && p.Valkey.EvictionPolicy != "allkeys-lru" && p.Valkey.EvictionPolicy != "allkeys-lfu" && p.Valkey.EvictionPolicy != "volatile-lru" {
		return fmt.Errorf("unsupported Valkey eviction policy %q", p.Valkey.EvictionPolicy)
	}
	if p.Mail.DMARCPolicy != "" && p.Mail.DMARCPolicy != "none" && p.Mail.DMARCPolicy != "quarantine" && p.Mail.DMARCPolicy != "reject" {
		return fmt.Errorf("unsupported DMARC policy %q", p.Mail.DMARCPolicy)
	}
	if p.DNS.Mode != "" && p.DNS.Mode != "authoritative" && p.DNS.Mode != "external" {
		return fmt.Errorf("unsupported DNS mode %q", p.DNS.Mode)
	}
	if p.Access.ShellMode != "" && p.Access.ShellMode != "disabled" && p.Access.ShellMode != "sftp" && p.Access.ShellMode != "nspawn" {
		return fmt.Errorf("unsupported shell mode %q", p.Access.ShellMode)
	}
	for _, runtime := range p.Applications.AllowedRuntimes {
		if runtime != "php" && runtime != "python" && runtime != "node" && runtime != "oci" {
			return fmt.Errorf("unsupported application runtime %q", runtime)
		}
	}
	for _, registry := range p.Applications.AllowedRegistries {
		if strings.TrimSpace(registry) == "" || strings.ContainsAny(registry, "/ \\") {
			return fmt.Errorf("invalid registry %q", registry)
		}
	}
	return nil
}

// Upgrade preserves stored values while supplying versioned safe defaults.
// Stored snapshots remain readable and are not rewritten until an operator
// saves them. Phase 30 permissions and limits use their disabled zero values.
func Upgrade(p types.HostingPolicy) types.HostingPolicy {
	if p.SchemaVersion != 1 && p.SchemaVersion != 2 {
		return p
	}
	if p.SchemaVersion == 1 {
		if p.PHP.FPMMode == "" {
			p.PHP.FPMMode = "ondemand"
		}
		if p.PHP.FPMIdleTimeoutSecs == 0 {
			p.PHP.FPMIdleTimeoutSecs = 10
		}
		if p.PHP.RequestTerminateSecs == 0 {
			p.PHP.RequestTerminateSecs = p.PHP.MaxExecutionSeconds + 5
		}
		if p.Web.IndexFiles == "" {
			p.Web.IndexFiles = "index.php index.html"
		}
		if p.Web.RequestBodyLimitMB == 0 {
			p.Web.RequestBodyLimitMB = p.PHP.PostMaxMB
		}
		if p.Web.SecurityHeaderPreset == "" {
			p.Web.SecurityHeaderPreset = "balanced"
		}
		if p.Access.FTPSPassiveStart == 0 {
			p.Access.FTPSPassiveStart = 49152
		}
		if p.Access.FTPSPassiveEnd == 0 {
			p.Access.FTPSPassiveEnd = 49252
		}
		if p.Valkey.EvictionPolicy == "" {
			p.Valkey.EvictionPolicy = "allkeys-lru"
		}
	}
	p.SchemaVersion = 3
	return p
}

func DefaultFromEntitlements(e types.SubscriptionEntitlements) types.HostingPolicy {
	versions := make([]string, 0)
	for _, version := range strings.Split(e.PHPAllowlist, ",") {
		if version = strings.TrimSpace(version); version != "" {
			versions = append(versions, version)
		}
	}
	dnsMode := e.ServicePresets.DNS.Mode
	if dnsMode == "" || dnsMode == "primary" || dnsMode == "authoritative" {
		dnsMode = "authoritative"
	} else if dnsMode == "secondary" || dnsMode == "external" {
		dnsMode = "external"
	}
	return types.HostingPolicy{
		SchemaVersion: 3,
		Resources: types.HostingResourcePolicy{
			DiskMB: e.DiskMB, TrafficMB: e.BandwidthMB, MaxSites: e.MaxSites,
			MaxDatabases: e.MaxDatabases, MaxMailboxes: e.MaxMailboxes,
			MaxSFTPIdentities: e.MaxFTPAccounts, MaxBackups: e.MaxBackups,
			BackupStorageMB: e.BackupStorageMB,
		},
		Permissions: types.HostingPermissionPolicy{
			Hosting: e.HostingEnabled, SSH: e.AllowSSH, SFTP: e.MaxFTPAccounts != 0,
			DNS: e.AllowDNS, TLS: e.AllowTLS, Mail: e.MaxMailboxes != 0,
			Databases: e.MaxDatabases != 0, Backups: e.AllowBackups,
			PHPSettings: e.AllowPHPSettings,
		},
		Web: types.HostingWebPolicy{
			PreferredDomain: e.ServicePresets.Hosting.PreferredDomain,
			MaxConnections:  e.ServicePresets.Performance.MaxConnections,
			StaticCache:     e.ServicePresets.Performance.StaticFileCache,
		},
		PHP: types.HostingPHPPolicy{
			DefaultVersion: e.DefaultPHPVersion, AllowedVersions: versions,
			FPMMaxChildren: e.PHPFPMMaxChildren, FPMMaxRequests: e.ServicePresets.PHP.FPMMaxRequests,
			MemoryLimitMB: e.PHPMemoryMB, MaxExecutionSeconds: e.ServicePresets.PHP.MaxExecutionSeconds,
			MaxInputSeconds: e.ServicePresets.PHP.MaxInputSeconds, PostMaxMB: e.ServicePresets.PHP.PostMaxMB,
			UploadMaxMB: e.ServicePresets.PHP.UploadMaxMB, DisplayErrors: e.ServicePresets.PHP.DisplayErrors,
			LogErrors: e.ServicePresets.PHP.LogErrors, AllowURLFOpen: e.ServicePresets.PHP.AllowURLFOpen,
		},
		Mail: types.HostingMailPolicy{
			Enabled: e.MaxMailboxes != 0, DKIM: e.ServicePresets.Mail.DKIM,
			DMARCPolicy: e.ServicePresets.Mail.DMARCPolicy, SpamFilter: e.ServicePresets.Mail.SpamFilter,
			Webmail: e.ServicePresets.Mail.WebmailEnabled,
		},
		DNS:     types.HostingDNSPolicy{Enabled: e.AllowDNS, Mode: dnsMode, DefaultTTL: e.ServicePresets.DNS.DefaultTTL},
		Access:  types.HostingAccessPolicy{ShellMode: "disabled", SFTPOnly: true},
		Backups: types.HostingBackupPolicy{Enabled: e.AllowBackups, RetentionDays: e.BackupRetentionDays},
		Applications: types.HostingApplicationPolicy{
			CatalogEnabled:      e.ServicePresets.Applications.CatalogEnabled,
			AllowedCatalogSlugs: e.ServicePresets.Applications.Allowed, Rootless: true,
		},
		Valkey: types.HostingValkeyPolicy{EvictionPolicy: "allkeys-lru"},
	}
}

// ValidateWithin rejects a delegated policy that grants more than its
// provider ceiling. An unlimited ceiling (-1) accepts every finite value;
// an unlimited child requires an unlimited ceiling.
func ValidateWithin(child, ceiling types.HostingPolicy) error {
	childLimits := []int{
		child.Resources.DiskMB, child.Resources.TrafficMB, child.Resources.CPUPercent,
		child.Resources.MemoryMB, child.Resources.IOReadMBPS, child.Resources.IOWriteMBPS,
		child.Resources.MaxTasks, child.Resources.MaxSites, child.Resources.MaxDatabases,
		child.Resources.MaxDatabaseUsers, child.Resources.MaxMailboxes, child.Resources.MaxMailAliases,
		child.Resources.MaxSFTPIdentities, child.Resources.MaxScheduledTasks, child.Resources.MaxBackups,
		child.Resources.BackupStorageMB, child.Resources.MaxApplications, child.Resources.ContainerStorageMB,
		child.Resources.MaxFTPAccounts, child.Resources.ValkeyMemoryMB,
		child.Resources.MaxPHPWorkers, child.Resources.MaxPHPReleases,
	}
	ceilingLimits := []int{
		ceiling.Resources.DiskMB, ceiling.Resources.TrafficMB, ceiling.Resources.CPUPercent,
		ceiling.Resources.MemoryMB, ceiling.Resources.IOReadMBPS, ceiling.Resources.IOWriteMBPS,
		ceiling.Resources.MaxTasks, ceiling.Resources.MaxSites, ceiling.Resources.MaxDatabases,
		ceiling.Resources.MaxDatabaseUsers, ceiling.Resources.MaxMailboxes, ceiling.Resources.MaxMailAliases,
		ceiling.Resources.MaxSFTPIdentities, ceiling.Resources.MaxScheduledTasks, ceiling.Resources.MaxBackups,
		ceiling.Resources.BackupStorageMB, ceiling.Resources.MaxApplications, ceiling.Resources.ContainerStorageMB,
		ceiling.Resources.MaxFTPAccounts, ceiling.Resources.ValkeyMemoryMB,
		ceiling.Resources.MaxPHPWorkers, ceiling.Resources.MaxPHPReleases,
	}
	for i := range childLimits {
		if !limitWithin(childLimits[i], ceilingLimits[i]) {
			return fmt.Errorf("resource limit %d exceeds provider ceiling", i)
		}
	}
	childPermissions := []bool{
		child.Permissions.Hosting, child.Permissions.SSH, child.Permissions.SFTP,
		child.Permissions.ScheduledTasks, child.Permissions.DNS, child.Permissions.TLS,
		child.Permissions.Mail, child.Permissions.Databases, child.Permissions.Backups,
		child.Permissions.PHPSettings, child.Permissions.CGI, child.Permissions.Applications,
		child.Permissions.CustomOCIImages, child.Permissions.ApplicationEgress,
		child.Permissions.FTPS, child.Permissions.Logs, child.Permissions.Git,
		child.Permissions.Staging, child.Permissions.Valkey,
		child.Permissions.Composer, child.Permissions.ComposerCodeExecution,
		child.Permissions.ManagedPHPDeployments, child.Permissions.PHPWorkers,
	}
	ceilingPermissions := []bool{
		ceiling.Permissions.Hosting, ceiling.Permissions.SSH, ceiling.Permissions.SFTP,
		ceiling.Permissions.ScheduledTasks, ceiling.Permissions.DNS, ceiling.Permissions.TLS,
		ceiling.Permissions.Mail, ceiling.Permissions.Databases, ceiling.Permissions.Backups,
		ceiling.Permissions.PHPSettings, ceiling.Permissions.CGI, ceiling.Permissions.Applications,
		ceiling.Permissions.CustomOCIImages, ceiling.Permissions.ApplicationEgress,
		ceiling.Permissions.FTPS, ceiling.Permissions.Logs, ceiling.Permissions.Git,
		ceiling.Permissions.Staging, ceiling.Permissions.Valkey,
		ceiling.Permissions.Composer, ceiling.Permissions.ComposerCodeExecution,
		ceiling.Permissions.ManagedPHPDeployments, ceiling.Permissions.PHPWorkers,
	}
	for i := range childPermissions {
		if childPermissions[i] && !ceilingPermissions[i] {
			return fmt.Errorf("permission %d is not delegated by the provider", i)
		}
	}
	for _, limit := range []struct {
		name           string
		child, ceiling int
	}{
		{"request_rate_per_second", child.Web.RequestRatePerSecond, ceiling.Web.RequestRatePerSecond},
		{"request_burst", child.Web.RequestBurst, ceiling.Web.RequestBurst},
		{"max_connections", child.Web.MaxConnections, ceiling.Web.MaxConnections},
		{"request_body_limit_mb", child.Web.RequestBodyLimitMB, ceiling.Web.RequestBodyLimitMB},
		{"cache_ttl_seconds", child.Web.CacheTTLSeconds, ceiling.Web.CacheTTLSeconds},
		{"rate_limit_per_second", child.Web.RateLimitPerSecond, ceiling.Web.RateLimitPerSecond},
		{"rate_limit_burst", child.Web.RateLimitBurst, ceiling.Web.RateLimitBurst},
		{"connect_timeout_seconds", child.Web.ConnectTimeoutSecs, ceiling.Web.ConnectTimeoutSecs},
		{"read_timeout_seconds", child.Web.ReadTimeoutSecs, ceiling.Web.ReadTimeoutSecs},
		{"fpm_max_children", child.PHP.FPMMaxChildren, ceiling.PHP.FPMMaxChildren},
		{"fpm_max_requests", child.PHP.FPMMaxRequests, ceiling.PHP.FPMMaxRequests},
		{"php_memory_limit_mb", child.PHP.MemoryLimitMB, ceiling.PHP.MemoryLimitMB},
		{"max_execution_seconds", child.PHP.MaxExecutionSeconds, ceiling.PHP.MaxExecutionSeconds},
		{"max_input_seconds", child.PHP.MaxInputSeconds, ceiling.PHP.MaxInputSeconds},
		{"post_max_mb", child.PHP.PostMaxMB, ceiling.PHP.PostMaxMB},
		{"upload_max_mb", child.PHP.UploadMaxMB, ceiling.PHP.UploadMaxMB},
		{"fpm_idle_timeout_seconds", child.PHP.FPMIdleTimeoutSecs, ceiling.PHP.FPMIdleTimeoutSecs},
		{"request_terminate_timeout_seconds", child.PHP.RequestTerminateSecs, ceiling.PHP.RequestTerminateSecs},
		{"opcache_memory_mb", child.PHP.OPcacheMemoryMB, ceiling.PHP.OPcacheMemoryMB},
		{"mailbox_quota_mb", child.Mail.MailboxQuotaMB, ceiling.Mail.MailboxQuotaMB},
		{"valkey_memory_mb", child.Valkey.MemoryMB, ceiling.Valkey.MemoryMB},
		{"valkey_max_clients", child.Valkey.MaxClients, ceiling.Valkey.MaxClients},
		{"valkey_idle_timeout_seconds", child.Valkey.IdleTimeoutSeconds, ceiling.Valkey.IdleTimeoutSeconds},
		{"valkey_cpu_percent", child.Valkey.CPUPercent, ceiling.Valkey.CPUPercent},
		{"valkey_process_limit", child.Valkey.ProcessLimit, ceiling.Valkey.ProcessLimit},
	} {
		if !boundedSettingWithin(limit.child, limit.ceiling) {
			return fmt.Errorf("%s exceeds or removes the provider ceiling", limit.name)
		}
	}
	for _, flag := range []struct {
		name           string
		child, ceiling bool
	}{
		{"static cache", child.Web.StaticCache, ceiling.Web.StaticCache},
		{"FastCGI microcache", child.Web.FastCGIMicrocache, ceiling.Web.FastCGIMicrocache},
		{"compression", child.Web.Compression, ceiling.Web.Compression},
		{"PHP error display", child.PHP.DisplayErrors, ceiling.PHP.DisplayErrors},
		{"PHP error logging", child.PHP.LogErrors, ceiling.PHP.LogErrors},
		{"PHP URL fopen", child.PHP.AllowURLFOpen, ceiling.PHP.AllowURLFOpen},
		{"PHP process execution", child.PHP.ExecEnabled, ceiling.PHP.ExecEnabled},
		{"OPcache", child.PHP.OPcacheEnabled, ceiling.PHP.OPcacheEnabled},
		{"mail service", child.Mail.Enabled, ceiling.Mail.Enabled},
		{"mail DKIM", child.Mail.DKIM, ceiling.Mail.DKIM},
		{"mail webmail", child.Mail.Webmail, ceiling.Mail.Webmail},
		{"DNS service", child.DNS.Enabled, ceiling.DNS.Enabled},
		{"DNSSEC", child.DNS.DNSSEC, ceiling.DNS.DNSSEC},
		{"FTPS service", child.Access.FTPSEnabled, ceiling.Access.FTPSEnabled},
		{"application catalog", child.Applications.CatalogEnabled, ceiling.Applications.CatalogEnabled},
		{"application egress", child.Applications.EgressEnabled, ceiling.Applications.EgressEnabled},
		{"Valkey service", child.Valkey.Enabled, ceiling.Valkey.Enabled},
	} {
		if flag.child && !flag.ceiling {
			return fmt.Errorf("%s is not delegated by the provider", flag.name)
		}
	}
	for _, list := range []struct {
		name           string
		child, ceiling []string
	}{
		{"PHP versions", child.PHP.AllowedVersions, ceiling.PHP.AllowedVersions},
		{"application catalog", child.Applications.AllowedCatalogSlugs, ceiling.Applications.AllowedCatalogSlugs},
		{"application registries", child.Applications.AllowedRegistries, ceiling.Applications.AllowedRegistries},
		{"application runtimes", child.Applications.AllowedRuntimes, ceiling.Applications.AllowedRuntimes},
	} {
		if !stringSubset(list.child, list.ceiling) {
			return fmt.Errorf("%s includes a value not delegated by the provider", list.name)
		}
	}
	if securityHeaderStrength(child.Web.SecurityHeaderPreset) < securityHeaderStrength(ceiling.Web.SecurityHeaderPreset) {
		return errors.New("security headers cannot be weaker than the provider policy")
	}
	return nil
}

// ValidateSiteWithin prevents a domain override from expanding finite
// subscription runtime ceilings or enabling execution features denied above it.
func ValidateSiteWithin(sitePolicy, subscriptionPolicy types.HostingPolicy) error {
	if err := ValidateWithin(sitePolicy, subscriptionPolicy); err != nil {
		return err
	}
	limits := []struct {
		name           string
		child, ceiling int
	}{
		{"request_rate_per_second", sitePolicy.Web.RequestRatePerSecond, subscriptionPolicy.Web.RequestRatePerSecond},
		{"request_burst", sitePolicy.Web.RequestBurst, subscriptionPolicy.Web.RequestBurst},
		{"max_connections", sitePolicy.Web.MaxConnections, subscriptionPolicy.Web.MaxConnections},
		{"fpm_max_children", sitePolicy.PHP.FPMMaxChildren, subscriptionPolicy.PHP.FPMMaxChildren},
		{"fpm_max_requests", sitePolicy.PHP.FPMMaxRequests, subscriptionPolicy.PHP.FPMMaxRequests},
		{"php_memory_limit_mb", sitePolicy.PHP.MemoryLimitMB, subscriptionPolicy.PHP.MemoryLimitMB},
		{"opcache_memory_mb", sitePolicy.PHP.OPcacheMemoryMB, subscriptionPolicy.PHP.OPcacheMemoryMB},
	}
	for _, limit := range limits {
		if !limitWithin(limit.child, limit.ceiling) {
			return fmt.Errorf("%s exceeds subscription ceiling", limit.name)
		}
	}
	if sitePolicy.PHP.ExecEnabled && !subscriptionPolicy.PHP.ExecEnabled {
		return errors.New("PHP process execution is not enabled by the subscription")
	}
	for _, limit := range []struct {
		name           string
		child, ceiling int
	}{
		{"request_body_limit_mb", sitePolicy.Web.RequestBodyLimitMB, subscriptionPolicy.Web.RequestBodyLimitMB},
		{"cache_ttl_seconds", sitePolicy.Web.CacheTTLSeconds, subscriptionPolicy.Web.CacheTTLSeconds},
		{"connect_timeout_seconds", sitePolicy.Web.ConnectTimeoutSecs, subscriptionPolicy.Web.ConnectTimeoutSecs},
		{"read_timeout_seconds", sitePolicy.Web.ReadTimeoutSecs, subscriptionPolicy.Web.ReadTimeoutSecs},
		{"fpm_idle_timeout_seconds", sitePolicy.PHP.FPMIdleTimeoutSecs, subscriptionPolicy.PHP.FPMIdleTimeoutSecs},
		{"request_terminate_timeout_seconds", sitePolicy.PHP.RequestTerminateSecs, subscriptionPolicy.PHP.RequestTerminateSecs},
		{"max_execution_seconds", sitePolicy.PHP.MaxExecutionSeconds, subscriptionPolicy.PHP.MaxExecutionSeconds},
		{"max_input_seconds", sitePolicy.PHP.MaxInputSeconds, subscriptionPolicy.PHP.MaxInputSeconds},
		{"post_max_mb", sitePolicy.PHP.PostMaxMB, subscriptionPolicy.PHP.PostMaxMB},
		{"upload_max_mb", sitePolicy.PHP.UploadMaxMB, subscriptionPolicy.PHP.UploadMaxMB},
	} {
		if !boundedSettingWithin(limit.child, limit.ceiling) {
			return fmt.Errorf("%s exceeds or removes the subscription ceiling", limit.name)
		}
	}
	if sitePolicy.PHP.AllowURLFOpen && !subscriptionPolicy.PHP.AllowURLFOpen {
		return errors.New("PHP URL fopen is not enabled by the subscription")
	}
	if sitePolicy.PHP.DisplayErrors && !subscriptionPolicy.PHP.DisplayErrors {
		return errors.New("PHP error display is not enabled by the subscription")
	}
	if securityHeaderStrength(sitePolicy.Web.SecurityHeaderPreset) < securityHeaderStrength(subscriptionPolicy.Web.SecurityHeaderPreset) {
		return errors.New("site security headers cannot be weaker than the subscription policy")
	}
	if len(subscriptionPolicy.Web.AllowedCIDRs) > 0 && !slices.Equal(sitePolicy.Web.AllowedCIDRs, subscriptionPolicy.Web.AllowedCIDRs) {
		return errors.New("site access CIDRs cannot replace a subscription restriction")
	}
	return nil
}

func boundedSettingWithin(child, ceiling int) bool {
	if child == ceiling {
		return true
	}
	// Operational settings use zero as "provider default/no additional
	// ceiling"; feature availability is controlled by the typed permission.
	if ceiling == 0 {
		return true
	}
	if ceiling < 0 || child <= 0 {
		return false
	}
	return child <= ceiling
}

func securityHeaderStrength(value string) int {
	switch value {
	case "strict":
		return 2
	case "balanced":
		return 1
	default:
		return 0
	}
}

func limitWithin(child, ceiling int) bool {
	if child == 0 {
		return true
	}
	if ceiling == -1 {
		return true
	}
	if child == -1 {
		return false
	}
	return ceiling > 0 && child <= ceiling
}

func stringSubset(child, ceiling []string) bool {
	for _, item := range child {
		if !slices.Contains(ceiling, item) {
			return false
		}
	}
	return true
}
