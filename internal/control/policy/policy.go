package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"schema_version": {}, "permissions": {}, "web": {}, "php": {}, "mail": {}, "dns": {}, "applications": {},
}

// Resolve applies inheritance-aware JSON patches and returns a fully typed,
// validated policy. A JSON null means inherit, so it never erases the parent.
func Resolve(base types.HostingPolicy, subscriptionPatch, sitePatch []byte) (types.HostingPolicy, error) {
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
	if p.SchemaVersion != 1 {
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
		"fpm_max_children": p.PHP.FPMMaxChildren, "fpm_max_requests": p.PHP.FPMMaxRequests,
		"php_memory_limit_mb": p.PHP.MemoryLimitMB, "mailbox_quota_mb": p.Mail.MailboxQuotaMB,
		"backup_retention_days": p.Backups.RetentionDays,
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
	} {
		if value < 0 {
			return fmt.Errorf("%s cannot be negative", name)
		}
	}
	if p.PHP.DefaultVersion != "" && !slices.Contains(p.PHP.AllowedVersions, p.PHP.DefaultVersion) {
		return errors.New("default PHP version must be allowed")
	}
	for _, version := range p.PHP.AllowedVersions {
		if version != "8.2" && version != "8.3" {
			return fmt.Errorf("unsupported PHP version %q", version)
		}
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
		SchemaVersion: 1,
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
	}
	ceilingLimits := []int{
		ceiling.Resources.DiskMB, ceiling.Resources.TrafficMB, ceiling.Resources.CPUPercent,
		ceiling.Resources.MemoryMB, ceiling.Resources.IOReadMBPS, ceiling.Resources.IOWriteMBPS,
		ceiling.Resources.MaxTasks, ceiling.Resources.MaxSites, ceiling.Resources.MaxDatabases,
		ceiling.Resources.MaxDatabaseUsers, ceiling.Resources.MaxMailboxes, ceiling.Resources.MaxMailAliases,
		ceiling.Resources.MaxSFTPIdentities, ceiling.Resources.MaxScheduledTasks, ceiling.Resources.MaxBackups,
		ceiling.Resources.BackupStorageMB, ceiling.Resources.MaxApplications, ceiling.Resources.ContainerStorageMB,
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
	}
	ceilingPermissions := []bool{
		ceiling.Permissions.Hosting, ceiling.Permissions.SSH, ceiling.Permissions.SFTP,
		ceiling.Permissions.ScheduledTasks, ceiling.Permissions.DNS, ceiling.Permissions.TLS,
		ceiling.Permissions.Mail, ceiling.Permissions.Databases, ceiling.Permissions.Backups,
		ceiling.Permissions.PHPSettings, ceiling.Permissions.CGI, ceiling.Permissions.Applications,
		ceiling.Permissions.CustomOCIImages, ceiling.Permissions.ApplicationEgress,
	}
	for i := range childPermissions {
		if childPermissions[i] && !ceilingPermissions[i] {
			return fmt.Errorf("permission %d is not delegated by the provider", i)
		}
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
	}
	for _, limit := range limits {
		if !limitWithin(limit.child, limit.ceiling) {
			return fmt.Errorf("%s exceeds subscription ceiling", limit.name)
		}
	}
	if sitePolicy.PHP.ExecEnabled && !subscriptionPolicy.PHP.ExecEnabled {
		return errors.New("PHP process execution is not enabled by the subscription")
	}
	return nil
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
