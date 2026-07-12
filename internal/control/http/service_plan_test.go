package panelhttp

import (
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	controlquota "github.com/nakroteck/nakpanel/internal/control/quota"
	"github.com/nakroteck/nakpanel/internal/types"
)

func TestParsePlanAcceptsPleskStyleGroupedProperties(t *testing.T) {
	form := url.Values{
		"name": {"Business"}, "description": {"Managed hosting"}, "is_active": {"false", "true"},
		"disk_mb": {"25"}, "disk_mb_unit": {"GB"}, "max_sites": {"5"},
		"max_databases": {"10"}, "bandwidth_mb_unlimited": {"true"}, "max_mailboxes": {"0"},
		"backup_retention_days": {"30"}, "php_max_children": {"8"}, "php_memory_mb": {"256"},
		"site_disk_quota_mb": {"10"}, "site_disk_quota_mb_unit": {"GB"}, "max_backups": {"30"},
		"backup_storage_mb": {"25"}, "backup_storage_mb_unit": {"GB"}, "max_subdomains": {"5"},
		"max_domain_aliases": {"5"}, "max_ftp_accounts": {"2"}, "validity_days_unlimited": {"true"},
		"overuse_policy": {"not_suspend_notify"}, "disk_warning_percent": {"80"},
		"traffic_warning_percent": {"85"}, "hosting_enabled": {"false", "true"},
		"default_php_version": {"8.3"}, "php_versions": {"8.3", "8.2"},
		"allow_dns": {"true"}, "allow_tls": {"true"}, "allow_backups": {"true"},
		"hosting_web_server": {"nginx"}, "preferred_domain": {"www"},
		"dns_mode": {"primary"}, "dns_default_ttl": {"3600"}, "logs_retention_days": {"14"},
	}
	req := httptest.NewRequest("POST", "https://panel.test/plans", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	plan, err := parsePlan(req)
	if err != nil {
		t.Fatal(err)
	}
	if plan.DiskMB != 25*1024 || plan.SiteDiskQuotaMB != 10*1024 || plan.BandwidthMB != -1 {
		t.Fatalf("parsed size limits = disk:%d site:%d traffic:%d", plan.DiskMB, plan.SiteDiskQuotaMB, plan.BandwidthMB)
	}
	if plan.OverusePolicy != types.PlanOveruseNotSuspendNotify || !plan.HostingEnabled || plan.PHPAllowlist != "8.3,8.2" {
		t.Fatalf("parsed plan = %#v", plan)
	}
	if plan.Presets.Hosting.PreferredDomain != "www" || plan.Presets.DNS.DefaultTTL != 3600 {
		t.Fatalf("parsed presets = %#v", plan.Presets)
	}
}

func TestParsePlanLimitRejectsUnitConversionOverflow(t *testing.T) {
	form := url.Values{
		"disk_mb":      {strconv.Itoa(int(^uint(0) >> 1))},
		"disk_mb_unit": {"GB"},
	}
	req := httptest.NewRequest("POST", "https://panel.test/plans", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if _, err := parsePlanLimit(req, "disk_mb"); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("parsePlanLimit error = %v, want too large", err)
	}
}

func TestParsedPlanEntitlementsKeepsCompleteCustomSnapshot(t *testing.T) {
	plan := controlquota.Plan{
		Name: "Custom", DiskMB: 100, MaxSites: 2, BandwidthMB: 300,
		MaxSubdomains: 4, MaxDomainAliases: 5, MaxFTPAccounts: 6,
		HostingEnabled: true, DefaultPHPVersion: "8.3", PHPAllowlist: "8.3",
		AllowDNS: true, AllowTLS: true, AllowBackups: true, AllowPHPSettings: true,
		OverusePolicy: types.PlanOveruseNotify, DiskWarningPercent: 75, TrafficWarningPercent: 85,
		Presets: types.PlanServicePresets{SchemaVersion: 1, DNS: types.DNSPreset{Mode: "primary", DefaultTTL: 7200}},
	}
	got := parsedPlanEntitlements(plan)
	if !got.HostingEnabled || got.DefaultPHPVersion != "8.3" || !got.AllowTLS || !got.AllowBackups {
		t.Fatalf("custom permissions = %#v", got)
	}
	if got.MaxSubdomains != 4 || got.MaxDomainAliases != 5 || got.MaxFTPAccounts != 6 || got.BandwidthMB != 300 {
		t.Fatalf("custom resources = %#v", got)
	}
	if got.OverusePolicy != types.PlanOveruseNotify || got.ServicePresets.DNS.DefaultTTL != 7200 {
		t.Fatalf("custom policy/presets = %#v", got)
	}
}

func TestParsedAddonEntitlementsDoesNotEnableBaseHosting(t *testing.T) {
	plan := controlquota.Plan{
		Name:              "PHP boost",
		HostingEnabled:    true,
		DefaultPHPVersion: "8.3",
		PHPAllowlist:      "8.3,8.4",
		PHPMemoryMB:       256,
		Presets: types.PlanServicePresets{
			SchemaVersion: 1,
			Hosting:       types.HostingPreset{DefaultPHPVersion: "8.3"},
		},
	}

	got := parsedAddonEntitlements(plan)
	if got.HostingEnabled || got.DefaultPHPVersion != "" || got.ServicePresets.Hosting.DefaultPHPVersion != "" {
		t.Fatalf("add-on unexpectedly enables base hosting: %#v", got)
	}
	if got.PHPAllowlist != "8.3,8.4" || got.PHPMemoryMB != 256 {
		t.Fatalf("add-on increments were not preserved: %#v", got)
	}
}

func TestParsedCustomEntitlementsTranslatesLegacyPHPAllowlist(t *testing.T) {
	legacy := httptest.NewRequest("POST", "https://panel.test/subscriptions/1/mode", nil)
	legacy.Form = url.Values{"php_allowlist": {"8.3, 8.2"}}
	plan := controlquota.Plan{
		HostingEnabled: true,
		PHPAllowlist:   "8.3,8.2",
		Presets: types.PlanServicePresets{
			SchemaVersion: 1,
			Hosting:       types.HostingPreset{AllowedPHPVersions: []string{"8.3", "8.2"}},
		},
	}
	got := parsedCustomEntitlements(legacy, plan)
	if got.DefaultPHPVersion != "8.3" || got.ServicePresets.Hosting.DefaultPHPVersion != "8.3" {
		t.Fatalf("legacy custom PHP default = %#v, want first allowed version", got)
	}

	modern := httptest.NewRequest("POST", "https://panel.test/subscriptions/1/mode", nil)
	modern.Form = url.Values{"default_php_version": {""}}
	got = parsedCustomEntitlements(modern, plan)
	if got.DefaultPHPVersion != "" {
		t.Fatalf("explicit empty PHP default was silently replaced: %#v", got)
	}
}
