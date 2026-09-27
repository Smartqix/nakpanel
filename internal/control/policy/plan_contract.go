package policy

import (
	"reflect"
	"sort"
	"strings"
	"unicode"

	"github.com/nakroteck/nakpanel/internal/types"
)

// PlanContractFields is the authoritative classification of every value in a
// hosting-policy snapshot. Keeping this separate from the form makes it
// possible to audit whether a plan property is truly enforced before it is
// presented as a sellable feature.
func PlanContractFields() []types.PlanContractField {
	var paths []string
	collectPolicyPaths(reflect.TypeOf(types.HostingPolicy{}), "", &paths)
	fields := make([]types.PlanContractField, 0, len(paths))
	for _, path := range paths {
		fields = append(fields, types.PlanContractField{
			Path:        path,
			Label:       planFieldLabel(path),
			Enforcement: classifyPlanField(path),
			Description: planFieldDescription(path),
		})
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Path < fields[j].Path })
	return fields
}

func collectPolicyPaths(t reflect.Type, prefix string, out *[]string) {
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		if field.Type.Kind() == reflect.Struct {
			collectPolicyPaths(field.Type, path, out)
			continue
		}
		*out = append(*out, path)
	}
}

func classifyPlanField(path string) types.PlanEnforcementKind {
	if path == "resources.disk_mb" || path == "resources.traffic_mb" {
		return types.PlanEnforcementMeasuredLimit
	}
	if strings.HasPrefix(path, "resources.") {
		return types.PlanEnforcementHardLimit
	}
	if strings.HasPrefix(path, "permissions.") {
		switch strings.TrimPrefix(path, "permissions.") {
		case "ssh", "php_settings", "custom_oci_images", "composer_code_execution", "web_statistics":
			return types.PlanEnforcementManagementPermission
		default:
			return types.PlanEnforcementServicePermission
		}
	}
	switch path {
	case "php.allowed_versions", "mail.enabled", "mail.dkim", "mail.webmail",
		"dns.enabled", "access.ftps_enabled", "backups.enabled",
		"applications.catalog_enabled", "applications.allowed_catalog_slugs",
		"applications.allowed_registries", "applications.allowed_runtimes",
		"applications.egress_enabled", "valkey.enabled":
		return types.PlanEnforcementServicePermission
	case "schema_version", "mail.autoresponders", "mail.catch_all", "dns.dnssec",
		"access.nspawn_image", "backups.remote_target":
		return types.PlanEnforcementStoredOnly
	default:
		return types.PlanEnforcementCreationDefault
	}
}

func planFieldLabel(path string) string {
	part := path[strings.LastIndex(path, ".")+1:]
	words := strings.Fields(strings.ReplaceAll(part, "_", " "))
	for i, word := range words {
		runes := []rune(word)
		if len(runes) > 0 {
			runes[0] = unicode.ToUpper(runes[0])
		}
		words[i] = string(runes)
	}
	return strings.Join(words, " ")
}

func planFieldDescription(path string) string {
	switch classifyPlanField(path) {
	case types.PlanEnforcementHardLimit:
		return "Provisioning is blocked when current usage reaches this limit."
	case types.PlanEnforcementMeasuredLimit:
		return "Enforced only from a fresh and complete usage measurement."
	case types.PlanEnforcementServicePermission:
		return "Controls whether this service may be provisioned."
	case types.PlanEnforcementManagementPermission:
		return "Controls whether the customer may change this setting."
	case types.PlanEnforcementCreationDefault:
		return "Copied into desired configuration and subject to inheritance."
	default:
		return "Stored for compatibility; not currently enforced as a sellable entitlement."
	}
}

// ValidatePlanCapabilities returns deterministic, user-safe readiness issues.
// It never probes the machine itself; callers provide the agent's signed
// runtime inventory so draft editing remains possible while activation fails
// closed when an enabled service cannot be delivered.
func ValidatePlanCapabilities(policy types.HostingPolicy, capabilities types.RuntimeCapabilities) []types.PlanCapabilityIssue {
	var issues []types.PlanCapabilityIssue
	if StatisticsEngine(policy.Logs) == "goaccess" && !capabilities.GoAccessAvailable {
		issues = append(issues, capabilityIssue("goaccess_unavailable", "logs.statistics_engine", "GoAccess is not available on this server."))
	}
	readyPHP := make(map[string]bool, len(capabilities.PHPVersions))
	for _, version := range capabilities.PHPVersions {
		readyPHP[strings.TrimSpace(version)] = true
	}
	if policy.Permissions.Hosting {
		if len(readyPHP) == 0 {
			issues = append(issues, capabilityIssue("php_inventory_unavailable", "php.allowed_versions", "No validated PHP-FPM runtime is available."))
		}
		defaultVersion := strings.TrimSpace(policy.PHP.DefaultVersion)
		if defaultVersion != "" && !readyPHP[defaultVersion] {
			issues = append(issues, capabilityIssue("php_default_unavailable", "php.default_version", "Default PHP "+defaultVersion+" is not ready on this server."))
		}
		for _, version := range policy.PHP.AllowedVersions {
			version = strings.TrimSpace(version)
			if version != "" && !readyPHP[version] {
				issues = append(issues, capabilityIssue("php_version_unavailable", "php.allowed_versions", "Allowed PHP "+version+" is not ready on this server."))
			}
		}
	}
	if policy.Resources.DiskMB > 0 && !capabilities.DiskQuota {
		issues = append(issues, capabilityIssue("disk_quota_unavailable", "resources.disk_mb", "Linux disk quotas are unavailable; the finite disk limit cannot be enforced."))
	}
	if (policy.Permissions.Composer || policy.Permissions.ManagedPHPDeployments) && !capabilities.ComposerAvailable {
		issues = append(issues, capabilityIssue("composer_unavailable", "permissions.composer", "Composer is unavailable; managed PHP deployment cannot be delivered."))
	}
	applications := policy.Permissions.Applications || policy.Permissions.CustomOCIImages || policy.Applications.CatalogEnabled
	if applications {
		if strings.TrimSpace(capabilities.PodmanVersion) == "" {
			issues = append(issues, capabilityIssue("podman_unavailable", "permissions.applications", "Podman is unavailable for application containers."))
		}
		if !capabilities.RootlessPodman {
			issues = append(issues, capabilityIssue("rootless_podman_unavailable", "permissions.applications", "Rootless Podman is not ready for subscription isolation."))
		}
		if !capabilities.SubordinateIDSupport {
			issues = append(issues, capabilityIssue("subordinate_ids_unavailable", "permissions.applications", "Subordinate UID/GID mappings are unavailable for subscription containers."))
		}
	}
	if policy.Permissions.Valkey || policy.Valkey.Enabled {
		if strings.TrimSpace(capabilities.PodmanVersion) == "" {
			issues = append(issues, capabilityIssue("valkey_runtime_unavailable", "permissions.valkey", "The Podman runtime required by the managed Valkey service is unavailable."))
		}
	}
	if policy.Permissions.WordPressToolkit {
		if !capabilities.WPCLIAvailable {
			issues = append(issues, capabilityIssue("wp_cli_unavailable", "permissions.wordpress_toolkit", "WP-CLI is unavailable; WordPress Toolkit cannot be delivered."))
		}
		if len(readyPHP) == 0 {
			issues = append(issues, capabilityIssue("wordpress_php_unavailable", "permissions.wordpress_toolkit", "No validated PHP-FPM runtime is available for WordPress."))
		}
	}
	return dedupeCapabilityIssues(issues)
}

func capabilityIssue(code, field, message string) types.PlanCapabilityIssue {
	return types.PlanCapabilityIssue{Code: code, Field: field, Message: message, Blocking: true}
}

func dedupeCapabilityIssues(issues []types.PlanCapabilityIssue) []types.PlanCapabilityIssue {
	seen := make(map[string]bool, len(issues))
	out := make([]types.PlanCapabilityIssue, 0, len(issues))
	for _, issue := range issues {
		key := issue.Code + "\x00" + issue.Field + "\x00" + issue.Message
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, issue)
	}
	return out
}
