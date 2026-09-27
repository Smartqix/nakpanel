package quota

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	controlpolicy "github.com/nakroteck/nakpanel/internal/control/policy"
	"github.com/nakroteck/nakpanel/internal/types"
)

type SubscriptionComplianceUsage struct {
	Sites               int
	Databases           int
	Backups             int
	Mailboxes           int
	DiskBytes           int64
	TrafficBytes        int64
	BackupBytes         int64
	MeasurementComplete bool
}

func CanonicalPlanDefinition(plan Plan) (json.RawMessage, string, error) {
	plan = normalizePlanDefaults(plan)
	var price *int64
	if plan.PriceCents.Valid {
		value := plan.PriceCents.Int64
		price = &value
	}
	lifecycle := plan.LifecycleStatus
	if lifecycle == "" {
		if plan.IsActive {
			lifecycle = types.PlanLifecycleActive
		} else if plan.ID > 0 {
			lifecycle = types.PlanLifecycleRetired
		} else {
			lifecycle = types.PlanLifecycleDraft
		}
	}
	definition := types.PlanDefinition{
		ID: plan.ID, ResellerID: plan.ResellerID, Name: strings.TrimSpace(plan.Name), Description: strings.TrimSpace(plan.Description),
		PriceCents: price, LifecycleStatus: lifecycle, IsActive: lifecycle == types.PlanLifecycleActive,
		Revision: plan.Revision,
		Resources: types.PlanResources{
			DiskMB: plan.DiskMB, TrafficMB: plan.BandwidthMB, MaxSites: plan.MaxSites,
			MaxDatabases: plan.MaxDatabases, MaxMailboxes: plan.MaxMailboxes,
			MaxBackups: plan.MaxBackups, BackupStorageMB: plan.BackupStorageMB,
			MaxSubdomains: plan.MaxSubdomains, MaxDomainAliases: plan.MaxDomainAliases,
			MaxFTPAccounts: plan.MaxFTPAccounts, ValidityDays: plan.ValidityDays,
			OverusePolicy: plan.OverusePolicy, DiskWarningPercent: plan.DiskWarningPercent,
			TrafficWarningPercent: plan.TrafficWarningPercent,
			BackupRetentionDays:   plan.BackupRetentionDays, SiteDiskQuotaMB: plan.SiteDiskQuotaMB,
			PHPFPMMaxChildren: plan.PHPFPMMaxChildren, PHPMemoryMB: plan.PHPMemoryMB,
			PHPAllowlist: strings.TrimSpace(plan.PHPAllowlist),
		},
		Permissions: types.PlanPermissions{
			HostingEnabled: plan.HostingEnabled, AllowSSH: plan.AllowSSH, AllowDNS: plan.AllowDNS,
			AllowTLS: plan.AllowTLS, AllowBackups: plan.AllowBackups, AllowPHPSettings: plan.AllowPHPSettings,
		},
		Presets: plan.Presets, HostingPolicy: plan.HostingPolicy,
	}
	raw, err := json.Marshal(definition)
	if err != nil {
		return nil, "", err
	}
	hash := sha256.Sum256(raw)
	return raw, hex.EncodeToString(hash[:]), nil
}

func DiffPlanDefinitions(current, candidate Plan) ([]types.PlanFieldChange, error) {
	current = normalizePlanDefaults(current)
	candidate = normalizePlanDefaults(candidate)
	oldValues, err := flattenedHostingPolicy(current.HostingPolicy)
	if err != nil {
		return nil, err
	}
	newValues, err := flattenedHostingPolicy(candidate.HostingPolicy)
	if err != nil {
		return nil, err
	}
	contract := make(map[string]types.PlanContractField)
	for _, field := range controlpolicy.PlanContractFields() {
		contract[field.Path] = field
	}
	var changes []types.PlanFieldChange
	appendChange := func(path, label, oldValue, newValue string, enforcement types.PlanEnforcementKind) {
		if oldValue == newValue {
			return
		}
		changes = append(changes, types.PlanFieldChange{
			Path: path, Label: label, OldValue: oldValue, NewValue: newValue, Enforcement: enforcement,
		})
	}
	appendChange("name", "Name", strings.TrimSpace(current.Name), strings.TrimSpace(candidate.Name), types.PlanEnforcementCreationDefault)
	appendChange("description", "Description", strings.TrimSpace(current.Description), strings.TrimSpace(candidate.Description), types.PlanEnforcementCreationDefault)
	appendChange("price_cents", "Reference price", formatNullablePrice(current.PriceCents), formatNullablePrice(candidate.PriceCents), types.PlanEnforcementCreationDefault)
	if current.LifecycleStatus != candidate.LifecycleStatus {
		changes = append(changes, types.PlanFieldChange{
			Path: "lifecycle_status", Label: "Lifecycle", OldValue: string(current.LifecycleStatus),
			NewValue: string(candidate.LifecycleStatus), Enforcement: types.PlanEnforcementServicePermission,
		})
	}
	appendChange("resources.max_subdomains", "Subdomains", strconv.Itoa(current.MaxSubdomains), strconv.Itoa(candidate.MaxSubdomains), types.PlanEnforcementHardLimit)
	appendChange("resources.max_domain_aliases", "Domain aliases", strconv.Itoa(current.MaxDomainAliases), strconv.Itoa(candidate.MaxDomainAliases), types.PlanEnforcementHardLimit)
	appendChange("resources.site_disk_quota_mb", "Hosting account disk quota", strconv.Itoa(current.SiteDiskQuotaMB), strconv.Itoa(candidate.SiteDiskQuotaMB), types.PlanEnforcementHardLimit)
	appendChange("resources.validity_days", "Subscription validity", strconv.Itoa(current.ValidityDays), strconv.Itoa(candidate.ValidityDays), types.PlanEnforcementCreationDefault)
	appendChange("resources.overuse_policy", "Overuse policy", string(current.OverusePolicy), string(candidate.OverusePolicy), types.PlanEnforcementMeasuredLimit)
	appendChange("resources.disk_warning_percent", "Disk warning threshold", strconv.Itoa(current.DiskWarningPercent), strconv.Itoa(candidate.DiskWarningPercent), types.PlanEnforcementMeasuredLimit)
	appendChange("resources.traffic_warning_percent", "Traffic warning threshold", strconv.Itoa(current.TrafficWarningPercent), strconv.Itoa(candidate.TrafficWarningPercent), types.PlanEnforcementMeasuredLimit)
	for path, field := range contract {
		oldValue := formatPlanContractValue(oldValues[path])
		newValue := formatPlanContractValue(newValues[path])
		if oldValue == newValue {
			continue
		}
		changes = append(changes, types.PlanFieldChange{
			Path: path, Label: field.Label, OldValue: oldValue, NewValue: newValue, Enforcement: field.Enforcement,
		})
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return changes, nil
}

func formatNullablePrice(value sql.NullInt64) string {
	if !value.Valid {
		return "Not set"
	}
	return strconv.FormatInt(value.Int64, 10)
}

func flattenedHostingPolicy(policy types.HostingPolicy) (map[string]any, error) {
	raw, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	out := make(map[string]any)
	var flatten func(string, any)
	flatten = func(prefix string, value any) {
		if object, ok := value.(map[string]any); ok {
			for key, child := range object {
				path := key
				if prefix != "" {
					path = prefix + "." + key
				}
				flatten(path, child)
			}
			return
		}
		out[prefix] = value
	}
	flatten("", root)
	return out, nil
}

func formatPlanContractValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return "Not set"
	case bool:
		if typed {
			return "Enabled"
		}
		return "Disabled"
	case float64:
		if typed == -1 {
			return "Unlimited"
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case string:
		if strings.TrimSpace(typed) == "" {
			return "Not set"
		}
		return typed
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			values = append(values, formatPlanContractValue(item))
		}
		if len(values) == 0 {
			return "None"
		}
		return strings.Join(values, ", ")
	default:
		return fmt.Sprint(typed)
	}
}

func EvaluateSubscriptionCompliance(entitlements types.SubscriptionEntitlements, usage SubscriptionComplianceUsage) (types.SubscriptionComplianceStatus, []string) {
	var violations []string
	appendCountViolation := func(label string, used, limit int) {
		if limit >= 0 && used > limit {
			violations = append(violations, fmt.Sprintf("%s %d/%d", label, used, limit))
		}
	}
	appendCountViolation("sites", usage.Sites, entitlements.MaxSites)
	appendCountViolation("databases", usage.Databases, entitlements.MaxDatabases)
	appendCountViolation("backups", usage.Backups, entitlements.MaxBackups)
	appendCountViolation("mailboxes", usage.Mailboxes, entitlements.MaxMailboxes)
	appendMeasuredViolation := func(label string, bytes int64, limit int) {
		if limit < 0 {
			return
		}
		usedMB := bytesToCeilingMB(bytes)
		if usedMB > int64(limit) {
			violations = append(violations, fmt.Sprintf("%s %d/%d MB", label, usedMB, limit))
		}
	}
	// Backup sizes come from PostgreSQL intent, not the agent usage scan, so
	// they remain authoritative even when filesystem or traffic data is stale.
	appendMeasuredViolation("backup storage", usage.BackupBytes, entitlements.BackupStorageMB)

	if usage.MeasurementComplete {
		appendMeasuredViolation("disk", usage.DiskBytes, entitlements.DiskMB)
		appendMeasuredViolation("traffic", usage.TrafficBytes, entitlements.BandwidthMB)
	}

	if len(violations) > 0 {
		return types.SubscriptionComplianceOverLimit, violations
	}
	if !usage.MeasurementComplete {
		return types.SubscriptionComplianceUnknown, nil
	}
	return types.SubscriptionComplianceCompliant, nil
}

func bytesToCeilingMB(bytes int64) int64 {
	if bytes <= 0 {
		return 0
	}
	const mb = int64(1024 * 1024)
	return 1 + (bytes-1)/mb
}

func loadSubscriptionComplianceUsage(ctx context.Context, q queryRower, subscriptionID int64) (SubscriptionComplianceUsage, error) {
	var usage SubscriptionComplianceUsage
	err := q.QueryRowContext(ctx, `SELECT
    COALESCE((SELECT COUNT(*) FROM sites WHERE subscription_id=$1 AND status<>'failed'),0)::int,
    COALESCE((SELECT COUNT(*) FROM databases WHERE subscription_id=$1 AND status<>'failed'),0)::int,
    COALESCE((SELECT COUNT(*) FROM backups WHERE subscription_id=$1 AND status<>'failed'),0)::int,
    COALESCE((SELECT COUNT(*) FROM mailboxes mailbox JOIN mail_domains domain ON domain.id=mailbox.mail_domain_id WHERE domain.subscription_id=$1 AND NOT domain.delete_requested),0)::int,
    COALESCE(usage.disk_bytes,0)::bigint,
    COALESCE(usage.traffic_bytes,0)::bigint,
    COALESCE((SELECT SUM(size_bytes) FROM backups WHERE subscription_id=$1 AND status='active'),0)::bigint,
    COALESCE(usage.is_complete,false)
FROM (SELECT $1::bigint AS subscription_id) selected
LEFT JOIN subscription_usage_current usage ON usage.subscription_id=selected.subscription_id`, subscriptionID).Scan(
		&usage.Sites, &usage.Databases, &usage.Backups, &usage.Mailboxes,
		&usage.DiskBytes, &usage.TrafficBytes, &usage.BackupBytes, &usage.MeasurementComplete,
	)
	return usage, err
}

func evaluateSubscriptionComplianceTx(ctx context.Context, tx *sql.Tx, subscriptionID int64, entitlements types.SubscriptionEntitlements) error {
	usage, err := loadSubscriptionComplianceUsage(ctx, tx, subscriptionID)
	if err != nil {
		return err
	}
	status, violations := EvaluateSubscriptionCompliance(entitlements, usage)
	message := strings.Join(violations, "; ")
	_, err = tx.ExecContext(ctx, `UPDATE subscriptions SET compliance_status=$2,compliance_error=$3,
compliance_checked_at=now(),updated_at=now() WHERE id=$1`, subscriptionID, status, message)
	return err
}

func refreshSubscriptionComplianceTx(ctx context.Context, tx *sql.Tx, subscriptionID int64) error {
	var entitlements types.SubscriptionEntitlements
	err := tx.QueryRowContext(ctx, `SELECT disk_mb,bandwidth_mb,max_sites,max_databases,max_backups,backup_storage_mb,max_mailboxes
FROM subscription_entitlements WHERE subscription_id=$1`, subscriptionID).Scan(
		&entitlements.DiskMB, &entitlements.BandwidthMB, &entitlements.MaxSites,
		&entitlements.MaxDatabases, &entitlements.MaxBackups, &entitlements.BackupStorageMB,
		&entitlements.MaxMailboxes,
	)
	if err != nil {
		return err
	}
	return evaluateSubscriptionComplianceTx(ctx, tx, subscriptionID, entitlements)
}
