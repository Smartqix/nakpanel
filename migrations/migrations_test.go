package migrations

import (
	"os"
	"strings"
	"testing"
)

func TestPhase23DownRemovesScheduledTaskNotificationsBeforeConstraint(t *testing.T) {
	body, err := os.ReadFile("20260723000025_phase23_logs_tasks_statistics.sql")
	if err != nil {
		t.Fatal(err)
	}
	down := string(body)
	if marker := strings.Index(down, "-- +goose Down"); marker >= 0 {
		down = down[marker:]
	}
	removeRows := strings.Index(down, "DELETE FROM notifications WHERE kind='scheduled_task_failed'")
	restoreConstraint := strings.LastIndex(down, "ALTER TABLE notifications ADD CONSTRAINT notifications_kind_check")
	if removeRows < 0 || restoreConstraint < 0 || removeRows > restoreConstraint {
		t.Fatal("Phase 23 down migration must remove scheduled_task_failed rows before restoring the older kind constraint")
	}
	if strings.Contains(down[restoreConstraint:], "'scheduled_task_failed'") {
		t.Fatal("Phase 23 down constraint still permits the Phase 23 notification kind")
	}
}

func TestPhase23DownRestoresLegacyTaskScope(t *testing.T) {
	body, err := os.ReadFile("20260723000025_phase23_logs_tasks_statistics.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(body)
	for _, required := range []string{
		"phase23_legacy_site_backfill",
		"phase23_legacy_enabled",
		"SET site_id=NULL",
		"enabled=COALESCE(phase23_legacy_enabled,enabled)",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("Phase 23 migration is missing rollback provenance %q", required)
		}
	}
}

func TestPhase25DownRestoresExactEntitlementSnapshot(t *testing.T) {
	body, err := os.ReadFile("20260723000030_phase25_entitlement_snapshot_trigger.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(body)
	for _, required := range []string{
		"CREATE TABLE phase25_entitlement_snapshot_backup",
		"INSERT INTO phase25_entitlement_snapshot_backup",
		"SET hosting_policy=backup.hosting_policy",
		"DROP TABLE phase25_entitlement_snapshot_backup",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("Phase 25 migration is missing snapshot rollback step %q", required)
		}
	}
}

func TestApplicationRevisionTriggerUsesGooseStatementBoundaries(t *testing.T) {
	data, err := os.ReadFile("20260723000032_application_convergence_revisions.sql")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	begin := strings.Index(script, "-- +goose StatementBegin")
	function := strings.Index(script, "CREATE OR REPLACE FUNCTION nakpanel_application_desired_revision()")
	end := strings.Index(script, "-- +goose StatementEnd")
	if begin < 0 || function < 0 || end < 0 || !(begin < function && function < end) {
		t.Fatal("application revision trigger is not protected by Goose statement boundaries")
	}
	if !strings.Contains(script[function:end], "END;\n$$;") {
		t.Fatal("application revision trigger has an unterminated PL/pgSQL body")
	}
}

func TestAccountTeardownMutationGateSerializesAndCoversTenantIntent(t *testing.T) {
	data, err := os.ReadFile("20260723000033_account_teardown_mutation_gate.sql")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, marker := range []string{
		"pg_advisory_xact_lock",
		"provisioning_state_value IN ('terminating','terminated')",
		"current_setting('nakpanel.account_teardown', true) = 'on'",
		"old_subscription_id := nakpanel_resource_subscription",
		"new_subscription_id := nakpanel_resource_subscription",
		"old_subscription_id < new_subscription_id",
		"sites_account_teardown_guard",
		"mail_domains_account_teardown_guard",
		"application_instances_account_teardown_guard",
		"server_operations_account_teardown_guard",
		"END;\n$$;",
	} {
		if !strings.Contains(script, marker) {
			t.Fatalf("account teardown mutation gate is missing %q", marker)
		}
	}
}

func TestEffectiveMailDeliveryViewsFailClosed(t *testing.T) {
	data, err := os.ReadFile("20260723000034_effective_mail_delivery.sql")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, marker := range []string{
		"ADD COLUMN effective_enabled BOOLEAN NOT NULL DEFAULT false",
		"WHERE mb.enabled AND md.effective_enabled",
		"WHERE effective_enabled AND NOT delete_requested",
		"ALTER TABLE mail_domains DROP COLUMN effective_enabled",
	} {
		if !strings.Contains(script, marker) {
			t.Fatalf("effective mail delivery migration is missing %q", marker)
		}
	}
}

func TestGlobalDNSTemplateMigrationIsVersionedAndConservative(t *testing.T) {
	data, err := os.ReadFile("20260724000035_global_dns_template.sql")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, marker := range []string{
		"CREATE TABLE dns_template_revisions",
		"CREATE TABLE dns_template_sync_runs",
		"origin IN ('template', 'system', 'custom')",
		"UPDATE dns_records record",
		"template_status",
		"desired_revision",
		"applied_revision",
		"mode IN ('primary', 'secondary', 'disabled')",
		"DNS template revisions are immutable",
		"owner_site_id",
		"transfer_cidrs CIDR[]",
		"record_type IN ('A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA', 'DS')",
	} {
		if !strings.Contains(script, marker) {
			t.Fatalf("global DNS template migration is missing %q", marker)
		}
	}
}

func TestDNSTemplateIntegrityMigrationUsesCompleteRecordIdentity(t *testing.T) {
	data, err := os.ReadFile("20260724000038_dns_template_integrity.sql")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, marker := range []string{
		"dns_records_identity_key",
		"priority, weight, port",
		"dns_records_template_owner_key_idx",
		"WHERE origin='template'",
	} {
		if !strings.Contains(script, marker) {
			t.Fatalf("DNS template integrity migration is missing %q", marker)
		}
	}
}

func TestDNSZoneTemplatePinningIsReversible(t *testing.T) {
	data, err := os.ReadFile("20260724000039_dns_zone_template_pinning.sql")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, marker := range []string{
		"dns_zones_template_revision_fk",
		"ALTER COLUMN template_revision SET NOT NULL",
		"'out_of_sync'",
		"ALTER COLUMN template_revision DROP NOT NULL",
	} {
		if !strings.Contains(script, marker) {
			t.Fatalf("DNS zone template pinning migration is missing %q", marker)
		}
	}
}

func TestDNSTemplateAdoptionStateIsPerSiteAndReversible(t *testing.T) {
	data, err := os.ReadFile("20260724000040_dns_template_adoption_state.sql")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, marker := range []string{
		"ADD COLUMN dns_template_adoption_completed",
		"record.owner_site_id=site.id",
		"site.parent_site_id=zone.site_id",
		"DROP COLUMN dns_template_adoption_completed",
	} {
		if !strings.Contains(script, marker) {
			t.Fatalf("DNS template adoption migration is missing %q", marker)
		}
	}
}

func TestDNSRootZoneModeUsesSafeDefault(t *testing.T) {
	data, err := os.ReadFile("20260724000041_dns_root_zone_mode_default.sql")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, marker := range []string{
		"ALTER COLUMN dns_zone_mode SET DEFAULT 'separate'",
		"WHERE parent_site_id IS NULL",
		"ALTER COLUMN dns_zone_mode SET DEFAULT 'parent'",
	} {
		if !strings.Contains(script, marker) {
			t.Fatalf("DNS root-zone default migration is missing %q", marker)
		}
	}
}

func TestPhase28ApplicationRuntimeMigrationPreservesAndFencesGenerations(t *testing.T) {
	data, err := os.ReadFile("20260724000036_phase28_application_runtime.sql")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, marker := range []string{
		"CREATE TABLE application_manifest_revisions",
		"CREATE TABLE application_generations",
		"CREATE TABLE application_secret_bindings",
		"application_instances_endpoint_port_idx",
		"application_instances_domain_route_idx",
		"application_instances_prefix_route_idx",
		"runtime <> 'oci'",
		"Phase 28 supports OCI containers only",
		"NEW.route_mode",
		"-- +goose StatementBegin",
	} {
		if !strings.Contains(script, marker) {
			t.Fatalf("Phase 28 application runtime migration is missing %q", marker)
		}
	}
}

func TestPhase28ManifestCompatibilityMigration(t *testing.T) {
	data, err := os.ReadFile("20260724000037_phase28_manifest_compatibility.sql")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, marker := range []string{
		"ADD COLUMN IF NOT EXISTS catalog_revision",
		"ADD COLUMN IF NOT EXISTS manifest",
		"ADD COLUMN IF NOT EXISTS read_only",
		"NEW.catalog_revision,NEW.manifest",
	} {
		if !strings.Contains(script, marker) {
			t.Fatalf("Phase 28 compatibility migration is missing %q", marker)
		}
	}
}
