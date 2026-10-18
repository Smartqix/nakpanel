package quota

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// These fingerprints cover every seeded plan field and service preset after all
// migrations, excluding identity and timestamps. Changing any built-in definition
// requires deliberately updating this fresh-install baseline and its migration test.
var nativeBootstrapSeedFingerprints = map[string]string{
	"Starter":          "67865611fde1b1c0144eb9ca2bf0450787f711bed51125d84a31c425787f7a4f",
	"Business":         "09420133d845dddbc16c857c34fc0388e870228f1be083d0e8676ed4117bea91",
	"Pro":              "bad71e6c0f282e56d47439b834f8adb199b2795f265cec622422839c61c6ea5f",
	"Legacy Unlimited": "c386720eaa357f1e7be4c6d12b9095496edd47369fb47b284d5474e51a4faf12",
}

const bootstrapDefinitionSQL = `jsonb_build_object('plan',to_jsonb(p)-'created_at'-'updated_at'-'last_validated_at'-'readiness_error','presets',` + planPresetJSON + `)`

// BootstrapNativePlans adapts only an empty installation's exact built-in seed.
// Its audit receipt makes a committed operation retryable if the installer crashes
// before clearing its root-owned bootstrap_pending marker. This function never
// updates subscription snapshots or historical immutable revisions.
func BootstrapNativePlans(ctx context.Context, db *sql.DB, profile string, ready []string, actor string, discardDemo bool) error {
	if profile != "ubuntu-26.04-native" {
		return errors.New("plan bootstrap requires ubuntu-26.04-native")
	}
	if version, err := ResolveReadyPHPVersion(Limits{PHPAllowlist: "8.5", DefaultPHPVersion: "8.5"}, "8.5", ready); err != nil || version != "8.5" {
		return errors.New("plan bootstrap requires ready PHP 8.5")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `LOCK TABLE plans,plan_service_presets,subscriptions,sites,plan_revisions,audit_events IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return err
	}
	var populated bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM subscriptions) OR EXISTS(SELECT 1 FROM sites)`).Scan(&populated); err != nil {
		return err
	}
	if populated && discardDemo {
		if err = discardPristineDemoSubscriptionsTx(ctx, tx); err != nil {
			return err
		}
		populated = false
	}
	if populated {
		return errors.New("plan bootstrap requires no subscriptions or sites")
	}
	before, err := bootstrapFingerprintsTx(ctx, tx)
	if err != nil {
		return err
	}
	var receipt []byte
	err = tx.QueryRowContext(ctx, `SELECT metadata->'fingerprints' FROM audit_events WHERE action='platform.plans_bootstrapped' AND metadata->>'profile'=$1 ORDER BY id DESC LIMIT 1`, profile).Scan(&receipt)
	if err == nil {
		var committed map[string]string
		if err = json.Unmarshal(receipt, &committed); err != nil {
			return fmt.Errorf("invalid plan bootstrap receipt: %w", err)
		}
		if !reflect.DeepEqual(before, committed) {
			return errors.New("bootstrapped plans have changed; refusing retry")
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if !reflect.DeepEqual(before, nativeBootstrapSeedFingerprints) {
		return errors.New("plan bootstrap requires untouched built-in definitions only")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE plans SET php_allowlist='8.5',default_php_version='8.5',hosting_policy=jsonb_set(jsonb_set(hosting_policy,'{php,default_version}','"8.5"'),'{php,allowed_versions}','["8.5"]'),revision=revision+1,updated_at=now() WHERE reseller_id IS NULL AND name IN ('Starter','Business','Pro')`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE plan_service_presets ps SET php=jsonb_set(jsonb_set(ps.php,'{default_version}','"8.5"'),'{allowed_versions}','"8.5"') FROM plans p WHERE p.id=ps.plan_id AND p.reseller_id IS NULL AND p.name IN ('Starter','Business','Pro')`); err != nil {
		return err
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "installer"
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO plan_revisions(plan_id,revision,lifecycle_status,definition,definition_hash,actor_label,change_reason)
 SELECT p.id,p.revision,p.lifecycle_status,`+bootstrapDefinitionSQL+`,encode(sha256(convert_to((`+bootstrapDefinitionSQL+`)::text,'UTF8')),'hex'),$1,'Bootstrap untouched built-in plans for ubuntu-26.04-native'
 FROM plans p JOIN plan_service_presets ps ON ps.plan_id=p.id WHERE p.reseller_id IS NULL AND p.name IN ('Starter','Business','Pro')`, actor); err != nil {
		return err
	}
	after, err := bootstrapFingerprintsTx(ctx, tx)
	if err != nil {
		return err
	}
	metadata, err := json.Marshal(map[string]any{"profile": profile, "fingerprints": after, "discarded_demo_subscriptions": discardDemo})
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(actor_label,action,target_type,metadata) VALUES($1,'platform.plans_bootstrapped','platform',$2)`, actor, metadata); err != nil {
		return err
	}
	return tx.Commit()
}

func bootstrapFingerprintsTx(ctx context.Context, tx *sql.Tx) (map[string]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT p.name,encode(sha256(convert_to(jsonb_build_object('plan',to_jsonb(p)-'id'-'created_at'-'updated_at'-'last_validated_at'-'readiness_error','presets',`+planPresetJSON+`)::text,'UTF8')),'hex') FROM plans p LEFT JOIN plan_service_presets ps ON ps.plan_id=p.id ORDER BY p.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	fingerprints := make(map[string]string)
	for rows.Next() {
		var name, hash string
		if err = rows.Scan(&name, &hash); err != nil {
			return nil, err
		}
		if _, exists := fingerprints[name]; exists {
			return nil, errors.New("duplicate built-in plan name")
		}
		fingerprints[name] = hash
	}
	return fingerprints, rows.Err()
}

// The two demo subscriptions are historical migration artifacts. This explicit
// installer-only path removes them only when every seeded identity, entitlement
// and account is byte-for-byte pristine (apart from creation/update timestamps).
func discardPristineDemoSubscriptionsTx(ctx context.Context, tx *sql.Tx) error {
	expected := map[string]string{
		"users":                        "d5f8b20e4ccd40166ed9c17be13dd1fc926fdcd7eb12a063fcb4516989d6c884",
		"customers":                    "4cb631856a9a112862e481be0e119464f1c1609eff8864a67b1123e52e97deaf",
		"subscriptions":                "175018ba061e8948b6574234993bd3c0afce8c514b3239788db5ebfa5a31ed36",
		"subscription_entitlements":    "27982273e15ca81d747fef4366c906b3a5be468bd4fcab74b7afc2fa5cfbb093",
		"subscription_system_accounts": "a7f266f49d2a28bc005fae263a0cb12ca3a32b4083a58a530f54461cefc46fa7",
	}
	emptyTables := []string{"sites", "databases", "database_create_requests", "backups", "sftp_access_identities", "scheduled_tasks", "mail_domains", "mailboxes", "mail_aliases", "application_instances", "ftp_accounts", "subscription_addons", "subscription_policy_overrides", "billing_accounts", "api_keys", "reseller_accounts", "reseller_subscriptions", "account_quotas", "subscription_usage_current", "subscription_usage_history", "addon_plans", "php_applications", "valkey_instances", "dns_zones", "sessions", "user_totp", "user_recovery_codes", "customer_login_tokens", "audit_events"}
	// Fixed table identifiers only. Lock all the inspected tables before checking
	// any of them, so a concurrent user/resource edit cannot race demo removal.
	tables := append([]string{"users", "customers", "subscriptions", "subscription_entitlements", "subscription_system_accounts"}, emptyTables...)
	if _, err := tx.ExecContext(ctx, "LOCK TABLE "+strings.Join(tables, ",")+" IN SHARE ROW EXCLUSIVE MODE"); err != nil {
		return err
	}
	for table, want := range expected {
		var hash string
		query := `SELECT encode(sha256(convert_to(COALESCE(jsonb_agg(to_jsonb(t)-'created_at'-'updated_at' ORDER BY COALESCE(to_jsonb(t)->>'id',to_jsonb(t)->>'subscription_id')),'[]'::jsonb)::text,'UTF8')),'hex') FROM ` + table + ` t`
		if err := tx.QueryRowContext(ctx, query).Scan(&hash); err != nil {
			return err
		}
		if hash != want {
			return fmt.Errorf("refusing to discard changed demo %s", table)
		}
	}
	for _, table := range emptyTables {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM `+table+`)`).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("refusing to discard demo subscriptions with existing %s", table)
		}
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM subscriptions WHERE id IN (1,2)`)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 2 {
		return errors.New("expected exactly two pristine demo subscriptions")
	}
	return nil
}
