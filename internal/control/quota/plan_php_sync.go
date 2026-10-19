package quota

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	controlpolicy "github.com/nakroteck/nakpanel/internal/control/policy"
	"github.com/nakroteck/nakpanel/internal/types"
)

type planSyncCause uint8

const (
	resolvePlanHistory planSyncCause = iota
	requireFullSync
)

type planPHPSyncDecision struct {
	PHPOnly                      bool
	BaseRevision, SourceRevision int
	PHPVersions                  []string
	DefaultPHPVersion            string
}

type planPHPPolicyConflict struct{ cause error }

func (e *planPHPPolicyConflict) Error() string {
	return "PHP-only intent conflicts with an existing effective policy: " + e.cause.Error()
}

func resolvePlanPHPSyncTx(ctx context.Context, tx *sql.Tx, subscriptionID int64, currentPlan Plan, composed types.SubscriptionEntitlements, cause planSyncCause) (planPHPSyncDecision, error) {
	full := planPHPSyncDecision{}
	if cause == requireFullSync {
		return full, nil
	}
	var cursor int
	var mode string
	if err := tx.QueryRowContext(ctx, `SELECT plan_revision,sync_mode FROM subscriptions WHERE id=$1`, subscriptionID).Scan(&cursor, &mode); err != nil {
		return full, err
	}
	if mode != "synced" || cursor <= 0 || cursor > currentPlan.Revision {
		return full, nil
	}
	start := cursor + 1
	if cursor == currentPlan.Revision {
		start = cursor
	}
	rows, err := tx.QueryContext(ctx, `SELECT revision,definition,definition_hash=encode(sha256(convert_to(definition::text,'UTF8')),'hex') FROM plan_revisions WHERE plan_id=$1 AND revision>=$2 AND revision<=$3 ORDER BY revision`, currentPlan.ID, start, currentPlan.Revision)
	if err != nil {
		return full, err
	}
	type revision struct {
		number     int
		definition []byte
		hashOK     bool
	}
	var revisions []revision
	for rows.Next() {
		var item revision
		if err = rows.Scan(&item.number, &item.definition, &item.hashOK); err != nil {
			rows.Close()
			return full, err
		}
		revisions = append(revisions, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return full, err
	}
	rows.Close()
	eligible := len(revisions) == currentPlan.Revision-start+1
	operations := make([]planPHPOperation, 0, len(revisions))
	// Validate every explicitly marked row before deciding eligibility. An
	// ordinary revision, gap or changed input cannot hide a later corrupt marker.
	for index, item := range revisions {
		if item.number != start+index {
			eligible = false
		}
		var definition map[string]json.RawMessage
		if err = json.Unmarshal(item.definition, &definition); err != nil {
			return full, &PlanPHPIntegrityError{PlanID: currentPlan.ID, Revision: item.number, Field: "definition"}
		}
		marker, marked := definition["_operation"]
		if !marked {
			eligible = false
			continue
		}
		invalid := func() (planPHPSyncDecision, error) {
			return full, &PlanPHPIntegrityError{PlanID: currentPlan.ID, Revision: item.number, Field: "_operation"}
		}
		var operation planPHPOperation
		decoder := json.NewDecoder(bytes.NewReader(marker))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&operation) != nil || !item.hashOK || operation.SchemaVersion != 1 || operation.Kind != "php_versions_only" || operation.FromRevision != item.number-1 || operation.ToRevision != item.number || operation.SubscriptionInputs == nil {
			return invalid()
		}
		normalized, err := NormalizePlanPHPVersions(PlanPHPVersionsInput{ExpectedRevision: operation.FromRevision, PHPVersions: operation.PHPVersions, DefaultPHPVersion: operation.DefaultPHPVersion, ChangeReason: "validate immutable operation"})
		if err != nil || strings.Join(normalized.PHPVersions, ",") != strings.Join(operation.PHPVersions, ",") {
			return invalid()
		}
		var rawPlan struct {
			ID        int64  `json:"id"`
			Revision  int    `json:"revision"`
			Allowlist string `json:"php_allowlist"`
			Default   string `json:"default_php_version"`
		}
		if json.Unmarshal(definition["plan"], &rawPlan) != nil || rawPlan.ID != currentPlan.ID || rawPlan.Revision != item.number || rawPlan.Allowlist != strings.Join(operation.PHPVersions, ",") || rawPlan.Default != operation.DefaultPHPVersion {
			return invalid()
		}
		var previousID int64
		for _, participant := range operation.SubscriptionInputs {
			digestBytes, digestError := hex.DecodeString(participant.AddonsSHA256)
			if participant.SubscriptionID <= previousID || len(participant.AddonsSHA256) != 64 || digestError != nil || hex.EncodeToString(digestBytes) != participant.AddonsSHA256 {
				return invalid()
			}
			previousID = participant.SubscriptionID
		}
		operations = append(operations, operation)
	}
	if !eligible {
		return full, nil
	}
	digest, err := planPHPAddonDigestTx(ctx, tx, subscriptionID)
	if err != nil {
		return full, err
	}
	for _, operation := range operations {
		found := false
		for _, participant := range operation.SubscriptionInputs {
			if participant.SubscriptionID == subscriptionID {
				if participant.AddonsSHA256 != digest {
					return full, nil
				}
				found = true
			}
		}
		if !found {
			return full, nil
		}
	}
	var matches bool
	err = tx.QueryRowContext(ctx, `SELECT r.definition->'plan'=d.raw->'plan' AND r.definition->'presets' IS NOT DISTINCT FROM d.raw->'presets' FROM plans p LEFT JOIN plan_service_presets ps ON ps.plan_id=p.id JOIN plan_revisions r ON r.plan_id=p.id AND r.revision=p.revision CROSS JOIN LATERAL(SELECT `+planPHPRawDefinitionSQL+` AS raw)d WHERE p.id=$1`, currentPlan.ID).Scan(&matches)
	if err != nil {
		return full, err
	}
	if !matches {
		return full, &PlanPHPIntegrityError{PlanID: currentPlan.ID, Revision: currentPlan.Revision, Field: "current_definition"}
	}
	return planPHPSyncDecision{PHPOnly: true, BaseRevision: currentPlan.Revision, SourceRevision: composed.SourceRevision, PHPVersions: strings.Split(composed.PHPAllowlist, ","), DefaultPHPVersion: composed.DefaultPHPVersion}, nil
}

func projectPlanPHPEntitlementsTx(ctx context.Context, tx *sql.Tx, id int64, composed types.SubscriptionEntitlements) (types.SubscriptionEntitlements, error) {
	current, err := readSubscriptionEntitlementsTx(ctx, tx, id)
	if err != nil {
		return current, err
	}
	var policy, presets []byte
	if err = tx.QueryRowContext(ctx, `SELECT hosting_policy,service_presets FROM subscription_entitlements WHERE subscription_id=$1`, id).Scan(&policy, &presets); err != nil {
		return current, err
	}
	versions := strings.Split(composed.PHPAllowlist, ",")
	policy, err = patchRawPHPPolicy(policy, versions, composed.DefaultPHPVersion)
	if err != nil {
		return current, rejectPlanPHP(err)
	}
	presets, err = patchRawPHPPresets(presets, versions, composed.DefaultPHPVersion)
	if err != nil {
		return current, rejectPlanPHP(err)
	}
	if err = json.Unmarshal(policy, &current.HostingPolicy); err != nil {
		return current, rejectPlanPHP(err)
	}
	if err = json.Unmarshal(presets, &current.ServicePresets); err != nil {
		return current, rejectPlanPHP(err)
	}
	current.PHPAllowlist = composed.PHPAllowlist
	current.DefaultPHPVersion = composed.DefaultPHPVersion
	current.SourceRevision = composed.SourceRevision
	if err = ValidateEntitlements(current); err != nil {
		return current, rejectPlanPHP(err)
	}
	if err = validatePlanPHPPolicyProjectionTx(ctx, tx, id, current.HostingPolicy); err != nil {
		return current, err
	}
	return current, nil
}

func validatePlanPHPPolicyProjectionTx(ctx context.Context, tx *sql.Tx, id int64, base types.HostingPolicy) error {
	var subscriptionPatch []byte
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT policy_patch FROM subscription_policy_overrides WHERE subscription_id=$1),'{}'::jsonb)`, id).Scan(&subscriptionPatch); err != nil {
		return err
	}
	if _, err := controlpolicy.Resolve(base, subscriptionPatch, nil); err != nil {
		return &planPHPPolicyConflict{cause: err}
	}
	rows, err := tx.QueryContext(ctx, `SELECT o.policy_patch FROM sites s JOIN site_policy_overrides o ON o.site_id=s.id WHERE s.subscription_id=$1 ORDER BY s.id`, id)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var sitePatch []byte
		if err = rows.Scan(&sitePatch); err != nil {
			return err
		}
		if _, err = controlpolicy.Resolve(base, subscriptionPatch, sitePatch); err != nil {
			return &planPHPPolicyConflict{cause: err}
		}
	}
	return rows.Err()
}

func writePlanPHPEntitlementsTx(ctx context.Context, tx *sql.Tx, id int64, decision planPHPSyncDecision) error {
	if !decision.PHPOnly {
		return errors.New("PHP-only snapshot writer requires validated revision provenance")
	}
	allowed, err := json.Marshal(decision.PHPVersions)
	if err != nil {
		return err
	}
	hosting := planPHPVersionMirrorsSQL("service_presets->'hosting'", "allowed_php_versions", "default_php_version", "$2::jsonb")
	php := planPHPVersionMirrorsSQL("service_presets->'php'", "allowed_versions", "default_version", "to_jsonb($4::text)")
	presets := `CASE WHEN service_presets ? 'hosting' THEN jsonb_set(service_presets,'{hosting}',` + hosting + `,false) ELSE service_presets END`
	presets = `CASE WHEN service_presets ? 'php' THEN jsonb_set((` + presets + `),'{php}',` + php + `,false) ELSE (` + presets + `) END`
	result, err := tx.ExecContext(ctx, `UPDATE subscription_entitlements SET php_allowlist=$4,default_php_version=$3,source_revision=$5,hosting_policy=jsonb_set(hosting_policy,'{php}',COALESCE(hosting_policy->'php','{}'::jsonb)||jsonb_build_object('allowed_versions',$2::jsonb,'default_version',$3::text),true),service_presets=`+presets+`,updated_at=now() WHERE subscription_id=$1`, id, string(allowed), decision.DefaultPHPVersion, strings.Join(decision.PHPVersions, ","), decision.SourceRevision)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count != 1 {
		return sql.ErrNoRows
	}
	return err
}
