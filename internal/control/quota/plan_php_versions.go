package quota

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nakroteck/nakpanel/internal/control/auth"
	controlpolicy "github.com/nakroteck/nakpanel/internal/control/policy"
	"github.com/nakroteck/nakpanel/internal/types"
)

type PlanPHPVersionsInput struct {
	ExpectedRevision  int
	PHPVersions       []string
	DefaultPHPVersion string
	ChangeReason      string
}

// PlanPHPVersionsCommand is an internal manager-to-store command. Its actor,
// provider scope and ready inventory must never be decoded from an HTTP form.
type PlanPHPVersionsCommand struct {
	PlanID           int64
	Input            PlanPHPVersionsInput
	Actor            auth.SessionUser
	Scope            types.ProviderScope
	ReadyPHPVersions []string
}

type PlanPHPBlocker struct {
	Code            string  `json:"code"`
	Message         string  `json:"message"`
	SubscriptionIDs []int64 `json:"subscription_ids,omitempty"`
}
type PlanPHPVersionsPreview struct {
	PlanID   int64             `json:"plan_id"`
	Revision int               `json:"revision"`
	NoChange bool              `json:"no_change"`
	Preview  types.PlanPreview `json:"preview"`
	Blockers []PlanPHPBlocker  `json:"blockers,omitempty"`
}
type PlanPHPVersionsResult struct {
	PlanID    int64  `json:"plan_id"`
	Revision  int    `json:"revision"`
	Changed   bool   `json:"changed"`
	SyncState string `json:"sync_state"`
}
type PlanPHPConflictCode string
type PlanPHPConflictError struct {
	Code                              PlanPHPConflictCode
	PlanID                            int64
	ExpectedRevision, CurrentRevision int
	SubscriptionIDs                   []int64
}

func (e *PlanPHPConflictError) Error() string { return string(e.Code) }

type PlanPHPIntegrityError struct {
	PlanID   int64
	Revision int
	Field    string
}

func (e *PlanPHPIntegrityError) Error() string { return "plan PHP revision integrity check failed" }

type PlanPHPReadinessError struct {
	UnreadyVersions []string
	Cause           error
}

func (e *PlanPHPReadinessError) Error() string {
	if e.Cause != nil {
		return "authoritative PHP readiness is unavailable"
	}
	return "requested PHP versions are not ready: " + strings.Join(e.UnreadyVersions, ", ")
}
func (e *PlanPHPReadinessError) Unwrap() error { return e.Cause }

// PlanPHPRejectedError marks an explicitly checked input/domain refusal. Other
// unclassified errors may be transport failures and must not be exposed as input.
type PlanPHPRejectedError struct{ Cause error }

func (e *PlanPHPRejectedError) Error() string { return e.Cause.Error() }
func (e *PlanPHPRejectedError) Unwrap() error { return e.Cause }
func rejectPlanPHP(err error) error {
	if err == nil {
		return nil
	}
	return &PlanPHPRejectedError{Cause: err}
}

var planPHPVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func NormalizePlanPHPVersions(input PlanPHPVersionsInput) (PlanPHPVersionsInput, error) {
	if input.ExpectedRevision <= 0 || input.ExpectedRevision >= maxPlanLimit {
		return input, rejectPlanPHP(errors.New("expected_revision must be a positive revision with room for an update"))
	}
	if len(input.PHPVersions) == 0 || len(input.PHPVersions) > 32 {
		return input, rejectPlanPHP(errors.New("one to 32 php_versions values are required"))
	}
	versions := make(map[string]struct{}, len(input.PHPVersions))
	for _, item := range input.PHPVersions {
		item = strings.TrimSpace(item)
		if len(item) > 16 || !planPHPVersion.MatchString(item) {
			return input, rejectPlanPHP(errors.New("php_versions must contain individual major.minor versions"))
		}
		versions[item] = struct{}{}
	}
	input.PHPVersions = make([]string, 0, len(versions))
	for item := range versions {
		input.PHPVersions = append(input.PHPVersions, item)
	}
	sort.Strings(input.PHPVersions)
	input.DefaultPHPVersion = strings.TrimSpace(input.DefaultPHPVersion)
	if _, ok := versions[input.DefaultPHPVersion]; !ok {
		return input, rejectPlanPHP(errors.New("default_php_version must be in php_versions"))
	}
	input.ChangeReason = strings.TrimSpace(input.ChangeReason)
	if !utf8.ValidString(input.ChangeReason) || len(input.ChangeReason) == 0 || len(input.ChangeReason) > 1024 {
		return input, rejectPlanPHP(errors.New("change_reason must contain 1 to 1024 UTF-8 bytes"))
	}
	return input, nil
}

func checkPlanPHPReady(input PlanPHPVersionsInput, ready []string) error {
	if len(ready) == 0 {
		return &PlanPHPReadinessError{Cause: errors.New("empty authoritative inventory")}
	}
	available := make(map[string]bool, len(ready))
	for _, version := range ready {
		available[strings.TrimSpace(version)] = true
	}
	var missing []string
	for _, version := range input.PHPVersions {
		if !available[version] {
			missing = append(missing, version)
		}
	}
	if len(missing) != 0 {
		return &PlanPHPReadinessError{UnreadyVersions: missing}
	}
	return nil
}

func checkPlanPHPCommand(cmd PlanPHPVersionsCommand, plan Plan) error {
	if cmd.Actor.ID <= 0 || cmd.Actor.ID != cmd.Scope.ActorUserID || string(cmd.Actor.Role) != cmd.Scope.Role {
		return ErrProviderScope
	}
	switch cmd.Actor.Role {
	case auth.RoleAdmin:
	case auth.RoleReseller:
		if cmd.Scope.ResellerID <= 0 || plan.ResellerID != cmd.Scope.ResellerID {
			return ErrProviderScope
		}
	default:
		return ErrProviderScope
	}
	if cmd.Input.ExpectedRevision != plan.Revision {
		return &PlanPHPConflictError{Code: "stale_revision", PlanID: plan.ID, ExpectedRevision: cmd.Input.ExpectedRevision, CurrentRevision: plan.Revision}
	}
	return nil
}

func candidatePlanPHP(plan Plan, input PlanPHPVersionsInput) Plan {
	plan.PHPAllowlist = strings.Join(input.PHPVersions, ",")
	plan.DefaultPHPVersion = input.DefaultPHPVersion
	plan.HostingPolicy = EffectivePlanHostingPolicy(plan)
	plan.HostingPolicy.PHP.AllowedVersions = append([]string(nil), input.PHPVersions...)
	plan.HostingPolicy.PHP.DefaultVersion = input.DefaultPHPVersion
	plan.Presets.Hosting.AllowedPHPVersions = append([]string(nil), input.PHPVersions...)
	plan.Presets.Hosting.DefaultPHPVersion = input.DefaultPHPVersion
	return plan
}

func readPlanPHPTx(ctx context.Context, tx *sql.Tx, id int64) (Plan, error) {
	return scanPlanWithPresets(tx.QueryRowContext(ctx, `SELECT `+planCoreColumns+`,`+planPresetJSON+` FROM plans p LEFT JOIN plan_service_presets ps ON ps.plan_id=p.id WHERE p.id=$1`, id))
}

// JSONB already discarded lexical formatting. Decode raw members only to check
// shape and build typed validation projections; all writes below patch SQL leaves.
func rawPHPObject(raw []byte) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, errors.New("PHP version container must be an object")
	}
	return object, nil
}

func patchRawPHPMembers(raw []byte, fields map[string]any, mirrorsOnly bool) ([]byte, error) {
	object, err := rawPHPObject(raw)
	if err != nil {
		return nil, err
	}
	for key, value := range fields {
		old, present := object[key]
		if mirrorsOnly && !present {
			continue
		}
		if present {
			switch value.(type) {
			case string:
				var v string
				if string(old) == "null" || json.Unmarshal(old, &v) != nil {
					return nil, fmt.Errorf("invalid PHP mirror %s", key)
				}
			case []string:
				var v []string
				if string(old) == "null" || json.Unmarshal(old, &v) != nil {
					return nil, fmt.Errorf("invalid PHP mirror %s", key)
				}
			}
		}
		object[key], err = json.Marshal(value)
		if err != nil {
			return nil, err
		}
	}
	return json.Marshal(object)
}

func patchRawPHPPolicy(raw []byte, versions []string, defaultVersion string) ([]byte, error) {
	object, err := rawPHPObject(raw)
	if err != nil {
		return nil, err
	}
	php, ok := object["php"]
	if !ok {
		php = []byte(`{}`)
	}
	object["php"], err = patchRawPHPMembers(php, map[string]any{"allowed_versions": versions, "default_version": defaultVersion}, false)
	if err != nil {
		return nil, err
	}
	return json.Marshal(object)
}

func patchRawPHPPresets(raw []byte, versions []string, defaultVersion string) ([]byte, error) {
	object, err := rawPHPObject(raw)
	if err != nil {
		return nil, err
	}
	for _, group := range []struct {
		key    string
		fields map[string]any
	}{
		{"hosting", map[string]any{"allowed_php_versions": versions, "default_php_version": defaultVersion}},
		{"php", map[string]any{"allowed_versions": strings.Join(versions, ","), "default_version": defaultVersion}},
	} {
		if child, ok := object[group.key]; ok {
			object[group.key], err = patchRawPHPMembers(child, group.fields, true)
			if err != nil {
				return nil, err
			}
		}
	}
	return json.Marshal(object)
}

const planPHPRawDefinitionSQL = `jsonb_build_object('plan',to_jsonb(p)-'created_at'-'updated_at'-'last_validated_at'-'readiness_error','presets',to_jsonb(ps)-'created_at'-'updated_at')`

type planPHPParticipant struct {
	SubscriptionID int64  `json:"subscription_id"`
	AddonsSHA256   string `json:"addons_sha256"`
}
type planPHPOperation struct {
	SchemaVersion      int                  `json:"schema_version"`
	Kind               string               `json:"kind"`
	FromRevision       int                  `json:"from_revision"`
	ToRevision         int                  `json:"to_revision"`
	PHPVersions        []string             `json:"php_versions"`
	DefaultPHPVersion  string               `json:"default_php_version"`
	SubscriptionInputs []planPHPParticipant `json:"subscription_inputs"`
}

func planPHPAddonDigestTx(ctx context.Context, tx *sql.Tx, id int64) (string, error) {
	var digest string
	err := tx.QueryRowContext(ctx, `SELECT encode(sha256(convert_to(COALESCE(jsonb_agg(to_jsonb(a)-'created_at'-'updated_at' ORDER BY a.id),'[]'::jsonb)::text,'UTF8')),'hex') FROM subscription_addons sa JOIN addon_plans a ON a.id=sa.addon_plan_id WHERE sa.subscription_id=$1`, id).Scan(&digest)
	return digest, err
}

func planPHPVersionMirrorsSQL(expression, allowedKey, defaultKey, allowedParam string) string {
	return `CASE WHEN ` + expression + ` ? '` + defaultKey + `' THEN jsonb_set(CASE WHEN ` + expression + ` ? '` + allowedKey + `' THEN jsonb_set(` + expression + `,'{` + allowedKey + `}',` + allowedParam + `,false) ELSE ` + expression + ` END,'{` + defaultKey + `}',to_jsonb($3::text),false) ELSE CASE WHEN ` + expression + ` ? '` + allowedKey + `' THEN jsonb_set(` + expression + `,'{` + allowedKey + `}',` + allowedParam + `,false) ELSE ` + expression + ` END END`
}

func planPHPValidateRawTx(ctx context.Context, tx *sql.Tx, plan Plan, input PlanPHPVersionsInput) error {
	var policy, presets []byte
	if err := tx.QueryRowContext(ctx, `SELECT p.hosting_policy,to_jsonb(ps) FROM plans p LEFT JOIN plan_service_presets ps ON ps.plan_id=p.id WHERE p.id=$1`, plan.ID).Scan(&policy, &presets); err != nil {
		return err
	}
	if err := validatePlanPHPMirrors(plan, policy, presets); err != nil {
		return rejectPlanPHP(err)
	}
	patched, err := patchRawPHPPolicy(policy, input.PHPVersions, input.DefaultPHPVersion)
	if err != nil {
		return rejectPlanPHP(err)
	}
	var typed types.HostingPolicy
	if err = json.Unmarshal(patched, &typed); err != nil {
		return rejectPlanPHP(err)
	}
	if err = controlpolicy.Validate(EffectivePlanHostingPolicy(candidatePlanPHP(plan, input))); err != nil {
		return rejectPlanPHP(err)
	}
	if len(presets) != 0 {
		_, err = patchRawPHPPresets(presets, input.PHPVersions, input.DefaultPHPVersion)
	}
	return rejectPlanPHP(err)
}

func validatePlanPHPMirrors(plan Plan, policy, presets []byte) error {
	check := func(raw []byte, allowedKey, defaultKey string, csv bool) error {
		object, err := rawPHPObject(raw)
		if err != nil {
			return err
		}
		if allowed, present := object[allowedKey]; present {
			var versions []string
			if csv {
				var value string
				if err = json.Unmarshal(allowed, &value); err != nil {
					return err
				}
				versions = strings.Split(value, ",")
			} else if err = json.Unmarshal(allowed, &versions); err != nil {
				return err
			}
			if !samePHPVersionSet(versions, strings.Split(plan.PHPAllowlist, ",")) {
				return errors.New("stored PHP version mirrors disagree")
			}
		}
		if value, present := object[defaultKey]; present {
			var version string
			if err = json.Unmarshal(value, &version); err != nil {
				return err
			}
			if version != plan.DefaultPHPVersion {
				return errors.New("stored PHP default mirrors disagree")
			}
		}
		return nil
	}
	object, err := rawPHPObject(policy)
	if err != nil {
		return err
	}
	if php, present := object["php"]; present {
		if err = check(php, "allowed_versions", "default_version", false); err != nil {
			return err
		}
	}
	if len(presets) == 0 {
		return nil
	}
	object, err = rawPHPObject(presets)
	if err != nil {
		return err
	}
	if hosting, present := object["hosting"]; present {
		if err = check(hosting, "allowed_php_versions", "default_php_version", false); err != nil {
			return err
		}
	}
	if php, present := object["php"]; present {
		return check(php, "allowed_versions", "default_version", true)
	}
	return nil
}

func (s *SQLStore) PreviewPlanPHPVersions(ctx context.Context, cmd PlanPHPVersionsCommand) (PlanPHPVersionsPreview, error) {
	input, err := NormalizePlanPHPVersions(cmd.Input)
	if err != nil {
		return PlanPHPVersionsPreview{}, err
	}
	cmd.Input = input
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return PlanPHPVersionsPreview{}, err
	}
	defer tx.Rollback()
	plan, err := readPlanPHPTx(ctx, tx, cmd.PlanID)
	if err != nil {
		return PlanPHPVersionsPreview{}, err
	}
	if err = checkPlanPHPCommand(cmd, plan); err != nil {
		return PlanPHPVersionsPreview{}, err
	}
	if err = planPHPValidateRawTx(ctx, tx, plan, input); err != nil {
		return PlanPHPVersionsPreview{}, err
	}
	view, _, err := previewPlanPHPTx(ctx, tx, plan, input, false)
	if err != nil {
		return view, err
	}
	if err = checkPlanPHPReady(input, cmd.ReadyPHPVersions); err != nil {
		view.Preview.Allowed = false
		view.Blockers = append(view.Blockers, PlanPHPBlocker{Code: "php_version_unready", Message: err.Error()})
		view.Preview.BlockingReasons = append(view.Preview.BlockingReasons, err.Error())
	}
	return view, tx.Commit()
}

func (s *SQLStore) UpdatePlanPHPVersions(ctx context.Context, cmd PlanPHPVersionsCommand) (result PlanPHPVersionsResult, err error) {
	input, err := NormalizePlanPHPVersions(cmd.Input)
	if err != nil {
		return result, err
	}
	cmd.Input = input
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	defer func() {
		if err != nil {
			var state interface{ SQLState() string }
			if errors.As(err, &state) && state.SQLState() == "55P03" {
				err = &PlanPHPConflictError{Code: "plan_busy", PlanID: cmd.PlanID, ExpectedRevision: input.ExpectedRevision}
			}
		}
	}()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout='250ms';SET LOCAL statement_timeout='2s';LOCK TABLE subscriptions,subscription_addons,addon_plans IN SHARE ROW EXCLUSIVE MODE NOWAIT`); err != nil {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT id FROM plans WHERE id=$1 FOR UPDATE NOWAIT`, cmd.PlanID); err != nil {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT plan_id FROM plan_service_presets WHERE plan_id=$1 FOR UPDATE NOWAIT`, cmd.PlanID); err != nil {
		return result, err
	}
	plan, err := readPlanPHPTx(ctx, tx, cmd.PlanID)
	if err != nil {
		return result, err
	}
	if err = checkPlanPHPCommand(cmd, plan); err != nil {
		return result, err
	}
	if err = checkPlanPHPReady(input, cmd.ReadyPHPVersions); err != nil {
		return result, err
	}
	if err = planPHPValidateRawTx(ctx, tx, plan, input); err != nil {
		return result, err
	}
	result = PlanPHPVersionsResult{PlanID: plan.ID, Revision: plan.Revision, SyncState: "in_sync"}
	if samePHPVersionSet(strings.Split(plan.PHPAllowlist, ","), input.PHPVersions) && plan.DefaultPHPVersion == input.DefaultPHPVersion {
		result.SyncState, err = planPHPCurrentSyncStateTx(ctx, tx, plan.ID, plan.Revision)
		if err != nil {
			return result, err
		}
		return result, tx.Commit()
	}
	view, participants, err := previewPlanPHPTx(ctx, tx, plan, input, true)
	if err != nil {
		return result, err
	}
	if len(view.Blockers) > 0 {
		return result, &PlanPHPConflictError{Code: "plan_sync_pending", PlanID: plan.ID, ExpectedRevision: input.ExpectedRevision, CurrentRevision: plan.Revision}
	}
	if !view.Preview.Allowed {
		return result, rejectPlanPHP(errors.New(strings.Join(view.Preview.BlockingReasons, "; ")))
	}
	candidate := candidatePlanPHP(plan, input)
	if err = validatePlanWithinResellerTx(ctx, tx, candidate); err != nil {
		return result, err
	}
	if err = enforceCommittedAllocationCapTx(ctx, tx); err != nil {
		return result, err
	}
	allowed, _ := json.Marshal(input.PHPVersions)
	if _, err = tx.ExecContext(ctx, `UPDATE plans SET php_allowlist=$4,default_php_version=$3,hosting_policy=jsonb_set(hosting_policy,'{php}',COALESCE(hosting_policy->'php','{}'::jsonb)||jsonb_build_object('allowed_versions',$2::jsonb,'default_version',$3::text),true),revision=revision+1,updated_at=now() WHERE id=$1`, plan.ID, string(allowed), input.DefaultPHPVersion, strings.Join(input.PHPVersions, ",")); err != nil {
		return result, err
	}
	presetSQL := `UPDATE plan_service_presets SET hosting=` + planPHPVersionMirrorsSQL("hosting", "allowed_php_versions", "default_php_version", "$2::jsonb") + `,php=` + planPHPVersionMirrorsSQL("php", "allowed_versions", "default_version", "to_jsonb($4::text)") + ` WHERE plan_id=$1`
	if _, err = tx.ExecContext(ctx, presetSQL, plan.ID, string(allowed), input.DefaultPHPVersion, strings.Join(input.PHPVersions, ",")); err != nil {
		return result, err
	}
	op := planPHPOperation{SchemaVersion: 1, Kind: "php_versions_only", FromRevision: plan.Revision, ToRevision: plan.Revision + 1, PHPVersions: input.PHPVersions, DefaultPHPVersion: input.DefaultPHPVersion, SubscriptionInputs: participants}
	marker, _ := json.Marshal(op)
	var hash string
	if err = tx.QueryRowContext(ctx, `INSERT INTO plan_revisions(plan_id,revision,lifecycle_status,definition,definition_hash,actor_user_id,actor_label,change_reason) SELECT p.id,p.revision,p.lifecycle_status,d.definition,encode(sha256(convert_to(d.definition::text,'UTF8')),'hex'),$3,$4,$5 FROM plans p LEFT JOIN plan_service_presets ps ON ps.plan_id=p.id CROSS JOIN LATERAL(SELECT `+planPHPRawDefinitionSQL+` || jsonb_build_object('_operation',$2::jsonb) AS definition)d WHERE p.id=$1 RETURNING definition_hash`, plan.ID, string(marker), cmd.Actor.ID, cmd.Actor.Email, input.ChangeReason).Scan(&hash); err != nil {
		return result, err
	}
	if s.river != nil {
		if _, err = tx.ExecContext(ctx, `UPDATE subscriptions SET sync_status='pending',sync_error='',updated_at=now() WHERE plan_id=$1 AND sync_mode='synced'`, plan.ID); err != nil {
			return result, err
		}
		if _, err = s.river.InsertTx(ctx, tx, NewSyncPlanArgs(plan.ID, int64(plan.Revision+1)), nil); err != nil {
			return result, err
		}
	} else {
		for _, participant := range participants {
			if err = syncSubscriptionTx(ctx, tx, participant.SubscriptionID, false); err != nil {
				return result, err
			}
			if _, err = EnqueueSubscriptionConvergenceTx(ctx, tx, nil, participant.SubscriptionID); err != nil {
				return result, err
			}
		}
	}
	if err = enforceCommittedAllocationCapTx(ctx, tx); err != nil {
		return result, err
	}
	metadata, _ := json.Marshal(map[string]any{"operation": "php_versions_only", "old_revision": plan.Revision, "new_revision": plan.Revision + 1, "definition_hash": hash, "change_reason": input.ChangeReason, "php_versions": input.PHPVersions, "default_php_version": input.DefaultPHPVersion, "affected": len(participants), "excluded": view.Preview.LockedSubscriptions + view.Preview.CustomSubscriptions})
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(actor_user_id,actor_label,action,target_type,target_id,metadata)VALUES($1,$2,'plan.saved','plan',$3,$4)`, cmd.Actor.ID, cmd.Actor.Email, plan.ID, string(metadata)); err != nil {
		return result, err
	}
	result.Revision++
	result.Changed = true
	if len(participants) > 0 {
		result.SyncState = "pending"
	}
	return result, tx.Commit()
}

func planPHPCurrentSyncStateTx(ctx context.Context, tx *sql.Tx, planID int64, revision int) (string, error) {
	var complete bool
	err := tx.QueryRowContext(ctx, `SELECT NOT EXISTS(SELECT 1 FROM subscriptions s LEFT JOIN subscription_entitlements e ON e.subscription_id=s.id LEFT JOIN subscription_system_accounts a ON a.subscription_id=s.id WHERE s.plan_id=$1 AND s.sync_mode='synced' AND NOT COALESCE(s.plan_revision=$2 AND s.sync_status='in_sync' AND s.sync_error='' AND e.source_revision=GREATEST($2::int,COALESCE((SELECT MAX(addon.revision) FROM subscription_addons assigned JOIN addon_plans addon ON addon.id=assigned.addon_plan_id WHERE assigned.subscription_id=s.id),0)) AND a.convergence_status='in_sync' AND a.desired_revision=a.applied_revision AND a.last_error='',false))`, planID, revision).Scan(&complete)
	if err != nil {
		return "", err
	}
	if complete {
		return "in_sync", nil
	}
	return "pending", nil
}

func previewPlanPHPTx(ctx context.Context, tx *sql.Tx, plan Plan, input PlanPHPVersionsInput, lock bool) (PlanPHPVersionsPreview, []planPHPParticipant, error) {
	view := PlanPHPVersionsPreview{PlanID: plan.ID, Revision: plan.Revision, NoChange: samePHPVersionSet(strings.Split(plan.PHPAllowlist, ","), input.PHPVersions) && plan.DefaultPHPVersion == input.DefaultPHPVersion, Preview: types.PlanPreview{Allowed: true}}
	candidate := candidatePlanPHP(plan, input)
	if err := ValidatePlan(candidate); err != nil {
		return view, nil, rejectPlanPHP(err)
	}
	if err := validatePlanWithinReseller(ctx, tx, candidate, lock); err != nil {
		return view, nil, err
	}
	// Preview the actual leaf operation, independently of typed normalization used
	// for validation. Full-plan diffs would advertise unwritten schema defaults.
	for _, field := range controlpolicy.PlanContractFields() {
		var oldValue, newValue string
		switch field.Path {
		case "php.allowed_versions":
			if samePHPVersionSet(strings.Split(plan.PHPAllowlist, ","), input.PHPVersions) {
				continue
			}
			oldValue = formatPlanContractValue(strings.Split(plan.PHPAllowlist, ","))
			newValue = formatPlanContractValue(input.PHPVersions)
		case "php.default_version":
			if plan.DefaultPHPVersion == input.DefaultPHPVersion {
				continue
			}
			oldValue = plan.DefaultPHPVersion
			newValue = input.DefaultPHPVersion
		default:
			continue
		}
		view.Preview.Changes = append(view.Preview.Changes, types.PlanFieldChange{Path: field.Path, Label: field.Label, OldValue: oldValue, NewValue: newValue, Enforcement: field.Enforcement})
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,sync_mode FROM subscriptions WHERE plan_id=$1 ORDER BY id`, plan.ID)
	if err != nil {
		return view, nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		var mode string
		if err = rows.Scan(&id, &mode); err != nil {
			rows.Close()
			return view, nil, err
		}
		switch mode {
		case "synced":
			ids = append(ids, id)
			view.Preview.SyncedSubscriptions++
		case "locked":
			view.Preview.LockedSubscriptions++
		default:
			view.Preview.CustomSubscriptions++
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return view, nil, err
	}
	rows.Close()
	participants := make([]planPHPParticipant, 0, len(ids))
	for _, id := range ids {
		if lock {
			var acquired bool
			if err = tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended('nakpanel:subscription:'||$1::bigint::text,0))`, id).Scan(&acquired); err != nil {
				return view, nil, err
			}
			if !acquired {
				return view, nil, &PlanPHPConflictError{Code: "plan_busy", PlanID: plan.ID}
			}
			if err = LockSubscriptionMutationTx(ctx, tx, id); err != nil {
				return view, nil, err
			}
			for _, query := range []string{`SELECT id FROM subscriptions WHERE id=$1 FOR UPDATE NOWAIT`, `SELECT subscription_id FROM subscription_entitlements WHERE subscription_id=$1 FOR UPDATE NOWAIT`, `SELECT subscription_id FROM subscription_system_accounts WHERE subscription_id=$1 FOR UPDATE NOWAIT`} {
				if _, err = tx.ExecContext(ctx, query, id); err != nil {
					return view, nil, err
				}
			}
		}
		addons, err := loadSubscriptionAddonsTx(ctx, tx, id)
		if err != nil {
			return view, nil, err
		}
		current, err := ComposeEntitlements(entitlementsFromPlan(plan), addons)
		if err != nil {
			return view, nil, rejectPlanPHP(err)
		}
		var converged bool
		if err = tx.QueryRowContext(ctx, `SELECT s.plan_revision=$2 AND s.sync_status='in_sync' AND s.sync_error='' AND COALESCE(e.source_revision=$3,false) AND COALESCE(a.convergence_status='in_sync' AND a.desired_revision=a.applied_revision AND a.last_error='',false) FROM subscriptions s LEFT JOIN subscription_entitlements e ON e.subscription_id=s.id LEFT JOIN subscription_system_accounts a ON a.subscription_id=s.id WHERE s.id=$1`, id, plan.Revision, current.SourceRevision).Scan(&converged); err != nil {
			return view, nil, err
		}
		if !converged {
			view.Blockers = append(view.Blockers, PlanPHPBlocker{Code: "plan_sync_pending", Message: "Subscription must finish its current plan synchronization", SubscriptionIDs: []int64{id}})
			view.Preview.Allowed = false
			// An absent/unfinished snapshot is an admission blocker, not a new
			// entitlement source or a missing-plan error. Never synthesize it.
			continue
		}
		composed, err := ComposeEntitlements(entitlementsFromPlan(candidate), addons)
		if err != nil {
			return view, nil, rejectPlanPHP(err)
		}
		projected, err := projectPlanPHPEntitlementsTx(ctx, tx, id, composed)
		if err != nil {
			var policyConflict *planPHPPolicyConflict
			if errors.As(err, &policyConflict) {
				view.Preview.Allowed = false
				view.Preview.BlockingReasons = append(view.Preview.BlockingReasons, policyConflict.Error())
				continue
			}
			return view, nil, err
		}
		usage, err := loadSubscriptionComplianceUsage(ctx, tx, id)
		if err != nil {
			return view, nil, err
		}
		_, violations := EvaluateSubscriptionCompliance(projected, usage)
		if len(violations) > 0 {
			view.Preview.SubscriptionImpacts = append(view.Preview.SubscriptionImpacts, types.SubscriptionImpact{SubscriptionID: id, Violations: violations})
		}
		digest, err := planPHPAddonDigestTx(ctx, tx, id)
		if err != nil {
			return view, nil, err
		}
		participants = append(participants, planPHPParticipant{SubscriptionID: id, AddonsSHA256: digest})
		if plan.ResellerID > 0 {
			if err = validateResellerCapacity(ctx, tx, plan.ResellerID, id, projected, lock); err != nil {
				return view, nil, err
			}
		}
	}
	settings, err := getSettingsTx(ctx, tx)
	if err != nil {
		return view, nil, err
	}
	committed, unlimited, err := committedAllocationTx(ctx, tx, 0)
	if err != nil {
		return view, nil, err
	}
	view.Preview.ServerCapacityMB = settings.ServerDiskCapacityMB
	view.Preview.CommittedDiskMB = committed
	if unlimited {
		view.Preview.CommittedDiskMB = -1
	}
	if settings.OversellPolicy == OversellPolicyCap && (unlimited || (settings.ServerDiskCapacityMB > 0 && committed > settings.ServerDiskCapacityMB)) {
		view.Preview.Allowed = false
		view.Preview.BlockingReasons = append(view.Preview.BlockingReasons, "Current preserved allocations exceed server capacity")
	}
	return view, participants, nil
}
