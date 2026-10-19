# PHP-Only Service Plan Update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement task-by-task. Steps use checkbox syntax. The parent task authorized implementation after design review. This document grants no deployment, commit or VM authority. Do not delegate unless separately authorized.

**Goal:** Add preview/apply APIs for PHP version intent while preserving all other raw plan and subscription data through subsequent synchronization.

**Architecture:** Narrow HTTP input → existing provider/readiness manager → raw-leaf transaction and immutable operation revision → central revision-aware snapshot patch. Existing full plan updates and explicit full composition remain the default.

**Tech Stack:** Go, PostgreSQL JSONB, existing session/CSRF middleware, River and current account convergence workers.

**Spec:** `docs/superpowers/specs/2026-10-19-php-only-plan-update-design.md`.

Local implementation and test milestones are recorded in the private SDD ledger; these end-to-end checklists remain open until independent review and new-runtime acceptance.

## Global Constraints

- Design approval and parent implementation authorization are recorded in the private implementation ledger. Source 19/artifacts/evidence remain immutable; changed product bytes require a new signed runtime and qualification.
- No new table/migration, full-form reconstruction, typed JSON writeback, Python updater, automatic plan activation or runtime installation/remapping.
- Preserve locked/custom snapshots, non-PHP raw plan/preset/policy/snapshot leaves and unknown JSON. Keep all existing ownership, reseller, teardown, capacity, compliance and readiness gates.
- Compare expected revision before no-op. Apply requires all synced participants converged and locks/rechecks actual membership; busy/pending/stale is 409 with no mutation.
- Every apply, including inactive/hosting-disabled/no-op, requires every requested version authoritatively ready. Preview may report blockers; never activate an inactive plan.
- Use `subscriptions.plan_revision` for base history; validate composed `source_revision` separately because add-on revisions can be higher.
- Audit/history/jobs are atomic. Partial failure and untrusted marked history cannot produce success.

## Review Focus

Prove that later same-revision/manual/stale-worker/reboot sync cannot erase preservation; an intervening ordinary/full or add-on change must still synchronize fully. Review raw history hashing, sparse JSON patch allowlists, contention/deadlocks and genuine no-write preview/no-op behavior.

## Intended Files And Interfaces

Add focused files rather than expanding full-form parsing:

- `internal/control/quota/plan_php_versions.go`: input/result types, raw reader/patch/revision helpers and SQLStore preview/apply.
- `internal/control/quota/plan_php_sync.go`: validated revision-kind/participant resolver and PHP-only snapshot projection/writer.
- `internal/control/provision/plan_php_versions.go`: authenticated manager methods and existing readiness/ownership adapter.
- `internal/control/http/plan_php_versions.go`: two handlers, strict form parser, response/error mapping.
- Matching `_test.go` files; `plan_php_versions_postgres_test.go` owns isolated real 55/56 schemas and concurrency/worker fixtures.

Touch `http/server.go` only for route registration; `quota/provider.go` for sync dispatch; `quota/plans.go` for necessary projected-enforcement/preview extraction; `quota/plan_sync.go` and its tests for base/composed revision observation; `quota/domain.go` for actual reassignment versus same-plan retry; `quota/customers.go` only to type the existing teardown rejection; `http/error_ui.go` only for sanitized new-route machine errors. Touch worker tests/related callers only for actual full-mutation provenance versus stale replay. Avoid changing public full-save signatures or growing unrelated fake interfaces.

Concrete narrow interfaces below belong to the quota package unless a receiver says otherwise; the matching spec defines JSON field names/HTTP envelopes. These do not change public full-save interfaces:

```go
type PlanPHPVersionsInput struct {
    ExpectedRevision int
    PHPVersions []string
    DefaultPHPVersion string
    ChangeReason string
}
type PlanPHPVersionsCommand struct {
    PlanID int64
    Input PlanPHPVersionsInput
    Actor auth.SessionUser
    Scope types.ProviderScope
    ReadyPHPVersions []string // manager's fresh agent observation; never HTTP input
}
type PlanPHPBlocker struct { Code, Message string; SubscriptionIDs []int64 }
type PlanPHPVersionsPreview struct {
    PlanID int64; Revision int; NoChange bool
    Preview types.PlanPreview; Blockers []PlanPHPBlocker
}
type PlanPHPVersionsResult struct { PlanID int64; Revision int; Changed bool; SyncState string }
type PlanPHPConflictCode string // stale_revision | plan_sync_pending | plan_busy
type PlanPHPConflictError struct {
    Code PlanPHPConflictCode; PlanID int64
    ExpectedRevision, CurrentRevision int; SubscriptionIDs []int64
}
type PlanPHPIntegrityError struct { PlanID int64; Revision int; Field string }
type PlanPHPReadinessError struct { UnreadyVersions []string; Cause error }
type PlanPHPRejectedError struct { Cause error } // explicitly checked input/domain refusal
// Each error implements Error(); readiness/rejected implement Unwrap(). Non-nil Cause means
// unknown/dependency failure (503); known UnreadyVersions means php_version_unready (400).

func (s *SQLStore) PreviewPlanPHPVersions(context.Context, PlanPHPVersionsCommand) (PlanPHPVersionsPreview, error)
func (s *SQLStore) UpdatePlanPHPVersions(context.Context, PlanPHPVersionsCommand) (PlanPHPVersionsResult, error)
// provision package, using quota-qualified types:
func (m *Manager) PreviewPlanPHPVersions(context.Context, auth.SessionUser, int64, quota.PlanPHPVersionsInput) (quota.PlanPHPVersionsPreview, error)
func (m *Manager) UpdatePlanPHPVersions(context.Context, auth.SessionUser, int64, quota.PlanPHPVersionsInput) (quota.PlanPHPVersionsResult, error)

// Internal quota synchronization only:
type planSyncCause uint8 // resolvePlanHistory (zero) | requireFullSync
type planPHPSyncDecision struct {
    PHPOnly bool; BaseRevision, SourceRevision int
    PHPVersions []string; DefaultPHPVersion string
}
func resolvePlanPHPSyncTx(ctx context.Context, tx *sql.Tx, subscriptionID int64, currentPlan Plan, composed types.SubscriptionEntitlements, cause planSyncCause) (planPHPSyncDecision, error)
func writePlanPHPEntitlementsTx(ctx context.Context, tx *sql.Tx, subscriptionID int64, decision planPHPSyncDecision) error
```

The command is internal-only. Require positive actor/plan IDs, `Actor.ID == Scope.ActorUserID`, matching admin/reseller role and owned reseller scope; recheck stored ownership. Manager supplies session identity/label and fresh authoritative inventory. Preview may report unknown readiness; update fails closed, even for no-op. JSON tags use `plan_id`, `revision`, `no_change`, `preview`, `blockers`/`subscription_ids`, `changed` and `sync_state`; `SyncState` is `pending` or `in_sync` from the corrected authoritative predicate. Resolver reads the locked base cursor/history/inputs; `PHPOnly:false` means full synchronization, malformed marked history means `PlanPHPIntegrityError`. Keep `syncSubscriptionTx` as the normal wrapper with a private cause-aware helper for actual foreground full mutations, not stale background jobs. Integrity errors produce safe `500` without raw data; operation timeout is `plan_timeout`/503. Known checked validation and existing capacity/teardown sentinels remain400; unknown/non-SQLState dependency errors produce safe503, never a raw diagnostic. Preserve only the exact canonical sanitized new-route 5xx envelopes through the existing UI mapper; raw/extra/duplicate/panic payloads retain its normal sanitizer.

### Task 1: Reproduce Raw Preservation And Define The Contract

**Files:** new quota types/test files above; existing migrations are read-only test inputs.

- [ ] Add `TestPlanPHPVersionsPreservesRawPostgreSQL` at actual migration 55 and 56 with canonical/sparse/unknown policy+presets, absent presets, legacy version mirrors and synced/locked/custom snapshots. Compare non-PHP JSONB projections and scalar values directly.
- [ ] Add expected-revision/no-op tests, including stale identical values; capture current full typed-save normalization as a focused counterexample without changing its contract.
- [ ] Add `TestPlanPHPVersionsPreviewReadOnlyPostgreSQL`; assert read-only transaction behavior, raw row/history/audit/queue equality and no SQL write calls.
- [ ] Keep default developer/CI PostgreSQL coverage optional. Required qualification sets `NAKPANEL_REQUIRE_PLAN_PHP_POSTGRES=1` and `NAKPANEL_PLAN_PHP_TEST_DSN` to the owned Unix-socket cluster; missing/invalid DSN then fails. Use a distinct owned plan-test database on the same cluster, with disposable 55/56 schemas and startup `search_path` plus unique `application_name` on every connection; required runs have zero skips. Database separation avoids cross-package advisory-lock collisions without changing production locks.
- [ ] Define narrow input, result and typed conflict/integrity errors; document strict normalization/size limits and pure raw intent projection. No store mutation yet.

### Task 2: Add The Atomic Raw Plan Operation

**Files:** `quota/plan_php_versions.go`, matching unit/PG tests; minimal shared enforcement extraction from `plans.go` only if needed.

**Interfaces:** SQLStore preview/apply consume authenticated scope/actor plus expected revision; produce current/new revision, changed flag, preview and convergence state.

- [ ] Add failing tests for leaf-only patch/mirror shapes, lifecycle preservation, spoofed marker rejection, exact PostgreSQL JSONB history hash and immutable raw history/actor/reason.
- [ ] Prove preview/admission capacity and compliance use the preserved snapshot projection, including non-PHP resource values differing from current full recomposition; extract shared rules without changing full-save projections.
- [ ] Add convergence admission tests for missing/pending/failed state, higher-revision add-on, attachment/mode changes, teardown and simultaneous writers. Contend with actual normal full `UpsertPlan`/add-on transactions in both acquisition orders and at a later shared-enforcement lock; require bounded refusal, no SQLSTATE deadlock and no phantom participant.
- [ ] Implement mutually exclusive `SHARE ROW EXCLUSIVE MODE NOWAIT` membership barriers/nonwaiting mutation and row locks; compatible SHARE entrants must not create a later upgrade deadlock. Use a 10-second `BeginTx` context plus `SET LOCAL lock_timeout='250ms'` and `statement_timeout='2s'` for every later shared helper/advisory/queue query; no reset/background context, network call or internal retry. Test rollback and wall-clock bounds.
- [ ] Patch only approved scalar/PHP leaves. Generate raw revision plus `_operation` participant/add-on digests before synchronous sync; insert one transactional `plan.saved` audit and normal transactional pending/job metadata.
- [ ] Inject revision/audit/queue/enforcement failure and prove complete rollback. Verify current no-op leaves timestamps, revision, JSON shape, audit and queue unchanged.
- [ ] Run PG/race tests with at least two real connections and assert `current_schema()` on each; a single pooled `SET search_path` or single-connection migration helper cannot substantiate concurrency/isolation.

### Task 3: Preserve Snapshots In The Central Sync Path

**Files:** new `quota/plan_php_sync.go` and tests; narrow `provider.go` dispatch/cause changes; existing worker tests as required.

**Interfaces:** `syncSubscriptionTx` resolves latest persisted kind under existing locks. Actual foreground full mutations require full behavior; plan/manual/background add-on retries consult history/current input digests.

- [ ] Add failing `TestPlanPHPSyncSameRevisionPreservesRaw`, `TestOldPlanJobUsesLatestPHPKind`, `TestOldAppliedAddonJobPreservesPHPOnlySnapshot`, `TestPlanPHPSyncFullRevisionFallsBack` and restart/reboot-equivalent replay fixtures.
- [ ] Cover contiguous PHP-only history, gaps, unmarked typed/migration revisions, malformed/hash-corrupt markers, current raw mismatch, excluded modes and changed/higher-revision add-on inputs. Use actual River worker entrypoints for stale queued jobs.
- [ ] Implement revision-chain/participant validation, explicit same-revision decision and the raw snapshot PHP projection. Preserve overrides and every other scalar/JSON leaf; write only successful revision/status/convergence metadata.
- [ ] Validate the resulting preserved snapshot through existing composition/capacity/compliance and effective policy rules. Keep actual full add-on assignment/change and locked/custom-to-synced conversion behavior. Unchanged add-on/mode forms resolve persisted history and preserve the narrow operation.
- [ ] Correct/test `PlanSynchronization` using base `plan_revision` and expected composed `source_revision`; a higher-revision add-on must report in-sync when actually converged. Run existing full-save/worker/lifecycle/capacity regressions; pending full changes refuse admission then synchronize all fields normally.

### Task 4: Add Authorized Preview And Apply Routes

**Files:** new provision/HTTP files and tests; `http/server.go` registration only.

**Interfaces:** exact two routes and four input fields from the spec; optional narrow manager interfaces follow existing `plan_sync.go` conventions.

- [ ] Add failing full-handler tests for actual middleware: admin/reseller ownership, client rejection, cross-provider non-disclosure, CSRF, body limits, unsupported media type, extra/query/duplicate scalar fields and spoofed actor/marker.
- [ ] Add manager/store tests rejecting any unready requested version in active, draft, retired-synced, hosting-disabled and no-op apply, plus missing/empty/failed inventory. Preview exposes blockers; inactive lifecycle stays unchanged. Prove preview does not call save/audit/job APIs.
- [ ] Implement strict parser and manager candidate/readiness adapter using stored typed data only for validation/preview. Recheck revision/provider in SQLStore; map typed stale/pending/busy to 409 and dependency failure to 503.
- [ ] Return preview/result JSON with desired-versus-applied distinction. The new handler must not call the old post-commit `recordAudit` path.
- [ ] Run HTTP/provision/quota tests and inspect one valid preview/apply/no-op response without using a real server or tenant.

### Task 5: Verify, Review And Qualify New Bytes

- [ ] Add a narrow helper and behavioral tests to the end of `deploy/multipass/phase31-verify.sh`: real authenticated preview/apply changes existing draft 9.9 to ready fixture PHP without activation/non-PHP/readiness drift; verify immutable revision, one audit, stale/no-op/unready boundaries. On 24/Surý with multiple ready versions, additionally change an owned active plan's synced snapshot, wait convergence and repeat manual same-revision sync with preservation; restore PHP intent as needed. Native 8.5-only must perform the draft write and active zero-write/no-op and unready-request checks before its alternate-runtime branch; derive actual ready versions, never assume 8.3.
- [ ] Run actual migration 55/56 schemas with the required isolated DSN and zero skips, then race/vet/full pinned-toolchain suite. Preserve per-schema/concurrency/timeout logs, hashes and counterevidence.
- [ ] Request independent code review of raw preservation, marker integrity, central retry dispatch, locks and full-update compatibility. Fix verified findings and repeat affected tests before integration.
- [ ] Report exact files/diff, tests and limitations for implementation approval/integration. Do not commit, build, deploy or modify a VM without separate authority.
- [ ] After authorized integration, build/sign a new runtime and run fresh Ubuntu 24.04 and Ubuntu 26.04 native/private-provider gates. Exercise preview/apply, real convergence, queued retry and reboot preservation on owned fixtures. Existing source 19 proof cannot be reused as new-runtime acceptance.

## Verification Commands

Use the existing owned Unix-socket cluster, disposable per-test schemas, supported host tools and pinned Go. Export its DSN explicitly; these checks run during implementation; fresh signed-runtime qualification remains a separate acceptance step:

```sh
: "${NAKPANEL_PLAN_PHP_TEST_DSN:?Set the isolated owned Unix-socket PostgreSQL DSN}"
export NAKPANEL_PLAN_PHP_TEST_DSN NAKPANEL_REQUIRE_PLAN_PHP_POSTGRES=1
TMPDIR=/tmp GOTOOLCHAIN=go1.26.9 go test ./internal/control/quota -run 'TestPlanPHP|TestOldPlanJobUsesLatestPHPKind' -count=1 -v
TMPDIR=/tmp GOTOOLCHAIN=go1.26.9 go test ./internal/control/http ./internal/control/provision ./internal/control/quota -count=1
TMPDIR=/tmp GOTOOLCHAIN=go1.26.9 go test -race ./internal/control/http ./internal/control/provision ./internal/control/quota -count=1
TMPDIR=/tmp GOTOOLCHAIN=go1.26.9 go vet ./internal/control/http ./internal/control/provision ./internal/control/quota
TMPDIR=/tmp GOTOOLCHAIN=go1.26.9 go test ./... -count=1
git diff --check
```

Integration fixtures must report both terminal migrations (`20261015000055`, `20261018000056`), per-connection schema assertions and zero skips. Never fall back to an ambient/default database or start/reset a shared cluster. Clean up only test-owned schemas; keep production data, signed artifacts and protected guests outside these commands.
