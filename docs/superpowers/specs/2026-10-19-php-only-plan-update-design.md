# PHP-Only Service Plan Updates

Status: design independently reviewed and implementation authorized by the parent task. Product implementation is under verification; deployment and new-runtime qualification remain pending.

## Goal And Scope

Allow a provider to change a stored plan's allowed PHP versions and default PHP version through a narrow preview/apply API. Preserve every other stored plan and subscription setting, including sparse and unknown JSON members. Reuse existing Go validation, provider ownership, capability readiness, composition, capacity, compliance and convergence machinery.

This addresses the full-form limitation investigated in `b3f9…`: reconstructing a plan through `POST /plans` cannot guarantee raw preservation. The inspected implementation is source 19, `17e586b21a5bb9d048319b9741070e9a8cb67764`. Its signed artifacts and qualification evidence remain immutable. The implementation requires a new runtime and fresh qualification.

No UI, PHP package installation, runtime remapping, full form rewrite, Python updater, database migration or restore-policy change is included. Existing full `UpsertPlan` semantics remain the default.

## Existing Interfaces And Constraints

| Source | Current behavior | Design consequence |
| --- | --- | --- |
| `internal/control/http/server.go` | `handleUpsertPlan` calls `parsePlan`, then records `plan.saved` after the store transaction. Both routes sit inside CSRF and same-origin middleware. | Add narrow handlers; do not route a partial form through `parsePlan`. The new operation owns one transactional audit row. |
| `internal/control/provision/manager.go` | `UpsertPlan`/`PreviewPlan` authorize admin/reseller, constrain reseller ownership and call `validatePlanReadiness`. | Reuse those gates with a typed candidate built from the stored plan; actor/provider scope comes from the authenticated session. |
| `internal/control/quota/plans.go` | `UpsertPlan` normalizes the whole plan, rewrites all preset groups and marshals typed hosting policy. `PreviewPlan` currently takes a write-capable transaction and plan row lock. | Add a raw-preserving writer and a genuinely read-only preview. Extract only shared enforcement/preview calculations where necessary. |
| `internal/control/quota/provider.go` | `syncSubscriptionTx` composes typed entitlements and replaces every snapshot field. | Centralize selection of a PHP patch versus the existing full writer; fixing only the endpoint is insufficient. |
| `internal/control/quota/lifecycle.go` | Plan/add-on workers process current definitions, including stale queued jobs. | Determine synchronization kind from persisted history/current inputs, never from a job kind or old revision alone. |
| Migration 47 and `platform_bootstrap.go` | Immutable `plan_revisions.definition` is unconstrained JSONB. Migration/bootstrap revisions already store raw `plan`/`presets` and hash PostgreSQL JSONB text. | Add a machine-generated operation marker to a new raw revision. No new table or migration is required. Preserve older definition formats and hashes. |

`ComposeEntitlements` sets `source_revision` to the maximum of the base and assigned add-on revisions. Therefore `subscriptions.plan_revision` is the base-plan cursor; entitlement `source_revision` must be compared with the expected composed revision. Existing `PlanSynchronization` instead compares that source value to the base revision, which can report a permanently pending higher-revision add-on. Narrowly correct its observation predicate to check both base cursor and expected composed revision; preview/admission/result/status must agree. This changes no full-save data semantics and needs an explicit higher-revision add-on regression.

## API Contract

Both endpoints require an authenticated admin or reseller, positive path ID, existing provider ownership, CSRF and same-origin protection. Clients and cross-provider resellers cannot read a preview or mutate a plan. Ownership failures follow existing non-disclosing plan-route behavior.

| Route | Outcome |
| --- | --- |
| `POST /plans/{id}/php-versions/preview` | `200` JSON containing `ok`, the stored `revision`, `no_change`, the existing `types.PlanPreview` view and explicit convergence blockers. No database writes, audit rows or jobs. |
| `POST /plans/{id}/php-versions` | `200` JSON containing `ok`, `plan_id`, resulting `revision`, `changed` and `sync_state`. A committed write can be pending service convergence; this response never claims application has completed. |

Accept `application/x-www-form-urlencoded` with exactly these operation fields:

- `expected_revision`: one positive integer, within the database revision range.
- `php_versions`: one to 32 repeated version strings, each at most 16 bytes and canonical `major.minor` syntax. Trim, deduplicate and sort as a set; reject empty items, CSV-in-one-value and malformed values. Actual supported versions still come from authoritative capabilities, not a new hardcoded list.
- `default_php_version`: one version, present in that set.
- `change_reason`: one trimmed explanation of 1–1024 UTF-8 bytes for an actual change; accept the same field in preview/no-op requests.

`csrf_token` is allowed only as the existing transport field, alternatively use `X-Nakpanel-CSRF`. Reject unknown operation fields, query-string operation parameters, files, multipart/JSON bodies and repeated scalar fields. Fields such as `plan_id`, `revision_actor`, lifecycle, resource limits or an operation marker cannot be supplied. Apply the existing body limit as well as these field limits.

Return `400` for invalid input or a requested version known to be unready, `403` for role/CSRF rejection, `404` for an unavailable owned plan, `409` for stale revision, unfinished synchronization or lock contention, and `503` for unavailable readiness/dependencies or an operation deadline. A valid preview may return `Allowed:false` with capability/convergence reasons. Apply rejects those blockers without writes. Known input/domain rejections carry an explicit typed refusal (or existing capacity/teardown sentinel). Unknown and non-SQLState transport errors are dependencies and return a generic503 without their diagnostic. The existing 5xx UI layer preserves only the new routes' exact canonical sanitized code/message/status envelopes; raw, extra-field, duplicate-field, unknown or panic payloads keep the normal sanitizer. Stable codes include `php_version_unready`, `readiness_unavailable`, `stale_revision`, `plan_sync_pending`, `plan_busy` and `plan_timeout`.

Compare `expected_revision` before checking identical intent, on both endpoints. A stale request cannot succeed merely because its values happen to equal today's values. A current-revision identical-intent apply returns `changed:false` only after every requested version passes authoritative readiness; it changes no JSON shape, timestamp, revision, history, audit or queue. Authorization still applies and no-op cannot activate a plan. A current no-op returns the observed `pending` or `in_sync` state without mutating it. A changed request must also pass convergence admission below.

## Typed Validation, Raw Persistence

Introduce `quota.PlanPHPVersionsInput` and focused manager/store methods named `PreviewPlanPHPVersions` and `UpdatePlanPHPVersions`; concrete types/signatures are fixed in the matching implementation plan. HTTP passes only the narrow input. The manager loads the stored typed plan, substitutes PHP intent in memory and reuses `ValidatePlan`, preview calculations and capability validation. It does not normalize a replacement persistent document.

Preview reads a repeatable-read, read-only snapshot. Extract the existing preview/composition calculations from write-lock acquisition where needed; do not call current `SQLStore.PreviewPlan` or locking reseller validators from that read-only transaction. Reuse the same validation rules through read-only observations, then repeat authoritative locking/enforcement during apply. Preview is advisory and grants no write authority.

Keep lifecycle and `is_active` unchanged. This maintenance API is deliberately stricter than the full form: **every requested version must be in the authoritative `quota.ReadyPHPVersions` inventory for every apply**, including draft, retired-with-synced-subscriptions, hosting-disabled and no-op requests. A missing reader, failed observation or empty inventory fails closed; a known unready requested version is rejected. Preview lists blockers with `Allowed:false`, including for inactive plans, without changing lifecycle. Reuse `validatePlanReadiness` rules and obtain the ready inventory from the same fresh agent capabilities observation immediately before the transaction. The manager-generated command carries that inventory; SQLStore repeats the requested-set containment check and expected-revision/provider checks. Never trust a client readiness list. Actual provisioning retains its independent live readiness checks; this does not make external service state transactional with PostgreSQL.

The database patch allowlist is:

| Stored location | Permitted intent change |
| --- | --- |
| `plans.php_allowlist`, `plans.default_php_version` | Canonical CSV allowlist and default scalar. |
| `plans.hosting_policy.php.allowed_versions`, `.default_version` | Version array and default, using leaf patches. |
| Existing `plan_service_presets.hosting.allowed_php_versions`, `.default_php_version` | Update these mirrors only when present. Preserve absent mirrors. |
| Existing `plan_service_presets.php.allowed_versions`, `.default_version` | Update legacy bootstrap mirrors only when present; `allowed_versions` retains its existing CSV-string representation. |

Revision and `updated_at` advance once on change. No resource, permission, price, lifecycle, validation timestamp/error, PHP tuning, mail, DNS, web/CIDR, statistics, application, backup, override or unknown leaf changes. An absent presets row remains absent. A sparse object stays sparse outside the intended PHP leaves. Do not call `upsertPlanPresetsTx`, marshal typed policy back to storage, or materialize unrelated defaults. Validate raw object/leaf shapes before patching; malformed containers fail without replacement. PostgreSQL JSONB equality and absent-versus-null preservation are the contract; original JSON lexical whitespace/order is not available in JSONB.

No-op compares effective requested version intent with the stored intent without materializing mirrors. Contradictory existing mirrors are a validation conflict, not an opportunity for a hidden no-op repair.

## Apply Transaction And Convergence Admission

The transaction must observe a stable set of attached subscriptions and composition inputs, not merely trust a previously fetched sync-status page.

1. Derive a **10-second transaction context** from the request and pass it to `BeginTx` and every helper. Immediately `SET LOCAL lock_timeout='250ms'` and `SET LOCAL statement_timeout='2s'`. These limits cover all later reseller/capacity/compliance, advisory and queue SQL, not just initial locks; no helper may replace the context or reset the local limits. Take membership barriers on `subscriptions`, `subscription_addons` and `addon_plans` (`SHARE ROW EXCLUSIVE MODE NOWAIT`), existing per-subscription advisory locks in ID order using nonwaiting acquisition, and required subscription/account/entitlement, plan and preset row locks with `NOWAIT`. Keep existing teardown exclusion. Lock refusal/timeout is `409 plan_busy`; statement/overall timeout is `503 plan_timeout`, with rollback and no internal replay. Test contention with actual ordinary full-plan and add-on transactions; do not introduce a plan-versus-subscription inversion or rely on PostgreSQL deadlock detection as success.
2. Re-read provider ownership, raw plan/presets, revision and attached modes. Compare expected revision first, recheck every requested version against the command's authoritative inventory, validate raw shapes and build the in-memory candidate. Return a true no-op before any persistent mutation.
3. For every attached `sync_mode='synced'` subscription require: base `plan_revision` equals the expected revision; an existing entitlement snapshot has the expected composed `source_revision`; snapshot sync status is `in_sync` with no error; its system account exists, is `in_sync`, has equal desired/applied revisions and no outstanding failure. Missing, pending, failed or terminating participants refuse the entire operation before writing. Locked/custom rows are counted as excluded and remain untouched.
4. Build each resulting snapshot in memory by applying the PHP-only projection to its **current raw snapshot**, composing PHP intent with assigned add-ons. Preview and apply admission run the same reseller/projected/committed-capacity, compliance and effective-policy rules on that preserved result; existing helpers assuming full replacement need a narrow projected-input extraction. Never validate full recomposition's different non-PHP resources and then persist a partial snapshot. Retain all overrides; no capacity or unavailable-offer check is weakened.
5. Patch only the allowlisted plan leaves/scalars; increment revision once. Insert the raw immutable revision and its operation marker **before** any synchronous subscription sync, so that path can resolve the kind within the same transaction.
6. Use existing River transaction insertion and pending/convergence metadata, or the existing synchronous branch when no River client exists. Preserve old valid snapshots on asynchronous failure; failures stay visible through `PlanSynchronization`. Do not move source/applied metadata ahead of a successful snapshot patch.
7. Insert exactly one `plan.saved` audit row in this transaction with operation kind, actor, reason, old/new revisions, revision definition hash, normalized PHP intent and excluded/affected counts. Commit all changes together. Audit/history/job failure rolls everything back; the new HTTP handler does not append a second best-effort audit.

The mutually exclusive membership barrier prevents two compatible entrants from both attempting a later lock upgrade. This conservative barrier briefly serializes subscription/add-on mutations across plans. It is preferable here to an unproven partial locking protocol. Keep the transaction free of agent/network calls, use nonwaiting admission and document contention as retryable. Avoid changing ordinary full-save lock behavior as an incidental refactor.

## Raw Revision And Operation Marker

Store the new revision as a raw migration-style definition with `plan`, `presets` and one reserved top-level `_operation` member. Capture the actual stored plan row minus the existing timestamp/readiness exclusions; capture raw preset columns without typed decoding, preserving a missing row explicitly. The marker is generated exclusively by the store:

```json
{
  "schema_version": 1,
  "kind": "php_versions_only",
  "from_revision": 12,
  "to_revision": 13,
  "php_versions": ["8.3", "8.5"],
  "default_php_version": "8.5",
  "subscription_inputs": [{"subscription_id": 42, "addons_sha256": "<sha256>"}]
}
```

`subscription_inputs` records the admitted synced participants and a canonical digest of their assigned add-on IDs, revisions, provider and raw definition inputs. It is bounded by the operation's actual participants, sorted deterministically and covered by the definition hash. This is needed because a base-plan marker alone cannot prove that a later add-on resource change is safe to ignore. It adds no mutable subscription JSON or new table.

Hash the complete definition, including the marker, exactly as migration 47/bootstrap do: SHA-256 of UTF-8 PostgreSQL `definition::text`. Store actor ID/label and reason in existing revision columns. Existing immutable triggers remain in force. Do not recalculate or rewrite old typed or migration-format rows.

A marker is usable only when its shape, kind, plan/revision linkage, adjacent revision numbers, canonical intent, participant inputs and PostgreSQL raw hash validate. Verify that the raw definition matches current persisted plan/preset state when using the latest marker. Never infer kind from human `change_reason`, a client field or an old worker argument. Unmarked historical revisions mean ordinary/full. An unrecognized or unprovable chain cannot authorize preservation. Validate every explicitly marked row in the queried range before any ordinary-row, gap, participant or changed-input fallback; malformed explicitly marked/hash-corrupt history must surface an integrity error before writes rather than being hidden by an earlier full revision.

## Central Subscription Sync Rules

Keep `syncSubscriptionTx` as the authoritative decision point. Normal plan/manual/background add-on retries resolve persisted history and current inputs. An actual foreground add-on assignment/change, plan reassignment, locked/custom conversion or another full mutation requires the full writer. Resubmitting the same assigned add-ons or already-synced mode resolves persisted history; it is not evidence of a new full mutation. **A stale `SyncAddonWorker` is not itself proof of a new mutation**: if its current input digest still matches the admitted marker, replay must preserve; changed inputs take the full path. Actual plan/mode reassignment also explicitly requires the full writer; a same-plan already-synced retry resolves history. Caller intent cannot force the narrow path.

For a currently synced subscription, use its base `subscriptions.plan_revision` as the history cursor. The narrow path is eligible only when every intervening base revision up to the current plan is a valid PHP-only revision, the participant was admitted and its add-on digest still matches. A gap, unmarked/full revision, different provider, absent participant or changed add-on input uses the existing full synchronization behavior. Do not swallow a pending ordinary plan or add-on change to preserve an old snapshot.

For a same-revision retry, validate the **current** PHP-only revision and participant/add-on input anyway. An empty revision interval is not proof of a full operation. This protects repeated manual sync, stale queued `SyncPlanArgs`, worker restarts and reboots after a successful narrow patch. When a later full revision exists, it immediately returns the subscription to ordinary full behavior. Explicitly changing a locked/custom subscription to synced retains the existing full composition contract; the PHP-only API never forces that conversion.

On the narrow path, run normal composition for the PHP allowlist/default with assigned add-ons. Patch only entitlement `php_allowlist`, `default_php_version`, `hosting_policy.php.allowed_versions/default_version` and existing PHP-version preset mirrors (`service_presets.hosting.allowed_php_versions/default_php_version` and legacy `service_presets.php` version mirrors). Preserve all other raw snapshot scalars and JSON leaves. Do not serialize the full `SubscriptionEntitlements` value. Preserve override tables byte-for-byte. Apply existing effective override resolution and compliance to the resulting raw snapshot's typed view; do not validate a different normalized full replacement and then write a partial one.

Update base `subscriptions.plan_revision`, composed entitlement `source_revision`, normal sync status and desired/applied convergence metadata using existing rules. Retain resource/capacity/compliance checks and actual convergence jobs. A snapshot commit is not proof that a selected site's runtime changed; this endpoint does not select or remap site/application execution versions. Selected/desired unavailable runtimes and required/offer inventory checks remain strict.

## Tests And Acceptance

Tests must execute Go endpoints/store/worker behavior and real migrated PostgreSQL, not mirror SQL strings. Default developer/CI runs follow the repository's optional PostgreSQL pattern. **Qualification sets both `NAKPANEL_REQUIRE_PLAN_PHP_POSTGRES=1` and `NAKPANEL_PLAN_PHP_TEST_DSN`**: missing/invalid/non-owned configuration then fails with `t.Fatal`, never skips. Use a separate owned test database on the existing owned Unix-socket cluster because subscription advisory locks are database-wide across schemas. Retain that database for root/reviewer reuse; drop only per-test schemas. Use disposable schemas ending at migrations `20261015000055` and `20261018000056`, and the real `sync_mode` column. Install each schema as pgx startup `RuntimeParams["search_path"]` and a unique schema-valued `application_name` before opening its pool so every connection is scoped. Assert schema identity on concurrent connections, use at least two connections for races, and drop only test-owned schemas. Required qualification records both schema runs with zero skips; no shared reset/new cluster is permitted.

| Area | Required evidence |
| --- | --- |
| Raw preservation | Canonical, sparse, absent-preset and unknown JSON fixtures; compare all non-PHP projections, null/absence, lifecycle, quotas, CIDRs, mail, statistics and PHP tuning before/after plan and snapshot writes. Validate each supported mirror representation. |
| Transactions | Current no-op has zero writes/audit/jobs; stale identical request is 409; rollback after history/audit/queue failure leaves complete before-state; preview uses read-only SQL and never invokes write APIs. |
| Concurrency | Two identical expected-revision writers yield one changed result and one 409; changed attachment/mode/add-on/full revision or convergence state cannot pass admission. Actual normal `UpsertPlan` and add-on transactions contend in both orders, including a later shared-enforcement lock; refusal completes within the 10-second bound without deadlock, partial commit or hidden replay. |
| Sync history | Synced versus locked/custom, contiguous PHP revisions, ordinary/full pending revision, gaps/unknown marker, corrupt hash, same-revision repeat and restart; stale plan **and already-applied add-on** workers preserve; changed add-on input fully applies resources; higher add-on revision reports correct status. |
| Security/readiness | Real HTTP middleware for role, cross-reseller ownership, CSRF, invalid/duplicate/extra fields; active, draft, retired-synced, hosting-disabled and identical-intent apply reject any unready requested version and unknown inventory; inactive plans remain inactive; audit actor/reason cannot be spoofed. |
| Compatibility | Existing full `UpsertPlan`, lifecycle routes, manual explicit conversions, compliance/capacity/reseller checks, required PHP inventory and restore behavior unchanged. |

After implementation, run red/green tests, required PostgreSQL 55/56 coverage, race, vet and the full supported-toolchain suite, then independent review. Extend `phase31-verify.sh` at its end with real authenticated preview/apply of the existing draft 9.9 fixture to an authoritatively ready version: retain draft/non-PHP raw contract/readiness metadata, one immutable revision/one audit, stale conflict, no-op and unready refusal. On 24/Surý profiles with multiple ready versions, also update an owned active plan with synced snapshots, wait actual convergence, repeat manual same-revision sync and prove raw preservation, restoring PHP intent if needed. Native 8.5-only still performs the real draft write; never assume 8.3 availability. A narrow gate helper with behavioral tests must exercise these boundaries. Fresh Ubuntu 24/26 qualification plus later source-positive forward/reboot checks is still required; no unit or source19 evidence substitutes for new-runtime acceptance.

## Tradeoffs And Review Decisions

The endpoint deliberately refuses unfinished synced participants rather than absorbing an earlier full change. Operators must finish normal synchronization and retry with the current revision. The raw revision marker keeps old history compatible without a schema migration, at the cost of validating two existing history formats and storing participant composition digests. Brief nonwaiting membership barriers trade concurrency for a clear first implementation; optimizing them requires separate evidence. A partial or contradictory raw document is an actionable validation/integrity failure, never permission to normalize unrelated data.
