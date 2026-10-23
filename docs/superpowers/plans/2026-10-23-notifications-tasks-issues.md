# Notifications, Tasks and Issues Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make operational work discoverable, actionable and verifiably recovered
without duplicate alerts, lost task results or cross-tenant disclosure.

**Architecture:** Extend the existing PostgreSQL/River foundations with correlated
operations, incidents and personal notification receipts. Reuse templ, fragment
navigation and the existing polling controller. Workers keep control of mutation
and independent verifiers establish recovery.

**Tech stack:** Go, PostgreSQL, River, templ, the existing JavaScript lifecycle and
Nakpanel CSS tokens. No SPA rewrite or new message broker.

**Spec:** [proposed design and research](../specs/2026-10-23-notifications-tasks-issues-design.md).
**Figma:** [editable UI/UX flows](https://www.figma.com/design/xKb9jZ6VvLAWEwwsKRZeG5).

**Authorization:** The owner authorized local implementation on 23 October 2026
(“implement now”). Report each phase before continuing to the next. Hosted tests,
external email tests, PR, merge and deployment still require explicit approval.

## Global constraints

- Nakpanel is in active development, before production release. Breaking changes
  are allowed. Implement the current design directly.
- Do not add legacy adapters, compatibility shims, dual-read/write paths,
  backfills, or transitional migrations unless the user explicitly requests them.
- Ubuntu 26.04 LTS (Resolute) is the only supported server OS. Reject unsupported
  server OS versions before mutation.
- Keep hosting PHP 8.3, 8.4 and 8.5, with their required extensions, isolated
  FPM/CLI execution and readiness checks. Internal tools use validated PHP 8.5.
- Reuse the existing signed Resolute Surý provider and trusted PHP descriptors.
- Preserve current-version backup/restore, application recovery, security and
  tenant isolation. Historical failures remain failures.
- Keep administrator-only retry initially. Viewing a task does not grant recovery
  permissions. Use current ownership/intent at read, mutation and delivery time.
- Never resolve on read, acknowledgement, timeout or worker completion alone.
- Do not send notifications to real external recipients during implementation.

## Review focus

1. A task finishes outside the recent eight-row window or while the tab is hidden:
   the durable result must still appear once.
2. Two users read one message, or two resources produce the same error title:
   personal receipts and resource incidents must remain independent.
3. Ownership, role, policy or removal state changes while a page is open:
   stale links and retry requests must not authorize access or mutation.
4. Preflight passes but verification later fails, or the observation is stale:
   the issue remains open and the original failure is preserved.
5. SMTP accepts, rejects or repeatedly times out:
   delivery labels remain truthful and failure handling cannot create a loop.

## Phase 1 — Define durable states, scope and incident identity

**Files:** create `internal/control/operations/model.go`, `store.go`,
`store_test.go`, `scope.go`, `scope_test.go`; add a current-design SQL migration
under `migrations/`; update notification contracts in `internal/types/envelope.go`
and their callers in `internal/control/quota/usage.go`.

- [x] Add failing PostgreSQL tests for per-user receipts, identical-title
  incidents on different resources, repeated failures on one resource and
  transactional event/outbox uniqueness.
- [x] Introduce operations/attempts, issues and typed scope. Replace shared
  notification read state with receipts. Recreate development fixtures for the
  new contract; do not backfill historical jobs or notifications.
- [x] Define one state vocabulary, event identity, public error summary, role
  visibility and per-kind recovery capability. Separate acknowledgement from
  verified resolution in both schema and methods. Include incident generation,
  latest occurrence and resource intent revision in the verification contract.
- [x] Run the new focused package tests with a dedicated local test database.
  Confirm rollback, concurrent dedupe and independent user state.
- [x] Report schema/contracts and exact local results before phase 2.

**Exit:** durable state and tenant boundaries pass; no UI or hosted acceptance
claim is made.

## Phase 2 — Provide scoped queries and reliable updates

**Files:** create `internal/control/operations/queries.go`, `queries_test.go`,
`feed.go`, `feed_test.go`, `dispatch.go`, `dispatch_test.go`,
`internal/control/http/operations.go` and
`operations_test.go`; update `dashboard/tasks.go`, `dashboard/jobs.go`,
`http/tasks.go`, routing in `http/server.go`, and `web/tasks.go` together.

- [x] Add failing tests for roles, empty and truncated pages, cursor replay,
  hidden-tab gaps, counts independent of page size, resource deletion and role
  changes. Include explicit cross-tenant detail and badge-count denial.
- [x] Add dispatcher crash/restart tests between source commit, enqueue and
  dispatch acknowledgement; duplicate consumption must be idempotent. Include
  concurrent transactions committing out of order in feed tests so a cursor
  cannot permanently skip a late-committing event.
- [x] Implement replayable outbox dispatch using River and PostgreSQL, with
  atomic enqueue/acknowledgement where supported and unique event consumers.
- [x] Implement authorized Issues/Tasks/History queries, personal inbox/receipts
  and bounded cursor updates. Counts and lists use the same predicate.
- [x] Replace the old eight-item-only HTTP contract and remove its unused reader.
  Keep bounded quick views while exposing full pagination and durable transitions.
- [x] Return human labels, resource identity, stage, timestamps, correlation and
  capabilities. Do not expose raw argument JSON or credentials.
- [x] Run focused operations, dashboard and HTTP tests. Report before phase 3.

**Exit:** refreshing or reopening can recover all relevant results; direct URLs
and counts cannot disclose another tenant's data.

## Phase 3 — Connect workers, incidents and verified recovery

**Files:** create `operations/recorder.go`, `recorder_test.go`, `recovery.go`,
`recovery_test.go`, `verification.go`, `verification_test.go`, `conditions.go`,
`conditions_test.go`; update
`provision/recovery.go`, `site_job_intent.go`, `site_job_fence.go`, worker files
`jobs.go`, `phase6_jobs.go`, `mail_jobs.go`, relevant backup/update workers and
`quota/usage.go`. Inventory exact producers before editing each worker.

- [x] Add failing tests for duplicate terminal signals, failed verification,
  concurrent/double retries, a removed or transferred resource, changed policy,
  recurrence after recovery and unsupported destructive job kinds. Include an
  older successful verifier arriving after a newer failure or intent change.
- [x] Record logical operation events transactionally. Group retries under the
  operation and preserve each original terminal attempt outcome.
- [x] Inventory non-job conditions, initially certificate expiry and overdue
  backups. Define scheduled detection, thresholds/grace periods, observation
  freshness, re-observation and recovery predicates per kind. Test deadline
  crossing without a job, repeated observations, missing/stale evidence and
  recovery followed by recurrence. Unknown checks cannot establish recovery.
- [x] Add only typed, allowlisted safe recovery. Recheck current intent,
  permission and prerequisites; create a new retry attempt atomically. Keep
  unsupported retry/cancel actions absent with a clear reason.
- [x] Add verifier receipts for initially supported sources: backups, TLS,
  provisioning and mail readiness. State precisely what each receipt proves;
  archive integrity is not a restore rehearsal. Mark stale/unknown checks as such.
- [x] Record verified recovery, resolve only the matching incident, and keep its
  original failures and linked history. Require a conditional match on incident
  generation, latest occurrence and current resource intent revision; discard
  stale receipts and recheck. Never resolve because a viewer read it.
- [x] Run focused local worker/recovery/isolation tests. Report before phase 4.

**Exit:** the notification → operation → issue → safe retry → verified result
chain works in local fixtures, without weakening existing mutation fences.

## Phase 4 — Implement the reviewed Figma experience

**Files:** create `web/operations.templ`, `web/operations_helpers.go`,
`web/operations_render_test.go`, `web/static/operations.js`,
`web/static/operations.test.cjs`, `web/static/operations.css`; update
`workspace.templ`, `tasks.go`, `static/tasks.js`, HTTP view routing and the existing
navigation lifecycle. Regenerate affected templ output using the pinned tool.

- [x] Before UI implementation, review the Figma flow and settle the remaining
  design decisions. Preserve the current sidebar and visual tokens.
- [x] Add meaningful tests for counts/scope, read versus resolve, late responses,
  reconnect, focus return, modal behavior, polling cancellation and source errors.
- [x] Build Activity tabs, task quick view, inbox, task/issue details, recovery
  confirmation, receipt and history. Add preference controls, validation and save feedback. Phase 5 supplies and
  verifies their persisted policy; the combined flow must work before release.
- [x] Replace the matching transient attention projections and raw dashboard
  jobs with durable scoped issues, preserving severity without duplicate counts.
- [x] Wire the root-page badges and initial tray to the operations read model,
  replacing the remaining dashboard job projections and their render helpers.
- [x] Reuse one lifecycle owner for live updates. Keep context during fragment
  navigation; no reload is needed to see a task result. Respect reduced motion.
- [x] Render loading, stale, empty, denied, removed, blocked-retry and email-failure
  states. Show typed recovery actions only when authorized.
- [x] Run focused Go/JavaScript checks, regenerate templates once, then inspect
  desktop/mobile, keyboard, screen-reader announcements and contrast. Repeat
  only checks affected by a subsequent change. Report before phase 5.

**Exit:** reviewed screens and interaction contracts are implemented locally;
controls are usable and state changes do not fabricate healthy results.

## Phase 5 — Preferences, email policy and delivery health

**Files:** add `operations/preferences.go`, `preferences_test.go`,
`delivery_policy.go`, `delivery_policy_test.go`; update the existing delivery
worker in `quota/usage.go`, notification security producers in
`http/login_security.go`, preference routes/views and operator documentation.

- [x] Add failing tests for mandatory in-app categories, invalid recipient scope,
  digest dedupe, role changes before send, repeated SMTP failure and suppressed
  delivery-failure recursion.
- [x] Implement per-user channel/digest preferences and administrator delivery
  policy. Keep in-app state independent from SMTP availability.
- [x] Reuse bounded delivery retries; label SMTP acceptance accurately and show
  delivery degradation. Redact secrets from diagnostics and exports.
- [x] Test with a local SMTP capture and owned fixture recipients only. Prove
  one event cannot create an unbounded alert/email loop.
- [x] Report effective defaults and local results before phase 6.

**Exit:** preference changes are enforceable, delivery status is truthful and
server email failure does not silence the inbox.

## Phase 6 — Acceptance and release, only when authorized

**Files:** focused cross-feature acceptance tests alongside operations/web tests;
an evidence report under `docs/verification/`; update the active support plan if
authorization changes. Reuse existing required CI workflows.

- [x] Review the full scenario matrix: backup failure/retry, mail readiness, TLS
  expiry/recovery, duplicate alerts, permission changes, disconnect/reconnect,
  both personal inboxes and original-failure preservation.
- [x] Run complete required local checks once, including generated-file checks.
  Fix failures and rerun affected checks; do not repeat unchanged suites.
- [x] User authorized focused hosted Ubuntu 26.04 notifications, tasks, recovery
  and both UX fixes on 2026-10-23. Use an owned disposable guest and loopback
  SMTP capture only; no external recipients, Ubuntu 24.04 or legacy matrices.
- [x] Capture scoped hosted evidence and preservation checks.
  Current support remains PHP 8.3/8.4/8.5 with internal PHP 8.5.
- [ ] Prepare/open a PR only when requested. Run required CI, including the
  hosted security gate, under that authorization; do not skip required gates.
- [x] Report exact source revision, checks, skips and remaining limits before
  merge or deployment. Merge/deployment remain separate user decisions.

**Exit:** requirements have evidence, with code and hosted claims clearly
separated. A visually complete Figma file is never treated as system acceptance.

Local acceptance is recorded at implementation commit `d2eedb9` in
[phase 6 evidence](../../verification/2026-10-23-operations-phase6.md). The two minor
UX follow-ups were resolved in [focused follow-up evidence](../../verification/2026-10-23-operations-ux-followup.md).

The current hosted authorization covers a fresh signed candidate, all three PHP
CLI/FPM runtimes and extensions, actual queued Run now failures/deduplication,
foreign tenant denial, personal read-on-open without issue acknowledgement or
resolution, support-context settings links, twelve results across a real browser
disconnect/reconnect and fragment navigation, typed backup recovery with an
independent checksum receipt and original failed attempts retained, bounded SMTP
failure/recovery without recursive mail, and website/database/archive preservation.
Manual Run now must use the durable worker so it appears in Tasks. Build and push
this candidate branch only as needed for the manual hosted selection. PR creation,
required PR CI/security gate, merge and deployment remain separately gated.

Focused hosted acceptance passed at `40a3faf` in
[run 39983722531](https://github.com/Smartqix/nakpanel/actions/runs/39983722531).
The [hosted report](../../verification/2026-10-23-operations-hosted.md) records both
earlier failures and their fixes, final scenario results, all three PHP runtimes,
preservation and owned-guest cleanup. PR/CI/security, merge and deployment remain
outside this authorization.
