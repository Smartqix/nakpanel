# Service Controls Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Make service actions submit correctly and expose durable progress in the service row and Tasks.

**Architecture:** Reuse the existing system queue and Operations recorder. Link each server operation to its recorded task; expose a bounded administrator-only service-operation snapshot and refresh it from the existing Operations poller. Preserve the current grouped UI.

**Tech Stack:** Go, PostgreSQL 18, River, templ, embedded CSS, vanilla JavaScript.

**Spec:** docs/superpowers/specs/2026-10-28-service-controls-design.md

## Global Constraints

- Ubuntu 26.04 only; hosting PHP 8.3/8.4/8.5 and internal PHP 8.5 remain required.
- Preserve administrator authorization, CSRF and recent-password checks.
- No automatic replay of uncertain commands; one active operation per service.
- No compatibility adapters or historical backfills.
- Local verification only; report before hosted tests or deployment.

## Review Focus

- Browser encoding and valid-password confirmation must work with the real handler.
- Closing a menu before confirmation must preserve submitter intent and restore reachable focus.
- Fast completion, navigation and late responses must not lose or overwrite task state.
- Failures on different services must remain separate; terminal queue state must reflect the persisted outcome.
- Concurrent or uncertain submissions must not repeat a service action.

### Task 1: Repair submissions and dropdowns

**Files:** internal/control/http/server_admin.go and server_admin_test.go; internal/control/web/static/app.js; internal/control/web/server_interaction_test.cjs; internal/control/web/assets/input.css.
**Interfaces:** submitServerAdminForm keeps URL-encoded bodies and CSRF; service controls use the dedicated visible feedback node.

- [x] Add real-handler browser-form regression cases and JavaScript behavior cases; observe current failures.
- [x] Fix bounded form decoding/serialization, feedback routing and menu dismissal/focus without weakening authorization.
- [x] Run focused HTTP and JavaScript tests; record results.

### Task 2: Correlate durable service actions and Tasks

**Files:** internal/control/serveradmin/service_operations.go (new), jobs.go/tests, store.go; internal/control/http/server_admin.go/server.go/tests; internal/types/server_admin.go; migrations/20261028000063_service_operation_tasks.sql (new); operations recorder/query tests; internal/control/operations/queries.go; internal/control/web/static/operations.js/app.js.
**Interfaces:** ServiceOperation snapshots contain operation_id, task_id, service_id, action, status and timestamps with safe errors. Accepted actions return task_id; GET /tools-settings/services/operations returns active and recent snapshots to administrators. Operations poll refresh events update the service rows.

- [x] Add failing integration cases for correlation, readable task labels, separate service failures, recent completion, terminal consistency and conflicting actions.
- [x] Implement atomic task linkage and typed metadata; update the current recorder and add the current-schema linkage/serialization migration without backfills.
- [x] Render busy/progress/result and task links, refresh on the existing poller, and recover state after navigation; preserve uncertain requests until status is checked.
- [x] Verify actual post-action state, including stop; remove unsupported PHP placeholders and clarify startup/optional-service display.
- [x] Run focused Go/PostgreSQL and JavaScript tests.

### Task 3: Verify the integrated flow

**Files:** internal/control/web/services_browser_test.go (new fixture); focused browser acceptance and docs/verification/2026-10-28-service-controls.md.
**Interfaces:** Loopback-only fictional fixture serves real templates/assets and records requests; it never contacts an agent.

- [x] Exercise desktop/mobile menu, cancel, authorization, action failure, fast completion, duplicates, navigation and stale response cases.
- [x] Regenerate templates/CSS; run Go tests/vet and JavaScript suites with dedicated local PostgreSQL fixtures.
- [x] Review the complete diff, fix material findings and document exact local results and hosted limits.

## Execution rulings

The instruction “implement recommended” approves the preceding concrete recommendation; continue in this session without another approval round. Use the existing clean attached worktree on ricky/services-task-feedback. Record work locally and report before PR/push/hosted tests/deployment.
