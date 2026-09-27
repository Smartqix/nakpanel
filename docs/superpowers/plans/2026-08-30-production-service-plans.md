# Production Service Plans Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make hosting plans capability-gated, revisioned, compliance-aware provider contracts with an actionable Plesk-like change preview and editor.

**Architecture:** PostgreSQL owns lifecycle, immutable definitions, and subscription compliance. The quota store builds deterministic definitions and impact previews; the provision manager adds live agent capability validation before activation. Existing snapshot synchronization remains the delivery mechanism and gains compliance evaluation.

**Tech Stack:** Go 1.23, PostgreSQL/goose, River, templ, embedded vanilla JavaScript/CSS, stdlib HTTP, Ubuntu 24.04 Multipass.

**Spec:** `docs/superpowers/specs/2026-08-30-production-service-plans-design.md`

## Global Constraints

- Preserve all Phase 1-30 routes, data, provider scope, CSRF, audit behavior, and non-JavaScript fallbacks.
- Never delete customer resources when a plan limit is lowered.
- Never advertise an enabled capability that the live agent reports unavailable.
- Never place credentials or secret values in plan definitions, previews, revisions, River arguments, audit metadata, or responses.
- Use `-1` for unlimited, `0` for disabled, and positive values for finite limits.

---

### Task 1: Lifecycle, Revisions, And Compliance Schema

**Files:**
- Create: `migrations/20260830000047_phase31_production_service_plans.sql`
- Create: `migrations/phase31_postgres_test.go`
- Modify: `internal/types/envelope.go`

**Interfaces:**
- Produces `types.PlanLifecycleStatus`, `types.PlanRevision`, `types.SubscriptionComplianceStatus`, `types.PlanFieldChange`, `types.SubscriptionImpact`, and `types.PlanCapabilityIssue`.
- Adds lifecycle metadata to `types.PlanDefinition` and production impact arrays to `types.PlanPreview`.

- [x] Write PostgreSQL tests for active/inactive backfill, new draft default, immutable revision rows, lifecycle constraints, subscription compliance constraints, and reversible down migration.
- [ ] Run `go test ./migrations -run Phase31 -count=1` and confirm the tests fail because the migration is absent.
- [x] Add the migration and types, including compatibility synchronization between `is_active` and lifecycle writes.
- [ ] Run the focused migration/type tests and commit the green slice.

### Task 2: Enforcement Registry And Capability Readiness

**Files:**
- Create: `internal/control/policy/plan_contract.go`
- Create: `internal/control/policy/plan_contract_test.go`
- Modify: `internal/control/provision/manager.go`
- Test: `internal/control/provision/manager_test.go`

**Interfaces:**
- Produces `policy.PlanContractFields() []types.PlanContractField` and `policy.ValidatePlanCapabilities(types.HostingPolicy, types.RuntimeCapabilities) []types.PlanCapabilityIssue`.
- The provision manager uses readiness validation for activation and returns issues in preview.

- [x] Write failing registry coverage tests proving every exposed hosting-policy property has one classification.
- [x] Write failing capability tests for unavailable/default PHP, disk quota, Composer/managed PHP, rootless Podman, subordinate IDs, and Valkey.
- [x] Implement the complete registry and deterministic capability checks.
- [x] Add manager activation and preview tests, then wire capability checks without weakening draft saves.
- [ ] Run `go test ./internal/control/policy ./internal/control/provision -count=1` and commit.

### Task 3: Immutable Definitions And Subscription Compliance

**Files:**
- Modify: `internal/control/quota/plans.go`
- Modify: `internal/control/quota/provider.go`
- Create: `internal/control/quota/plan_compliance.go`
- Test: `internal/control/quota/service_plan_test.go`
- Test: `internal/control/quota/provider_test.go`

**Interfaces:**
- Produces deterministic `Plan.Definition()` and `EvaluateSubscriptionComplianceTx` behavior.
- `UpsertPlan` writes one immutable revision per saved revision with actor and reason.
- Synchronization updates compliance after installing a valid snapshot.

- [x] Write failing definition hash and revision insert tests.
- [x] Write failing compliance tests for finite, zero, unlimited, count, and fresh measured usage cases.
- [x] Implement canonical JSON definitions, SHA-256 hashes, revision inserts, and duplicate protection.
- [x] Implement subscription usage evaluation and non-destructive compliance updates after sync.
- [ ] Run focused quota tests and commit.

### Task 4: Production Synchronization Preview And Lifecycle HTTP

**Files:**
- Modify: `internal/control/quota/plans.go`
- Modify: `internal/control/provision/manager.go`
- Modify: `internal/control/http/server.go`
- Test: `internal/control/quota/service_plan_test.go`
- Test: `internal/control/http/service_plan_test.go`

**Interfaces:**
- `PreviewPlan` returns field diffs, subscription conflicts, capacity, capability issues, blockers, and warnings.
- `POST /plans/status` accepts `lifecycle_status=draft|active|retired` while continuing to translate legacy `is_active`.

- [x] Write failing preview tests for structured diffs and over-limit subscription impacts.
- [x] Write failing handler tests for lifecycle parsing, unavailable capability activation rejection, and legacy active/inactive compatibility.
- [x] Implement preview queries and lifecycle manager/store methods.
- [x] Ensure over-limit impact warns but capability/capacity blockers fail closed.
- [ ] Run focused quota/provision/http tests and commit.

### Task 5: Service Plan Workspace

**Files:**
- Modify: `internal/control/web/workspace.templ`
- Modify: `internal/control/web/helpers.go`
- Modify: `internal/control/web/static/app.js`
- Modify: `internal/control/web/static/app.css`
- Regenerate: `internal/control/web/workspace_templ.go`
- Test: `internal/control/web/web_test.go`
- Test: `internal/control/http/service_plan_test.go`

**Interfaces:**
- Renders Overview, Resources, Services, Customer Permissions, Defaults, and Advanced sections.
- Renders enforcement badges and preview change/conflict/capability lists from server-generated JSON.

- [x] Write failing render/handler tests for lifecycle labels, readiness summary, enforcement labels, change reason, and preview containers.
- [x] Recompose the existing controls into the six-section information architecture without dropping form fields.
- [x] Extend preview JavaScript for diffs, conflicts, blockers, warnings, and activation confirmation.
- [x] Add responsive styles for desktop and 390px layouts.
- [ ] Run templ generation and focused UI/HTTP tests, then commit.

### Task 6: Deployment Verification And Documentation

**Files:**
- Create: `deploy/multipass/phase31-verify.sh`
- Create: `deploy/multipass/phase31_verify_test.go`
- Modify: `deploy/multipass/deployment-verify.sh`
- Modify: `README.md`
- Modify: `IMPLEMENTATION_PLAN.md`

**Interfaces:**
- Phase 31 runs after Phase 30 on `nakpanel-lab` and becomes the final canonical verifier.

- [x] Write failing static verifier tests for chaining, lifecycle, capability denial, immutable revisions, compliance, and recovery.
- [x] Implement the verifier using CSRF-protected panel forms and direct read-only PostgreSQL assertions.
- [x] Update deployment/docs to make Phase 31 the final gate.
- [x] Run shell syntax and verifier static tests.

### Task 7: Two-Pass Verification And Lab Installation

**Files:**
- No production files unless verification exposes a defect.

**Interfaces:**
- Produces a tested Phase 31 build and installed `nakpanel-lab` instance.

- [x] Run pass one: focused packages, `go test ./... -count=1`, `go vet ./...`, `task build`, `git diff --check`, and `bash -n deploy/**/*.sh`.
- [x] Fix every observed regression and rerun its smallest failing test first.
- [x] Run pass two from a clean test cache plus generated-code checks and browser QA at desktop/mobile sizes.
- [x] Install the exact worktree build on `nakpanel-lab`, run `phase31-verify.sh`, and confirm panel/agent health.
- [x] Inspect the live service-plan page and record remaining operational limitations in the implementation closeout.
