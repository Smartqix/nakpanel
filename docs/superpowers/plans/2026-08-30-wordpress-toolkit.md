# Phase 32 WordPress Toolkit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a production WordPress management workflow for Classic PHP sites.

**Architecture:** A dedicated control-plane package persists WordPress state and identifier-only River jobs, while a typed agent adapter executes fixed WP-CLI workflows in agent-derived site roots. Existing ownership, entitlement, database, backup, secret, staging, notification, and domain-shell services remain authoritative.

**Tech Stack:** Go 1.23, PostgreSQL/goose, River, stdlib HTTP, templ, embedded CSS/JavaScript, WP-CLI 2.12.0, Ubuntu 24.04.

**Spec:** `docs/superpowers/specs/2026-08-30-wordpress-toolkit-design.md`

## Global Constraints

- WordPress Toolkit is available only to Classic PHP sites with an active subscription entitlement.
- Browser and River payloads never contain database or WordPress credentials.
- Agent operations accept typed actions and object identity, never shell strings or filesystem paths.
- Cross-tenant object access returns `404`; every mutation requires CSRF and records an audit event.
- Updates require a completed Nakpanel backup and failures never discard the recovery point.

---

### Task 1: Policy And Schema

**Files:** `internal/types/hosting_policy.go`, `internal/control/policy/policy.go`, `internal/control/quota/provider.go`, `migrations/20260830000048_phase32_wordpress_toolkit.sql`, and their tests.

- [x] Write failing tests for schema-v4 upgrade preservation, toolkit permission composition, WordPress site limits, migration constraints, teardown guards, and notification kinds.
- [x] Run the focused tests and confirm failures describe the missing v4 fields and tables.
- [x] Add the v4 policy fields and migration with immutable ownership and secret constraints.
- [x] Run migration, policy, and quota tests to green.

### Task 2: Typed Agent WordPress Operations

**Files:** `internal/types/wordpress.go`, `internal/agent/ops/wordpress.go`, `internal/agent/rpc/dispatcher.go`, `internal/control/agentclient/client.go`, `cmd/agent/main.go`, and tests.

- [x] Write failing tests for derived roots, typed action validation, Classic-only operation, bounded JSON inventory, secret-free results, temporary bootstrap cleanup, checksum checks, updates, maintenance, and hardening.
- [x] Run focused tests and confirm the dispatcher and provisioner operations are missing.
- [x] Implement fixed-command WP-CLI execution and atomic configuration helpers.
- [x] Register typed RPC and client methods, then run agent and RPC tests to green.

### Task 3: Control Plane, Secrets, And River

**Files:** `internal/control/wordpress/*.go`, `cmd/panel/main.go`, and tests.

- [x] Write failing manager/store tests for ownership, entitlement, Classic mode, site counts, durable install, encrypted secrets, database wait, backup fencing, revision conflicts, redaction, and sweeps.
- [x] Run focused tests and confirm the package lacks the required behavior.
- [x] Implement the manager, SQL store, identifier-only River arguments, workers, and periodic refresh sweep.
- [x] Wire the existing database, backup, secret, notification, and agent services and run control-plane tests to green.

### Task 4: Routed Domain Workspace

**Files:** `internal/control/http/wordpress.go`, `internal/control/http/server.go`, `internal/control/web/workspace.templ`, `internal/control/web/assets/input.css`, `internal/control/web/static/app.js`, and tests.

- [x] Write failing handler/render tests for all routes, active domain navigation, empty/installed/disabled/pending/failed states, CSRF, support view, cross-tenant `404`, dialogs, and write-only credentials.
- [x] Run focused tests and confirm the workspace and routes are missing.
- [x] Implement the WordPress tabs, summaries, dialogs, enhanced responses, and legacy-safe navigation.
- [x] Generate templ/CSS and run HTTP/web tests to green.

### Task 5: Installation, Documentation, And Ubuntu Acceptance

**Files:** `deploy/multipass/phase32-verify.sh`, verifier tests, `deployment-verify.sh`, `README.md`, `IMPLEMENTATION_PLAN.md`, and `docs/RECOVERY.md`.

- [x] Write failing static tests for verifier chaining and WordPress installation, inventory, checksum, maintenance, backup fencing, isolation, and secret checks.
- [x] Run verifier tests and confirm Phase 32 is absent.
- [x] Add the executable verifier, make it the final single-VM gate, and document the exact product boundary and recovery workflow.
- [x] Run all Go tests, race-sensitive tests, vet, build, whitespace, shell syntax, and the Ubuntu 24.04 Phase 32 verifier.
