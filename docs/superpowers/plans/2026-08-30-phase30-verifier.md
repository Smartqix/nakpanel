# Phase 30 Verifier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the final Ubuntu 24.04 Phase 30 PHP/WordPress acceptance gate, chain it after Phase 29, and document the proven product boundary.

**Architecture:** A host-side executable verifier reuses `common.sh` and the existing `nakpanel-lab` VM. It installs the current worktree, drives only supported panel and `panelctl` control paths, uses root-only guest fixtures for secrets, and checks Classic WordPress plus managed PHP behavior without persisting plaintext credentials. Go tests enforce the shell and documentation contracts without requiring Multipass.

**Tech Stack:** Bash, Multipass, Go static contract tests, curl, WP-CLI 2.12.0, Composer 2, PHP-FPM 8.3/8.4/8.5, nginx, MariaDB, systemd.

**Spec:** `.superpowers/sdd/phase30-production-php/task-8-verifier-brief.md`

## Global Constraints

- Do not run the destructive full fresh Multipass chain during implementation.
- Keep all destructive VM operations restricted to Nakpanel-named VMs.
- Never print or persist plaintext application or database secrets.
- Use real panel ownership, plan intent, subscription accounts, tracked databases, and supported mutation paths.
- Final WordPress TLS checks must trust the Phase 30 CA and must not use `curl -k`.
- WordPress compatibility is proved at exactly version 7.1; Nakpanel is not a WordPress Toolkit and does not offer Node/Python applications.

---

### Task 1: Static Verifier Contract

**Files:**
- Create: `deploy/multipass/phase30_verify_test.go`
- Modify: `deploy/multipass/single_vm_verify_test.go`

**Interfaces:**
- Consumes: existing `readExecutableScript`, `common.sh`, and deployment-chain conventions.
- Produces: static assertions for Phase 30 runtime, Classic WordPress, managed PHP, secret, UI, reboot, and chain contracts.

- [x] **Step 1: Write the failing tests** for the missing executable verifier, Phase 30 chain order, and legacy cleanup name.
- [x] **Step 2: Run `go test ./deploy/multipass -run 'TestPhase30|TestDeploymentVerification|TestLegacy' -count=1`** and confirm failure is caused by the missing verifier/wiring.
- [x] **Step 3: Implement only the chain/cleanup shell needed for those assertions.**
- [x] **Step 4: Rerun the focused tests** and keep the exact red/green output for the report.

### Task 2: Phase 30 Runtime Acceptance Script

**Files:**
- Create: `deploy/multipass/phase30-verify.sh`

**Interfaces:**
- Consumes: `common.sh`, `sync_repo`, `vm_ip`, `panelctl`, authenticated panel routes, and Phase 29 state.
- Produces: bounded acceptance checks for current binaries, PHP runtimes, Classic WordPress 7.1, managed releases/workers, isolation, suspension, and reboot recovery.

- [x] **Step 1: Extend the static test with one failing assertion per required acceptance group.**
- [x] **Step 2: Run the focused verifier test** and confirm each missing group is reported.
- [x] **Step 3: Add the minimal bounded shell implementation** using derived IDs/paths, root-only secret files, supported control-plane paths, and trusted TLS.
- [x] **Step 4: Run focused tests plus `bash -n deploy/multipass/phase30-verify.sh`.**

### Task 3: Product Documentation Contract

**Files:**
- Modify: `README.md`
- Modify: `docs/RECOVERY.md`
- Modify: `.superpowers/sdd/phase30-production-php/progress.md`
- Test: `deploy/multipass/phase30_verify_test.go`

**Interfaces:**
- Consumes: the verifier’s actual acceptance scope.
- Produces: truthful installation, recovery, verification, PHP/WordPress compatibility, and Node/Python boundary documentation.

- [x] **Step 1: Add failing static documentation assertions** for Phase 30, WordPress compatibility-only wording, managed PHP, and the Node/Python exclusion.
- [x] **Step 2: Run the focused tests** and confirm the stale documentation causes failure.
- [x] **Step 3: Update the three documentation surfaces** without claiming a WordPress Toolkit or unsupported runtimes.
- [x] **Step 4: Rerun the focused tests.**

### Task 4: Verification and Report

**Files:**
- Create: `.superpowers/sdd/phase30-production-php/task-8-verifier-report.md`

**Interfaces:**
- Consumes: test and build output from the completed tree.
- Produces: final evidence, expected runtime/prerequisites, commits, and concerns for the controller’s fresh Multipass run.

- [x] **Step 1: Run `go test ./... -count=1`, `go vet ./...`, `task build`, `git diff --check`, and `bash -n deploy/**/*.sh`.**
- [x] **Step 2: Write the report** with red/green evidence and explicitly state that full Multipass was deferred to the controller.
- [x] **Step 3: Commit all changes and verify `git status --short` is empty.**
