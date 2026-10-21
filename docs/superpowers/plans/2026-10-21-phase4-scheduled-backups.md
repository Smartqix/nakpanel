# Phase 4 Scheduled Backup and Restore Verification

> **For agentic workers:** Use `superpowers:executing-plans` inline. Report
> results before any merge or deployment; do not repeat unchanged qualification.

**Goal:** Prove real scheduled encrypted backups and a fresh-host restore on
hosted Ubuntu 26.04 AMD64 with hosting PHP 8.3/8.4/8.5.

**Spec:** The current user request and the Phase 4 scheduled-backup requirement
in [the support plan](2026-10-18-ubuntu-26-04-support.md#current-phases).

**Architecture:** Initially reuse the exact development-signed application from passing
Phase 3 run `39652821843`, runtime commit `63c00f6`, and its pinned Ubuntu image.
Add a separate focused dispatch to the existing hosted workflow. Use the real
installer, product APIs, normal River cron sweep and operator restore command
on two fresh, explicitly owned disposable guests. A locally reproduced runtime
repair requires a fresh current-source signed build using the existing canonical
builder, then only this affected verification slice. No canonical 16-gate rerun.

**Tech stack:** GitHub Actions, Multipass/KVM, Bash 5, Python, existing signed
Go panel/agent/panelctl binaries, PostgreSQL and MariaDB.

## Constraints and decisions

- Ubuntu 26.04/resolute only; signed Surý PHP 8.3/8.4/8.5 throughout.
- Reuse the attached isolated worktree. Preserve the primary checkout's edits
  and all protected local VMs, databases and services.
- Pin the accepted run, source commit, archive, manifest and public-key hashes.
  Refuse artifact expiry/tampering or changes to previously qualified runtime
  sources before VM creation. New verifier/workflow/docs changes are permitted.
  The explicit `scheduled_backups_build_current` mode permits only the scoped
  classic-site reconciliation repair and its regression test, requires a new
  signed current-run candidate matching the checkout, and records its own hashes.
- The latest instruction authorizes this hosted backup/restore slice, not a
  full architecture matrix, security-version advance, elapsed soak, merge or
  deployment. Existing Phase 3 evidence remains attributed to its tested source.
- Observe actual `scheduled=true`, active and verified backup rows for the
  exact destination, with a scheduler-attributed audit event and completed
  River backup job. Never manually run a backup or alter its status flags.
- Restore that exact encrypted archive to a distinct fresh guest. Verify its
  hash, control/MariaDB canaries, tenant file bytes, PHP HTTP execution and
  recorded runtime intent; repeat after a real reboot without service repairs.
- Require another naturally scheduled verified backup after the restored
  guest's reboot. Preserve private archive keys outside uploaded evidence.
- Retain safe stage/failure receipts and perform ownership-checked cleanup on
  every outcome. A short focused run does not establish long-term reliability.

## Review focus

1. Manual, unrelated, unverified or stale backup rows cannot count as scheduling.
2. Reused Phase 3 artifacts must remain bound to the accepted source and bytes.
3. Backup keys and arbitrary command output must not enter uploaded receipts.
4. Source/DR collisions and foreign VM records must fail before destructive work.
5. Restore must retain all three PHP selections and scheduler operation after boot.

## Task 1: Implement the focused verifier and dispatch

**Files:** Create `deploy/multipass/scheduled-backup-verify.py`, its Python/Go
behavior tests and a thin Bash entrypoint; modify the existing hosted workflow.

**Interfaces:** The preparation operation consumes the pinned Phase 3 artifact
and exports verified release/image paths. The run operation consumes those
paths and the explicit run/VM identities, then publishes a bounded outcome.

- [x] Write and run failing tests for baseline tampering, scope isolation,
  scheduler evidence rejection, data/PHP drift, inert imports and hosted guards.
- [x] Implement the preparation and real backup/restore orchestration using
  current helpers; keep normal product qualification defaults unchanged.
- [x] Run focused new tests plus affected existing hosted/soak guard checks;
  validate Bash syntax, workflow syntax and the diff. Do not run local VMs.
- [x] Commit and push the focused changes to the existing task branch.

## Task 2: Run hosted verification and report

- [x] Dispatch only the new focused mode, with a finite 75-minute observer and
  90-minute workflow bound; fresh installs previously took about ten minutes.
- [ ] Inspect actual scheduled rows/jobs/audits, exact archive identity, restored
  canaries, all three PHP runtimes, reboot and postboot scheduling receipts.
- [ ] Diagnose and fix a concrete observed failure if needed, then rerun only
  affected checks; never relabel a failure or silently relax a gate.
- [x] Perform one independent review of this Phase 4 change range, address
  important findings, retain terminal evidence and cleanup results.
- [ ] Update the support plan and report measured outcomes and remaining limits.
  Keep runtime changes unmerged and undeployed.

## Hosted failure and bounded diagnosis

Run `39669768594` (`a59bf68`, unchanged runtime `63c00f6`) produced a real
scheduler-created verified encrypted backup, SHA-256
`c734c0f3d3505ea6ae541205f3c651a546e007f1930c919ab0f3cb99a8e1d922`.
Fresh-host restore exited successfully and restored PostgreSQL/MariaDB and tenant
file canaries, but the PHP HTTP check failed before reboot. Owned cleanup passed
for both guests. This is a FAIL, not completed restore acceptance.

The next focused run adds read-only selected FPM unit/socket, nginx error-category
and reconciliation diagnostics on first/final failure, plus HTTP status and curl
exit code. Response bodies, credentials and arbitrary logs remain private. No
runtime fix is assumed until the failure is identified. If runtime sources need
repair, build a new signed candidate and verify the affected slice; retain Phase
3 attribution to its original source instead of reusing old binaries as new-fix
proof. Nine Python behavior cases cover the added failure evidence and privacy;
the two new cases were observed RED before implementation and GREEN afterward.

### Locally reproduced runtime gap

A real filesystem/reconciler regression reproduced matching restored classic PHP
configuration with a stopped dedicated unit: reconciliation incorrectly returned
`unchanged` for all three minors. The repair inspects the dedicated unit's actual
active state before declaring matching configuration unchanged, reusing the
existing desired-state application path. Active sites restart; suspended sites
stop; a second healthy reconciliation remains unchanged without service mutation.
Six cases were RED before the repair and GREEN afterward; affected managed-site
and suspension/rollback checks also passed. Hosted diagnostic run `39674960173`
on unchanged runtime is still pending and must confirm the live failure cause.
The repaired candidate will be built by the existing signed-bundles job only
when explicitly requested. That build does not enable full qualification jobs.
