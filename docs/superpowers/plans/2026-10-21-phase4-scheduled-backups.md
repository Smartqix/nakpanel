# Phase 4 Scheduled Backup and Restore Verification

> **For agentic workers:** Use `superpowers:executing-plans` inline. Report
> results before any merge or deployment; do not repeat unchanged qualification.

**Goal:** Prove real scheduled encrypted backups and a fresh-host restore on
hosted Ubuntu 26.04 AMD64 with hosting PHP 8.3/8.4/8.5.

**Result: PASS for the requested hosted Ubuntu 26.04 AMD64 local-destination
backup/restore slice.** [Run 39676085171](https://github.com/Smartqix/nakpanel/actions/runs/39676085171)
tested fresh signed runtime/qualifier `0654aa39eee180935f8dbed3cc3b1458e156ba1d`.
The independent downloaded-evidence, source/signature, scheduler and cleanup
checks passed. Active backup job: 25m46s; drill: 22m10s, including two fresh
installs of 9m25s and 9m35s. No merge or deployment occurred.

| Check | Actual result |
| --- | --- |
| Source scheduled backup | ID 1; scheduler audit; completed River job; encrypted archive verified at 21:41:38 UTC |
| Exact archive restore | Fresh distinct 26.04 guest; control PostgreSQL, MariaDB and all three tenant file canaries match |
| PHP execution | CLI and HTTP 8.3.36, 8.4.27, 8.5.12; correct unchanged intent; tenant UID 59997 before/after restore and reboot |
| Real restored reboot | `516ab3de-e5e9-4dfb-8296-192a179a8cfc` → `b79e5117-9d82-4e0f-b94a-c87181e8cfca`; no verifier service repairs |
| Postboot scheduled backup | New ID 3, created 21:52:55 UTC, verified/completed 21:52:57 UTC; scheduler audit and completed River job |
| Cleanup | Two owned guests; exit code 0; both destroyed |
| Scope | Full product qualification/PHP-maintenance/diagnostic jobs skipped; no legacy tests or elapsed-soak claim |

Source archive SHA-256:
`a9bc0905928059f053d1793d33f1c8b18b6d82eef9f80cd116f43a5975d06a27`.
Postboot archive SHA-256:
`048832aba45ed199353283dd470242e19efa1dabcc88d9fa645b81eace6803f0`.
Fresh signed application archive SHA-256:
`63a172350958bed3bfce7d7dff02fd70b6547fdb701eaefe65b41c8cdd844b4c`.
Manifest SHA-256:
`a09d9efb92ae9064ae5ab92e2cbe4129e6a56ec697e0e45bc9f65d59bd2cca8b`.
Signing public-key SHA-256:
`66a34f5a669f8944b6c8b115aa01d41e515bd91aa8af5de07acd208f08a4e56f`.
The exact candidate signature and manifest/source binding were independently
verified after download. Public JSON receipts contain no archive key.

Retained local evidence: `/Users/rickynkansah/.local/state/nakpanel/qualification/2026-10-21/phase4-restored-runtime-repair/acceptance.json`;
raw structured receipts and public signed candidate are in the run artifacts.
The two failed runs below remain failures. Phase 3 full qualification remains
attributed to `63c00f6`; other architectures, destinations, genuine security
version advancement and longer endurance are not established by this slice.

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
- [x] Inspect actual scheduled rows/jobs/audits, exact archive identity, restored
  canaries, all three PHP runtimes, reboot and postboot scheduling receipts.
- [x] Diagnose and fix a concrete observed failure if needed, then rerun only
  affected checks; never relabel a failure or silently relax a gate.
- [x] Perform one independent review of this Phase 4 change range, address
  important findings, retain terminal evidence and cleanup results.
- [x] Update the support plan and report measured outcomes and remaining limits.
  Keep runtime changes unmerged and undeployed.

## Hosted failure and bounded diagnosis

Run `39669768594` (`a59bf68`, unchanged runtime `63c00f6`) produced a real
scheduler-created verified encrypted backup, SHA-256
`c734c0f3d3505ea6ae541205f3c651a546e007f1930c919ab0f3cb99a8e1d922`.
Fresh-host restore exited successfully; PostgreSQL/MariaDB and the first tenant
file canary matched, but PHP HTTP validation failed before reboot. Owned cleanup passed
for both guests. This is a FAIL, not completed restore acceptance.

The diagnostic run added read-only selected FPM unit/socket, nginx error-category
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
on unchanged runtime subsequently confirmed the live failure cause.
The repaired candidate will be built by the existing signed-bundles job only
when explicitly requested. That build does not enable full qualification jobs.

### Hosted cause confirmed

Diagnostic run `39674960173` (`798d430`, unchanged runtime `63c00f6`) reproduced
HTTP 502 with all three dedicated units loaded/enabled but inactive/dead and all
three sockets missing. Two completed reconciliation runs reported 3/3 sites
healthy with no errors. First/final read-only snapshots agree. Both owned guests
were cleaned up (two records, exit 0); uploaded JSON contains no archive key.
This confirms the locally reproduced service-state drift defect. Repaired
candidate run `39676085171` (`0654aa3`) then passed on a new signed current
candidate. No broader qualification or legacy test was selected.

### Final repair acceptance

Run `39676085171` passed on the fresh signed candidate `0654aa3`. There were no
health retries requiring diagnostic snapshots and no verifier service repairs.
All source/restored/postboot data and PHP proofs matched; both the actual reboot
and a newly scheduled verified backup after it were observed. Focused local
verification passed nine affected runtime Go tests (including the six new intent
cases), four harness/workflow Go checks (including ten Python cases), actionlint
and diff checks. One read-only review of the initial harness found a fixture
principal defect, fixed RED→GREEN; a narrow review of the new runtime/candidate
work found no important defects. The bounded observer ended and terminal logs,
artifacts, independent acceptance and owned cleanup receipts are retained.

## Follow-up recheck — 21 October 2026

The requested recheck independently revalidated the retained run `39676085171`:
its candidate signature/source binding, actual scheduled archives, restored data
and PHP, changed boot ID and owned cleanup still pass. Nine affected runtime Go
checks and four focused harness/workflow Go checks passed again; actionlint and
diff validation passed. One fresh bounded read-only review found no important
runtime, scheduling, restore, evidence or cleanup defect in the Phase 4 range.
Other architecture/destination/endurance claims and unchanged shared helper
failure paths were outside this recheck; no broader readiness claim is added.

One concrete verifier diagnostics defect was reproduced and fixed: the first
`git rev-parse HEAD` command ran before the result state existed, outside the
central failure handler. A command failure raised `AttributeError` and hid its
original exit code instead of writing the intended receipt. Initialization now
records the hosted source identity first, then checks the real checkout inside
the failure handler before any ownership/VM operation. The regression was RED
before the fix and GREEN after it; it now retains the original exit code and a
private-mode sanitized receipt. A second regression proves a different checkout
still rejects before VM work. All 12 Python behavior cases pass through the Go
harness wrapper after the fix.

Only the verifier, its tests and this report changed. Served runtime, installer,
workflow and PHP support remain unchanged, so no hosted test was relaunched.
The existing hosted PASS remains attributed to runtime `0654aa3`; the new
initialization failure path has focused local evidence. No merge or deployment
was performed.
