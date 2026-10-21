# Ubuntu 26.04-Only Support Transition Plan

> **Current authorization, 21 October 2026:** Continue Phase 3 only: run hosted
> Ubuntu 26.04 PHP maintenance with the new diagnostics, fix the observed failure
> and verify recovery through both reboots. Keep hosting PHP 8.3/8.4/8.5; skip
> legacy tests. Report before Phase 4; no production deployment.

**Current status: Phase 3 PASS on hosted Ubuntu 26.04 AMD64.** Full run
[39652821843](https://github.com/Smartqix/nakpanel/actions/runs/39652821843)
passed on runtime/qualifier commit
`63c00f6006df3bba1ca9ef474e0f350ff7835165`. All 16 current-version gates,
actual PHP maintenance recovery, both unassisted reboots, three fresh Roundcube
send/read flows and owned cleanup passed. The workflow summary and independently
checked downloaded receipts agree. The run and its observer have ended.
**Phase 4 is unstarted.** Runtime changes are pushed on
`ricky/ubuntu26-recovery-phase3` and remain unmerged.

The two measured recovery errors are fixed. APT rejected `--reinstall` of the
half-configured FPM package despite all 56 cached archives being present.
Recovery now finishes only its pending configuration after removing the owned
fault, verifying the original full package inventory and signed installed
postinst, and accepting only a Conf-only simulation. It forbids unpacking,
downloads, removals and configuring unrelated packages. The deliberate failures
also consumed FPM's start counter. The fix retains that unit's actual state
before clearing only its counter, following the documented
[systemctl behavior](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).
Reboot verification does not start, restart or reset existing application
services to repair them; its transient smoke probes are separate.

| Run / tested source | Actual outcome |
| --- | --- |
| [39632906571](https://github.com/Smartqix/nakpanel/actions/runs/39632906571) / `a82d6ec` | All 16 gates PASS; PHP recovery FAIL at `drill_minor`; zero verified maintenance reboots; owned cleanup PASS. New safe frames identified the package step. |
| [39647396390](https://github.com/Smartqix/nakpanel/actions/runs/39647396390) / `02fd182` | Isolated diagnostic FAIL: APT `Internal Error, No file name` on the half-configured FPM reinstall. A cleanup log was retained, but no independent cleanup exit receipt; deletion is not promoted from that log alone. |
| [39649611313](https://github.com/Smartqix/nakpanel/actions/runs/39649611313) / `034284b` | Configuration-only recovery reached signed postinst, then FAIL on the consumed FPM start limit. Owned cleanup receipt PASS. |
| [39651263936](https://github.com/Smartqix/nakpanel/actions/runs/39651263936) / `63c00f6` | Isolated diagnostic PASS: real postinst failure, half-configured state and recovery for PHP 8.3/8.4/8.5; owned cleanup PASS. Product/reboot qualification explicitly false. |
| [39652821843](https://github.com/Smartqix/nakpanel/actions/runs/39652821843) / `63c00f6` | Full qualification PASS: 16 gates, real same-version delivery/configuration recovery, both reboots, three fresh actual mail flows, database-manager FastCGI health, unchanged package/configuration/desired state and owned cleanup. |

Final baseline: **77m40s**; maintenance preparation, actual recovery and both
reboots: **10m11s**. The isolated credential-free package diagnostic avoided
repeating the full baseline solely to collect APT errors. Local maintenance61/
preparation25 Python cases and seven focused Go checks passed. One independent
reviewer found no important defects and independently checked the affected
recovery tests.

Both reboot receipts are HEALTHY, have different boot IDs and record
`service_repair_performed=false`:

- Reboot 1: `c7300542-a335-4606-8e75-62410e882e2b`.
- Reboot 2: `afdd2d61-d723-4a4c-838d-95ce1ae9ec50`.

CLI and nonroot FastCGI checks retained PHP **8.3.36, 8.4.27 and 8.5.12** through
recovery and both boots, together with tool/worker and isolation assertions.
This is development-signed AMD64 same-version maintenance evidence. It does not
qualify ARM64, establish a genuine security-version advance or elapsed soak,
prove physical firmware servicing, or promote a production release. The
explicit owned-KVM firmware exclusion remains attributed to the observed LVFS
HTTP 503. Earlier failed runs below retain their original outcomes.

**Goal:** Ship one Ubuntu 26.04 LTS (Resolute) server contract with hosting PHP
8.3, 8.4 and 8.5 and validated internal PHP 8.5. Ubuntu 26.04 remains experimental
until its remaining release qualification passes.

**Architecture:** Reuse the Go panel, privileged agent, panelctl, APT/systemd
installer, central platform resolver, root-owned PHP runtime descriptors,
current-format encrypted backups and existing product/security verifiers.
Use the existing signed Resolute Surý provider for the full hosting runtime
set. A native PHP 8.5-only profile is not completion of this contract.

**Policy:** [AGENTS.md](../../../AGENTS.md).
**Design and rationale:** [Ubuntu 26.04 research](../../UBUNTU_26_04_RESEARCH.md).

## Current support contract

| Area | Required contract |
| --- | --- |
| Server OS | Ubuntu 26.04 LTS / Resolute only; reject all other server releases before mutation |
| Hosting PHP | 8.3/8.4/8.5, each with required extensions, CLI/FPM readiness and tenant isolation |
| Internal PHP | Validated PHP 8.5 for webmail and database-management tools |
| PHP supply | Existing signed Resolute Surý source, scoped origin/key policy and trusted descriptors |
| Application lifecycle | Fresh install and current-version application update/no-op/failure recovery on 26.04 |
| Data recovery | Current-format backup and restore to a compatible fresh 26.04 host; scheduler execution and real restored data |
| Architectures | Qualify each advertised architecture independently; cross-build success alone does not qualify ARM64 |
| Security | Preserve authorization, entitlement, agent boundaries, AppArmor, confinement, secrets and tenant isolation |

Ubuntu 24.04 installation/update support, Noble-specific runtime/default paths,
24.04 regression cells, 24.04-to-26.04 migration and reverse migration are
retired release requirements. Do not build compatibility adapters, backfills,
old-schema translators or historical archive/binary matrices. Development
schemas, fixtures and backups may be recreated. Preserve required user data,
security properties and explicit tenant PHP intent in current-version recovery.
In-place OS release upgrades and cross-architecture full-server restores remain
outside the support claim.

The support decision is effective now. Phase 2 implementation is complete
locally in the attached worktree identified below. The primary checkout holds
the policy/continuation record; its runtime code has not been merged with the
implementation branch, `ricky/ubuntu26-recovery-phase3`. Implementation commits
are pushed there; they are unmerged. A CI host named `ubuntu-24.04` can still build artifacts or host a
verified 26.04 guest without being a supported server OS.

## Current phases

These phases replace the previous dual-OS checklist and Tasks 1–10. Historical
results below retain their original attribution and create no authorization to
resume retired work. Report each phase before the next; start later phases only
after a new user instruction.

1. **Phase 1 — Policy, documentation and plan.**
   - [x] Set Ubuntu 26.04 LTS as the sole server OS in AGENTS.md, README and the
     root implementation plan.
   - [x] Retain hosting PHP 8.3/8.4/8.5 and internal PHP 8.5; full multi-PHP supply
     is required, not an optional parity project.
   - [x] Update active installation, recovery, verifier and soak documentation,
     clearly marking code/default alignment as pending Phase 2.
   - [x] Retire Noble and cross-OS migration requirements while preserving
     historical results, current recovery and security obligations.
   - [x] Review documentation consistency and verify runtime/workflow files were
     unchanged. No hosted tests or Phase 2 execution.
2. **Phase 2 — Align implementation and run focused local checks.**
   - [x] Update the shared resolver and standalone installer guards to accept
     only Ubuntu 26.04/resolute before package, file, schema or service mutation.
   - [x] Select the full PHP 8.3/8.4/8.5 Resolute contract consistently for fresh
     installs, plans, capability reporting and UI/API defaults. Keep explicit
     runtime choices and the ready allowlisted 8.4 preference. Internal tools
     remain on validated PHP 8.5; global PHP alternatives are not a shortcut.
   - [x] Remove Noble-only package/configuration branches, guest images, test
     cells and defaults. Remove obsolete cross-OS migration entrypoints and
     release gates; unsupported OS archives must still reject before mutation.
   - [x] Reuse the signed Resolute source, dependency pins and runtime
     descriptors. Native 8.5-only diagnostics may remain only if clearly
     separate from the required full hosting contract.
   - [x] Keep safe run ownership, distinct source/recovery VM identities and
     cleanup protection. Preserve existing worktree edits; do not reset them.
   - [x] Run affected local installer, runtime, plan and restore checks. Assert
     24.04 rejection with zero mutations and all three PHP versions on 26.04.
     Review workflow syntax without dispatching it. Report before Phase 3;
     no hosted tests in Phase 2 without a separate explicit instruction.
3. **Phase 3 — Resolve and validate Ubuntu 26.04 operational recovery.**
   - [x] Diagnose the actual `fwupd-refresh.service` failure from the DR
     prerequisite. Retain the unit journal and exact failed command before
     cleanup; distinguish host/image problems from application failures using
     measured evidence rather than silently masking failed services.
   - [x] Fix and locally verify the diagnosed issue. Expose per-gate progress
     and useful failure details before another long full qualification run.
   - [x] Pass the bounded current-version 26.04 recovery and PHP delivery/
     configuration-failure/recovery checks, including both required reboots and
     fresh webmail assertions. Full hosted run `39652821843` passed on `63c00f6`
     with PHP 8.3/8.4/8.5; the receipts are recorded above.
   - [x] Record actual outcomes, skips, cleanup and remaining blockers. A
     prerequisite failure cannot count as executing or passing the PHP drill.
     No cross-OS migration or legacy test is required. Report before Phase 4.
4. **Phase 4 — Scheduled backups, final qualification and handover.**
   - [ ] After operational recovery passes and this phase is authorized, prove
     real scheduler execution, current-format backup creation and restoration
     on 26.04 with the required hosting PHP inventory.
   - [ ] Run the affected CI/product/security chain and verify PHP 8.3/8.4/8.5,
     internal tools, mail, DNS/TLS, SQL, files, quotas, WordPress, workers,
     containers, Valkey, reboot and fresh-host recovery for each advertised
     architecture. Do not repeat accepted unchanged checks without a reason.
   - [ ] Keep genuine security-version advancement and 30–60 day endurance
     claims separate from same-version package delivery or a short test pass.
   - [ ] Update release documentation and PR evidence with measured source,
     dependency and architecture attribution. Promote only qualified claims.

## Phase 1 changes — 21 October 2026

Updated AGENTS.md, README.md, IMPLEMENTATION_PLAN.md, the research guidance,
this plan, recovery/soak/domain-removal guidance and database-manager README.
The policy now selects 26.04 only and retains the full hosting PHP set. Existing
source installers, runtime/profile code and workflows are unchanged; their
alignment is Phase 2 work. No local service/VM/database or hosted test was
started. Existing protected labs/soaks and source worktrees are untouched.

## Phase 2 local alignment results — 21 October 2026

Implementation is local and uncommitted in the attached `ubuntu-26-support`
worktree on `codex/ubuntu-26-support`, based on
`889c891ed9d4e8b948ef085aa779174a7df0104d`.

- The central resolver and component installers reject Ubuntu 24.04, unknown
  releases/codenames and unsupported architectures before mutation. Fresh 26.04
  selects `ubuntu-26.04-sury` with hosting PHP 8.3/8.4/8.5. Native 8.5-only remains
  an explicit diagnostic configuration, not the product acceptance contract.
- Internal PHP defaults, webmail rendering and the database-manager service use
  PHP 8.5. Trusted runtime mappings no longer accept the Noble profile. Tenant
  PHP selection and the ready allowlisted 8.4 preference are retained.
- Removed Noble package/PPA/webmail branches and their dedicated helper/tests.
  Package origins remain restricted to the actual Resolute suite and scoped
  signed Surý source. Existing key/dependency pins and confinement are retained.
- Backup collection/recovery require 26.04 identity, recorded compatible
  profiles, complete database/PHP provenance and required ready runtimes.
  Unsupported archives reject before service/database mutation. The forward
  migration CLI, provenance-reconstruction flag, migration shell verifier and
  historical-upgrade entrypoint are removed. Existing edits in the now-unwired
  migration fixture/probe files are preserved rather than reset.
- Main CI and hosted guest matrices/images now target only 26.04; native cells
  cover amd64 and arm64 separately. Current signed bundles are required, with
  no prior binary/image prerequisite. The canonical report has exactly 16
  current-version gates, explicitly excludes `real-upgrade`, and cannot pass
  the product summary with an incomplete PHP contract. CI host labels may
  remain `ubuntu-24.04`.
- New/updated behavioral contract tests failed against the old implementation
  before the fixes. Final focused verification passed across nine packages:
  **280 top-level Go tests passed, 16 skipped, zero failures**. Script/unit
  subtests also execute through these Go wrappers; this is not a count of every
  nested assertion. Fifteen top-level skips require an isolated PostgreSQL DSN;
  one is an existing DNS test placeholder. A ClamAV distinct-UID subcheck also
  skipped where passwordless sudo was unavailable. No local database/service
  was started to bypass these limits.
- Checks cover installer/package rejection, all hosting PHP mappings, internal
  PHP/webmail, CLI, current restore/integrity/mutation boundaries, ready plan
  selection and workflow/report/image behavior. A broader local harness run
  exposed stale Noble/old-matrix fixture expectations; they were corrected,
  and the affected tests passed their focused rerun. No hosted result was
  changed or claimed by these local checks.
- Final static checks passed: workflow actionlint, syntax for 11 changed Bash
  and 11 changed Python files, Go formatting and `git diff --check`. No hosted workflow,
  existing VM, system service, database, commit, push or deployment was started.

Phase 2 is complete locally. Phase 3 is now authorized and in progress. The actual
`fwupd-refresh.service` DR failure, unexecuted PHP recovery drill, scheduled
backup acceptance and other unproved operational claims remain pending.

## Existing implementation and evidence

The attached implementation worktree is
`/Users/rickynkansah/.codex/worktrees/ubuntu-26-support/nakpanel`, on
`codex/ubuntu-26-support`, based on `889c891ed9d4e8b948ef085aa779174a7df0104d`.
It now accepts only 26.04 and defaults to the complete Surý PHP profile; the
native 8.5-only configuration remains explicit and diagnostic. Phase 2 reused
the existing panel/provider implementation and removed the Noble contract.

Previous AMD64 product baselines passed for Ubuntu 24.04, native 26.04 and Surý
26.04. Those results stay attributed to their tested sources; they do not prove
this new scope is implemented or that maintenance/scheduler acceptance passed.
ARM64 hosted qualification, genuine PHP security-version advancement and the
longer endurance window remain unproved. No readiness claim is upgraded by
retiring an OS or deleting a failing test requirement.

## Historical hosted attempts — previous Phase 3

These were the one-attempt workflows authorized under the former dual-OS
scope. Both are closed; there is no continuing launch or retry authorization.

| Workflow | Hosted run | Original result | Effect of the new scope |
| --- | --- | --- | --- |
| Current-version Ubuntu 24.04 → 26.04 migration | [39580017306](https://github.com/Smartqix/nakpanel/actions/runs/39580017306) | FAIL during source preparation; no 26.04 target created; cleanup passed | Retired requirement; not a release blocker and not a pass |
| Current-version Ubuntu 26.04 PHP maintenance recovery | [39582799272](https://github.com/Smartqix/nakpanel/actions/runs/39582799272) | FAIL in the DR prerequisite (`phase29`); PHP maintenance skipped; cleanup passed | Still relevant to Phase 3 operational acceptance |

Migration stopped at `prepare` after 223 commands. Its precise inner error was
not retained; the public job log contained only a generic refusal. No target
restore was verified. The source was cleaned up and the process group drained.
No further investigation or retry is required for this retired migration path.

The 26.04 maintenance prerequisite ran from 10:15:02 to 11:06:20 UTC. Six gates
passed: bundle, fresh-install, inventory, phase28, valkey-platform and security.
The `phase29` gate then reported a failed `fwupd-refresh.service` on the restored
VM; its underlying failure cause was not retained. Nine later gates were
pending, and the actual PHP prepare/maintenance drill was skipped. Package
delivery, intentional FPM failure, recovery and maintenance reboot/webmail were
not exercised. Canonical execution and cleanup process groups drained; owned
cleanup passed with zero owned VMs remaining.

That runner explicitly excluded the historical `real-upgrade` gate and required
16 current-version prerequisites. Its test qualifier was
`6381b526c936569876f029c9134c5baca2d465b0`; the signed application runtime was
`6378b0ae9d15f17481b080926af7fb0bf0761724`. These are historical bindings, not
instructions to reuse old artifacts automatically. No scheduled-backup or
legacy workflow was launched in that phase.

## Historical local integration results — previous Phase 2

The two fixes and their regression tests are integrated in the attached
`ubuntu-26-support` worktree on `codex/ubuntu-26-support`, as local, uncommitted
changes on commit `889c891ed9d4e8b948ef085aa779174a7df0104d`.

- Migration checks now wait, with the existing 300-second deadline, for the
  owned application/account revisions, healthy generation and endpoint to agree,
  and for relevant convergence work to finish. Future periodic jobs do not block
  readiness. Existing isolation, listener, image and HTTP checks remain strict.
- The dpkg parser accepts the exact 1.22 and 1.23 postinst diagnostic forms used
  by the supported OS versions. It still requires APT exit 100, the owned FPM
  configuration failure and a half-configured package. Wrong packages/scripts,
  exit 10 and unrelated exit-1 text are rejected.
- Eight new regression methods reproduced the defects against the unchanged
  implementations: 15 assertion failures, zero test errors. After the fixes, the
  two affected Python modules ran 157 tests: 156 passed and one PostgreSQL
  integration case was skipped because no isolated database DSN was supplied.
- Ten focused installer tests passed, covering the Ubuntu 24.04/26.04 profile
  contract, rejection before mutation, package origins and Noble Roundcube
  behavior. Ubuntu 24.04 still resolves internal PHP 8.3 and hosting PHP
  8.3/8.4/8.5. Installer/profile files were unchanged.
- `git diff --check` passed. No local VM, service or database was started; no
  historical compatibility fixes were integrated. No agents, hosted tests,
  commits, pushes or deployments were started.

## Completion evidence

Phase 1 is complete after the documentation agrees on Ubuntu 26.04-only scope,
required hosting PHP 8.3/8.4/8.5, retired 24.04/migration obligations, historical
result attribution and the explicit stop before implementation/hosted tests.
Document review and unchanged-runtime checks are sufficient for this phase.

Later completion requires the implemented contract and measured current-version
26.04 evidence for the remaining operational and scheduled-backup requirements.
A successful cross-build, OS guard change, retired failure or health endpoint
alone does not qualify a platform. Historical archives, prior binaries,
compatibility wrappers, backfills and transitional migrations remain excluded.

## Phase 3 diagnosis and hosted execution — 21 October 2026

Active implementation branch: `ricky/ubuntu26-recovery-phase3`, in the same
attached `ubuntu-26-support` worktree. Commit `c602d66` records the Phase 2
implementation and the bounded diagnostic entrypoint; the primary checkout's
runtime remains unmerged.

The standalone [diagnostic run 39600020263](https://github.com/Smartqix/nakpanel/actions/runs/39600020263)
used the original signed image pin, serial `20260927`, Ubuntu 26.04.1 KVM
AMD64, fwupd/libfwupd3 `2.1.1-1ubuntu3.1`. With only stderr redirected to the
journal, the vendor service exited 1: LVFS metadata download returned HTTP
503, “Timed out while waiting”, Varnish error 54113. Root's manual refresh
also exceeded its 90-second diagnostic limit (exit 124). The diagnostic job
succeeded in collecting a real service failure; that is not a firmware-refresh
pass. Cleanup succeeded. The original run 39582799272 lacked the underlying
unit journal, so its exact error cannot retrospectively be asserted as 503.

The upstream auth bug was investigated but not reproduced; no polkit privilege
change is applied. The measured failure is an external firmware metadata
outage, independent of Nakpanel's data restore. Hosted qualification now has
an explicit firmware policy enabled only for owned disposable Actions KVM
guests. An ExecCondition skips physical-firmware metadata refresh in these
guests and records `EXCLUDED_HOST_FIRMWARE` / `physical_firmware_validated=false`
in each VM receipt and the canonical report. It does not claim LVFS is repaired,
accept failed downloads, reset failed units or mask a service. Firmware remains
the hypervisor's responsibility in this test environment. Production installers
and physical-host firmware policy are unchanged. All other failed units remain
fatal. Recovery now also captures the actual target VM's failing-unit result,
exit code and bounded journal before failing.

Retained standalone evidence:
`/Users/rickynkansah/.local/state/nakpanel/qualification/2026-10-21/phase3-fwupd/`.
Hosted operational recovery and actual PHP maintenance results remain pending.
Phase 4 has not started.

Phase 3 current-version run: [39601839959](https://github.com/Smartqix/nakpanel/actions/runs/39601839959),
source `9424e592ab1b1f396f8707c2cb1f98bec0713ebe`, attempt 1, hosted AMD64
Ubuntu 26.04 / full Surý PHP contract, database-manager coverage and actual PHP
maintenance requested. Signed bundle/image verification passed. The baseline
is running; PHP maintenance is not yet executed or accepted. Runtime source is
pinned to this commit even while these continuation notes are updated locally.

One observer (exec session `62838`) records state at
`/Users/rickynkansah/.local/state/nakpanel/qualification/2026-10-21/phase3-current/`.
It will retain terminal artifacts/logs and cancel this run after a three-hour
observation limit. Do not start another run or observer while it is active.
No Phase 4 scheduler, endurance, ARM64 qualification, promotion or deployment
is being performed.

Run 39601839959 is terminal: all 16 current-version canonical gates PASS,
including phase29 populated recovery/rollback/reboot, phase30 all three hosting
PHP versions and internal-tools/mail/browser assertions. Source, DR and fault
VM firmware receipts explicitly record `EXCLUDED_HOST_FIRMWARE` and actual
`exec-condition`; physical firmware is not validated. Owned guest cleanup PASS.

Actual PHP package mutation did not execute: preparation failed closed at
`signed-provider-baseline/exact-php-closure`, code
`signed-runtime-row-mismatch`. The retained inventory plus the exact
native-gpgv-authenticated InRelease and checked index confirm an upstream
publication changed 44 package rows during qualification. Installed CLI
versions were 8.3.35/8.4.26/8.5.11; the authenticated current index now contains
8.3.36/8.4.27/8.5.12 and a new php-common build dated 20261021. Both the index
bytes and their signed Release digests were checked locally against the
retained native signature receipt. This is publication drift, not a dpkg parser
failure. The overall hosted summary correctly FAILs and does not accept missing
maintenance coverage. No signature/origin/version checks are relaxed.

The first observer has exited after retaining artifacts/logs and the bounded
provider comparison at `phase3-current/provider-publication-drift.json`. One
fresh run is authorized within this same phase to test the changed PHP package
builds; previous runtime results remain attributed to the previous patch
versions. Keep the original cancellation deadline, 15:43:54 UTC on 21 October,
and report any remaining blocker rather than launching further attempts.
Phase 4 remains unstarted.

The one follow-up is [39613417644](https://github.com/Smartqix/nakpanel/actions/runs/39613417644),
source still `9424e592ab1b1f396f8707c2cb1f98bec0713ebe`. Only active observer:
exec session `24103`; evidence under
`/Users/rickynkansah/.local/state/nakpanel/qualification/2026-10-21/phase3-new-php/`.
Original hard cancellation deadline remains `2026-10-21T15:43:54Z`; the
observer will then wait only for cleanup and terminal collection. Observer
62838 and run 39601839959 are complete; do not resume them. No further hosted
retry is planned in this phase.

## Historical Phase 3 terminal report — 21 October 2026

> Snapshot before the newly authorized diagnostic/recovery work. The failures
> remain failures; the current acceptance and source are recorded at the top.

**Outcome: operational recovery passes; PHP maintenance recovery remains an
unresolved Phase 3 blocker. No Phase 4 work, promotion or deployment.**

| Run | Tested source / packages | Operational baseline | PHP maintenance | Cleanup |
| --- | --- | --- | --- | --- |
| [39601839959](https://github.com/Smartqix/nakpanel/actions/runs/39601839959) | `9424e592ab1b1f396f8707c2cb1f98bec0713ebe`; initial inventory 8.3.35/8.4.26/8.5.11 | All 16 gates PASS; 65m55s | FAIL before package mutation: live signed index publication replaced installed-version rows | PASS |
| [39613417644](https://github.com/Smartqix/nakpanel/actions/runs/39613417644) | Same application source; authenticated baseline 8.3.36/8.4.27/8.5.12 | All 16 gates PASS; 62m59s | FAIL with ValueError before a confirmed RECOVERED receipt; zero verified maintenance reboots | PASS |

Both baselines covered current-format populated fresh-host DR, application
update/rollback, reboot/reconciliation, full hosting PHP, tenant isolation,
internal tools, webmail/browser flows and the current product/security gates.
The 26.04-only current-version scope explicitly excludes `real-upgrade`; no
legacy archives/binaries, Noble regression or cross-OS migration was run.
Source/DR/fault firmware receipts record actual ExecCondition skips, not a
firmware-refresh pass. LVFS's external HTTP 503 is not repaired by this project.

The first run's canonical window was 12:51:57–13:57:52 UTC. Its signed provider
Release was published at 13:37:15 UTC, inside that window. The initial inventory
has 44 versions absent from that later authenticated index; this is an inventory
snapshot comparison, not a reconstructed final guest inventory. The guard
correctly refused same-version delivery without an authenticated matching row.
The second run obtained a matching authenticated package baseline, real
Roundcube baseline, measured capacity and cold retention. Those safeguards
passed; they are not proof that the subsequent package recovery succeeded.

The second drill's result is `FAIL`, `error_type=ValueError`,
`guest_state=stopped_after_failure`, `reboots=[]`. No `recovery.json` or reboot
receipt was published. A guest transfer/staging write occurred, but retained
public evidence cannot establish how far PHP package mutation progressed.
Detailed private guest stdout/stderr was not uploaded and is no longer
available after runner cleanup, so the underlying failing guest check is
**unknown**. Do not infer a parser, package or runtime root cause from the
exception type. The overall hosted summaries correctly FAIL both attempts.

A follow-up reporting fix, locally tested after these runs, now records the
maintenance stage and reviewed source function/line frames, including safe
frames from a failed guest action. It excludes exception text, paths, locals
and command output; malformed or foreign guest frame fields are discarded.
This fix does not change package/signature/health checks or turn a failure into
a pass. It was **not hosted-validated** and cannot recover the missing details
from either completed run. Runtime qualification remains attributed to `9424e59`.

Focused local verification passed for recovery unit diagnostics, hosted guest
ownership/exclusion guards and the maintenance behavior/preparation suites
(57 + 25 Python cases, including the new privacy and source-location tests).
The hosted workflow passed actionlint; changed shell syntax and diff checks
passed. No local VM, database or protected service was started or changed.

Both observers (62838 and 24103) have exited after collecting terminal artifacts
and logs under the two evidence directories above. There is no active hosted
run, retry, watcher or scheduled automation. No further hosted retry was made.
The remaining Phase 3 work is to identify/fix the guest maintenance failure
using the improved receipts, then obtain actual RECOVERED, two unassisted reboot
and three fresh Roundcube-flow receipts before accepting PHP maintenance.
Report that result before Phase 4.

## Historical two-pass recheck — 21 October 2026

> Local review before the latest hosted authorization. Its pending work was
> subsequently completed by run `39652821843`, as recorded above.

**Scope:** Review and fix the Phase 3 changes twice, using focused local checks.
Keep Ubuntu 26.04 only, hosting PHP 8.3/8.4/8.5, and the unresolved hosted PHP
failure visible. No Phase 4 work, new hosted run, merge or deployment.

1. **Maintenance failure reporting.** Reproduced missing FAIL receipts for early
   host ownership/identity refusals and a stale STARTED receipt for a helper hash
   refusal. Put these checks inside the existing guarded failure path, before any
   guest write, and record explicit stages. Reboot identity, restart, cloud-init,
   guest health and final identity checks now record their own stages before
   execution rather than inheriting the previous Roundcube label. Regression
   cases cover three early refusals and eight reboot failure positions; early
   refusal performs no guest write or stop, while later failure stops only a
   still-owned guest. The complete maintenance suite passed: **59 Python cases**.
2. **Independent health and evidence review.** Reproduced an empty failed
   systemd query being accepted when the helper is called from a shell
   conditional, which disables implicit errexit within the function. Failed or
   incomplete queries now fail explicitly before interpreting their output.
   Regression cases cover empty and partial query errors, healthy output, real
   failed units and unavailable journals. Rechecked the maintenance publication,
   cancellation/ownership guards, firmware exclusion and OS/PHP contracts using
   **8 focused Go checks**, including the full **59 + 25 Python suites**. All
   passed. Actionlint, changed Bash syntax, gofmt and `git diff --check` passed.

Both fixes had failing regression cases before implementation. Raw exception
text and command output remain private. The firmware policy remains limited to
owned disposable hosted KVM guests and records an exclusion; physical firmware
is not validated. Protected local VMs, PostgreSQL and services were untouched.

**Remaining blocker:** The completed hosted PHP maintenance failure has no
recoverable detailed guest diagnostic. These local fixes do not identify its
root cause or prove recovery. Actual RECOVERED, two unassisted reboot and three
fresh Roundcube-flow receipts are still required. Phase 3 remains incomplete.
