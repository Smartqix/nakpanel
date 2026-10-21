# Ubuntu 26.04-Only Support Transition Plan

> **Current authorization, 21 October 2026:** Phase 3 only: diagnose and fix
> `fwupd-refresh.service`, then run bounded hosted Ubuntu 26.04 current-version
> recovery and PHP maintenance tests with hosting PHP 8.3/8.4/8.5. Skip legacy
> tests. Report results before Phase 4; no Phase 4 work or production deployment.

**Goal:** Ship one Ubuntu 26.04 LTS (Resolute) server contract with hosting PHP
8.3, 8.4 and 8.5 and validated internal PHP 8.5. Ubuntu 26.04 remains experimental
until its operational qualification passes.

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
implementation branch. No commit/push, deployment or hosted qualification is
implied. A CI host named `ubuntu-24.04` can still build artifacts or host a
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
   - [ ] After explicit hosted-test authorization, run bounded current-version
     26.04 recovery and PHP delivery/configuration-failure/recovery checks,
     including required reboot and webmail assertions.
   - [ ] Record actual outcomes, skips, cleanup and remaining blockers. A
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
