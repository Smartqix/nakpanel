# Ubuntu 26.04-only support research and design

Research began on 18 October 2026. The current decision was approved on
21 October 2026: Ubuntu 26.04 LTS is the only supported server OS; hosting
PHP 8.3/8.4/8.5 remains required. This supersedes the former dual-OS proposal,
Noble-preservation requirements and cross-OS migration milestone.

Code/default/workflow alignment is implemented on the unmerged
`ricky/ubuntu26-recovery-phase3` branch. Hosted AMD64 Phase 3 recovery and PHP
maintenance passed in run `39652821843` on `63c00f6`; the Phase 4 scheduled
local-backup/restore slice passed in run `39676085171` on `0654aa3`. The later
verifier diagnostics fix `1140165` has focused local evidence and changes no
served runtime. [AGENTS.md](../AGENTS.md) is project policy; the
[transition plan](superpowers/plans/2026-10-18-ubuntu-26-04-support.md) records
the source bindings and remaining release requirements. Current authorization
permits pushing the prepared branch, opening its PR into main and running only
required CI, including the hosted security gate. Report before merging or
deploying; do not dispatch optional hosted qualification.
Ubuntu 26.04 remains experimental.

## Decision and rationale

A pre-production product can choose one server release and recreate development
environments instead of maintaining older installation, migration and regression
paths. Ubuntu 26.04 provides standard security maintenance through May 2031;
26.04.1 was released on 27 August 2026. Package-level security coverage still
depends on the package origin and repository. This decision narrows the supported
OS matrix without relaxing runtime, recovery or security requirements.
[Ubuntu lifecycle](https://ubuntu.com/about/release-cycle),
[26.04.1 announcement](https://lists.ubuntu.com/archives/ubuntu-announce/2026-August/000326.html).

Ubuntu 24.04 support, Noble-specific installer/runtime branches and qualification
cells, and 24.04-to-26.04 migration are no longer release obligations. Their old
results remain historical evidence. In-place OS upgrades, reverse migration and
cross-architecture full-server restore are outside the support claim.

## Required PHP contract

| Area | Required behavior |
| --- | --- |
| Tenant hosting | PHP 8.3, 8.4 and 8.5, with required extensions and real CLI/FPM checks |
| Internal tools | Validated PHP 8.5 for webmail and database management |
| Package supply | Existing signed Resolute Surý provider with scoped key/origin policy |
| Selection | Explicit site versions preserved; implicit selection uses only permitted ready runtimes, retaining the ready 8.4 preference |
| Isolation | Per-tenant units, sockets, filesystem permissions and confinement remain enforced |
| Maintenance | Maintained package delivery, intentional configuration-failure recovery, reboot and webmail checks |

Ubuntu's native PHP 8.5 packages alone do not satisfy the three-version hosting
requirement. The implementation already has a separate `ubuntu-26.04-sury`
profile for the complete set. Reuse it; a new Nakpanel PHP build/repository
project is not required by this scope change. A native 8.5-only profile may be a
separate diagnostic/minimal configuration, but cannot stand in for full product
acceptance. [Ubuntu PHP package index](https://packages.ubuntu.com/resolute/php/),
[Surý suite index](https://packages.sury.org/php/dists/).

PHP 8.3 has upstream security support through December 2027, PHP 8.4 through
December 2028 and PHP 8.5 through December 2029. These dates are separate from
the Ubuntu OS lifecycle. Nakpanel project maintainers own the PHP update and
recovery policy through GitHub, as previously selected by the user.
[PHP supported versions](https://www.php.net/supported-versions.php).

The original research found no valid Resolute suite at the old Ondřej Ubuntu
PPA URL; its `devel` alias resolved to Noble. That observation concerned the old
source, not the implemented signed Resolute Surý path. Never reuse Noble
packages, rewrite suite names or weaken signature/origin checks on Resolute.
Package metadata must be refreshed during future implementation/qualification;
this documentation phase performs no package installation or enrollment.

## Reuse the existing architecture

Keep the Go panel, privileged agent and panelctl, immutable service-plan
contracts, central installer platform resolver, trusted runtime descriptors,
APT/systemd deployment and current encrypted backup design. The Phase 2 alignment removed obsolete Noble branches from the supported paths
and reused this architecture. Go targets `linux/amd64` or `linux/arm64`; distribution-specific
package and service contracts still require real guest tests.
[Go targets](https://go.dev/doc/install/source),
[Go compatibility](https://go.dev/doc/go1compat).

Use the same trusted runtime descriptor for capability probes, isolated PHP-FPM
units, CLI, cron/workers, Composer, WP-CLI and internal tools. Root-owned profile
state supplies executable/configuration roots; HTTP/RPC clients cannot register
arbitrary executable paths. Changing the server OS contract must not alter a
site's explicit PHP version or collapse tenant runtimes into an unrestricted
shared service.

Keep internal PHP separate from hosting choices. The implementation worktree
already records internal PHP 8.5, Composer 2.10.3 and signed/checksummed upstream
Roundcube 1.6.19 for its 26.04 profiles. Preserve and qualify those dependencies;
do not return internal tools to hardcoded PHP 8.3 or patch installed vendor PHP
with ad hoc substitutions. The original Roundcube research found an
`array_first` collision with PHP 8.5 in the older distribution source; upstream
1.6.19 guards that declaration. This source finding alone is not complete
application qualification.
[Roundcube 1.6.19 source](https://github.com/roundcube/roundcubemail/blob/1.6.19/program/lib/Roundcube/bootstrap.php),
[PHP array_first](https://www.php.net/manual/en/function.array-first.php).

Plesk's useful pattern is explicit platform qualification, distribution-specific
PHP packages and registered handlers. Nakpanel can use that separation while
supporting a single server OS; it does not need Plesk packages or Plesk's OS
matrix. [Plesk PHP handler interface](https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/php_handler-php-handlers.72490/).

## Installation, recovery and test boundaries

- Reject every server OS except Ubuntu 26.04/resolute before package, installed
  file, schema or service mutation. Recorded platform/profile mismatches must
  reject even on a same-version/no-op application update.
- Recreate development fixtures and schemas directly when the design changes;
  no legacy adapters, old-schema translation or backfills are required.
- Require current-format archive provenance, compatible database tools, required
  runtimes and the same qualified OS/architecture before stopping services or
  replacing files/databases. Reject unsupported archives before mutation.
- Restore current-version data to a compatible fresh 26.04 host and verify mail,
  tenant files/databases, secrets, numeric ownership, quotas, TLS, desired stopped
  services, reconciliation and a second reboot.
- Describe application rollback honestly: it does not reverse an OS release or
  all APT package transactions. PHP maintenance recovery is a separate test.
- Use unique run-owned source/recovery guests and retain failure details before
  cleanup. Protect existing lab/soak VMs. A name prefix alone does not establish
  ownership.
- A CI host running Ubuntu 24.04 can remain where it merely builds or hosts
  verified 26.04 guests; it is not a supported-server qualification cell.

## Existing results and remaining blockers

Earlier AMD64 product baselines passed for native and Surý Ubuntu 26.04. Previous
Ubuntu 24.04 passes are retained as historical evidence. Those results remain
attributed to their tested source and dependencies; the new policy does not
turn them into acceptance of changed implementation or unexecuted maintenance.

| Historical attempt | Actual result | Current relevance |
| --- | --- | --- |
| [24.04 → 26.04 migration, 39580017306](https://github.com/Smartqix/nakpanel/actions/runs/39580017306) | Failed during source preparation; exact inner cause unknown; cleanup passed | Retired release requirement; remains a failure, not a pass |
| [26.04 PHP maintenance, 39582799272](https://github.com/Smartqix/nakpanel/actions/runs/39582799272) | Six prerequisite gates passed, then DR failed on `fwupd-refresh.service`; actual PHP drill skipped; cleanup passed | Historical failure; original inner error was not retained. Later diagnosis and accepted recovery are recorded in the transition plan |

Subsequent accepted AMD64 results are separately bound to their tested source:
[Phase 3 run 39652821843](https://github.com/Smartqix/nakpanel/actions/runs/39652821843)
passed all 16 gates, PHP delivery/configuration-failure recovery, both reboots and
fresh webmail flows on `63c00f6`;
[Phase 4 run 39676085171](https://github.com/Smartqix/nakpanel/actions/runs/39676085171)
passed actual scheduled local backups, exact-archive fresh-host restore, all
three PHP runtimes/data before and after reboot, resumed scheduling and cleanup
on `0654aa3`. Final-branch CI, ARM64 qualification, a genuine PHP security-version
advance and 30–60 day endurance remain separate. Static Go cross-builds and
package availability do not establish those remaining claims.

## Phased rollout and completion

1. **Phase 1:** update policy, active documentation and the plan for the sole OS
   and full hosting PHP set; report and stop. No runtime or workflow edits/tests.
2. **Phase 2:** align installer/runtime/defaults/CI, remove retired Noble and
   migration requirements, run focused local checks and report. No hosted launch
   without explicit authorization.
3. **Phase 3:** diagnose and fix the 26.04 DR failure; after explicit
   authorization, obtain actual current-version recovery and PHP maintenance
   results with clear per-gate progress and retained failure details.
4. **Phase 4:** after recovery acceptance and authorization, prove scheduled
   backups and complete affected product/security/reboot/restore qualification
   for every advertised architecture; publish measured results.

All three hosting PHP runtimes must be supplied and exercised for the final
contract. Do not claim a percentage reduction in validation cost merely from
removing one OS: provider choices, runtimes and architectures still require
coverage. The linked plan replaces the original dual-release and optional-PHP
proposal; no later phase is launched by this document.
