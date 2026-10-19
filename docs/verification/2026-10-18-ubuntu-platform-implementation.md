# Ubuntu platform implementation evidence — 18 October 2026

Baseline: `ef8b5a7ebc0462cb90a1ae5b8fa98e4a3af46466`.
This is an implementation and qualification record, not a production support declaration.
See [qualification procedures](../PLATFORM_QUALIFICATION.md), [recovery boundaries](../RECOVERY.md), and [the original plan](../superpowers/plans/2026-10-18-ubuntu-26-04-support.md).

## Implemented contracts

| Profile | Internal PHP | Hosting PHP | Enrollment |
| --- | --- | --- | --- |
| `ubuntu-24.04` | 8.3 | 8.3, 8.4, 8.5 | Existing default preserved |
| `ubuntu-26.04-native` | 8.5 | 8.5 | Fresh Resolute default; experimental |
| `ubuntu-26.04-sury` | 8.5 | 8.3, 8.4, 8.5 | Explicit fresh `--php-provider sury`; experimental |

The optional Surý source uses the actual Resolute suite, a pinned public key and authenticated Release identity, repository-specific trust, and PHP-only APT priorities. It cannot enroll a Noble host or silently change an existing native installation's provider. The old Launchpad Resolute PPA still returns 404; the separate upstream repository now publishes Resolute packages. Private Nakpanel PHP packaging remains an optional unqualified fallback.

All installers check actual OS/codename/architecture and trusted installation metadata before version no-op. Existing unrecorded installations on Resolute reject; neither binary compatibility nor a missing metadata file authorizes an in-place OS upgrade. Package candidates and simulated transactions precede application replacement and migrations.

Both architecture release bundles contain matching binaries, migrations, units and installer assets. RSA signatures cover the exact inventory, static ELF policy and CPU baseline. Installation authenticates a private root-owned staged copy. Go 1.26.9 is pinned consistently; the source migration path still requires Go.

Runtime readiness and execution use one trusted descriptor. Internal tools use their profile-selected PHP independently of tenant intent. Native fresh-plan initialization is transactional, requires validated PHP and exact pristine seed state, and records immutable revisions/audit receipt. A persistent systemd condition blocks panel background jobs until that initialization and supplied administrator setup commit, including across interrupted installs and reboot. Effective pending state includes the root-owned marker after an interrupted JSON commit. An ordinary retry resumes fresh prerequisites even if only binaries were copied, preserves original administrator intent, and retains downgrade refusal. Seven interrupted-stage control-flow tests pass.

Recovery authenticates the complete archive and checks actual target runtime readiness before stopping services or replacing data. Roundcube SQLite uses the online backup API and atomic restoration; archives carrying it require format 2 and a new restore binary. Legacy format-1 archives remain readable under conservative provenance rules. Forward migration is explicit and experimental; same-platform restore rejects profile changes.

New tenant accounts use UID/GID10000–59999; existing marked identities remain unchanged. Exact legacy identity collisions on a migration target reject. Fresh Noble Roundcube setup selects SQLite before its first package installation and preserves existing configured backends. New complete backups reject configured SQL Roundcube backends they cannot export, instead of silently omitting their state; old same-platform format1 readers remain unchanged.

Rootless application units enforce policy limits in root-managed cgroups. Podman's accepted command-line flags alone do not count as enforcement. Qualification checks actual memory/PID/CPU limits before and after reboot.

## Completed local verification

- Full `go test ./... -count=1` passed with pinned Go1.26.9 on the frozen merged source, including the final runtime, installer retry, identity, recovery and harness corrections.
- `go vet ./...`, full generation, focused installer/harness tests and 18 release policy tests passed on the merged source. Focused race tests, shell syntax and workflow lint have passed at the recorded checkpoints. The final independent review also passed the five affected packages and all21 concrete forward-fixture Python tests.
- Static panel/agent/panelctl builds and signed development bundle verification passed for both amd64 and arm64. Development signatures are explicitly nonpromotion evidence.
- Real PostgreSQL integration covered strict fresh bootstrap, drift rejection, transaction rollback, immutable history and idempotent receipt.
- Real SQLite tests included an uncheckpointed WAL and encrypted contact/preference archive round trip.
- Actual Chrome browser verification passed the merged Mail workspace on desktop/mobile, keyboard/focus/dialogs, no-JavaScript fallback and persistent mounted-shell navigation. This is loopback fixture evidence; live mail/SSO remains part of native qualification.
- Both pinned Stalwart 0.11.8 archives passed official Sigstore certificate/log and GitHub SLSA provenance checks. Installer preflight validates digest/size/archive layout/architecture before application mutation; installation revalidates the exact bytes and publishes atomically.
- A real isolated PostgreSQL removal-guard database passed all ten reference categories, including active/desired site versions, backups and tombstones.
- Actual ARM64 private PHP 8.3.35 and 8.4.26 source builds produced installable Debian packages and passed CLI/FPM extensions, isolated FastCGI, Composer/WP-CLI, private workers and removal-guard smoke. This does not qualify production provider activation.

## Native qualification in progress

| Evidence | Result at this checkpoint |
| --- | --- |
| Noble ARM64 genuine fresh installation | Passed; site, database, DNS and TLS provisioned through product routes |
| Noble populated signed candidate update | Passed; rootless application resource/reboot gate passed; complete security/DR chain pending |
| Resolute ARM64 native genuine fresh installation | Candidates 3 and 4 passed bootstrap plus actual site/database/DNS/TLS product checks; complete gate chain pending |
| Resolute ARM64 optional Surý profile | Signature/suite and both-architecture inventory verified; actual PHP83/84/85 APT, extensions, CLI/FPM/FastCGI/tools and fresh application installation passed; rootless application/reboot gate passed; full chain pending |
| AMD64 native execution | Hosted KVM qualification workflow implemented; execution pending |
| Cross-release full migration | Concrete fixture preparation/driver and strict restore implemented; real rehearsal pending a complete compatible source fixture |
| Soak/security-patch delivery | Not yet completed; no production promotion |

The same current ARM64 application payload is used on both releases. Native evidence remains local while execution continues; final accepted summaries must replace this pending table before support promotion.

## Failures found and corrected

Native tests exposed an `apt-cache` SIGPIPE under `pipefail`, Resolute's removed `postgresql-contrib` metapackage, legitimate Roundcube archive links rejected by an overly broad check, premature panel workers mutating pristine bootstrap seeds, ignored rootless Podman cgroup flags, and APT's negative repository priority display under a PHP-only allow rule. Each correction has a regression test; the affected native gate must pass after the fix. Later native probes exposed Valkey parent ACL loss after reboot, Resolute Podman runtime-directory confinement, Noble Roundcube preseed ordering and historical-upgrade/security fixture assumptions. Corrections now have passing behavior tests and source review; the final candidate must rerun these native gates. These earlier failures are not passing qualification results.

An independent review found six Important issues in candidate 1: circular bootstrap readiness, CI ownership/matrix gaps, legacy missing-profile enrollment, omitted Roundcube SQLite persistence, preflight-triggered service restart, and restore readiness differing from execution. A second independent review confirmed all six resolved with no new Important/Critical findings. The final source review found and closed interrupted-install retry, startup-marker cleanup, early prerequisite resumption, shared Podman backup dependency, and development-bundle environment handoff gaps. No open source-review finding remains in that scope. Native acceptance is still pending.

All live mutations used uniquely owned disposable guests. Existing lab, soak, Hestia and Plesk guests were not modified. Failed run evidence is retained; a new run identity is required after cleanup. No production signing identity, package endpoint, private provider activation, or OS release upgrade was created implicitly.
