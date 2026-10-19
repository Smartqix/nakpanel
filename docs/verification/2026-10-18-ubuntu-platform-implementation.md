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

Recovery authenticates the complete archive and checks actual target runtime readiness before stopping services or replacing data. Roundcube SQLite uses the online backup API and atomic restoration; archives carrying it require format 2 and a new restore binary. Default local Noble MySQL Roundcube uses format 3 with a separate encrypted SQL payload, active credentials and private dbconfig package state. Same-platform recovery restores its original backend and only its local database-scoped account; trusted target CLI/FPM PDO MySQL checks precede mutation. SQL forward migration and remote/custom configurations reject explicitly. Legacy format-1 archives remain readable under conservative provenance rules. Forward migration is explicit and experimental; same-platform restore rejects profile changes.

New tenant accounts use UID/GID10000–59999; existing marked identities remain unchanged. Exact legacy identity collisions on a migration target reject. Fresh Noble Roundcube setup selects SQLite before its first package installation and preserves existing configured backends. Default local MySQL Roundcube backups are included through the explicit format-3 contract; unsupported remote/custom SQL backends reject rather than being omitted. Old same-platform format-1 archives remain readable with their original coverage limitations. The real retained Noble MySQL disaster-recovery test is pending; source tests alone do not qualify it.

Rootless application units enforce policy limits in root-managed cgroups. Podman's accepted command-line flags alone do not count as enforcement. Qualification checks actual memory/PID/CPU limits before and after reboot.

## Completed local verification

- Full `go test ./... -count=1` passed with pinned Go1.26.9 on the frozen merged source, including the candidate6 installer, format-3 MySQL recovery, complete PHP intent inventory, durable artifact staging and isolated rollback-companion corrections.
- `go vet ./...`, full generation, focused installer/harness tests and 18 release policy tests passed on the merged source. Focused race tests, shell syntax and workflow lint have passed at the recorded checkpoints. The final candidate6 checkpoint also passed all33 concrete forward-fixture Python tests and14 real-signature artifact-staging tests. Independent reviews closed all identified source findings; native acceptance remains separate.
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
| Noble ARM64 genuine fresh installation | Candidate5 application, site/database/DNS/TLS, inventory and new UID59999 passed; actual Roundcube backend remained MySQL because of an incorrect debconf namespace. Fresh candidate6 SQLite acceptance is pending. |
| Noble populated historical update and containers | Actual ef8b5a7 to candidate5 populated signed update passed. Full Phase28 resource/network/rollback/suspend/reboot/teardown passed. Next gate correctly rejected artifacts deleted from `/tmp`; the complete rerun is pending. |
| Resolute ARM64 native fresh installation | Candidate5 failed BIND startup under umask077 because its managed parent lacked bind traversal. The corrected installer has passing regression tests; fresh candidate6 acceptance is pending. |
| Resolute ARM64 optional Surý profile | Actual PHP83/84/85 package, extension, CLI/FPM/FastCGI/tool and earlier application checks passed. Candidate5 genuine fresh installation hit the same BIND parent defect; complete candidate6 qualification is pending. |
| AMD64 native execution | Signed bundles built on hosted AMD64. Both candidate5 native cells failed Multipass daemon startup before guest launch; bounded readiness and a runnable hosted baseline security gate are implemented and locally verified. New native execution is pending. |
| Legacy Noble MySQL recovery | Format3, private scoped-account import, backend package-state preservation and authoritative PDO readiness are implemented and reviewed; actual archive/DR/privilege/second-boot rehearsal is pending. |
| Cross-release full migration | Dedicated OCI fixture, actual plan revision/history checks and complete plan/effective-entitlement PHP inventory pass local tests; real native/Surý rehearsals await a compatible qualified source. |
| Soak/security-patch delivery | Signed initialization, valid private recovery key, actual scheduled verified-backup requirement and exact reconciliation-ID checks are implemented; new endurance guests and the elapsed30–60day evidence window remain pending. |

Candidate6 will use one identical current signed payload per architecture across its release/profile cells. Synthetic rollback versions run only on a separate owned companion; the main and fresh disaster-recovery guests retain and verify the selected signed binaries. Source/release/key transfers are bound to the host's exact bytes before private extraction, and frozen probes survive guest temporary-file cleanup. Final accepted summaries must replace this pending table before support promotion.

## Failures found and corrected

Native tests exposed an `apt-cache` SIGPIPE under `pipefail`, Resolute's removed `postgresql-contrib` metapackage, legitimate Roundcube archive links rejected by an overly broad check, premature panel workers mutating pristine bootstrap seeds, ignored rootless Podman cgroup flags, and APT's negative repository priority display under a PHP-only allow rule. Each correction has a regression test; the affected native gate must pass after the fix. Later native probes exposed Valkey parent ACL loss after reboot, Resolute Podman runtime-directory confinement, Noble Roundcube preseed ordering and historical-upgrade/security fixture assumptions. Corrections now have passing behavior tests and source review; the final candidate must rerun these native gates. These earlier failures are not passing qualification results. Candidate5 added measured failures for inherited BIND parent permissions, the actual Roundcube debconf namespace, transient Multipass readiness and temporary artifact loss. Review also corrected synthetic-version contamination of primary/DR qualification, ambiguous reconciliation evidence, incomplete preserved PHP offers and default Noble MySQL backup coverage. Each has behavioral regression coverage; fresh native reruns remain required.

An independent review found six Important issues in candidate 1: circular bootstrap readiness, CI ownership/matrix gaps, legacy missing-profile enrollment, omitted Roundcube SQLite persistence, preflight-triggered service restart, and restore readiness differing from execution. A second independent review confirmed all six resolved with no new Important/Critical findings. The final source review found and closed interrupted-install retry, startup-marker cleanup, early prerequisite resumption, shared Podman backup dependency, and development-bundle environment handoff gaps. No open source-review finding remains in that scope. Native acceptance is still pending.

All live mutations used uniquely owned disposable guests. Existing lab, soak, Hestia and Plesk guests were not modified. Failed run evidence is retained; a new run identity is required after cleanup. No production signing identity, package endpoint, private provider activation, or OS release upgrade was created implicitly.
