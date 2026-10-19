# Ubuntu 26.04 Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task by task. The user subsequently authorized all implementation. Execution and native evidence are tracked in [the qualification guide](../../PLATFORM_QUALIFICATION.md) and the implementation evidence report; unchecked qualification items are not support claims.

**Goal:** Add an independently qualified Ubuntu 26.04 server profile while preserving existing Ubuntu 24.04 behavior and support evidence.

**Architecture:** Keep the existing Go control plane, privileged agent and APT/systemd deployment model. Publish portable Go bundles per architecture, centralize release-specific installer values, and route PHP discovery and execution through one trusted runtime descriptor. Keep internal PHP distinct from tenant runtimes and use native guest qualification for both releases. Treat multi-PHP package supply, cross-release migration and in-place OS upgrades as separate support claims.

**Tech Stack:** Go/templ, Bash, PostgreSQL, MariaDB, PHP-FPM, nginx, BIND, Stalwart/Roundcube, Podman, systemd, Multipass and GitHub Actions.

**Spec:** [Research and proposed design](/Users/rickynkansah/Projects/nakpanel/docs/UBUNTU_26_04_RESEARCH.md).

## Existing foundations and evidence

Reuse the three commands in `cmd/`, the existing systemd units, `RuntimeCapabilityProbe`, `RuntimeCapabilities.PHPRuntimes`, immutable plan validation, native configuration validators, backup/restore code and Multipass verification. This plan adds platform contracts around those components; it does not require another panel implementation or a generic provider framework.

On 18 October 2026, unchanged source built successfully with CGO disabled into static Linux panel/agent/panelctl executables for both amd64 and arm64. The probes used Go 1.26.4, explicit baseline CPU settings and current generated sources. This is build evidence only. Release generation, service execution and Ubuntu compatibility still require the steps below.

Tasks 1–8 establish the proposed native profile. Task 9 is optional multi-PHP supply with additional qualification; Task 10 qualifies a separate migration direction. If 8.3/8.4 parity is a launch requirement, complete Task 9 and repeat Task 8 before promotion.

## Global Constraints

- Ubuntu 24.04 remains the default image and retains hosting PHP 8.3/8.4/8.5, the ready 8.4 preference, and existing internal PHP 8.3 behavior.
- The proposed Ubuntu 26.04 native profile supplies only validated PHP 8.5. Do not advertise PHP 8.3/8.4 without a signed Resolute package source and complete native qualification.
- Never use Noble or the current `devel` alias as a Resolute repository workaround.
- Preserve explicit tenant versions, custom plans, immutable revisions, existing subscription snapshots, identities, mail data, TLS and pinned container digests.
- Do not edit historical schema migrations to adapt one OS. Fresh built-in plan adaptation must be an explicit guarded bootstrap operation.
- Preserve authorization, fail-closed plan readiness, AppArmor and current service/container hardening.
- Protect existing lab and soak VMs; destructive helpers may act only on verified resources owned by the current disposable run.
- Initially support installation/application updates on an already-installed OS. No implied `do-release-upgrade` or reverse database migration support.
- Existing legacy archives must remain readable. Missing provenance never silently authorizes a cross-release restore.
- A passing panel health endpoint or static script-string test alone cannot qualify a platform.
- Keep one Go codebase and use Linux build constraints only for actual kernel-family differences. Ubuntu package/layout differences belong in the platform profile and runtime descriptor.
- A portable Nakpanel binary does not make Stalwart, PHP or database executables portable. Record and qualify each external artifact's actual platform requirements.

## Review Focus

1. A mislabeled existing VM or a source/DR name collision must produce zero destructive or install calls (Task 1).
2. Unsupported OS/repository/runtime combinations must reject before application, schema, package or service mutation (Task 2).
3. The same architecture-specific release bundle must work on each qualified Ubuntu version; an artifact needing a newer libc or CPU must fail release validation (Tasks 3 and 8).
4. Discovery and execution must use the same PHP descriptor; internal PHP and tenant PHP remain independent, with existing versions/plans unchanged (Tasks 4–6).
5. Old archives and incompatible database/runtime targets must fail safely before stopping services or dropping data (Task 7).
6. Reboot or restore must preserve actual service/resource boundaries without verifier repairs hiding defects (Task 8).

## Task 1: Make the qualification harness safe

**Files:** Modify `deploy/multipass/common.sh`, `deployment-verify.sh`, `phase29-verify.sh`, `current-install-verify.sh`, `single_vm_verify_test.go` and `phase29_verify_test.go`. Add `deploy/multipass/platform_identity_test.go`.

**Interfaces:** Add shell helpers `assert_vm_identity NAME VERSION ARCH RUN_TOKEN` and `destroy_owned_vm NAME RUN_TOKEN`. The release/architecture/run identity is explicit input; guest identity is read from `/etc/os-release` and `dpkg --print-architecture`. Store ownership in a root-owned guest marker and a per-run host manifest. Later tasks consume these helpers.

- [ ] Add behavioral tests using a fake `multipass` executable: wrong guest version, wrong architecture, absent/wrong token, protected lab name, equal source/DR names and an unrelated existing VM all reject with zero sync/install/delete calls.
- [ ] Run `go test ./deploy/multipass -run 'PlatformIdentity|SingleVM|Phase29' -count=1`; confirm the new behavior tests fail for the current harness.
- [ ] Remove automatic legacy sweeping from ordinary qualification. Keep intentional legacy cleanup as a separately invoked maintenance action. Put ownership validation inside each destructive helper.
- [ ] Generate names from release, architecture and unique run identity. Assert actual identity before any reuse, sync or installer execution. Do not automatically claim an existing unowned VM.
- [ ] Preserve `NAKPANEL_MULTIPASS_IMAGE=24.04` and `nakpanel-lab` defaults, but treat existing default/soak VMs as protected unless explicitly adopted for a disposable run. New qualification runs must use their own unique names.
- [ ] Verify the behavioral tests pass, check shell syntax, and commit this independently before any live 26.04 probe.

## Task 2: Add explicit platform profiles and early preflight

**Files:** Create `deploy/install/platform.sh` and `deploy/multipass/platform_install_test.go`; modify `deploy/install/install.sh`, `phase7-install.sh`, `phase8-install.sh`, `phase18-install.sh`, `phase21-25-install.sh`, `phase30-install.sh`, `database-manager-install.sh` and their contract tests.

**Interfaces:** `nakpanel_load_platform OS_RELEASE_FILE ARCH` resolves only `ubuntu/24.04/noble` or `ubuntu/26.04/resolute`, with amd64/arm64. It produces `NAKPANEL_PLATFORM_ID`, `NAKPANEL_INTERNAL_PHP_VERSION` and the array `NAKPANEL_HOSTING_PHP_VERSIONS`. Noble values are `ubuntu-24.04`, `8.3`, `(8.3 8.4 8.5)`; the proposed Resolute values are `ubuntu-26.04-native`, `8.5`, `(8.5)`. Resolve production input from the actual host, never from an unchecked environment override.

- [ ] Add failing fixture tests for both profiles, inconsistent codename/version, absent metadata, another distro, unsupported architecture and 26.10. Stub all mutating commands and assert none execute after rejection.
- [ ] Implement the shared resolver and load it from every installer entrypoint before mutation. Derive versioned package/service names from its constrained values.
- [ ] Add a read-only preflight report for required packages, candidate origins, external artifact availability, disk/filesystem requirements and existing installation/profile compatibility. Refresh supported-host APT metadata as a separate preparatory step; do not install until complete candidate resolution succeeds.
- [ ] For the Noble PPA, validate the actual expected signed suite and candidates, not just a `Signed-By` marker. For Resolute native, do not add the missing PHP PPA. Simulate the complete package transaction and reject unavailable required extensions.
- [ ] Keep 26.04 explicitly experimental until Task 8 evidence is accepted. Persist the successful platform/profile and internal PHP choice in root-owned `/etc/nakpanel/platform.json`; perform a local host/profile check before the existing same-version no-op branch. Preserve offline no-op behavior; package/network preflight runs only when an installation/update is actually required.
- [ ] Reject recorded OS/profile mismatch with a clear unsupported-OS-upgrade message. Do not introduce an automatic OS repair or release-upgrade path.
- [ ] Run profile and existing installer tests, shell syntax checks and a fake-command mutation-order test; commit the additive profile infrastructure.

## Task 3: Make the existing Go release artifacts portable and verifiable

**Files:** Modify `Makefile`, `.github/workflows/ci.yml` and the artifact-input/preflight path in `deploy/install/install.sh`; add `deploy/release/build.sh` and release manifest documentation under `deploy/release/`.

**Interfaces:** Build a versioned bundle for `linux/amd64` and one for `linux/arm64`, each containing panel, agent, panelctl and the matching installation/configuration/migration assets. Manifest fields include application version, commit, Go toolchain, CGO mode, CPU baseline, architecture and file digests. Preserve the existing source-build path initially.

- [ ] Select one maintained Go patch release satisfying the module minimum; align CI and the source installer's accepted/downloaded toolchain policy. The probe's installed 1.26.4 is evidence, not a recommendation to freeze that patch.
- [ ] Run generation once from a clean release checkout, then build all three commands with `CGO_ENABLED=0`, `GOOS=linux`, explicit `GOARCH` and `GOAMD64=v1` or `GOARM64=v8.0`. Preserve current version/commit ldflags and embedded assets. Do not disable security-relevant code to make a build succeed.
- [ ] Inspect ELF architecture, interpreter and dynamic dependencies for every artifact. Fail a promised-static release if it acquires a dynamic loader or shared-library dependency. Record hashes and sign the manifest using the project's chosen release mechanism.
- [ ] Validate manifest integrity, application version and host architecture/CPU compatibility before installed-file replacement; keep existing no-op, downgrade and rollback guarantees. Start with verified bundles rather than making operation of a new APT service a prerequisite.
- [ ] Retain the source installer and its documented Goose/River `go run` prerequisites initially. A compiler-free binary installation requires a separately reviewed bundle of pinned migration executables and SQL assets, with unchanged ordering/failure recovery; do not claim that the three application binaries already provide it.
- [ ] In Task 8 run the same artifact digest on Noble and Resolute for each architecture. Exercise DNS, TLS trust, Unix peer credentials, local user/supplementary-group lookup and database connections under the actual hardened units. If libc/NSS integration is required, use an explicit tested CGO build strategy rather than silently changing identity behavior.
- [ ] Add release-manifest and ELF policy checks and verify that source and bundle inputs both preserve the existing 24.04 installation path. Commit packaging independently of enabling 26.04.

## Task 4: Connect existing PHP probes and execution through one descriptor

**Files:** Create `internal/agent/ops/php_runtime.go` and `php_runtime_test.go`; modify `php_capabilities.go`, `create_site.go`, `php_application.go` and every other PHP command/unit/pool renderer identified by a source-wide path audit. Extend existing config/render/probe tests rather than replacing them.

**Interfaces:** Define an internal `PHPRuntimeDescriptor` with provider/version, absolute CLI/FPM paths, INI/extension locations and supported configuration roots. A resolver returns the sole validated descriptor for a version from the root-owned installed profile. Keep `types.PHPRuntimeCapability` and the existing ready-version RPC fields; populate them from probes of the descriptor. No client-controlled executable paths are added.

- [ ] Inventory hardcoded `/usr/bin/php`, `/usr/sbin/php-fpm`, `/etc/php` and socket construction across site creation, runtime changes, application releases, cron/workers, Composer, WP-CLI and internal tools. Record the call sites covered by the change.
- [ ] Add behavior tests with a fake descriptor/probe/executor for today's distro layout and a private `/opt/nakpanel/php/8.4` candidate. Demonstrate that readiness probes and generated/executed commands select the same runtime and matching INI/extensions. The private-prefix fixture does not establish package availability.
- [ ] First wrap current Noble paths unchanged for 8.3/8.4/8.5, and native Resolute paths for 8.5. Preserve existing rendered configuration where behavior is unchanged, including per-tenant units, users, sockets, permissions and restrictions.
- [ ] Pass the descriptor to existing probe and provisioner boundaries and remove independent executable-path reconstruction. Validate profile ownership and executable/configuration path policy before privileged use. Do not trust arbitrary discovered PATH entries or request parameters as runtime registration.
- [ ] Preserve version-only site records, plans and backups while one provider maps to each version. Reject ambiguous provider mappings. Adding multiple same-version handlers later requires a separate backwards-compatible handler-ID migration.
- [ ] Keep internal runtime selection separate from the site's PHP version, but resolve both through the same descriptor mechanism. Task 5 threads the existing internal-tools selection through this interface.
- [ ] Run focused probe/provisioner/render tests, real CLI/isolated-FPM tests and FastCGI requests on Noble before enabling any new provider. Record the required future private-prefix confinement tests for Task 9. Commit the descriptor refactor independently.

## Task 5: Qualify internal PHP and packaged tools

**Files:** Modify `internal/config/runtime.go`, `cmd/agent/main.go`, `internal/agent/ops/phase6.go`, `webmail_tls_test.go`, `deploy/install/phase18-install.sh`, `phase30-install.sh`, `database-manager-install.sh` and `deploy/systemd/nakpanel-database-manager.service`. Add `deploy/systemd/nakpanel-database-manager.service.tmpl` and focused render/config tests.

**Interfaces:** Add validated `NAKPANEL_INTERNAL_PHP_VERSION` configuration, allowing only `8.3` and `8.5`, with the legacy absent-value default `8.3`. Add `PHPFPMVersion string` to `WebmailProvisionerOptions`. Keep the exported legacy webmail renderer as a default-8.3 compatibility wrapper; provisioner rendering resolves the trusted Task 4 descriptor and managed socket for HTTP and HTTPS. Do not accept request-supplied executable or socket paths.

- [ ] Add failing tests proving the legacy wrapper still emits the exact 8.3 socket, the new provisioner emits the 8.5 socket for both HTTP/HTTPS, and invalid configuration is rejected before writing vhosts.
- [ ] Thread the constrained value from the profile into the agent environment and isolated database-manager unit. Retain the checked-in 8.3 service as the Noble baseline; render a target-specific unit for 26.04.
- [ ] Resolve the Roundcube package blocker before enabling 26.04 webmail. Prefer a fixed native candidate if available; otherwise qualify the signed upstream **1.6.19 LTS complete** release in a separate directory without replacing 24.04 webmail. Verify its published SHA-256 and signature and record the artifact in a versioned dependency manifest. If it fails the 8.5 application tests, stop this profile's support promotion for a revised dependency decision.
- [ ] Adapt Roundcube root/config integration deliberately; preserve DES key, SQLite/MariaDB session data and IMAP/SMTP settings. Do not apply ad hoc edits to installed upstream PHP files.
- [ ] Run internal phpMyAdmin/Adminer and webmail compatibility checks on the resolved dependency versions. Qualify a maintained Composer/WP-CLI pin against native 8.5; preserve Noble pins until their own regression gate permits changing them.
- [ ] Keep tenant-selected binaries separate from internal tool interpreter selection; never change global PHP alternatives as a shortcut.
- [ ] Verify actual FastCGI INI paths, required extensions, sessions, uploads, database access, webmail login/send/read, database SSO and hardened service startup in owned native guests. Add a reproducible `deploy/multipass/internal-tools-verify.sh` for these checks.
- [ ] Run Go config/render tests and installer contract tests; commit only after both profile renderings remain correct. Full promotion still depends on Task 8.

## Task 6: Keep plan defaults consistent with available runtimes

**Files:** Add `internal/control/quota/platform_defaults.go` and `platform_defaults_test.go`, and a guarded bootstrap entrypoint in `cmd/panelctl/platform.go`; modify `internal/control/quota/quota.go`, its tests, `internal/control/provision/manager.go`, `internal/control/provisioningapi/accounts.go`, `accounts_runtime_test.go` and affected UI default helpers.

**Interfaces:** Add `ResolveReadyPHPVersion(limits Limits, requested string, ready []string) (string, error)`. Explicit requests must be both permitted and ready. For implicit selection preserve ready allowlisted 8.4 preference, then use a ready configured default, then the first permitted ready version. No ready permitted version is an error. Existing validation still checks every advertised allowed version.

- [ ] Add failing tests for ready inventories `{8.3,8.4,8.5}`, `{8.5}`, empty and partially broken inventories; browser/API behavior must agree, explicit 8.3 must not become 8.5, and disallowed versions must reject.
- [ ] Use the shared helper at provisioning boundaries while preserving existing explicit site updates. Keep `PreferredNewSitePHPVersion` behavior for existing callers until they receive validated readiness input; do not change authorization or entitlement checks.
- [ ] Implement a transactional `panelctl platform bootstrap-plans --profile ubuntu-26.04-native` operation for fresh installation only. Require the recorded profile, an incomplete fresh-bootstrap marker, no subscriptions/sites, and untouched built-in definitions. Emit normal immutable revisions/audit records and set default/allowlist consistently to ready 8.5. Reject custom or already-populated state.
- [ ] Invoke that operation after existing migrations and validated agent inventory, before declaring fresh 26.04 installation ready. Do not alter the historical 8.4 seed migration.
- [ ] Test that an application update never invokes fresh bootstrap, an imported/custom plan is unchanged, and restored unavailable PHP stays blocked rather than being rewritten.
- [ ] Run focused quota/provisioning/API/policy/render tests and native create-site smoke on both profiles; commit the shared selection and guarded bootstrap.

## Task 7: Record platform provenance and protect restores

**Files:** Modify `internal/backup/archive.go`, `restore.go`, `archive_test.go`, `restore_phase30_test.go`, `internal/agent/ops/server_backup.go`, related archive/restore tests, `deploy/install/install.sh` and `docs/RECOVERY.md`.

**Interfaces:** Extend `Manifest` with optional `Platform *PlatformProvenance`. Define provenance fields for OS ID/version/codename, architecture, installed profile/internal PHP, hosted PHP versions, PostgreSQL server/dump versions, MariaDB server/dump/client versions, Stalwart version and relevant image digests. Define `RestoreMode` values `same-platform` and `forward-migration`; add `CheckRestoreCompatibility(source Manifest, target PlatformProvenance, mode RestoreMode) error`, executed before any service stop or state replacement.

- [ ] Add failing round-trip/legacy manifest tests; old archives decode with nil provenance. Test foreign OS/architecture, unsupported backward database targets and missing required PHP produce zero stop/drop/write calls.
- [ ] Collect source/target provenance from actual installed tools and server queries, not package-name assumptions. Keep encryption keys and credentials out of metadata.
- [ ] Preserve existing legacy recovery on the documented same-platform path, including old 24.04 archives, with its current schema/key checks. Require explicit forward-migration mode plus reviewed provenance reconstruction for an old archive crossing releases; absent fields cannot pass that mode. Do not add a new mandatory legacy-recovery prompt or require repacking old backups.
- [ ] Enforce compatible PostgreSQL tools and real target import requirements. Keep native target platform state from being overwritten by archived source settings.
- [ ] Verify new migration checks do not narrow legitimate same-release 24.04 recovery. Document that application rollback does not reverse the OS/APT package transaction.
- [ ] Run archive/restore unit tests and owned same-release restore drills. Cross-release restore remains unadvertised until Task 10.

## Task 8: Establish full dual-release qualification

**Files:** Modify `.github/workflows/ci.yml`, `deploy/multipass/deployment-verify.sh`, `phase29-verify.sh`, product fixture scripts and `docs/SOAK.md`; add `deploy/multipass/ubuntu-platform-verify.sh` and private per-cell reports under the owned run directory (`${NAKPANEL_OWNERSHIP_DIR}/${NAKPANEL_RUN_TOKEN}/reports/` by default), with explicit report destinations still supported.

**Interfaces:** The wrapper consumes explicit OS/architecture/run identity from Task 1, invokes the canonical installer and modern product chain, and emits image/commit/package/tool versions, validator results, boot state and failure logs. No implicit fixture skip can count as a passing advertised feature.

- [ ] Define four native cells: `24.04/amd64`, `24.04/arm64`, `26.04/amd64`, `26.04/arm64`. Use architecture-appropriate runners, unique run/DR names and bounded runner concurrency. Keep existing baseline checks required.
- [ ] Consume the Task 3 bundle for each architecture and record identical digests across its two release cells; DR uses the same architecture-compatible release artifact. Inspect external executables independently. Keep pinned toolchain, image, package-origin and feature records with every result.
- [ ] Run a genuine clean installer first, without the verifier's existing blanket `--force --allow-downgrade`. Capture all package origins and runtime capabilities.
- [ ] Execute the full modern security/product chain including native PHP, service plans, Toolkit, uninstall, GoAccess, domain removal, current mail/DNS flows and optional database-manager coverage. Adapt version fixtures to explicit profile contracts, retaining all Noble runtime tests.
- [ ] Add exact rootless application and rootful Valkey tests for networking, cgroup resource limits, denied access, secrets, health, rollback, teardown and reboot.
- [ ] Upgrade a populated real prior Nakpanel release in every cell. Retain synthetic pre/post-migration and health-failure rollback drills as additional tests.
- [ ] Capture post-reboot service/quota state before repairs. Test finite quota enforcement and tenant denial after reboot/restore; missing fixtures fail explicitly.
- [ ] Restore to a fresh same-release guest in every cell and verify mail message contents, tenant files/database data, secret decryption, desired stopped services and a second reboot.
- [ ] Run separate owned soak environments for both releases; ensure scheduled backup creation is real and remove cleanup assumptions that could target a protected soak VM.
- [ ] Promote only cells whose complete evidence passes. Keep Ubuntu 24.04 defaults. Recheck full PHP parity before advertising it; experimental 8.5-only availability is not 8.3/8.4 support.

## Task 9: Optional multi-PHP packages using the same descriptor

**Files:** Add isolated build recipes, package metadata, dependency manifests and verification under `deploy/release/php/`; extend `deploy/install/platform.sh`, Task 4 descriptors and Task 8 fixtures. Exact packaging files depend on the selected maintained provider or Nakpanel-owned package route.

**Interfaces:** Supply complete PHP 8.3/8.4 runtimes and required extensions built for each advertised Resolute architecture. A maintained external signed provider is acceptable after verification; otherwise use Nakpanel package names and version-specific prefixes, with narrowly scoped package-origin policy. No Noble package reuse or Plesk package installation is part of this design.

- [ ] Refresh Resolute provider availability before choosing to own builds. Publish the required versions, architectures, extension set, security-update owner and response policy. Do not promise full parity before the supply path exists.
- [ ] If building, use isolated native/reproducible target environments and upstream verification; capture compiler/library versions, patches, licenses, SBOMs and source/artifact digests. PHP and extensions need native library/ABI qualification even though the panel is static Go.
- [ ] Package under private versioned roots and register through Task 4. Preserve distro PHP and all tenant isolation boundaries; require configuration/FastCGI/CLI/Composer/WP-CLI/worker tests for each runtime.
- [ ] Sign releases/repository metadata, preserve package provenance, scope APT preference rules to owned package families, and rehearse security patch delivery plus failed-update recovery. Never replace global system dependencies to satisfy one private runtime.
- [ ] Reject removal of any provider used by a site or internal tool. Require an explicit qualified site migration before switching providers; existing 24.04 sites remain on their current provider.
- [ ] Repeat Task 8 for every expanded advertised profile and architecture. Only then advertise full 8.3/8.4/8.5 parity or allow migration fixtures requiring these versions.

## Task 10: Qualify forward migration as a separate release

**Files:** Add `deploy/multipass/ubuntu-forward-migration-verify.sh`; extend restore compatibility tests and `docs/RECOVERY.md`; publish an explicit support matrix in `README.md` after evidence passes.

**Interfaces:** Consume a source-24.04 archive and target-native 26.04 artifacts/provenance at compatible application/schema versions. This path does not execute an OS release upgrade.

- [ ] Test rejection before mutation when source sites require unavailable 8.3/8.4, source/target mail stores are incompatible or database tools cannot restore the archive. Do not bypass this failure to make a native-8.5 target accept legacy sites.
- [ ] For a compatible same-architecture fixture, rehearse PostgreSQL 16-to-18 and MariaDB 10.11-to-11.8 logical transfer, tenant grants/collations/routines/events, identities, secrets and actual mail contents.
- [ ] Regenerate managed target configuration without silently changing tenant intent. Revalidate nginx/PHP/DNS/SSH/FTPS, workers, container state, quotas and trusted TLS, then reboot again.
- [ ] Retain the intact source and verified offline archive/key through acceptance. Document DNS/traffic cutover and how to return traffic while source data is still authoritative; do not promise downgrade restore after new writes occur on the target.
- [ ] Publish the exact tested migration direction and runtime/architecture limits. Leave 26.04-to-24.04, cross-architecture full restore and in-place `do-release-upgrade` unsupported pending their own designs.

## Completion evidence

The current research step is complete when findings, sources, blockers, the static-build evidence and this ordered plan are reviewable. Native-profile implementation completion requires Task 8's evidence for every advertised cell. Full PHP parity additionally requires Task 9; forward migration requires Task 10. In-place OS upgrade remains a separate unimplemented design. No success claim may be based only on changing OS guards, package names or successfully cross-compiling Go.
