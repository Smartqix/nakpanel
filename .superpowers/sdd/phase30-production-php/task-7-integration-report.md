# Task 7: Phase 30 integration audit and repair

## Status

Implementation commits:

- `b32998b1bdc78a5d79b314b5179caf2733295a5e` - initial integration repairs.
- `9d8f8bb` - review round 1 lifecycle, notification, redaction, teardown, and API readiness repairs.

All required local verification passed. The only remaining concern is that the Ubuntu package/PPA/ClamAV path and a destructive whole-server restore were not executed against a disposable Ubuntu host during this task.

## Findings audited

### New-site PHP selection

- Found: ready capability order could make PHP 8.5 the new-plan and new-site default, and the default plan retained only one selectable runtime.
- Repaired: new sites prefer PHP 8.4 whenever their allowlist permits it; all ready runtimes remain selectable; the browser selects the subscription default; provisioning API creation intersects plan permission with live agent readiness, falls back to another ready permitted runtime, and fails closed when none is ready.
- Preserved: an explicit existing/migrated PHP 8.3 selection is returned unchanged.

### Hosting-policy v3 propagation

- Audited canonical encode/decode and upgrades, provider/reseller ceilings, typed add-ons, snapshots, custom/locked subscriptions, synchronization behavior, plan UI rendering, and HTTP parsing.
- Existing coverage confirms v1/v2 upgrades and default policies leave Composer, managed deployment, and worker grants disabled until a v3 plan explicitly grants them; no production repair was required.
- Representative coverage: `TestUpgradeV1AndV2ToV3PreservesLegacyValuesWithPHPHostingDisabled`, `TestHostingPolicyV3RoundTripsPHPHostingFields`, `TestValidateWithinIncludesPHPHostingCeilings`, `TestComposeEntitlementsCombinesPHPHostingAddonWithoutImplicitGrant`, `TestEntitlementSnapshotPreservesTypedPlanPolicy`, `TestLockedSubscriptionEditPreservesSnapshotOnlyForSamePlan`, `TestParsePlanIncludesPHPHostingV3Fields`, and `TestHostingAndResellerPlanEditorsRenderPHPV3Entitlements`.

### Lifecycle, teardown, drift, and reboot recovery

- Audited inherited customer/reseller/subscription/site suspension in `sweepApplicationCandidatesSQL`, agent suspension behavior, startup/five-minute River scheduling, and authoritative workspace lifecycle state.
- Found: account teardown omitted managed PHP candidate units, worker generations, application slices, agent state, candidate nginx/socket artifacts, and loaded candidates whose unit file had disappeared.
- Repaired: teardown snapshots now carry only validated application, worker, site, and deployment identifiers; the agent derives exact artifacts, stops loaded candidates, removes worker units/slices/state, and reloads systemd.
- Found: restore enumeration omitted worker and slice artifacts and would have started every newly enumerated worker.
- Repaired: server backup and restore include worker/slice units; restore never starts PHP FPM, worker, or slice units directly and leaves all PHP activation to the startup application reconciliation sweep. Desired-stopped and inherited-suspended workers therefore remain stopped.
- Existing coverage confirms inherited suspension stops FPM/workers and application sweeps run every five minutes with `RunOnStart: true`.

### Backup, restore, and retention

- Audited classic site backup/restore (`TestBackupProvisionerCreatesArchiveWithFilesAndDatabaseDumps`, `TestRestoreProvisionerRestoresFilesAndDatabaseDumps`).
- Audited server backup roots: `/home` retains domain `.nakpanel/releases` and `.nakpanel/shared`; PostgreSQL retains intent and encrypted `service_secrets`; MariaDB dumps retain classic databases; managed unit files are archived.
- Added focused worker/slice unit coverage and desired-state restore coverage.
- Existing `TestPHPReleaseRetentionAlwaysKeepsActiveAndPreviousWithinBudget` confirms active and previous healthy releases/environments are protected from cleanup.

### Quota and usage

- Audited subscription account measurement and per-site diagnostics.
- No collector repair was needed: every unique account home is measured once for subscription totals, including releases/shared data, while a domain site diagnostic measures only its public document root.
- Added `TestUsageCollectorCountsManagedPHPStorageOnceAtAccountScope` to pin this invariant and avoid a claim of separate filesystem enforcement.

### Bounded logs and secrets

- Audited agent path derivation and source allowlisting for `php_deployment`, `php_worker`, and `php_fpm`, plus cursor, line, byte, and control-character bounds.
- Found: agent output was bounded and sanitized but could still contain a referenced PHP environment secret.
- Repaired: the control plane loads only secret references bound to the requested site, decrypts them through the service-secret store, replaces longest values first, clears plaintext buffers, and fails closed on missing secret services or database cursor errors.

### Notifications

- Found: worker failures shared the reconciliation category; missing runtime and end-of-support shared one category; Composer findings lacked a separate durable lifecycle; legacy runtime warnings could remain stale.
- Repaired with reversible migration `20260830000045_phase30_integration.sql`: distinct worker, Composer, missing-runtime, and end-of-support categories; stable dedupe keys; resolution when conditions clear; legacy runtime-key cleanup.
- Composer findings now reconcile on healthy deployment and rollback, including JSON summaries loaded from PostgreSQL. Notification bodies still pass through bounded/redacted error handling.
- PostgreSQL Up/Down coverage passed against the local PostgreSQL test instance.

### ClamAV readiness

- Found: installer installed ClamAV but neither obtained nor validated signatures, so managed deployment capability could appear ready while scans failed later.
- Repaired: install `clamav-freshclam`, stop the updater for a bounded manual refresh, require a real `.cvd`/`.cld` database and working `clamscan`, then enable ongoing updates. Failure exits with an actionable message.

### Trust boundaries

- Audited Phase 30 HTTP parsers and River argument types.
- Existing tests confirm browser forms carry scoped identifiers and bounded domain values, not host paths/binaries/sockets/unit names/ports/shell strings; `TestPHPApplicationJobsCarryOnlyRevisionFencedIdentifiers` confirms River mutation arguments remain ID/revision-only.
- New teardown agent payload fields are also ID-only; all host artifact names remain agent-derived.

## Red/green evidence

- PHP default tests failed with PHP 8.5/one-runtime defaults, then passed with PHP 8.4 preferred and PHP 8.5 selectable.
- Notification tests initially failed to compile because distinct lifecycle helpers/categories were absent; migration and worker/sweep PostgreSQL tests now pass.
- ClamAV installer test failed because no `freshclam`/signature validation existed, then passed after fail-closed setup.
- Teardown test first failed because managed PHP units/state/artifacts remained; the loaded-candidate extension first failed because the ID-only deployment snapshot did not exist. Both now pass.
- Restore desired-state test first failed with undefined `shouldStartRestoredInstanceUnit`; it now passes for enabled, stopped, FPM, and slice cases.
- PHP log test first returned `worker echoed deployment-secret`; after redaction it returns `[REDACTED]`. The cursor-error test first returned partially redacted lines with no error; it now fails closed.
- Legacy notification-key test first observed `php:runtime-missing:*` where `php:runtime:*` resolution was expected; both old and new lifecycles now reconcile.
- Composer rollback PostgreSQL test first left the advisory unresolved; it now resolves a clean stored JSON audit summary.

## Review fix round 1

Review artifact: `.superpowers/sdd/phase30-production-php/task-7-integration-review.md`.

- Restore authority: `TestRestoreStartsOnlyDesiredActiveManagedPHPUnits` failed when an enabled PHP worker consulted systemd and returned start=true. The restore helper no longer accepts a systemd runner and returns false for every PHP FPM, worker, and application-slice unit.
- Stale runtime warnings: the sweep test failed because the first operation was current-key resolution instead of enumerating active warnings. The sweep now locks active runtime-warning rows, computes the complete current subscription/version key set, and resolves keys whose pair disappeared before reconciling current targets.
- Multiline/control secrets: the focused test returned `first` and `second\uFFFDthird` unchanged. Secret candidates now use the same buffered newline splitting, CR/LF trimming, and control-rune replacement as the agent log reader before longest-first replacement.
- Fileless loaded units: teardown first skipped a stable FPM whose unit file was absent and then failed the stronger `LoadState=not-found`, `ActiveState=active` case. It now inspects both states and stops the exact stable unit unless it is both absent and inactive. Loaded worker generations are enumerated through systemd, filtered through the exact numeric worker-unit regex, stopped, and then known files/state are removed.
- Provisioning API readiness: the initial focused test did not compile because the account service had no capability dependency. It now prefers ready permitted 8.4, falls back to ready permitted 8.5, rejects ready-but-unpermitted runtimes, returns a stable fail-closed API error when none are ready, and rolls back before customer/subscription/site mutation. `cmd/panel` supplies the agent capability reader.
- Review repair commit: `9d8f8bb`.

## Files changed

- Installer: `deploy/install/phase30-install.sh`, `deploy/multipass/phase30_install_test.go`.
- Agent lifecycle/backup/usage: `internal/agent/ops/server_backup.go`, `server_backup_phase30_test.go`, `teardown_subscription.go`, `teardown_subscription_test.go`, `usage_test.go`.
- Restore: `internal/backup/restore.go`, `restore_phase30_test.go`.
- PHP control plane: `internal/control/phpapp/sweeps.go`, `sweeps_test.go`, `workers.go`, `workers_test.go`, `postgres_state_test.go`.
- Log redaction: `internal/control/provision/account_services.go`, `php_log_test.go`, `internal/control/quota/php_logs.go`, `php_logs_test.go`, `quota.go`.
- Site defaults/teardown snapshot/UI: `cmd/panel/main.go`, `internal/control/provisioningapi/accounts.go`, `accounts_runtime_test.go`, `jobs.go`, `internal/control/quota/quota_test.go`, `internal/control/web/helpers.go`, `helpers_test.go`, `static/app.js`, `workspace.templ`, generated `workspace_templ.go`, `internal/types/envelope.go`.
- Notifications migration/tests: `migrations/20260830000045_phase30_integration.sql`, `migrations/migrations_test.go`, `migrations/phase30_postgres_test.go`.

## Verification

- Focused repaired-boundary unit tests: pass.
- Focused PostgreSQL integration tests, including notification migration and Composer rollback lifecycle: pass (not skipped).
- `go test ./... -count=1`: pass.
- `go test -race ./migrations ./internal/agent/ops ./internal/backup ./internal/control/phpapp ./internal/control/provision ./internal/control/provisioningapi ./internal/control/quota ./internal/control/web ./internal/types -count=1`: pass.
- `go vet ./...`: pass.
- `task build`: pass; sqlc/templ/Tailwind generation and panel/agent/panelctl builds completed.
- `git diff --check`: pass.
- `bash -n deploy/**/*.sh`: pass.

Review round 1 final verification:

- All five focused red/green tests: pass.
- `go test -race ./cmd/panel ./internal/backup ./internal/control/phpapp ./internal/control/quota ./internal/agent/ops ./internal/control/provisioningapi -count=1`: pass; `internal/agent/ops` race was rerun after the final systemd-state refinement.
- `go test ./... -count=1`: pass after the final refinement.
- `go vet ./...`: pass.
- `task build`: pass.
- `git diff --check`: pass.
- `bash -n deploy/**/*.sh`: pass.

## Remaining concerns

- The fail-closed installer logic was covered by Go contract tests and shell parsing, but `apt`, the Ondrej PPA, live ClamAV mirrors/signatures, and service enablement were not exercised on a fresh Ubuntu 24.04 VM in this task.
- Backup and restore layout/state selection were tested without performing a destructive end-to-end whole-server restore on a disposable host.
