# Phase 33: Safe WordPress Uninstall and Recovery Design

## Status

Approved in chat on 2026-08-30.

## Purpose

Nakpanel currently supports installing, inspecting, updating, securing, and detaching a WordPress installation. Detach removes Toolkit tracking but deliberately preserves the WordPress files and database. Phase 33 adds a distinct uninstall workflow that removes WordPress while preserving the hosted domain, subscription, TLS, DNS, PHP configuration, and other site resources.

The workflow must be safe under retries, panel or agent restarts, partial infrastructure failures, and stale River jobs. It must not expose filesystem paths, database credentials, or other secrets outside the protected control-plane and agent boundary.

## Product Decisions

- Uninstall and Detach remain separate actions with different wording and confirmation flows.
- Uninstall always removes the tracked WordPress files from `public_html`.
- A recovery backup is selected by default.
- A Toolkit-managed database may be deleted only after a successful recovery backup.
- Discovered, external, unlinked, or ambiguously owned databases are always preserved.
- The domain and hosting configuration remain active. Nakpanel restores its normal generated placeholder after WordPress is removed.
- Removed Toolkit instances remain as tombstones so their operation and audit history survive.
- A removed instance no longer consumes `max_wordpress_sites` allocation.
- Reinstalling WordPress on the same site reuses the tombstone and begins a new revision rather than erasing its history.
- The plan entitlement is not required to remove an existing installation. Ownership and lifecycle authorization still apply.

## User Experience

The WordPress workspace Danger Zone contains two independent actions:

1. **Detach from Toolkit** stops management and preserves all files and databases.
2. **Uninstall WordPress** opens a destructive-action dialog and removes the installation through the queued teardown workflow.

The uninstall dialog shows the domain, site, current WordPress version, linked database disposition, and consequences. It contains:

- `Create a recovery backup`, checked by default.
- `Delete the Toolkit-managed database`, offered only when the instance has a database proven to have been created by the Toolkit.
- A mandatory statement that all content under the WordPress document root will be removed.
- A confirmation input requiring the canonical stored domain name.
- A final button labeled `Uninstall WordPress`.

The database checkbox is disabled when backup creation is not selected. Clearing backup creation automatically clears database deletion. An external or discovered database is shown as `Preserved` and cannot be selected for deletion.

While an uninstall is pending, waiting for backup, or running, the workspace shows the current stage and disables incompatible WordPress actions. On success it shows:

- `WordPress removed`.
- Whether a recovery backup was created.
- Whether the database was deleted or preserved.
- The requesting actor and completion time through the existing operation and activity views.
- `Install WordPress again` when the site is eligible.

The existing non-JavaScript form behavior and enhanced JSON response behavior remain available. Dialog focus trapping, Escape handling, focus restoration, and the 390px mobile layout follow the existing workspace patterns.

## Authorization

All requests use the existing central site ownership policy and server-derived site identity.

- Clients may uninstall WordPress only from sites owned by their linked active customer and active subscription.
- Resellers may uninstall installations only inside their provider scope.
- Administrators may uninstall through the normal provider workspace or scoped support view.
- Cross-customer and cross-provider requests return `404`.
- Suspended clients cannot mutate resources.
- Administrators and owning resellers retain cleanup authority for suspended downstream sites.
- Removing an existing installation is allowed when the WordPress Toolkit entitlement was removed or its limit became zero. Entitlements must never trap customer data.
- CSRF validation applies to the HTML form and enhanced request.

The browser submits only the backup choice, database-removal choice, and confirmation domain. Site identity, Linux account, document root, database name, database user, subscription, customer, provider, and policy are re-derived by the server.

## Persistence Model

Migration `20260830000049_wordpress_uninstall.sql` extends the Phase 32 schema.

`wordpress_instances` changes:

- Add `database_managed BOOLEAN NOT NULL DEFAULT false`.
- Backfill `database_managed=true` for Phase 32 instances with a linked database. Phase 32 assigns `database_id` only through the Toolkit install reservation; discovery never links an external database.
- Extend `desired_state` with `absent`.
- Extend `observed_state` with `removing` and `removed`.
- Keep the unique site identity so a tombstone is reused on reinstall.

`wordpress_operations` changes:

- Add `uninstall` to operation kinds.
- Add `backup_requested BOOLEAN NOT NULL DEFAULT false`.
- Add `database_removal_requested BOOLEAN NOT NULL DEFAULT false`.
- Continue using `backup_id`, `desired_revision`, `status`, `result`, `output`, and `last_error` for dependency and convergence state.

`backups` gains `database_names TEXT[] NOT NULL DEFAULT '{}'`. The existing backup worker persists the server-derived database list from `CreateBackupArgs` when it marks a backup active. This creates a durable coverage manifest without reading River's internal job tables and also improves restore diagnostics outside the Toolkit.

An uninstall reservation atomically locks the site and instance, verifies that there is no active operation, increments the desired revision, changes the desired state to `absent`, creates the operation, and records `wordpress.uninstall.requested`. A database-removal request is valid only when `database_managed=true`, the linked database belongs to the exact site and subscription, and backup creation is requested.

The instance remains allocated until its observed state reaches `removed`. WordPress quota queries count instances whose observed state is not `removed`; this prevents a customer from reserving a replacement while teardown is incomplete. Successful removal clears the instance's live `database_id`, administrator fields, inventory, security report, checksum state, and retry-only secret reference while retaining the tombstone and operation history.

## Control-Plane Orchestration

The manager exposes:

```go
type UninstallInput struct {
    CreateBackup   bool
    DeleteDatabase bool
    ConfirmDomain  string
}

func (m *Manager) Uninstall(
    ctx context.Context,
    actor auth.SessionUser,
    siteID int64,
    input UninstallInput,
) (Operation, error)
```

The canonical stored domain must match the normalized confirmation value. Schemes, paths, ports, wildcard forms, and a different domain are rejected.

When backup creation is selected, the manager uses the existing subscription-scoped backup provisioner. The backup is derived from the site and subscription and includes the site document root plus the active site databases selected by the backup repository. The uninstall operation starts as `waiting_backup`; otherwise it is enqueued immediately as `pending`.

Before destructive work, the worker verifies that the backup is `active`, belongs to the same site and subscription, has a non-empty archive path, checksum, and size, and was created for this uninstall operation. Database removal additionally requires the linked database name to be present in `backups.database_names`. A failed, deleted, unrelated, or incomplete backup fails the uninstall without contacting the agent.

The worker loads and revision-fences the operation using the existing per-instance lock. Unlike install and update validation, uninstall validation does not require a current WordPress entitlement. It does require valid ownership identity and provider cleanup authority. The worker sends the agent only the operation ID, desired revision, validated site identity, the server-derived managed database name/user when deletion is selected, and no credentials or absolute paths.

## Agent Teardown

Add `WordPressActionUninstall` to the existing enumerated WordPress agent operation. The agent independently validates:

- Positive operation, instance, subscription, site, and revision identifiers.
- Classic PHP hosting identity and the server-derived Linux account/domain relationship.
- The document root derived from `/home/<account>/domains/<domain>/public_html`.
- Root ownership and no symlink traversal for every managed parent.
- A recognizable WordPress root containing bounded regular-file markers such as `wp-config.php`, `wp-settings.php`, and `wp-includes/version.php`.
- When database deletion is requested, the configuration database name matches the server-derived linked database and both the database and principal match the Toolkit naming pattern for the selected site.

The agent creates a deterministic, root-owned quarantine location beneath the domain's Nakpanel state directory. It prepares a new placeholder document root, then uses same-filesystem directory renames to replace `public_html` without copying tenant content. A root-owned operation marker records the operation ID, desired revision, and stage. A repeated request observes the marker and resumes instead of deleting new content.

When database deletion is not requested, the agent completes after the placeholder is active. When deletion is requested, the agent drops only the validated Toolkit database and its local MariaDB principal. The implementation uses parameter-free, identifier-quoted SQL after strict identifier validation and follows the guarded MariaDB code already used by subscription teardown.

If database removal fails before either object was removed, the agent restores the quarantined WordPress root. If removal is partially observable, the agent keeps the placeholder and quarantine, returns a bounded failure, and relies on the successful recovery backup for repair. It never claims rollback when the database state is ambiguous.

The result contains booleans and identifiers, never paths or secrets:

```go
type WordPressRemovalResult struct {
    FilesRemoved      bool  `json:"files_removed"`
    DatabaseRemoved   bool  `json:"database_removed"`
    DatabasePreserved bool  `json:"database_preserved"`
    BackupID          int64 `json:"backup_id,omitempty"`
}
```

On successful control-plane convergence, a separate idempotent agent cleanup removes the quarantine and marker. Until then, reconciliation can inspect the marker and finish the database or persistence stage. Quarantine is not exposed in the File Manager and cannot be accessed by the subscription account.

## Completion And Reconciliation

The worker finalizes success transactionally:

- Verify the operation and instance revisions still match.
- Set observed state to `removed`, applied revision to desired revision, and convergence to `in_sync`.
- Set maintenance false and clear live WordPress inventory and secret references.
- Clear `database_id`; delete the database intent row only when the agent confirmed both database and principal removal.
- Retire the WordPress administrator secret if one still exists.
- Store the bounded `WordPressRemovalResult`.
- Record `wordpress.uninstall.completed` with site ID, backup ID, and deletion booleans.

Terminal failures set convergence to `failed`, retain the recovery references, create the existing `wordpress_operation_failed` notification, and record `wordpress.uninstall.failed`. Error text is bounded and redacted.

Startup and periodic WordPress reconciliation include `desired_state='absent'` instances. They inspect the agent operation marker and the MariaDB objects, then either finish persistence, restore a safe pre-deletion state, or retain a clear operator-visible recovery failure. Stale jobs return without mutation. A failed uninstall can be retried with a new desired revision after the prior operation is terminal.

## Reinstall And Detach

`ReserveInstall` recognizes an `observed_state='removed'` tombstone. It resets live desired fields, increments the revision, provisions a new Toolkit database, and creates a new install operation while preserving earlier operations and audit history.

Detach keeps its existing behavior for present installations. Detaching a removed tombstone deletes Toolkit tracking and operation history but does not touch the placeholder, preserved databases, backups, or other site data.

## Security Invariants

- No browser-supplied path, Linux username, database identifier, service name, or resource owner is trusted.
- River arguments contain only numeric IDs and desired revision values.
- Database and WordPress credentials never enter River arguments, audit metadata, HTML, JSON responses, result payloads, or logs.
- The agent re-derives all filesystem paths and revalidates database identifiers.
- Symlinked roots, mount escapes, unexpected replacement content, mismatched `wp-config.php`, and unrecognized installations fail closed.
- The agent cannot delete an external database or any database not linked to the exact WordPress instance, site, and subscription.
- Audit events report what was removed without exposing paths or secrets.
- A successful backup is mandatory before managed database deletion.

## HTTP And UI Interfaces

Add:

```text
POST /sites/{id}/wordpress/uninstall
```

Accepted form fields:

```text
create_backup=on
delete_database=on
confirm_domain=<canonical-domain>
```

Normal HTML requests redirect back to `/sites/{id}/wordpress` with one of these notices:

- `wordpress-uninstall-queued`
- `wordpress-uninstall-backup-pending`
- `wordpress-uninstall-complete`
- `wordpress-uninstall-failed`

Enhanced requests return `202` with the operation ID, stage, and backup ID. They never report success before the worker converges.

## Testing Strategy

Migration tests prove the new constraints, managed-database backfill, tombstone state, and preservation of existing instances.

Manager and store tests cover ownership, exact-domain confirmation, active-operation exclusion, backup dependency creation, managed versus external databases, revision fencing, quota release timing, audit events, and tombstone reuse.

Worker tests cover backup ownership and completeness, missing database coverage, dependency snoozing, stale jobs, successful removal, terminal failure, notification creation, and persistence recovery after an agent success/database commit failure.

Agent tests use isolated directories and a fake SQL database to cover recognized roots, corrupted installations, arbitrary content, symlink escapes, identifier injection, atomic quarantine, placeholder activation, database deletion, failure rollback, ambiguous partial deletion, idempotent retries, and quarantine cleanup.

HTTP tests cover CSRF, confirmation mismatch, admin/reseller/client/support scope, cross-tenant `404`, suspended-client denial, enhanced JSON, redirects, and secret/path absence.

Browser QA covers the distinction between Detach and Uninstall, checkbox dependencies, typed confirmation, progress and result states, dialog keyboard behavior, and `1440x1000` plus `390x844` layouts.

`deploy/multipass/phase33-verify.sh` runs Phase 32 first, installs WordPress, creates content and an upload, requests uninstall with a recovery backup, verifies the backup, confirms WordPress files and the managed database are removed, confirms the domain placeholder still works, confirms the plan allocation is released, reinstalls WordPress, and verifies a discovered installation preserves its database. It also injects a database-removal failure and proves the original site remains available.

Repository verification remains:

```text
go test ./... -count=1
go test -race ./internal/control/wordpress ./internal/agent/ops ./internal/control/http -count=1
go vet ./...
task build
git diff --check
find deploy -type f -name '*.sh' -print0 | xargs -0 -n1 bash -n
deploy/multipass/deployment-verify.sh
```

## Out Of Scope

- Deleting the hosted domain, subscription, TLS certificate, DNS zone, mail, unrelated databases, or backups.
- Selective removal of individual WordPress plugins, themes, uploads, or tables.
- Removing WordPress from arbitrary subdirectories or multisite networks.
- Restoring an uninstall directly from the WordPress Toolkit. Recovery continues through the existing backup workspace.
- Allowing customers to supply filesystem paths, SQL identifiers, or shell commands.
