# Domain-Scoped Website and Subdomain Removal

## Status

The product direction, default retention choices, and this written specification
were approved in chat on 2026-10-13. The implementation plan requires review
before product code is created. Deployment and two verification passes on
nakpanel.com are part of the requested delivery.

## Purpose

Let authorized providers and customers remove an add-on website or subdomain
through a compact, understandable confirmation and progress flow. Keep sibling
websites, the subscription account, shared services, databases, and backups safe.
Removal must remain correct during concurrent provisioning, retries, restarts,
and partial cleanup failures.

This extends the existing Go/templ, embedded JavaScript, PostgreSQL/River, and
privileged-agent architecture. It is not subscription termination, WordPress-only
uninstall, a UI redesign, or a new trash/restore system.

## Research and Existing Constraints

Plesk's domain page exposes Remove Website or Remove Subdomain followed by
confirmation. Its Customer Panel protects the subscription's primary domain;
removing hosting does not cancel a domain registration:

- https://docs.plesk.com/en-US/obsidian/administrator-guide/website-management/websites-and-domains/domains-and-dns/adding-and-removing-domains.65150/
- https://support.plesk.com/hc/en-us/articles/12377450681879-How-to-remove-a-domain-subdomain-domain-alias-from-Plesk

Nakpanel has subscription-wide teardown, but no individual website-removal RPC
or HTTP flow. The existing teardown removes the account home and shared account
services and therefore must not be called for individual domain removal.

Relevant existing structures:

- Sites carry subscription/customer ownership and `parent_site_id`.
- Only billing-created subscriptions currently have an explicit primary-site
  reference. Other subscriptions need a stable primary designation.
- Databases and backups have nullable site links. A database's site link is an
  allocation association, not proof that another application never uses it.
- WordPress and PHP application records have composite ownership constraints;
  their secret references require intentional cleanup before retaining a database.
- Subdomains may use records in a parent zone rather than a separate zone.
- River jobs include both individual-site operations and multi-site reconciliation.
- Domains share a subscription Linux user, disk quota, SFTP account, container
  network/storage infrastructure, and potentially Valkey.

## Approved Product Decisions

1. Permanent removal is a distinct action, not suspension or disabling hosting.
2. Databases and existing backups are kept by default. No backup is forced or
   silently created for the default operation.
3. Optional database removal is explicit and offered only for eligible databases
   linked to the selected site set. Shared, external, unlinked, or ambiguous
   databases are retained. Existing WordPress database-removal backup safeguards
   remain authoritative; a domain removal cannot bypass them.
4. A removed add-on website includes its hosted child subdomains only when the
   confirmation explicitly lists and acknowledges them.
5. The primary website, configured panel hostname, and sites hosting configured
   server-wide mail/FTPS/hostname dependencies cannot be individually removed.
   The dialog explains the dependency rather than permitting accidental server
   service disruption. No hostname migration or primary reassignment is added.
6. The subscription remains available after removal. Its system account, primary
   access credentials, disk quota, other domains, and shared Valkey remain intact.
7. A successfully removed domain can be recreated as a new site identity. Old
   jobs cannot act on the replacement.
8. No current live resource is implicitly selected for deletion by implementing
   or deploying this feature. Destructive live QA uses explicitly identified test
   fixtures and confirmation before their removal.

## User Experience

### Entry Points

- Add a compact contextual Actions menu to website rows in the Websites and
  subscription views and to the domain page header.
- Show Remove website for an add-on root and Remove subdomain for a child.
- Keep removal separate from the Domain Tools navigation and common save actions.
- Show a Primary website badge where applicable. Its Actions menu explains why
  individual removal is unavailable instead of exposing a nonfunctional button.
- Use existing bundled icons and shared dialogs. Preserve support-view prefixes.
- Bulk removal is outside this first delivery.

### Confirmation

Load an authorized, server-generated impact preview when the operator opens the
dialog. The title includes the exact canonical hostname. Show concise grouped
counts and expandable details for:

- The selected website and any child subdomains.
- Files, PHP releases/workers, Git deployments, containers, tasks, and site access.
- Domain mailboxes/messages, aliases, signing configuration, and webmail.
- DNS records/zones, certificates, logs, and statistics.
- Databases to be kept or explicitly removed, and backups to be kept.

Always state that domain registration is unchanged, hosting deletion is permanent,
and shared subscription services and sibling websites are unaffected.

Keep Cancel and the explicit Remove website/Remove subdomain action in a stable
footer. Use a confirmation hostname input for populated sites, mail data, or
parent-plus-children removal; a genuinely empty single-site fixture needs one
clear acknowledgement instead. Child removal always requires explicit agreement
to the complete child list. Database removal controls are collapsed, off by
default, and unavailable for unsafe or ambiguous ownership.

Use readable 14px fields, an 18px dialog title, wrapped hostnames, 44px mobile
action targets, accessible errors, focus trapping/restoration, and Escape handling.
Preview loading and validation do not clear input or close the dialog.

### Progress and Completion

After acceptance, replace the form with progress in the same dialog/page. Show
stages for waiting on existing work, stopping services, removing hosting/data,
updating DNS/mail/access configuration, and finalizing records.

Disable duplicate submission. Poll a scoped operation status endpoint with
bounded requests and a five-minute foreground wait. Continue in background is
available, and a later page reload resumes observation. The backend operation
survives panel/agent restarts.

Redirect only after successful cleanup: to the surviving parent for a subdomain,
or the subscription's website list for an add-on root. Refresh usage counters and
show a concrete success notice including the retained database/backup disposition.

On failure retain the operation and its error, show which stages completed, and
offer Retry removal. Do not restore already-removed hosting, show a success banner,
release quota early, or offer cancellation after irreversible cleanup begins.
Uncertain POST results offer Check removal status rather than replaying deletion.

## Ownership and Protection

Use the central access policy to derive subscription, customer, and provider
ownership. Cross-tenant/provider/support-scope lookups return 404. CSRF protects
every reservation and retry; browser input never supplies paths, service names,
credentials, or deletion resource lists.

Administrators and owning resellers may clean up suspended downstream resources.
Clients require an active linked customer identity and an authorized subscription;
suspended clients cannot mutate. A lost hosting/WordPress entitlement or exhausted
creation quota does not itself prevent authorized cleanup.

Persist `subscriptions.primary_site_id`, bound to the same subscription. Backfill
from a valid billing-account primary reference first; otherwise use the earliest
root site by creation time and ID. Empty subscriptions have no primary until their
first root website is atomically designated. Do not recompute primary from the
current list on each request, and do not promote a child to primary.

Derive protected hostname/service dependencies from trusted configuration and
stored server settings, including dependencies on a domain's DNS zone. Never
trust the request Host header as the protection list. Block customer/provider
transfers of affected subscriptions while removal is pending or failed, so an
approved destructive operation cannot silently acquire a different owner.

## Persistence and API Contracts

Add a new sequential goose migration after the integrated SSL migration. It adds:

- The stable same-subscription primary-site relationship.
- A per-site removal marker/revision separate from existing hosting status enums.
- `site_removal_operations` containing the requesting actor, subscription/customer,
  target identity, immutable approved resource snapshot, retention choices,
  revision, status/stage, bounded sanitized errors, and timestamps.
- A uniqueness rule preventing multiple active removal operations for one site.
- Database mutation guards for resources attached to sites being removed.

Use site removal states `none`, `queued`, `removing`, and `failed`, with `none`
as the migration default. Operation states are `queued`, `waiting`, `running`,
`failed`, and `completed`. A completed operation survives the deleted live site.
Keep the existing whole-account teardown functional: primary-site linkage may be
cleared by the authorized account-teardown path, not by individual-domain removal.

Completed operation and audit identities survive the live site row's deletion.
Removal snapshots contain non-secret IDs and server-derived identities only.
Keep approval tokens session-bound and short-lived, and bind them to the exact
impact digest. If children or affected resources changed since preview, require
a refreshed confirmation before reserving deletion.

Suggested interfaces:

- `SiteRemovalPreview`, `RemoveSiteReq`, `SiteRemovalOperation`, and `TeardownSiteReq`.
- `Manager.PreviewSiteRemoval`, `Manager.RemoveSiteFor`, and `Manager.RetrySiteRemovalFor`.
- `GET /sites/{id}/removal/preview`.
- `POST /sites/{id}/remove`.
- `GET /site-removals/{operationID}` and `/status`.
- `POST /site-removals/{operationID}/retry`.
- Equivalent validated support-customer routes.
- `RemoveSiteArgs` with operation ID and desired revision only.
- Enumerated agent `OpTeardownSite`; no arbitrary cleanup command or path API.

Keep standard HTML POST/303/progress-page behavior as well as enhanced 202 JSON
responses. Status responses contain no secrets or unrelated ownership inventory.

## Reservation, Job Fencing, and Recovery

Reserve removal transactionally using the established subscription-before-resource
lock order. Resolve the complete target tree with same-subscription/customer
checks; reject corrupt cycles and cross-owner descendants. Mark selected sites
as removing, freeze new target mutations, record the immutable preview choices,
enqueue the River operation, and record the request audit in one transaction.

Hold the existing subscription runtime serialization while taking/applying runtime
snapshots. Cancel queued target-specific work and wait for running target work to
drain before irreversible cleanup. Cancellation cannot indiscriminately cancel
subscription-wide work needed by sibling domains.

Multi-site reconciliation/convergence must refresh and exclude removing sites;
single-site workers must re-derive identity and reject removing/deleted revisions.
Cover creation, SSL/custom certificate, WordPress, managed PHP, Git, applications,
tasks, staging, DNS, mail, backup/restore, and runtime generation jobs. Staging
operations involving either a deleted source or destination are blocked/cancelled.

Write a root-owned agent tombstone before destructive filesystem cleanup. Agent
site mutators reject stale removed site identities, including old creation jobs.
Legacy domain-only operations require a valid current identity; they must not
silently resurrect a tombstoned site. Recreated domains receive a new site ID and
fresh authorized runtime identity, not reuse of the removed site's revision.

Persist checkpoints and make each cleanup step idempotent. A restart after agent
cleanup but before database commit resumes finalization without ordering a new
certificate, recreating hosting, or double-deleting retained data. Retry uses the
same approved resource scope and cannot expand it without a new confirmation.

Keep domains reserved and counted against allocation until removal is complete.
Failed cleanup remains visible and counted. Audit request, retry, failed stage,
and completed removal, preserving actor and target names after site deletion.

## Agent Cleanup Boundary

Derive every path and unit from validated site/subscription/application IDs and
the canonical account/domain pair. Reject symlink traversal and non-owned roots.
Never delete the subscription home, reset its quota, kill all processes for its
UID, prune shared container state, or call subscription teardown.

Scoped cleanup includes:

- Stop/disable only the selected sites' FPM, PHP worker/candidate, container, and
  task services. Preserve sibling services and subscription networks.
- Remove only their generated nginx routes/includes, access/error/deployment logs,
  statistics, certificate directories, runtime markers, Git/deploy credentials,
  releases/shared data, application slots, and domain content directories.
- Revoke only domain-scoped FTPS/SFTP access. Retain primary and sibling account
  access and regenerate shared access configuration safely.
- Remove only selected domain mail accounts/messages and webmail configuration,
  then regenerate shared mail configuration without interrupting other domains.
- Remove a standalone deleted domain's zone. For parent-zone subdomains, remove
  only owned or explicitly previewed records for that host and update the zone
  serial. Never remove the parent zone or unrelated records.
- Preserve external-provider DNS and explain that it requires operator cleanup.
- Validate shared nginx, DNS, mail, and FTPS candidates before activation; roll
  back failed shared-configuration changes without restoring removed site data.

The cleanup result reports bounded stage outcomes and IDs, never passwords,
private keys, environment values, arbitrary command output, or directory contents.

## Retained and Optional Data

Default database retention detaches the allocation link from the removed site
while retaining the database, principal, encrypted credential reference, and
subscription/customer ownership. Remove obsolete WordPress/PHP tracking and
secrets in a deliberate order that respects composite foreign keys. Do not run
WordPress uninstall's placeholder-restoration behavior during domain teardown.

Optional database deletion must verify exact site/subscription linkage and all
known application references. Never delete a shared principal needed by another
database. Discovered/external WordPress databases are ineligible. Retain the
existing recovery-backup requirement for a Toolkit-managed database deletion.

Keep existing backup archives, checksums, names, ownership, and database coverage
manifests. Detach their site link after cleanup and keep them visible/downloadable
from subscription backups. Do not claim automatic undo: restore must use an
existing authorized target or an explicitly recreated website. Do not let old
restore jobs recreate the removed target implicitly.

## Validation and Deployment

Use test-first changes and a fresh-context code review. Verify:

1. Primary designation backfill, empty subscriptions, protected service hosts,
   child closure, and foreign-key-safe retained database/backup behavior.
2. Role/provider/support ownership, CSRF, preview changes, quota boundaries,
   expired sessions, duplicate reservations, and uncertain responses.
3. Empty and populated sites, WordPress, Git, managed PHP/workers, containers,
   tasks, FTPS/SFTP, mail, separate/parent/external DNS, certificates, and statistics.
4. Symlink/path escapes, sibling process/service/file isolation, and shared
   account/Valkey/database/backup survival.
5. Active jobs during removal, stale queued jobs after deletion, reconciliation,
   partial cleanup/retry, restart between agent cleanup and SQL finalization, and
   safe recreation of the same hostname under a new identity.
6. Dialog preview/errors/progress/focus/keyboard behavior and list refresh at
   1440x1000 and 390x844, with no overlapping controls or document overflow.
7. Non-JavaScript confirmation/progress/retry and support-prefix redirects.

Run `go test ./... -count=1`, JavaScript tests, `go vet ./...`, `task build`,
`git diff --check`, shell syntax checks, focused race tests, and migrated isolated
PostgreSQL integration tests. Add a domain-removal verification artifact following
the existing single-VM deployment pattern.

Deploy the tested build and migration to nakpanel.com with health checks and the
existing software rollback discipline. Run two documented live passes using
explicit QA fixtures, not the user's current sites: retain a database and backup,
remove a subdomain without touching the parent, remove an add-on with acknowledged
children, confirm freed quota, and prove reconciliation/restart cannot resurrect
them. Exercise optional database cleanup only on an eligible confirmed fixture.
Capture desktop/mobile proof and report exactly which flows passed. Keep existing
production content, server hostname SSL, mail, and unrelated subscriptions intact.

## Out of Scope

- Whole-subscription termination or destructive customer/reseller deletion.
- Primary reassignment, domain renaming/transfer, and registrar cancellation.
- Bulk deletion, delayed trash retention, and one-click undelete.
- Backup pruning and automatic deletion of unlinked/shared databases.
- A redesign of the panel or unrelated feature work.
