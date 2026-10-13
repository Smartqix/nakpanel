# Shared Dialog UX and Live Verification

## Scope

Improve the existing graphite/cobalt Service Provider workspace on nakpanel.com,
without rewriting routes, changing entitlement rules, or resetting hosted data.
The user approved merging and pushing to main after verification.

The domain-centered workspace and separate provider/customer navigation follow
[Plesk's panel model](https://docs.plesk.com/en-US/obsidian/administrator-guide/about-plesk/the-plesk-gui.70562/).
Nakpanel retains its own branding, embedded assets, and Go/templ implementation.

## Repairs

- Shared dialogs have readable 14px form text, 18px headings, consistent spacing,
  sticky headers/action footers, visible focus rings, and 44px mobile controls.
- Creation dialogs focus the first available field. Field-free review dialogs
  prefer Cancel. Nested confirmations preserve the parent dialog and body scroll
  lock; Escape and delayed native close events restore focus safely.
- Inline validation preserves entered values. Ordinary enhanced forms remain
  URL-encoded for Go ParseForm; custom certificate uploads remain multipart.
  Structured field errors survive the HTTP client, and uncertain mutations are
  never automatically replayed.
- PHP/policy resets accept their existing safe native redirect through the
  shared client, clear the unsaved-change guard only after success, and reject
  duplicate pending saves. Two final browser reset retries showed the success
  notice without the previous false AJAX error.
- Git dialogs use the shared spacing/footer and bundled icons. Password utilities
  are separate from the main action footer. Missing Lucide sprite symbols are
  restored from the official upstream subset.
- PHP/nginx settings, database dialogs, container forms, and plan revision rows
  retain their specialized layouts without the shared grid overriding them.
- Mobile-only navigation remains hidden on desktop. Mobile provider navigation
  has larger touch targets, and search uses readable object names.
- New mailbox forms derive their finite default from the effective subscription
  policy. Unlimited defaults no longer expose a raw -1; blank preserves the
  authoritative server-default behavior.
- WordPress uninstall's safety-backup quota rejection now returns an actionable
  HTTP 400 and a safe native-form notice instead of a generic HTTP 500. Missing
  active subscriptions return HTTP 409. Wrapped internal errors are not exposed.

## Verification Progress

- [x] Inspect and reproduce initial dialog/layout issues before editing.
- [x] Add failing regression tests for dialog focus, transport, icons, quota
  defaults, WordPress entitlement errors, and readable search labels.
- [x] Run full local Go tests, vet, Task build, JavaScript tests, whitespace and
  deployment shell syntax checks.
- [x] Run native Ubuntu tests/vet/build and activate rollback-capable releases.
- [x] Complete the first broad live workflow pass, diagnose failed attempts,
  retest recoverable checks, and remove temporary hosted fixtures.
- [x] Complete the independent second workflow pass and cleanup.
- [x] Verify final desktop/mobile dialogs, navigation and keyboard behavior.
- [x] Merge/push main and verify deployed source equivalence.

## Live Workflow Coverage

Two independently created test resource sets use audit-prefixed identifiers and
private .test domains. Destructive tests target only those new resources.

1. Authentication: secure session cookies, CSRF, RBAC, cross-customer 404, MFA
   enrollment/challenge/recovery/revocation, and support-view identity/audit.
2. Provider onboarding: plan preview, customer/subscription creation, atomic
   rejected onboarding, resource ownership and subscription-account convergence.
3. Domain hosting: PHP and WordPress creation, PHP version/override/reset,
   dedicated FPM identity, DNS edits/subdomains, files, scheduled tasks and logs.
4. Data and mail: database idempotency/connection, scoped phpMyAdmin grant,
   assets/logout, mailbox/alias management, trusted SMTP STARTTLS and IMAPS,
   local delivery, encrypted FTPS/passive transfer and SFTP confinement.
5. Runtime and recovery: Git SSH key preparation/reuse, managed Composer releases,
   workers/environment secrecy, failed-candidate rollback, OCI routing/isolation/
   rollback/removal, Valkey socket/ACL/limits, backups/restores and staging.
6. Lifecycle and quotas: inherited suspension/reactivation, desired-stopped
   worker preservation, site/database/backup rejection without intent/enqueue,
   WordPress operations, safety-backup uninstall and GoAccess sandbox/redaction.
7. Workspace integration: 103 administrator page URLs, customer-scoped pages,
   compatibility routes, embedded assets, dialogs, mobile drawer and search.

## First-Pass Diagnosis

- One phpMyAdmin request overlapped a deliberate panel restart. The complete
  grant/assets/logout/revocation sequence passed when rerun on a stable release.
- The statistics harness initially inspected an earlier empty report. It now
  waits for a newer generation after an accepted refresh and respects the
  existing rate limit; a new sandboxed, query-redacted GoAccess report passed.
- The local mail harness initially used the leaf certificate as its only trust
  anchor. Independent OpenSSL verification established the valid served chain
  and hostname. The corrected system-trust/hostname SMTP and IMAPS checks passed.
- The uninstall request followed deliberate backup-quota exhaustion. The gate
  correctly preserved WordPress, but its HTTP error classification was wrong.
  Regression tests reproduced this before the typed error mapping was repaired.
- Deliberate unhealthy candidates and HTTP-only private test WordPress sites can
  produce expected test notifications. Resolve only fixture notifications after
  their resources are torn down; do not hide genuine hostname-service alerts.

## Browser Evidence

Local screenshots are under `/tmp/nakpanel-ux-20261013` on the verification Mac.
Final-build measurements are distinguished from earlier screenshots;
viewport-transition frames are not accepted as settled mobile QA.

Selected evidence includes database form/icons, mobile Git form, preserved-input
DNS error, mailbox plan default, and the plan synchronization preview. Shared
focus/stack behavior is additionally covered by executable JavaScript tests.

Final settled browser measurements cover 1440x1000 and 390x844: no document
overflow on the checked workspaces; 18px dialog headings and 14px form text;
44px mobile dialog actions and provider navigation links; Cancel-first plan
reviews; keyboard wrapping within the top dialog; Escape/focus restoration;
visible password-eye/copy icons; plan-derived mailbox quota; and inline DNS
validation retaining the entered host/value. The specialized container form
remains block layout with sticky actions. No JavaScript errors were recorded in
the final clean browser tab. Plan previews were cancelled without applying a
change to the hostname plan.

## Final Workflow Evidence

The first resource set was audit1791865896. The independent second set was
audit1791867730, with 140 named checks and no unresolved failures. Its single
failed command attempt was a harness query using convergence_status instead of
subscriptions.sync_status after increasing the disposable backup allowance.
Correcting that query and repeating uninstall completed the safety backup,
removed only the Toolkit-managed database/files, and retained the domain.

The second pass also verified the repaired quota rejection before increasing
the allowance: HTTP 400, clear resource-limit message, no new backup, and a
present/healthy WordPress instance. Initial failed attempts remain in the local
transcript rather than being erased from the evidence.

Cleanup used the normal account teardown worker for both resource sets. Guarded
pruning ran only after billing termination and absence of hosted resources.
Restore-history login identities are disabled, their sessions are revoked, and
immutable retired test plan revisions remain as historical records. Final
hosted inventory is one customer/subscription/hostname site, two system
mailboxes, no tenant databases, and the original hostname recovery point.

Final server checks found no failed systemd units, unresolved critical
notifications, or pending/retry/discarded mutation jobs.

Local full Go tests, go vet, Task build, all 51 JavaScript tests, whitespace and
shell syntax checks passed. Native Ubuntu full Go tests, vet and panel build
passed for the tested releases. The final runtime change was tested as 92773b3;
the verification-report commit adds documentation only. Main was fast-forward
merged and pushed, and trusted HTTPS health identified the merged runtime.

## Safety and Limits

No public-server reset, OS upgrade, reboot, server-level archive restoration,
production credential rotation, or deletion of the hostname's mail/resources is
part of this task. Existing trusted certificates and SSH access are preserved.

The workflow suite exercises implemented core paths, not every possible
configuration combination. Reseller live onboarding, external inbox receipt,
new public ACME issuance, disaster recovery, and package upgrades are not repeated
as destructive live mutations here. Provider PTR remains an external prerequisite.
Unit/handler tests cover additional roles and error paths. A passing suite is not
a claim of complete Plesk parity or a production-readiness guarantee.
