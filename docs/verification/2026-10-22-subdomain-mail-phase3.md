# Subdomain mail — Phase 3 local verification

Date: 2026-10-22. Phase base: `c82f8ad` (completed Phase 2).
Local branch: `ricky/subdomain-mail-phase1`, in the attached implementation worktree.
Main remains at `d992462`. Only Phase 3 was authorized: quotas, suspension,
lifecycle and preservation with focused local tests. No hosted tests, server
operations, deployment, push, PR or merge were performed. Phase 4 has not started.

## Findings and changes

1. A nonzero but nonexistent mailbox/alias update ID skipped the create quota
   and inserted a row. Mailbox inserts could also bypass the new-account password
   requirement. Both update paths now lock and require an existing account in
   the selected owned mail domain before applying the update.
2. Customer/subscription suspension left directory accounts and aliases effective
   until the worker ran. The lifecycle transaction now revokes affected directory
   entries immediately and advances their mail intent. An older agent response
   cannot re-enable that captured intent. Inactive reseller ownership is included
   in the same lifecycle predicate; removing sites remain protected.
3. Revoking mail permission through the subscription policy left effective mail
   active until convergence. That policy transaction now revokes it immediately
   and changes the captured mail intent as well.
4. Explicit mail disable also left accounts visible until the worker ran. A
   disabled mail domain now clears `effective_enabled` in the same write;
   re-enable preserves its account/alias identities and requires convergence.
5. Existing mail settings required active website hosting. They now remain
   editable while website hosting is off, with the active subscription,
   immutable mail identity, tenant ownership and removal-state checks retained.

Existing shared count locking and finite mailbox storage clamping already worked;
no duplicate quota mechanism was added. No schema, serialized mail identity,
backup/restore format, agent storage, removal implementation, template or
JavaScript changed. Ubuntu 26.04 and PHP 8.3/8.4/8.5 requirements are unchanged.

## Local evidence

- Parent, child and sibling creates share the same subscription count. Two
  simultaneous mailbox requests for the last slot yield one success and one
  quota error; aliases are tested the same way. A child cannot get a separate
  allowance. Larger/unlimited mailbox requests respect the finite storage cap.
- Missing edit IDs now reject both resource types without inserting a row.
  Existing tenant and identity guards are exercised by the affected Phase 1
  regression slice; valid edits/repeated enable remain supported.
- Actual customer/subscription status and policy APIs are used against current
  PostgreSQL fixtures. Directory account and alias visibility drops in the same
  transaction, then convergence confirms disabled state. Reactivation restores
  enabled parent/child domains and keeps the explicitly disabled sibling off.
  The unrelated tenant remains enabled; all mailbox/alias rows remain identical.
- A fixture agent suspends the subscription after the worker captures its intent
  but before acknowledgement. The stale response is rejected and cannot restore
  directory access. No live service is involved.
- The actual site-settings API changes website-only intent; the test models the
  hosting acknowledgement and proves mail stays enabled. Mail disable/re-enable
  then keeps mailbox rows, aliases and parent/sibling DNS fingerprints intact.
- The child removal preview includes its mail domain, mailbox and alias without
  secrets. Missing permanent acknowledgement, wrong hostname and stale digest
  produce no operation or data mutation. The valid reservation contains only
  the child, hides its directory entries, preserves persisted mail data until
  execution and records the correct actor/customer/subscription audit ownership.
- A local agent provisioner with temporary paths and a fake runner/reloader
  retains parent/child/sibling message canary bytes and DKIM private-key bytes
  through child disable, all-domain suspension and re-enable. These are filesystem
  canaries; no actual Stalwart database or IMAP messages were accessed.
- Existing local removal checks cover parent-zone preservation, sibling-job
  continuity, failed-stage retry and sibling mail/access preservation.

## Verification

macOS ARM64, pinned Go 1.26.9, owned PostgreSQL 17.11 using only its private
Unix socket and `nakpanel_removal_test` database. Each SQL fixture migrates a
fresh current schema. Existing VMs and other databases were untouched.

Baseline: 5 existing focused tests passed. The initial new tests reproduced
missing-ID inserts, delayed revocation, stale acknowledgement and website/mail
coupling before the fixes. Shared counts and storage caps passed initially.
One website test initially requested PHP 8.4 from a fixture plan offering only
PHP 8.5; it now reads that fixture's resolved default. No required hosting
runtime was removed or substituted.

Final local command:

```sh
go test ./internal/control/quota ./internal/control/provision ./internal/agent/ops -run '^Test(SubdomainMail(SharedQuotaLastSlot|RejectsMissingUpdateIDs|MailboxStorageCap|SuspensionAndReactivation|WebsiteAndMailDisablePreserveData|StaleAcknowledgementCannotUndoSuspension|DisableImmediatelyPreservesData|RemovalRequiresReviewedScope|DisableKeepsStoreAndSigningKeys|EnableMailboxAndAlias|RepeatedEnableKeepsAccounts|RejectsRetargetedDomainID)|CustomerLifecycleQueuesAccountsEvenWithoutSites|SubscriptionLifecycleQueuesAccountServices|ResellerLifecycleQueuesAllCustomerAccounts|CustomerLifecycleRollsBackWhenAccountQueueFails|ExplicitSubscriptionLifecycleUpdatesAccountIntent|CustomerProviderTransferQueuesInheritedLifecycle|UpsertMailboxRejectsInvalidInputBeforeSQL|EnforceMailCountTxScopesCountToSubscription|EnsureMailDomainBelongsTxRejectsForeignDomain|EnsureAliasDestinationTxRejectsForeignMailbox|DeleteMailboxAndAliasScopeToSubscription|LockActiveSubscriptionRejectsSuspendedCustomerOrSubscription|LockActiveSubscriptionRejectsSuspendedResellerOrMissingAllocation|DeleteExternalServicesMarksCleanupBeforeConvergence|RemoveChildPreservesParentZone|SiteRemovalEachFailedStageRetainsIntentAndRequiresRetry|SiteRemovalDoesNotCancelSiblingJobs|RemovalKeepsSiblingMailAndPrimaryAccess|ConfigureMailIsIdempotentAndKeepsDKIMKeys)$' -count=1 -v
```

**31 top-level tests passed, no failures or skips.** `go vet` on quota,
provision and agent/ops passed. Formatting and `git diff --check` passed.
No generated frontend check was needed because its sources did not change.
The exact commands, full output and exit metadata remain in this plan's ignored
`.superpowers/sdd/2026-10-22-subdomain-mail/` directory as `phase3-*` evidence.
The earlier failures remain failures; the successful run is recorded separately.

No serialization, collection, restore or removal code changed. Current-format
backup/restore evidence was reused; no historical matrix or unrelated backup
rehearsal was launched. This does not establish new hosted backup acceptance.

## Review and acceptance boundary

A fresh independent review is pending before the final report. Stop before
Phase 4. No live BIND/Stalwart, SMTP, IMAP, Roundcube, external delivery, public
DNS, hosted Ubuntu acceptance or production message preservation is claimed
from these local fixtures. Those require the later explicitly authorized phase.
