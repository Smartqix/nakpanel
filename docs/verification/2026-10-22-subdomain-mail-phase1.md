# Subdomain mail — Phase 1 local verification

Date: 2026-10-22. Base: `d992462ead9b617cb068482922a07170a28b9687`.
Branch: `ricky/subdomain-mail-phase1`.

The user authorized Phase 1 only: enable mail, create a mailbox and create
an alias on an existing hosted subdomain, with focused local verification.
Phase 2 has not started. No hosted tests, server operations, push, PR,
merge or deployment were performed.

## Findings and changes

Basic child mail enablement, mailbox creation and alias routing already worked.
There was no general prohibition on child mail to remove.

1. Repeating Enable mail with no mail-domain ID failed with PostgreSQL
   `23505` on `mail_domains_domain_key`. The store now resolves and reuses the
   existing owned mail identity under the subscription mutation lock.
   Existing mailboxes and aliases keep their IDs and domain association.
2. An explicit mail-domain update ID could retarget the parent's mail identity
   to the child. A missing update ID could insert a new row. The store now
   requires an explicit ID to exist in the subscription and match the selected
   hosted site and its server-derived domain. Settings edits on the same child
   continue to work.

Only `internal/control/quota/account_services.go` changed product behavior.
No schema, dependency, template, JavaScript, DNS, OS, PHP or runtime configuration
changed. Ubuntu 26.04 and the hosting PHP 8.3/8.4/8.5 contract are unchanged.

## Coverage

- A current-schema PostgreSQL fixture contains an owned parent, its child and
  another subscription's site. It creates distinct parent/child/foreign mailboxes
  and the child alias `sales@shop.example.test` → `hello@shop.example.test`.
- The child mailbox has a verified password hash and its own directory address.
  Parent and foreign mailbox directory entries remain distinct.
- Real database mutations reject foreign site IDs, mail-domain IDs, mailbox IDs
  and alias destinations. Parent/foreign/missing domain-ID edits are rejected.
- Repeat enable returns the same domain ID and preserves mailbox/alias rows;
  a valid explicit settings edit also preserves those identities.
- The local HTTP flow renders the actual child's enable, mailbox and alias
  forms, posts their hidden IDs and CSRF tokens through the real handlers, and
  checks that each redirect returns to `/sites/32?tab=mail`. The handler fixture
  records storage requests; the separate SQL tests exercise actual persistence.
- Dialog target/form wiring and the ordinary form fallbacks are checked locally.
  This is server-rendered HTML evidence; JavaScript was not exercised in a browser.

## Local execution

macOS ARM64; pinned Go 1.26.9; owned disposable PostgreSQL 17.11, Unix socket
only, database `nakpanel_removal_test`. The existing PostgreSQL cluster and all
existing VMs were untouched. Each SQL fixture migrated the current schema into
its own temporary schema.

The initial database run failed on repeated enable and parent/missing-ID edits;
the successful basic child flow and foreign rejection were retained. After the
fix, all new SQL cases passed. An initial HTTP test-helper build attempted to
use an unavailable HTML parser dependency; the helper now uses the standard
library, without changing `go.mod` or `go.sum`.

Focused regression command:

```sh
go test ./internal/control/quota ./internal/control/http -run '^Test(SubdomainMail.*|ClientMailWorkspaceAndEmailAlias|MailDomainRequestUsesHostedSiteAndCrossTenantWebmailIsHidden|DomainMailReturnContextIsValidated|SupportCustomerFilterIncludesOnlyOwnedMailResources|DomainMailFigmaMailboxActions|MailClientConnectionContentAndOwnership|MailEnableDomainFallback|MailFormsUncheckedTogglesAreNotReenabled|UpsertMailboxRejectsInvalidInputBeforeSQL|EnforceMailCountTxScopesCountToSubscription|EnsureMailDomainBelongsTxRejectsForeignDomain|EnsureAliasDestinationTxRejectsForeignMailbox|DeleteMailboxAndAliasScopeToSubscription)$' -count=1 -v
```

Result: **17 top-level tests passed, no failures or skips**, exit 0.
Includes the new real PostgreSQL tests and the existing parent mail forms,
ownership, return-context, alias validation and shared-count unit checks.
After strengthening the dialog assertions, `TestSubdomainMailFormsKeepChildContext`
passed again: actual enable, mailbox and alias dialog forms retain the child IDs;
the alias action is checked on its Aliases tab.

```sh
go vet ./internal/control/quota ./internal/control/http
git diff --check
```

`go vet`, `git diff --check` and formatting checks passed. The owned temporary
PostgreSQL server was stopped after verification; its private evidence remains.

A fresh independent reviewer inspected the complete change, surrounding
ownership/locking code, test logs and exit metadata. Verdict: Phase 1 locally
complete, with no critical, important or minor findings. No second review or
unchanged test run was dispatched.

The reviewer explicitly left later DNS/readiness, concurrent quota, suspension,
deletion/lifecycle, browser JavaScript, live mail delivery, Ubuntu/PHP runtime,
backup/restore and release acceptance outside this phase. These are unchanged
paths or later authorized work; their acceptance is not established by this
patch. Existing requirements remain in the phased plan.

Execution decisions: honor the Phase 1 boundary even though the generic execution
skill says to continue tasks; retain the ignored ledger until the overall plan
finishes. The consequences are that later phases remain incomplete and private
local scratch remains until final cleanup. No minor findings were deferred.

Full command output and exit metadata are retained in this plan's ignored
`.superpowers/sdd/2026-10-22-subdomain-mail/` directory. No old matrix was rerun.

## Acceptance boundary

The SQL fixture explicitly models a successful agent acknowledgement when it
checks Stalwart directory views. No live agent, SMTP submission, IMAP retrieval,
Roundcube login, external recipient or DNS publication was tested. Those claims
require the later authorized phases. No Ubuntu hosted acceptance is claimed.

The next phase is DNS handling and readiness feedback, pending user authorization.
