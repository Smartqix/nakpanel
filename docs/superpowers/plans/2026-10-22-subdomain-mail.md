# Subdomain Mail Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Execute inline unless the user requests delegation.

**Goal:** Reliably enable mailboxes and aliases such as `sales@shop.example.com` on an existing hosted subdomain, while preserving its parent domain, subscription limits and tenant boundaries.

**Architecture:** Reuse the existing site-linked mail-domain model, Stalwart directory views, River convergence workers and parent-zone DNS reconciliation. Verify the existing behavior before changing it, and fix demonstrated failures. Mail-only subdomains without a hosted website are a separate follow-up because they change the current site requirement.

**Tech Stack:** Go, templ, PostgreSQL, River, Stalwart, BIND and Roundcube on Ubuntu 26.04.

**Spec:** The design contract below records the scope proposed in the preceding research discussion. This is a phased work plan, not implementation or deployment authorization.

## Current authorization

- Phases 1, 2 and 3 are locally complete; Phase 3 started from `c82f8ad`. The user authorized Phase 3 only on 2026-10-22: subdomain mail quotas, suspension and lifecycle, mailbox-data and parent/sibling preservation, with focused local tests. On 2026-10-22 the user authorized Phase 4 only: focused hosted Ubuntu 26.04 subdomain mail tests and relevant fixes. Publishing this feature ref and dispatching only its focused manual test selection are required for that run. Phase 4 is incomplete after the initial run and two allowed repair cycles; that original budget is exhausted. The user subsequently authorized the Ubuntu mirror repair and exactly one additional focused hosted run. That run completed: installation/PHP passed, initial message-canary setup failed before child-mail mutation. That additional run failed and exhausted its authorization. The user authorized diagnosing/fixing the missing IMAP seed message and exactly one further focused hosted run. That run `39806681641` completed: the IMAP repair and four acceptance groups passed, but the final reviewed child-removal gate failed. That authorization is consumed. The user subsequently authorized capturing/diagnosing/fixing the child-removal failure and exactly one focused hosted rerun. No second run is authorized under this continuation. Production server changes, PR, merge and deployment remain unauthorized.
- Report the result of each phase and stop before the next unless the user explicitly authorizes multiple phases together.
- Phase 4 requires explicit hosted-test authorization. Phase 5 separates PR/CI, merge and deployment approvals; prior deployment permission for the existing main build does not authorize publishing these future changes.
- Implementation continues on the local feature branch `ricky/subdomain-mail-phase1` in the existing attached worktree, based on `d992462ead9b617cb068482922a07170a28b9687`. Keep main unchanged; remove the feature branch after a separately authorized merge.

## Global constraints

- Ubuntu 26.04 LTS (Resolute) is the only supported server OS; reject unsupported OS versions before mutation.
- Keep hosting PHP 8.3, 8.4 and 8.5 with required extensions, isolated FPM/CLI execution and readiness checks. Internal tools use validated PHP 8.5.
- Reuse the existing signed Resolute Surý provider and trusted PHP descriptors.
- Implement the current development design directly. No legacy adapters, dual paths, backfills or historical release/archive matrices.
- Preserve current-version backup/restore, application recovery, security and tenant isolation.
- Use disposable, current-schema PostgreSQL fixtures locally. Never point test DSNs at nakpanel.com or another populated installation.
- Existing lab, shared, soak and held VMs remain untouched; a name prefix does not establish ownership.
- Run affected checks once per relevant change. A skipped database test is not passing evidence. Required CI remains mandatory; optional hosted suites are not dispatched implicitly.

## Design contract

- An active subdomain in an entitled subscription can explicitly enable its own mail domain and create separate mailboxes and aliases.
- The child inherits the subscription's customer, system account and plan ceilings. It does not create another subscription, system user or resource allocation. Its mailboxes consume the shared subscription allowance.
- Parent and child mail identities remain distinct. Enabling child mail does not copy parent accounts or automatically enable mail on other subdomains.
- The parent DNS zone is the default. Child MX, SPF, DKIM and DMARC records are scoped to the child's name and ownership. Preserve custom/external records; identify routing conflicts before claiming local mail is ready.
- A separate child DNS zone uses the existing explicit mode and requires correct delegation. External DNS receives required-record guidance instead of a false local publication success.
- Disabling website hosting does not delete existing mail. Explicit mail disable preserves mailbox data; permanent removal must show its mail dependencies and require the existing reviewed deletion workflow.
- Subscription/customer suspension applies to child mail as well. Child mail cannot bypass a parent account's suspension or mail entitlement.
- Block collisions with active service hostnames and conflicting CNAME data. Do not ban valid names such as `mail` merely because of their label.
- Keep the current one-level Add subdomain workflow in this scope. Do not describe nested names as invalid DNS or claim Plesk universally forbids them. Wildcard mail and catch-all expansion are excluded.

## Evidence already present

- `internal/control/quota/account_services.go`: `UpsertMailDomain(ctx, subscriptionID, actorID, types.MailDomainInput) (int64, error)` resolves an active owned site; it does not reject `parent_site_id`.
- `internal/control/quota/mail_accounts.go`: mailbox and alias mutations enforce subscription ownership and shared counts.
- `internal/control/http/subscription_services.go` and `internal/control/web/mail_workspace.templ`: site-specific Enable mail and Create email address flows already exist.
- `internal/control/provision/dns_defaults_test.go`: `TestChildMailDNSUsesParentZoneWithoutChangingParentMail` already covers child records, parent preservation and custom external routing. Reuse this coverage rather than rebuild the feature.
- `internal/control/provision/mail_jobs.go`: reconciliation already prefixes child records within the selected parent zone.

The initial observations above were source inspection. Phase 1 subsequently reproduced duplicate-domain failures on repeated enable and accepted attempts to retarget a mail-domain ID or insert a missing update ID. Both paths are fixed locally; see the [Phase 1 verification record](../../verification/2026-10-22-subdomain-mail-phase1.md). This is not live mailbox acceptance.

## Review focus

1. A forged child site ID, mailbox ID or mail-domain ID must never mutate another subscription's resources: Phase 1 ownership tests.
2. A child with a CNAME, external MX or delegated DNS must not receive destructive or misleading local DNS changes: Phase 2 conflict tests.
3. Two child mailbox requests at the last shared quota slot must not both succeed: Phase 3 concurrent database test.
4. A delayed/retried enable request must not create duplicate mail domains or report readiness before convergence: Phases 1 and 2 state tests.
5. Website disable or child removal must not erase mail silently or alter parent/sibling messages and records: Phase 3 lifecycle tests, then Phase 4 hosted canaries.

## Phase 1 — Verify and fix the existing subdomain mail flow

**Files:** `internal/control/http/subdomain_mail_test.go`, `internal/control/http/subscription_services.go`, `internal/control/http/mail_workspace.go`, `internal/control/http/mail_workspace_test.go`, `internal/control/web/mail_workspace.templ`, `internal/control/quota/account_services.go`, `internal/control/quota/mail_accounts.go`; create `internal/control/quota/subdomain_mail_postgres_test.go` only for missing real-database coverage.

**Interfaces:** Retain `types.MailDomainInput.SiteID`, `types.MailboxInput.MailDomainID` and the existing UpsertMailDomain/UpsertMailbox/UpsertMailAlias methods. Use the authenticated site ID to derive the domain; never trust a posted domain string for ownership.

- [x] Add a current fixture containing an active parent, child and unrelated tenant. Use the existing `removaldb.New` fixture support and an explicitly disposable `NAKPANEL_REMOVAL_TEST_DSN`.
- [x] Exercise child Mail → Enable mail → Create email address → Create alias, including normal form submission, dialog navigation and return to the same child's Mail page.
- [x] Assert the child address is `sales@shop.example.test`, not a parent-domain address; forged ownership is rejected; repeated enable does not create a second mail domain.
- [x] Run the focused tests first. Preserve the actual failure evidence; if the flow already passes, report that result and add only meaningful missing coverage.
- [x] Fix demonstrated failures in the existing layers. Regenerate templ output only if templates change, then rerun the affected tests and generated-code check.

**Result:** The local HTTP and real-database checks pass. Child forms and dialog targets retain child ownership and return context; repeat enable preserves mailbox and alias identities; parent/foreign/missing ID edits are rejected. Templates and JavaScript did not require changes. Stop here and report before Phase 2.

**Exit:** Local HTTP/database evidence proves child enable, mailbox and alias creation under the correct subscription. This is not hosted delivery acceptance.

## Phase 2 — Complete DNS handling and readiness feedback

**Files:** `internal/control/provision/mail_dns.go`, `internal/control/provision/subdomain_mail_dns_test.go`, `internal/control/dnstemplate/manager.go`, `internal/control/dnstemplate/jobs.go`, `internal/control/dnstemplate/subdomain_mail_dns_test.go`, `internal/control/provision/phase6_repository.go`, `internal/control/web/subdomain_mail_dns_test.go`, `internal/control/web/mail_design.templ` and generated output, `internal/control/web/static/mail.css`, `docs/MAIL.md`; `internal/control/provision/mail_jobs.go`, `internal/control/provision/dns_services.go`, `internal/control/provision/dns_service_convergence.go`, `internal/control/provision/dns_defaults_test.go`, `internal/control/http/mail_client.go`, `internal/control/web/mail_workspace.templ`, `internal/control/web/mail_helpers.go` as required by observed gaps.

**Interfaces:** Keep `ConfigureMailWorker.reconcileZoneRecords(ctx, mailDomainRow, []types.DNSRecord) error` and the existing mail-domain convergence status/error reporting. Preserve record ownership through `owner_site_id` and the selected zone.

- [x] Run the existing child-parent DNS regression with its real database fixture before changing reconciliation.
- [x] Add missing cases for CNAME conflicts, custom external MX/SPF, a separate child zone with delegation, external DNS guidance, repeated reconciliation and failed agent application.
- [x] Assert parent/sibling records are unchanged, no duplicate SPF is published, custom records survive disable/removal, and a failed convergence is visibly failed rather than ready.
- [x] Fix only uncovered cases; show actionable DNS requirements and pending/failed status in the existing child Mail workspace.
- [x] Run affected provision/HTTP/template checks and update the relevant mail guidance with exact parent-zone record examples.

**Result:** Focused real-database and rendered feedback checks pass for parent-zone scoping, preservation, CNAME/service conflicts, custom routing, delegation, external requirements and failed/pending application. Record, DNS mode and applied template changes queue the existing mail recheck atomically. A child failure no longer blocks independent domains. The final affected run passed 26 tests without skips after both review findings were fixed. See the [Phase 2 verification record](../../verification/2026-10-22-subdomain-mail-phase2.md). Report before Phase 3.

**Exit:** Each supported DNS mode has an explicit ready, pending, conflict or external-action result. Child changes preserve parent and sibling routing.

## Phase 3 — Enforce limits, lifecycle and data preservation

**Files:** `internal/control/quota/subdomain_mail_limits_test.go`, `internal/control/quota/lifecycle.go`, `internal/control/quota/inherited_lifecycle_test.go`, `internal/control/provision/subdomain_mail_lifecycle_test.go`, `internal/control/provision/subdomain_mail_removal_test.go`, `internal/agent/ops/subdomain_mail_lifecycle_test.go`; `internal/control/quota/mail_accounts.go`, `internal/control/quota/account_services.go`, `internal/control/quota/provider.go`, `internal/control/provision/mail_jobs.go`, their existing tests, `internal/control/quota/subdomain_mail_postgres_test.go`, `internal/control/provision/mail_jobs_test.go`, `internal/control/provision/site_removal.go`, `internal/control/provision/site_removal_jobs.go`, and matching removal tests where a demonstrated failure requires a change.

**Interfaces:** Reuse subscription mutation locking, effective mail policy, mailbox/alias ownership checks, mail convergence and the existing removal preview/confirmation workflow. Do not introduce independent child resource grants or a second mail identity model.

- [x] Add real-database tests that count parent and child mailboxes together, enforce mailbox size limits, reject cross-subscription edits and serialize concurrent requests for the last available slot.
- [x] Verify customer/subscription suspension disables effective child mail and reactivation restores only entitled, explicitly enabled domains.
- [x] Verify website-only disable and mail disable preserve mailbox rows/data; child removal presents mail dependencies and cannot proceed through an unconfirmed destructive path.
- [x] Verify child operations preserve parent/sibling accounts, aliases, records and audit ownership. Fix demonstrated failures with focused regressions.
- [x] If changes affect serialized mail identities, backup collection, restore or removal, run the affected current-format backup/restore fixtures. Reuse unchanged acceptance evidence; do not launch a new historical or full-server test matrix.

**Local result:** Focused tests cover shared counts and concurrent last-slot requests, finite storage caps, absent update-ID rejection, immediate directory revocation through lifecycle and resolved plan/policy changes, account-revision acknowledgement guards, website/mail disable separation, reactivation, data/key canaries and reviewed child removal scope. The final affected suite passed 38 tests without failures or skips; vet passed, and the one important review finding was fixed. No serialized identity, backup, restore or removal implementation changed; their historical/hosted checks were not repeated. See the [Phase 3 verification record](../../verification/2026-10-22-subdomain-mail-phase3.md). Report before Phase 4.

**Exit:** Limits cannot be bypassed through children; suspension is effective; disable is non-destructive; permanent deletion has explicit scope and confirmation. Report local evidence and any remaining hosted uncertainty.

## Local verification commands for Phases 1–3

Use the exact pinned Go toolchain and the existing owned PostgreSQL fixture setup. Set `NAKPANEL_REMOVAL_TEST_DSN` to that disposable database before running database cases; inspect verbose output for unexpected skips.

```sh
go test ./internal/control/quota -run 'TestSubdomainMail' -count=1 -v
go test ./internal/control/http -run 'Test.*(SubdomainMail|MailDomain|MailWorkspace|DomainMail)' -count=1 -v
go test ./internal/control/provision -run 'Test.*(ChildMailDNS|MailDNS|EffectiveMailDomain|SubdomainMail)' -count=1 -v
git diff --check
```

The new real-database tests use the `TestSubdomainMail` prefix. Add existing affected removal/backup tests to the command set when Phase 3 changes those paths. Use the repository's templ generation and generated-diff gate when templates change. Run relevant JavaScript tests only if JavaScript behavior changes. Full required CI belongs to Phase 5.

## Phase 4 — Focused hosted Ubuntu 26.04 acceptance

**Files:** Extend the existing `deploy/multipass/mail-workspace-live-verify.cjs` fixture if suitable, or add `deploy/multipass/subdomain-mail-verify.sh` as one bounded, ownership-checked wrapper; record results in `docs/verification/2026-10-22-subdomain-mail.md` when actually executed.

**Prerequisite:** Explicit authorization for hosted tests, an identified disposable Ubuntu 26.04 host, the exact source/artifact and a recorded fixture owner. Do not run against nakpanel.com or an unrelated lab server by implication.

**Run budget:** One initial focused run, with a 45-minute overall timeout and a 10-minute timeout per acceptance gate after prerequisites are ready. Allow at most two repair-and-verification cycles in this phase before reporting any unresolved blocker. Keep failure evidence and stop rather than extending the scope or repeating unchanged checks. **Additional authorization:** the user authorized one mirror repair and one additional focused hosted run after the original three attempts. This does not replenish the earlier retry budget.

- [x] Create one owned parent/child fixture and a separate tenant boundary fixture. Retain parent mailbox/message and DNS canaries before child mutations.
- [x] Enable child mail and create a mailbox/alias through the actual interface. Verify SMTP submission, local delivery, IMAP retrieval and Roundcube login for the child, plus parent mail continuity.
- [ ] Check shared quota rejection, forbidden foreign-resource requests, explicit disable/re-enable and reviewed child cleanup. Check the demonstrated fixes from Phases 1–3; avoid an unrelated full platform matrix.
- [ ] Exercise restore or reboot only if those runtime paths changed or the approved acceptance scope requires them. Preserve PHP 8.3/8.4/8.5 readiness; do not repeat unchanged PHP maintenance drills.
- [x] Enforce the run budget and capture the first actionable failure. Retry only after a relevant fix, then repeat the affected slice. Clean up only resources proven to belong to this run.

**Result: incomplete.** The current hosted run [39806681641](https://github.com/Smartqix/nakpanel/actions/runs/39806681641), source `8abe280`, passed signed Ubuntu 26.04 installation, PHP 8.3/8.4/8.5 readiness and four gate groups: child browser/protocol mail, Roundcube, quotas/tenant isolation, and disable/suspension/reactivation with actual message and parent/sibling preservation. The missing IMAP message was a probe normalization defect and is now verified fixed. The final reviewed child-removal gate failed; child-denial and parent/sibling preservation after removal remain unverified. Owned guest cleanup passed. The one authorized rerun is consumed. See the [Phase 4 report](../../verification/2026-10-22-subdomain-mail-phase4.md).

**Current continuation completed:** the missing IMAP seed probe was repaired and the focused hosted selection ran exactly once. Remaining: diagnose the final reviewed child-removal failure and verify its downstream preservation checks; further hosted execution requires explicit authorization. Preserve mailbox data and parent/sibling resources. Earlier failures stay attributed to their original source. Stop and report before PR, merge or deployment.

**Exit:** Report exact source, actual OS, named checks, failures/retries, parent preservation and cleanup. Distinguish local mailbox delivery from external-inbox acceptance; an external delivery claim requires an explicitly authorized recipient and separate evidence. Stop before release work.

## Phase 5 — Review, required CI and controlled release

**Files:** Relevant product documentation, the scoped verification record and existing `.github/workflows/ci.yml` only if required to execute the new focused coverage. Do not add a second hosted workflow for the same acceptance claims.

- [ ] Reconcile documentation and obtain a focused review of ownership, DNS record scope, shared quotas and deletion behavior. Resolve material findings with the relevant regression tests.
- [ ] When push/PR is authorized, prepare one PR into main and run required CI, including its hosted security gate. Confirm database cases execute and bind evidence to the exact tested source.
- [ ] Report the PR, final diff, CI result and outstanding limitations before merging. Merge only when explicitly authorized; remove the merged feature branch afterward.
- [ ] Deploy only when explicitly authorized. Use the tested main build and existing recovery procedure; verify trusted HTTPS, mail health and the affected subdomain flow without disturbing unrelated customer data.

**Exit:** The approved change is merged, and deployed only if requested, with a concise evidence-backed report. No remaining feature branch is retained after an authorized cleanup.

## Separate follow-up — Mail-only subdomains

This follow-up is not a blocker for completing mail on existing hosted subdomains. It requires a separate approved design: an owned mail-domain identity that can exist without an active website, with explicit DNS, lifecycle, removal and current-format backup semantics. Compare retaining a non-web hosted-domain identity with introducing a general domain identity before choosing a schema. Do not bypass ownership by accepting arbitrary domain strings or fabricate a website to satisfy validation.

## Research references

- [Plesk mail CLI: domain and subdomain mail service](https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/mail-mail-accounts.39181/).
- [Plesk subdomain capabilities](https://docs.plesk.com/en-US/obsidian/customer-guide/websites-and-domains/domains-and-dns/adding-subdomains.65180/).
- [Plesk subscription resources](https://docs.plesk.com/en-US/obsidian/reseller-guide/understanding-service-plans-and-subscriptions/properties-of-hosting-plans-addons-and-subscriptions/resources.65718/).
- [DNS CNAME exclusivity, RFC 2181 section 10.1](https://www.rfc-editor.org/rfc/rfc2181.html#section-10.1).

Research supports the proposed product rules; it does not establish that Nakpanel's hosted workflow has passed.
