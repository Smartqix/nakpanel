# Plesk Migration Rehearsal Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans for any later authorized execution. Steps use checkbox (`- [ ]`) syntax for tracking. Current authorization (27 October 2026): execute hosted R0 and R1 only with S01/S02/S03. Necessary harness commit/push and focused manual dispatch are authorized; later rehearsals, real migration, PR, merge and production deployment are not.

**Goal:** Establish requirements and acceptance for representative Plesk-to-Nakpanel rehearsals before considering customer migration.

**Architecture:** Start with operator-assisted, subscription-scoped rehearsals using existing Nakpanel tools. Use isolated, uniquely owned source fixtures and Ubuntu 26.04 targets; do not install Nakpanel over Plesk or treat a Plesk backup as a Nakpanel archive. A full automated importer is separate work.

**Tech Stack:** Ubuntu 26.04, signed Resolute Surý PHP 8.3/8.4/8.5, internal PHP 8.5, nginx, MariaDB, Stalwart/Roundcube, BIND and current backup/recovery tooling.

**Spec:** [Requirements and synthetic inventory](../specs/2026-10-26-plesk-requirements-inventory.md).

## Global Constraints

- Phase 2 local planning is complete. The current execution is limited to hosted R0 and R1 with synthetic customers S01/S02/S03.
- Only the focused R0/R1 hosted job may run. No live source connections, live migration, public DNS/MX/DS changes, external customer messages, PR, merge or production deployment.
- Ubuntu 26.04 LTS/resolute is the only target. Keep hosting PHP 8.3/8.4/8.5 and internal PHP 8.5 with the existing signed provider/descriptors.
- No older target PHP/OS, legacy Nakpanel restore paths, compatibility shims or silent feature substitutions.
- Preserve mailbox data, source recoverability, tenant ownership and parent/sibling resources.
- R0/R1 are authorized. R2–R5 still require separate authorization. Existing hosted results retain their original source and scope.

## Review Focus

1. Mail arriving after initial copy must be reconciled without loss or duplicate append; R3 must prove the cutover rule.
2. New target orders/uploads/mail make DNS-only rollback insufficient; R5 must preserve post-switch writes.
3. Apache access rules can become public exposure on nginx; R2 must exercise forbidden URLs.
4. Shared databases, aliases and child DNS can cross subscription boundaries; R2/R4 must check ownership and unchanged canaries.
5. Clones can send real email, webhooks or payments; R0 must prove containment before any workload starts.

## Current Phase 2 deliverables

- [x] Inspect current capabilities and primary Plesk migration/inventory guidance.
- [x] Generate eight fictional subscriptions with supported and blocked requirements.
- [x] Map gaps to implementation/docs and define R0–R5 acceptance.
- [x] Validate fixture consistency and run focused local behavior tests; record actual results below.

Files: the linked requirements document, the
[synthetic JSON](../../migration/fixtures/plesk-customers.synthetic.json), this plan
and the [local result evidence](../../verification/evidence/2026-10-26-plesk-synthetic-local.json).
The hosted slice adds a dedicated verifier and workflow selection, plus a private bootstrap-file path in the test installer harness. Application code, OS/PHP defaults and schemas retain their current contract.

## R0: Freeze evidence and contain a disposable rehearsal

**Consumes:** Selected synthetic cases or a separately authorized, complete private inventory.
**Produces:** A reviewed case manifest, isolation proof and owned source/target identities.

- [ ] Record exact target bundle/hash/trust key, OS/architecture/provider and all PHP runtime/extension readiness. Initial AMD64 rehearsal is proposed because existing hosted evidence covers AMD64; ARM64 needs its own acceptance.
- [ ] Use synthetic data first. For later customer-derived copies, obtain explicit scope and sanitize privately; compare target preservation against the sanitized source baseline.
- [ ] Require nonempty file/database/mail canaries where applicable and a baseline checksum/count manifest. Empty fixtures cannot prove preservation.
- [ ] Block production egress, disable cron/workers/outbound notifications until reviewed, and use sandbox payment/mail/API credentials. Prove production endpoints are unreachable.
- [ ] Use isolated .test names, private DNS/hosts overrides and trusted test certificates. Never change public delegation, ACME production challenges or the live source.
- [ ] Bound time, storage and cleanup to exact owned identities. Retain evidence before deleting only owned fixtures.

Abort before import on missing ownership, untrusted TLS, insufficient capacity,
reachable production integrations or unresolved required inventory fields.

## R1: Three hosting PHP baselines

**Consumes:** R0 manifest and S01/S02/S03.
**Produces:** Per-runtime website/data/permission evidence for PHP 8.3, 8.4 and 8.5.

- [ ] Recreate separate customers/subscriptions and the reviewed plan/overrides through normal scoped operations. Preserve relationships; never copy Plesk numeric IDs as Nakpanel ownership.
- [ ] Use Classic PHP for mutable Plesk applications unless a Managed PHP conversion is explicitly selected. Keep each chosen PHP minor and validate required extensions plus FPM/CLI identity.
- [ ] Import scoped files and logical database data into disposable destinations. Validate application URLs, login, sessions, upload, permalinks, cron and a controlled update.
- [ ] Compare file hashes, symlinks, modes, mapped ownership, row/routine inventories and negative cross-tenant access. Test the final declared dataset, not just a welcome page.
- [ ] Back up, reboot and recheck the workload without repair actions masking failed boot persistence.

Pass only with all three runtimes independently evidenced and no unexplained
data/permission differences. This does not prove every WordPress/plugin version.

## R2: Application, SQL, access and job exceptions

**Consumes:** R0, S02/S04/S05/S07 and their gap records.
**Produces:** Explicit transformations or blockers with application-owner acceptance criteria.

- [ ] Prove S04's PHP 8.2 requirement stays blocked; do not enable an older runtime. Test a separately approved application upgrade on its clone if requested.
- [ ] Translate required Apache rules into reviewed nginx settings. Check legitimate redirects and denied paths, including hidden config, protected areas and nested .htaccess rules.
- [ ] Rehearse S07 MySQL-to-MariaDB logical conversion: SQL modes, collations, views/routines/triggers/events/definers, grants, actual queries and controlled transactions. No raw datadir copy or shared-principal takeover.
- [ ] Prove native Node.js/tenant PostgreSQL requests remain blocked in the current profile. External services or OCI redesigns need explicit separate decisions.
- [ ] Check SFTP/FTPS clients, confinement, private Git access with new scoped keys, branch/publication behavior and cron user/cwd/timezone. Git code rollback must not be mistaken for data rollback.

Abort on exposed private paths, changed unrelated resources, incompatible SQL,
unexpected outbound calls or a substituted runtime/service.

## R3: Mail preservation and final catch-up

**Consumes:** R0, S03/S06/S08; actual import IDs, message identities and private receipts.
**Produces:** Reconciled counts/content/metadata plus a verified cutover procedure or a blocker.

- [ ] Create only owned test mailboxes/aliases, map all selected folders and verify quota before transfer. Use certificate-verified source IMAP on 993 or reviewed Maildir.
- [ ] Prove bytes/attachments, dates, flags, folder hierarchy and distinct identical messages survive. Pause/resume and uncertain APPEND recovery must not duplicate mail.
- [ ] Inject new source messages during an active import and after completion. Active-run catch-up has local coverage; completed imports stop watching. Do not assume reopening/new-import deduplication works.
- [ ] Define and test a bounded final source-write/late-delivery policy before any future MX switch. If post-completion catch-up cannot be proved, mark local-mail migration blocked.
- [ ] Confirm S06's unsupported routing, filters, contacts/calendars and password-preservation requirements stay explicit blockers. No silent data dropping or unapproved password resets.
- [ ] Check S08 against every documented size/count limit. Boundary metadata does not count as a real oversized-message/large-archive transport test; use bounded fixtures or approved dedicated capacity tests later.
- [ ] Open imported messages/attachments through fresh IMAP and Roundcube sessions, then reboot and recheck. Source and unrelated mailbox data must remain intact.

Pass only with zero unexplained failed/uncertain messages, explicit intentional
exclusions and a proved final catch-up procedure. Local delivery is not external deliverability.

## R4: DNS, TLS and resource boundaries

**Consumes:** R0 and selected cases with complete public-record and ownership requirements.
**Produces:** Reviewed hypothetical change set and isolated endpoint/resource results.

- [ ] Snapshot parent/child/sibling DNS, aliases, custom MX/SPF/DKIM/DMARC, verification TXT, TTL, NS/glue/DS and IPv6 requirements.
- [ ] Test the planned local/external DNS mode without changing real delegation. Confirm parent/sibling records, external mail routes and unrelated resources remain unchanged.
- [ ] Verify Host/SNI routing, redirects and trusted HTTPS/mail endpoint certificates, SANs and renewal ownership. Do not use insecure TLS flags to obtain a pass.
- [ ] Describe DNSSEC/DS and authoritative-provider transitions explicitly; unmanaged requirements stay blocked. Applied local BIND records are not proof of public propagation.
- [ ] Plan external send/receive/PTR/reputation checks separately with named test recipients and authorization; do not send customer mail in this rehearsal.

## R5: Recovery, late writes and proposed pilot admission

**Consumes:** R1–R4 evidence, selected offsite destination, private recovery key custody and agreed downtime/data-loss limits.
**Produces:** Measured restore/rollback results and a decision for each rehearsed subscription.

- [ ] Verify the source's own recovery artifact separately. Retain Plesk backups for source recovery; they are not Nakpanel-format archives.
- [ ] Restore the exact scheduler-created Nakpanel archive from the selected offsite destination onto a fresh owned Ubuntu 26.04 host. Verify populated files/database/mail and all PHP runtimes before/after reboot.
- [ ] Simulate the cutover using private routing only. Add target-side orders/uploads/mail, abort, and prove the chosen reconciliation back to the disposable source without losing or duplicating those writes.
- [ ] Record measured backup age, transfer/restore duration and final verification time against owner-approved RPO/RTO/downtime. Unknown business limits cannot pass.
- [ ] Record each case as pass, failed, blocked or excluded with reason and original evidence; never convert a skip into acceptance. Preserve original failures.
- [ ] Report before any new phase. A successful rehearsal does not replace release signing, genuine PHP security-update, native architecture or elapsed-soak qualification, and does not authorize a live pilot.

## Local result record

Go 1.26.9 on macOS/ARM64: 51 accepted top-level local tests passed.
The [evidence JSON](../../verification/evidence/2026-10-26-plesk-synthetic-local.json)
records the exact selectors, accepted test names, original skips and dataset digest.

| Scope | Accepted top-level passes |
| --- | --- |
| IMAP TLS, message preservation/identity and Maildir extraction safety | 13 |
| Import engine recovery, catch-up within an active run, quota/receipt failures and access gates | 17 |
| SQL-mocked mailbox/alias input, subscription scope and foreign-resource rejection | 5 |
| Current PostgreSQL-backed child mail/alias, repeat enable, retarget rejection and quota cases | 6 |
| PHP 8.3/8.4/8.5 descriptor mapping, invalid profiles/DB engines and Maildir agent boundaries | 7 |
| Supported OS contract and rejection before mutation | 2 |
| Ubuntu 26.04/Surý/full multi-PHP defaults | 1 |

The initial no-database selection skipped database-dependent cases. A new,
owned PostgreSQL 17 fixture then ran six current production-schema tests with
no failures or skips; it used a private Unix socket, no TCP listener and only
synthetic records. Its service was stopped and its owned cluster data removed.
Existing PostgreSQL services were not changed.

The older optional TestMailTenantIsolationTwoTenants was not executed and is
not counted as passed. Real Stalwart compatibility, external delivery, native
PHP execution and complete application/hosting migrations were not run.
Local profile tests do not establish Ubuntu guest or native ARM64 qualification.

All eight JSON cases passed consistency checks, including the three supported
PHP minors, reserved domains, classifications and five over-limit metadata
values. The classifications are reviewed planning examples, not an executed
automatic classifier. The local behavior tests use their own synthetic
fixtures; the eight inventory records were not imported into a running panel.

Document link and case/gap/rehearsal cross-reference checks passed before
handoff. At that local checkpoint R0–R5 were unexecuted. The later R0/R1 authorization is recorded above; results will be source-bound in a separate hosted report.
