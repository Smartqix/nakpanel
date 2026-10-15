# Safe Mail Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking. Native execution is the selected project preference; no implementation is authorized until this written plan is reviewed.

**Goal:** Import Maildir++ and TLS IMAP messages into owned Stalwart mailboxes with durable verification and no silent loss or duplicate retries.

**Architecture:** A control-plane coordinator stores immutable source identity, encrypted credential references, folder mappings and per-message receipts. Source adapters and a maintained IMAP target adapter run through revision-fenced jobs. Agent operations expose only staged Maildir identities.

**Tech Stack:** Go, PostgreSQL/goose, River, existing service_secrets, maintained IMAP client library, templ, embedded JavaScript, Ubuntu 24.04, deployed Stalwart 0.11.8.

**Spec:** docs/superpowers/specs/2026-10-15-mail-import-design.md

## Global Constraints

- Additive destination writes only. Never delete source or destination mail.
- No automatic MX, nameserver, authentication, or Stalwart-version changes.
- Secret values never enter River arguments, URLs, logs, audits or responses.
- Default includes all folders and flagged deleted messages; exclusions require review.
- Cross-provider access returns 404; initial operations are admin/provider only.
- Uncertain APPEND receipts block completion and require reconciliation.
- No new agent operation accepts browser-selected absolute paths.
- Migration number 20261015000054 is proposed; recheck repository head before creating it.

## Review Focus

- Lost APPEND acknowledgement must not duplicate an identical legitimate message.
- UIDVALIDITY changes must not reuse a previous source cursor.
- Malicious archive links/expansion must never escape staging or exhaust disk.
- Source changes during import must not invalidate a successful verification claim.
- Quota, unsupported flags or failed messages must not be hidden by a green total.

## File Structure

- internal/types/mail_import.go: requests, state and progress contracts.
- migrations/20261015000054_mail_import.sql: jobs, mappings and receipts.
- internal/control/mailimport/{manager,store,worker,verify}.go: policy, durable intent, transitions and verification.
- internal/mailimport/{imap,maildir,messages}.go: protocol adapters and canonical identities.
- internal/agent/ops/mail_import.go: bounded staged-Maildir access.
- internal/control/http/mail_import.go: scoped CSRF routes.
- internal/control/web/mail_import.templ and static/mail-import.js: intake and progress.
- deploy/multipass/mail-import-verify.sh: native source/target acceptance.

### Task 1: Durable Import Contract And Ownership

**Interfaces:** Produce Manager.Preview(ctx, actor, types.MailImportRequest) (types.MailImportPreview, error), Manager.Start(ctx, actor, previewID) (types.MailImport, error), and Manager.Status(ctx, actor, importID) (types.MailImport, error). Requests reference destination mailbox IDs and secret refs, not target URLs.

- [ ] Write TestImportRejectsForeignMailbox, TestInactiveMailboxCreatesNoIntent, TestImportCredentialsNeverSerialize and migration round-trip tests. Assert no job/intent after denial.
- [ ] Run go test ./internal/control/mailimport ./migrations -run MailImport -count=1. Expected: tests fail because import contract is absent.
- [ ] Add normalized tables with source identity, desired/applied revision, counters and per-message uniqueness. Apply existing ownership and secret helpers; audit only object IDs.
- [ ] Re-run the tests. Expected: PASS including rollback on enqueue failure.
- [ ] Commit the contract and tests.

### Task 2: Verified IMAP Transport

**Interfaces:** Produce Source.Discover(ctx) ([]Folder, error), Source.Read(ctx, MessageIdentity) (Message, error), Target.Append(ctx, Message, ReceiptToken) (Receipt, error), and Target.FindReceipt(ctx, ReceiptToken) ([]Receipt, error). Source identity includes folder, UIDVALIDITY and UID.

- [ ] Select and pin a maintained IMAP library after checking its upstream API/license. Add TestIMAPTLSRequired, TestWrongCertificateRejected, TestAppendReplyLost, TestDistinctIdenticalMessages, TestUIDValidityChange and TestPreservesDatesFlagsAndBytes.
- [ ] Run go test ./internal/mailimport -count=1. Expected: failing behavior before adapters.
- [ ] Implement capability negotiation, TLS, bounded connections and source-address policy. Verify persistent keywords/UIDPLUS support on actual Stalwart 0.11.8. If a receipt cannot be proven, leave attention_required rather than repeat an uncertain APPEND.
- [ ] Run unit tests and a native Stalwart fixture. Expected: exact source identities retained; repeated imports create zero unintended copies.
- [ ] Commit transport and version compatibility evidence.

### Task 3: Confined Maildir Source

**Interfaces:** Produce MaildirSource using a server-issued staging ID and immutable manifest. Agent OpInspectMaildir and OpReadMaildirMessage accept IDs plus bounded cursors only.

- [ ] Write TestMaildirHierarchy, TestMaildirFlags, TestIgnoresTmp, TestUnsupportedLayout, TestArchiveTraversalAndLinks, TestExpansionLimit and TestChangedSourceManifest.
- [ ] Run go test ./internal/mailimport ./internal/agent/ops -run Maildir -count=1. Expected: FAIL before implementation.
- [ ] Safely extract into agent-derived staging, reject hardlinks/devices/symlinks, and read cur/new. Preserve Maildir++ hierarchy and message bytes. Report rather than silently skip invalid files.
- [ ] Re-run tests and fuzz bounded path/manifest parsing. Expected: no read/write outside staging.
- [ ] Commit confined source adapter.

### Task 4: Resumable Copy And Verification

**Interfaces:** Produce ImportWorker with River arguments {import_id, revision}; manager Pause, Resume and Cancel operations; verified counts never exceed durable receipts.

- [ ] Write TestCrashBeforeReceipt, TestCrashAfterAppend, TestPauseResume, TestSourceCatchup, TestQuotaFailure, TestUnsupportedFlagWarning and TestUnknownReceiptCannotComplete.
- [ ] Run go test ./internal/control/mailimport -count=1. Expected: FAIL before transitions.
- [ ] Implement revision fencing, receipt reconciliation, checkpoints and additive destination writes. Distinguish discovery/copy/verification. Lock one active job per mailbox; recheck ownership/lifecycle before writes.
- [ ] Re-run fault tests and race tests. Expected: completion only when every approved message is verified or an explicit reviewed exclusion applies.
- [ ] Commit worker and verification.

### Task 5: Domain Mail Import Workspace

**Interfaces:** Add scoped preview/start/status/pause/resume/cancel routes under /sites/{id}/mail-imports. Reuse domain Mail navigation and support-view identity.

- [ ] Write handler tests for every role, CSRF, cross-tenant 404, write-only credentials and ambiguous-retry messages.
- [ ] Write render/JavaScript tests for Source -> Mapping -> Review, accessible errors, progress and mobile layout.
- [ ] Implement dialogs and durable detail URLs without adding provider sidebar Mail. Never render message bodies in status JSON.
- [ ] Run handler/UI tests and browser QA at 1440x1000 and 390x844. Expected: preserved input, focus restoration and no horizontal overflow.
- [ ] Commit workspace.

### Task 6: Native And Live Acceptance

- [ ] Add native fixtures covering actual source Maildir and IMAP to pinned Stalwart, including repeated identical messages, non-ASCII folders, dates, flags and attachments.
- [ ] Run go test ./... -count=1 with disposable PostgreSQL, go vet ./..., task build, JavaScript tests, git diff --check and shell syntax checks.
- [ ] Run native mail-import-verify.sh with interruptions and a second catch-up. Expected: all approved messages verifiably available through IMAP and webmail, zero unintended duplicates.
- [ ] Deploy matching panel/agent binaries without upgrading Stalwart. Use two new isolated live QA mailboxes; preserve existing mail/MX. Test both source types, quotas, resumed copies and actual message opening.
- [ ] Record exact IDs, counts, hashes where meaningful, gaps and cleanup disposition. Commit factual verification. Do not claim source-data or protocol checks that were not performed.

