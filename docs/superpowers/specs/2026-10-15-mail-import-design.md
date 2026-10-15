# Safe Maildir and IMAP Import

Status: proposed for review; not implemented or deployed.

## Intent

Make existing customer mail usable in Nakpanel's Stalwart mailboxes without
silently losing folders, messages, dates, flags, or attachments. This is a
separate component of a future full hosting importer, not a claim that a full
Plesk/cPanel/Hestia importer already exists.

The user approved Maildir and IMAP support, resumability, verification, and
preservation of source data. The live Stalwart version is 0.11.8. Do not upgrade
it or introduce the latest migration utility without a tested compatibility
gate.

## Approach

Use a shared import coordinator with two source adapters and one tested IMAP
target adapter. Reuse a maintained IMAP client library; do not implement an
IMAP parser. Copy messages with APPEND and preserve supported flags and
INTERNALDATE. The target is always an existing, owned, active Nakpanel mailbox
derived by the server, never a browser-supplied target server.

Start with Maildir++ and TLS-protected IMAP. Reject unsupported Maildir layouts
with an actionable error; use IMAP for those sources. Vandelay is an alternative
only after its behavior and licensing, supported layouts, target-version
compatibility, and resumability are verified. Do not depend on mutable releases.

## Scope And Access

- Administration and provider-scoped reseller access initially; no unrestricted
  remote import endpoint for customers.
- Mail domain, subscription, mailbox, and provider checks use central access
  policy. Cross-provider objects return 404.
- No automatic DNS/MX changes, source deletion, destination deletion, mailbox
  renaming, service restart, or whole-server migration.
- Contacts, calendars, Sieve, shared-mailbox ACLs, and password-hash migration
  are explicitly outside the first version.

## Input And Secrets

IMAP input contains a source hostname, permitted TLS port, source mailbox,
and a write-only credential. Verify hostname and TLS chain. Source addresses
must pass an administrator-controlled destination policy, including DNS
re-resolution protections. Private-network sources require explicit
administrator approval; metadata, loopback, and unrelated local services are
not implicitly reachable.

Maildir input is a server-created staging reference to a bounded archive.
Validate extraction against traversal, symlinks, hardlinks, devices, duplicate
paths, entry counts, expanded bytes, and compression bombs. The agent derives
the staging root; the browser never supplies absolute paths. Read cur and new,
not delivery-in-progress tmp files.

Encrypt source and destination credential material using service_secrets.
River arguments contain import IDs and revisions only. Never put credentials
in process arguments, URLs, audit metadata, logs, HTML, or responses. Retire
credentials after completion or cancellation. Limit worker concurrency and
timeouts and redact tool errors.

## Durable Data Model

Add mail_imports, mail_import_folders, and mail_import_messages with provider,
subscription and mailbox FKs, immutable source identity, desired revision,
state, counts, byte totals, cursors, errors, and timestamps.

IMAP message identity includes the source account, folder, UIDVALIDITY and UID.
Maildir identity includes the staged-source manifest and message identity.
Record source content hashes for validation, not Message-ID alone. Identical
legitimate messages must not collapse into one solely because bodies match.

Persist destination UID/UIDVALIDITY and a stable import marker. Reconcile an
uncertain APPEND acknowledgement before retrying; do not blindly append again.
UIDVALIDITY changes trigger rediscovery and explicit reconciliation rather
than reusing stale cursors. No outcome can be marked complete with unknown
message acknowledgements.

## Workflow

1. Select an owned destination mailbox and source type.
2. Preflight source connectivity, destination capabilities, mailbox quota,
   account storage, and mapping.
3. Preview every folder, message count and byte total. Show unsupported flags,
   unreadable messages and estimated space. Include Trash/Junk and flagged
   deleted messages by default for preservation; exclusions require an
   explicit reviewed choice.
4. Queue a revision-fenced job. Show discovered, copied, verified, skipped,
   failed and uncertain counts separately.
5. Support pause, resume, cancellation and retry without deleting copied mail.
6. Run a final catch-up scan and verify the approved scope.
7. Display complete, complete-with-warnings, or attention-required truthfully.
   A mailbox with failed or uncertain copies is never shown as fully migrated.

Preserve folder hierarchy, special-use mappings, read/unread, answered,
flagged, draft and supported custom flags. Report every unsupported mapping.
Source internal dates and message MIME bodies must survive transport subject
only to documented IMAP line-ending normalization.

## Verification And Cutover

Verify target folder counts, import identities, bytes/content where supported,
dates, flags, attachments, and representative messages through actual IMAP
and webmail. Re-run after interruption and prove there are no duplicate
imports. Keep all source data. Show a reviewed MX cutover checklist only after
mail verification; cutover is a separate action.

## UI And Routes

Add a scoped Imports view in domain Mail with a Source -> Mapping -> Review
dialog and a durable import detail URL. Subscription Mail may aggregate links.
Use existing dialogs, CSRF, inline errors, accessible progress and refresh.
Do not add Mail to the service-provider sidebar.

Enumerated agent operations may inspect/read validated staged Maildir data;
no arbitrary paths or shell strings. HTTP routes accept object IDs, source
settings and confirmation only. Provider-scoped status responses contain no
message bodies or secrets.

## Acceptance Gates

- Empty and populated destination mailboxes; nested and non-ASCII folders.
- Sent/Drafts/Trash/Junk, duplicate Message-ID and identical distinct messages.
- Flags, dates, large attachments, oversize/quota failures and malformed input.
- Disconnect before/after APPEND, worker crash, timeout, source mutation,
  UIDVALIDITY change, cancellation and repeat catch-up.
- Cross-tenant denial, TLS verification, SSRF and archive confinement, secret
  absence in job/audit/HTTP/process output.
- Ubuntu 24.04 source fixture plus actual pinned Stalwart target and webmail.
- Two non-destructive live passes use new QA mailboxes/messages only. Existing
  customer mail and MX records are never changed by tests.

## References

- https://stalw.art/docs/migration/import-export/import/maildir/
- https://stalw.art/docs/migration/import-export/import/imap/
- https://stalw.art/docs/migration/guide/migrate-accounts/

