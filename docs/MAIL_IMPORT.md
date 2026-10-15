# Mail Import

Administrators and owning resellers can open **Mail -> Import mail** on a
domain. The destination mailbox must already exist and its subscription must
permit mail. Customers cannot run imports themselves.

Choose an IMAP source or upload a Maildir/Maildir++ tar archive. Supply the
destination mailbox password and, for IMAP, the source hostname, login and
password. These credentials are write-only and encrypted while the import
needs them. IMAP uses verified implicit TLS on port 993; there is no option to
disable certificate validation. Private source networks require an operator
allowlist in `NAKPANEL_MAIL_IMPORT_ALLOWED_CIDRS`.

Review each folder and destination name before starting. Explicitly unchecked
folders are excluded and counted separately. Existing destination messages are
not removed. Distinct source messages remain distinct even when their bytes
and Message-ID are identical.

Imports preserve message bytes, attachments, internal dates and supported
flags. Selected destination folders are subscribed so they appear in webmail.
The worker verifies receipts and message content through a fresh connection
before declaring completion. Unsupported metadata, changed source identities,
quota failures and uncertain append acknowledgements require attention rather
than a silent skip or blind append retry.

Pause and resume use the same import record. If an acknowledgement is lost,
retain that record: starting another import does not share its deduplication
receipts. Cancel stops future copying but keeps already copied messages. A
completed import does not continue watching the old server; arrange a final
cutover window and review the reported counts before retiring it.

## Bounds And Recovery

- At most 100,000 source messages and 1,000 folders per import.
- Messages are limited to 64 MiB.
- Maildir upload: 128 MiB compressed, 1 GiB expanded; links, devices, traversal
  and unsupported layouts are rejected.
- Uploaded archives are staged privately by the agent. Successful/cancelled
  imports remove disposable staging and encrypted credentials, not source mail.
- Explicit mailbox or subscription deletion also removes its detailed import
  ledger. Audit events remain.

Stalwart remains pinned to 0.11.8 for this feature. Its account cache is disabled
in Nakpanel-generated configuration because native tests exposed stale folder
visibility after CREATE/APPEND. This does not replace a separately planned
Stalwart security/version upgrade.

See [transport verification](verification/2026-10-15-mail-transport.md).
