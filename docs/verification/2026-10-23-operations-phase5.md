# Operations center — phase 5 local evidence

Implemented personal Off/Immediate/Daily digest preferences and an administrator
server email policy, both off by default. Critical/security in-app notices remain
mandatory. Direct API writes cannot disable those categories or change another
user's preferences. SMTP configuration is reported without returning credentials.

Delivery uses scoped user batches and per-event/user deduplication. Digest windows
close at 00:00 UTC; long digests explicitly count additional updates in Activity.
Current ownership, role, account address and preferences are checked before send.
Identity rows stay locked during bounded SMTP transmission. A concurrent transfer
cannot cross that final authorization boundary. Unscoped addresses are excluded.

Each batch has at most eight increasing-delay attempts. Stored failures use safe
codes. Successful transmission is labeled Accepted by SMTP, never Delivered.
A private delivery issue does not generate further email; later SMTP acceptance
resolves only that issue and preserves the original hosting failure.

All current producers use the same policy: quota, login security, maintenance,
PHP, WordPress, server backups and the operation projector. Domain worker failure
notices are correlated with their logical task so the inbox does not add another
copy. The duplicate custom-certificate notification sweep was retired in favor
of the durable certificate detector. Queue completion now respects persisted
terminal domain failures, including commands intentionally not replayed by River.

Evidence:

- PostgreSQL tests cover independent preferences, mandatory inbox state, invalid
  recipient scope, digest dedupe, changed ownership, bounded retries, redaction,
  delivery-failure recursion, correlated notices and SMTP-only recovery.
- A loopback SMTP capture exercised the production sender and recorded acceptance
  for an owned fictional recipient. No external mailbox was contacted.
- The ownership race and source-notice duplication were reproduced RED, fixed,
  and passed. A failed command incorrectly labeled successful was likewise fixed.
- Focused affected Go packages, JavaScript checks and go vet pass. Desktop/mobile
  browser checks verify saved personal mode and server policy survive reload,
  with zero script errors and no mobile horizontal overflow.

The shared local Herd database stalled in filesystem sync. It was not restarted.
Validation moved to a separate disposable loopback PostgreSQL 18 cluster and
private schemas. That fixture disables crash durability; tests assert transaction
behavior, not power-loss durability. No production PostgreSQL setting changed.
The mocked preparation test's local startup budget was widened to tolerate macOS
process scheduling; production/hosted timeouts remain unchanged.

The development schema replaces address-only email receipts without backfill.
Detailed history is retained; the earlier proposed 30/90-day pruning is inactive.
Full-suite and independent-review results are reported in final acceptance.
