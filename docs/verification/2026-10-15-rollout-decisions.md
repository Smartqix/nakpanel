# Rollout Decisions And Limits

These decisions were made while executing the approved plan-sync, mail-import
and DNS-template designs. No existing customer messages or production DNS
records were deleted.

- Destination authentication uses an encrypted, write-only mailbox credential.
  Password hashes cannot authenticate IMAP; using master authentication would
  broaden access. Operators must supply the destination password or app credential.
- The IMAP library is pinned to go-imap/v2 v2.0.0-beta.8 and tested natively.
  Its prerelease status means upgrades require the compatibility tests again.
- A dedicated staging RPC accepts generated upload identities, not browser
  paths. Disposable staging is bounded and removed after completion/cancellation;
  it is not a copy retained for long-term recovery.
- Unsupported metadata and uncertain append outcomes require operator attention
  instead of being dropped or blindly retried. This favors preservation over
  automatic completion and can require manual review.
- Identical source/destination accounts resolving to the same host are rejected
  to prevent self-import loops. A same-server migration needs a distinct mailbox.
- Multipart upload authentication precedes parsing; the handler then checks its
  session-bound CSRF token. This narrowly scoped exception avoids parsing large
  unauthenticated uploads without bypassing mutation protection.
- Detailed import history follows explicit mailbox/subscription deletion;
  persistent audit events remain. Deleted owners cannot retain their detailed
  import ledger through that destructive action.
- Stalwart 0.11.8 remains pinned. Its account cache is disabled to avoid the
  reproduced fresh-login folder visibility defect, at the cost of extra metadata
  reads. This is not a substitute for a separately tested security upgrade.
- DNS deletion tombstones begin with migration 55. Historical hard deletions
  cannot be reconstructed. Only explicit zone reset clears new tombstones.
- Mail and DNS implementation could proceed independently, but deployments were
  gated by their tests and one combined review. Existing production zones were
  never auto-applied as part of that parallel work.
- Reviewed imports verify a snapshot and one catch-up pass, not continuous
  replication. Final source shutdown and MX cutover remain deliberate operator
  actions; arrivals after the final scan are not included automatically.

The independent reviewer did not inspect production or independently rerun the
full database suite. Live acceptance, database regressions and deployment
verification were executed by the implementing agent and documented in the
adjacent reports. Unrelated backend behavior was outside this review.
