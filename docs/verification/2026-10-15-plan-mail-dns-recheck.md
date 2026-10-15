# Two-Pass Plan, Mail And DNS Recheck

Runtime deployed on nakpanel.com: `29.0.0+c06faf6`. Schema remains
`20261015000055`; no migration or Stalwart upgrade was needed.

## Fixes

The first pass reproduced worker paths that acknowledged temporary ledger or
database failures. State lookups, source discovery persistence, error checkpoints
and failed connection-state persistence now return retryable errors. Genuine
pause/cancel supersession remains distinct from database failure. A recovered
copy is never appended again without a provable receipt.

The second pass found abandoned previews retained credentials and staging after
their existing 30-minute start deadline. A bounded, minute-based/startup sweep
now cancels only expired unstarted previews, retires credentials, records an
audit event and queues existing terminal cleanup in one transaction. A failed
enqueue rolls back the cancellation, credential retirement and audit. Running
and paused imports remain resumable.

Both defects had failing regressions before the implementation. The full suite
also caught the missing removal classification for the new sweep; it is now a
shared job that reloads current intent rather than targeting one website.

## Verification

- Full Go suite passed with disposable PostgreSQL fixtures after the fixes.
- Race tests passed for mail import, IMAP transport, quota and DNS packages.
- Vet, all 113 JavaScript tests, shell syntax and diff checks passed.
- `task build` passed using the verified local Go module cache. The initial
  public proxy build failed on DNS resolution, not source compilation.
- Live desktop/mobile checks confirmed WordPress Toolkit enabled with a limit
  of five, correct provider nameservers and readable cutover content.
- Two fresh IMAP imports each copied and verified four selected messages.
- Two fresh Maildir imports each copied and verified three messages.
- Separate native comparisons matched bytes/hashes, multiplicity, folder names,
  dates and flags in both passes.
- Two abandoned Maildir previews expired through the periodic worker. Their
  credentials and staging were removed; neither copied a message.
- Both QA DNS zones again preserved custom MX/SPF/TXT and explicit deletions,
  rejected stale previews and returned correct authoritative A/NS/SOA answers.
  Original production-zone fingerprints remained unchanged.

The four completed QA imports were `imp_405099cfc7192f93d910a35202684b83fcbb6c533fa01a82`,
`imp_e3847a9e6a70685030f7c6cd99c5b894a17e118256f9446b`,
`imp_2c197694432023e8438cf11d0d75974228d1cc2ce4fa0e1c`, and
`imp_6afa18c12249e12145ed220fed261141fc6f0cd130af9d97`.
Existing customer mail and production DNS were not changed. Synthetic QA mail
and DNS resources remain available for inspection.

## Review Notes

The independent pre-merge review found no Critical or Important issues in the
new fixes. It did not independently run production or the full database suite;
those checks were performed by the implementing agent.

Two minor points remain: pausing during a failed connection attempt can cause
one harmless additional River retry, and the expiry-versus-start lock race lacks
a dedicated concurrent regression test. Rollback coverage was strengthened to
check retained credentials and absent expiry audits after enqueue failure.
Neither minor permits a duplicate append or premature completion.
