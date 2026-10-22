# Subdomain mail — Phase 4 hosted verification

**Status: incomplete. The IMAP probe repair passed hosted verification; four
of five focused acceptance groups passed. The final reviewed child-removal
gate failed.** The single authorized rerun has finished, with no further run
authorized. Stop before PR, merge or deployment. Main remains `d992462`.

## Results

| Attempt | Tested source | Outcome | Owned guest cleanup |
| --- | --- | --- | --- |
| [Initial](https://github.com/Smartqix/nakpanel/actions/runs/39781138752) | `0e53e46` | HTTP 400 creating a subdomain; no mail gates reached | 1 record, exit 0 |
| [Repair 1](https://github.com/Smartqix/nakpanel/actions/runs/39785595967) | `6c2c2ab` | Multipass initialization timeout before installation | 0 established records, exit 0 |
| [Repair 2](https://github.com/Smartqix/nakpanel/actions/runs/39788828299) | `8f41eea` | Installation stopped on an Ubuntu mirror index mismatch, exit 100 | 1 record, exit 0 |
| [Authorized mirror rerun](https://github.com/Smartqix/nakpanel/actions/runs/39798543643) | `2de7b5f` | Signed install and all PHP runtimes passed; initial message-canary setup failed before child-mail mutation | 1 record, exit 0 |
| [Authorized IMAP rerun](https://github.com/Smartqix/nakpanel/actions/runs/39806681641) | `8abe280` | IMAP repair and four acceptance groups passed; reviewed child removal failed | 1 record, exit 0 |

Full commits, signed-development artifact/archive/key/manifest hashes, pinned
image identity, original result fields and cleanup receipts are preserved in
[the evidence index](2026-10-22-subdomain-mail-phase4.json). All three original
failed outcomes remain failed.

Every run selected the existing manual workflow's `subdomain_mail_only` input.
Only its signed AMD64 build and focused mail job ran. The full qualification,
backup/restore, diagnostics and PHP maintenance jobs were excluded. Each
acceptance step had a 45-minute limit, bounded mail gates and ownership-checked
cleanup. The GitHub controller uses Ubuntu 24.04; the selected server guest is
the signed pinned Ubuntu 26.04 Resolute image, serial `20260927`, SHA256
`8800651811af9a85465ad1d552add729947bb16488dddb4a9b5305a3d97332b2`.
This does not reintroduce Ubuntu 24.04 server support.

The initial source actually verified `ubuntu:26.04:resolute`, PHP 8.3.36,
8.4.27 and 8.5.12, and all three FPM services before the fixture failure.
Those observations belong to `0e53e46`; they are not backfilled onto later
attempts. Later installation failure does not establish application readiness.
Hosting PHP 8.3/8.4/8.5 and internal PHP 8.5 requirements remain unchanged.

## Fixes and local proof

The test harness reuses the signed installer, existing Mail browser/protocol
and Roundcube probes. No mail product implementation changed in Phase 4.

- One independent review found that preservation canaries were captured too
  late and exhausted quotas could mask forbidden writes. Modeled corrupting
  transports reproduced both failures before fixes. Canaries now precede child
  mail mutations, and foreign probes run with spare shared capacity and compare
  mailbox resources. Child cleanup also requires denied login and no remaining
  child mail-domain row. No second review was run.
- Source investigation reproduced a fixture race: changing alias policy marks
  the parent website `activating`, but Add Subdomain requires `active`. The
  harness now waits for parent readiness and for hosting reactivation before
  removal. Sanitized JSON error details are retained. The initial HTTP response
  body was unavailable, so its exact server-side cause remains unattributed;
  the readiness correction has not passed hosted revalidation.
- The focused job now explicitly allows at most 600 seconds for initialization
  and retains verbose/bounded VM and daemon diagnostics. Unset configuration
  preserves existing launch arguments. Invalid budgets reject before launch,
  and a failed launch never creates an ownership claim. This is not a claim
  that the unexplained initialization delay was diagnosed. The final run did
  initialize a guest and reached installation. The [Canonical launch reference](https://canonical.com/multipass/docs/latest/reference/command-line-interface/launch/)
  documents the default five-minute startup/initialization limit and timeout
  option.

Seven Python cases and seven focused Go test functions passed across the
affected local slices, with no failures or skips. They include modeled
preservation/ownership failures, parent readiness, safe HTTP error evidence,
bounded launch options, pinned-image/actual-OS refusal and stale evidence
refusal. Vet, workflow lint, Python/shell syntax and diff checks passed. These
are harness checks; they do not replace hosted mail acceptance.

## Mirror repair and additional authorization

The user authorized one additional run after the original budget was exhausted.
[Run 39798543643](https://github.com/Smartqix/nakpanel/actions/runs/39798543643)
tests source `2de7b5fe6b82b33ee745edf53e8bdb2e4a7cff52`. No second run was dispatched under that mirror-repair authorization.

The disposable guest installer uses a temporary private `APT_CONFIG` with
`Acquire::Languages "none";` to skip optional package-description translations,
as documented in [Ubuntu Resolute apt.conf(5)](https://manpages.ubuntu.com/manpages/resolute/man5/apt.conf.5.html).
The setting reaches installer subprocesses, is removed after success or failure,
and does not change system APT configuration, package sources, signed metadata,
package hashes or error propagation. Other qualification runs retain their
existing behavior. This avoids the specific optional index that failed; it is
not a repair of Ubuntu's mirror or a guarantee against other repository errors.

Ten focused Go test functions and eight Python cases passed, with no failures
or skips, plus vet, workflow lint, shell/Python syntax and diff checks. New
coverage executes temporary-policy permission/cleanup/exit-status behavior,
rejects non-hosted use before guest operations, and checks mail-drill opt-in
without altering the parent environment. One fresh review of this narrow repair
found no issues. No product mail code changed.

## Mirror-rerun result (historical)

Run `39798543643` completed with failure. Signed installation finished in about
nine minutes, without the previous translation-index error. The run observed
`ubuntu:26.04:resolute`, PHP 8.3.36, 8.4.27 and 8.5.12, and active FPM services
for all three runtimes. These observations belong to source `2de7b5f`.

Parent, child, sibling and foreign-tenant website setup completed. Parent,
sibling and foreign mail-domain/account fixtures converged. During the initial
`seed` protocol probe, TLS IMAP login and authenticated SMTP submission returned
success, but the exact Message-ID was not found in INBOX within 90 seconds.
`subdomain-mail-protocol.py` raised `AssertionError: preserved message missing`
at line 32, called from `subdomain-mail-verify.py:176`.

This happened **before** the child mail domain was enabled and before the
parent/sibling preservation baseline was captured. It is a failed initial
canary seed, not evidence that child changes deleted an existing message.
The retained evidence does not identify whether delivery, filtering, indexing
or the probe caused the missing search result. No cause is asserted without
server queue/delivery logs and mailbox-folder evidence. Such diagnostics would
be the next narrowly scoped investigation if authorized; no new hosted run was
launched.

That source had zero completed mail gates. Browser child CRUD, alias delivery,
Roundcube, quota/isolation, suspension/reactivation and child removal were
unverified at that point; current-source results are recorded below. Cleanup removed the one proven-owned disposable guest with
exit 0. Production and existing local VMs/databases were untouched. No PR,
merge or deployment occurred.

## IMAP probe repair and current rerun

The user authorized diagnosing/fixing the missing initial message and exactly
one further focused run, [39806681641](https://github.com/Smartqix/nakpanel/actions/runs/39806681641),
source `8abe2800edd3d06e687c814e11861f47e0dac735`. This run completed with four passing groups and a final child-removal failure;
no second run is authorized under this continuation.

The pinned Stalwart0.11.8 source establishes a probe defect: [IMAP header search](https://github.com/stalwartlabs/stalwart/blob/v0.11.8/crates/imap/src/op/search.rs)
passes Message-ID search text into a literal keyword lookup, while [email indexing](https://github.com/stalwartlabs/stalwart/blob/v0.11.8/crates/email/src/index.rs)
uses the parsed identifier. Its locked [mail-parser0.10.2 parser](https://docs.rs/crate/mail-parser/0.10.2/source/src/parsers/fields/id.rs)
removes angle brackets. The old probe searched for `<id@host>`, which cannot
match the stored `id@host` keyword. The parser archive SHA256 was verified
against Stalwart's Cargo.lock before source inspection.

The fix normalizes only the lookup value, retaining the full wire Message-ID
and checking that the fetched message has exactly one matching Message-ID.
UID and message-byte SHA256 remain the unchanged preservation oracle.
Verification never resends or resets a failed baseline. INBOX selection is
read-only and body reads use `BODY.PEEK[]`. A missing-message timeout records
only account index, mode, INBOX message count and search status, with no
credentials or message body.

Five new tests execute the actual probe CLI against a model of the pinned
keyword behavior. They failed before the repair and passed after it, including
changed UID/bytes, wrong or duplicate Message-ID, no resubmission during
verification, read-only reads and bounded nonsecret timeout context. Six
focused Go tests, covering thirteen Python cases, passed without skips, plus
vet, Python syntax and diff checks. One fresh narrow review found no issues.
No product mail or mailbox-store code changed. The current rerun verified delivery with exact canaries. Delivery in the prior
failed attempt remains unknown; it is not backfilled from the new result.

## Current hosted results and remaining work

Run `39806681641` completed on source `8abe2800edd3d06e687c814e11861f47e0dac735`.
It observed Ubuntu `26.04:resolute`, PHP 8.3.36, 8.4.27 and 8.5.12, and all
three active FPM services. Fresh signed installation passed again. The initial
IMAP seed succeeded; all four parent/sibling/control/child Message-ID, UID and
byte-digest canaries are retained in the evidence index.

| Focused gate group | Result |
| --- | --- |
| Child browser CRUD, rotated-password denial, SMTP TLS/STARTTLS, local alias delivery and IMAP retrieval | PASS |
| Child Roundcube login, compose, local delivery and rendered-message read | PASS |
| Shared mailbox/alias counts, finite storage cap and forbidden foreign read/write | PASS |
| Child disable/re-enable and subscription suspension/reactivation; actual message and parent/sibling resource preservation | PASS |
| Reviewed child removal, denied child login and final parent/sibling preservation | FAIL / downstream checks not reached |

The final stage started at `2026-10-22T15:59:33Z` and failed approximately five
seconds later with `reviewed child cleanup did not complete`. The status-poll
failure path can reject an operation in `failed` state or an expired 360-second
budget; the observed short interval indicates the operation-failure path.
The retained evidence does not include its detailed removal state, stage or
server error. Do not attribute a specific deletion bug without those details.

**Outstanding:** diagnose the reviewed child-removal operation, capture its
state/stage/error, and verify completion, child authentication denial and exact
parent/sibling account/alias/DNS/message preservation afterward. The successful
lifecycle canary checks establish preservation before this removal attempt;
post-removal preservation was not reached and remains unverified. No further
hosted run was launched under this authorization.

Always-run infrastructure cleanup separately removed the one proven-owned
disposable guest with exit 0. This VM cleanup is not a passing child-removal
gate. Production, existing local VMs and databases were untouched. The tracked
report/evidence update after the run changes documentation only.

## Previous mirror blocker

The final installation failed fetching
`resolute-updates/main/i18n/Translation-en.xz` from `archive.ubuntu.com`.
APT reported HTTP 404 and an index size mismatch: **175984 bytes received,
176456 expected**, with a signed Release timestamp of
`2026-10-22 13:48:55 UTC`. It reported a mirror synchronization issue and
exited 100. This was a package-index failure before mail fixtures, not a
measured mailbox or subdomain failure. No signature/hash check was bypassed.
The sanitized original diagnostic remains with the run artifacts.

## Acceptance boundary

Four current-source acceptance groups passed as listed above. Phase 4 remains
incomplete until reviewed child removal and its final preservation checks pass.
The single additionally authorized IMAP-repair run is consumed. No PR, merge,
deployment or further hosted run was performed. Unchanged restore/reboot,
PHP-maintenance, historical compatibility and full platform checks were not
repeated. No external-inbox or public-DNS acceptance is claimed. SMTP/IMAP use
trusted TLS in the selected probes; the browser uses an explicit private-lab
certificate override, and Roundcube uses its internal HTTP vhost.
