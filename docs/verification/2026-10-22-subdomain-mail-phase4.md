# Subdomain mail — Phase 4 hosted verification

**Status: PASS — all five focused hosted acceptance groups passed.** The
single authorized child-removal rerun completed on source `e856cb1`. Reviewed
child removal, denied child login and final parent/sibling preservation passed.
The owned guest was removed successfully. Stop before PR, merge or deployment;
main remains `d992462`.

## Results

| Attempt | Tested source | Outcome | Owned guest cleanup |
| --- | --- | --- | --- |
| [Initial](https://github.com/Smartqix/nakpanel/actions/runs/39781138752) | `0e53e46` | HTTP 400 creating a subdomain; no mail gates reached | 1 record, exit 0 |
| [Repair 1](https://github.com/Smartqix/nakpanel/actions/runs/39785595967) | `6c2c2ab` | Multipass initialization timeout before installation | 0 established records, exit 0 |
| [Repair 2](https://github.com/Smartqix/nakpanel/actions/runs/39788828299) | `8f41eea` | Installation stopped on an Ubuntu mirror index mismatch, exit 100 | 1 record, exit 0 |
| [Authorized mirror rerun](https://github.com/Smartqix/nakpanel/actions/runs/39798543643) | `2de7b5f` | Signed install and all PHP runtimes passed; initial message-canary setup failed before child-mail mutation | 1 record, exit 0 |
| [Authorized IMAP rerun](https://github.com/Smartqix/nakpanel/actions/runs/39806681641) | `8abe280` | IMAP repair and four acceptance groups passed; reviewed child removal failed | 1 record, exit 0 |
| [Authorized child-removal rerun](https://github.com/Smartqix/nakpanel/actions/runs/39815224111) | `e856cb1` | All five acceptance groups, final child removal/preservation and PHP readiness passed | 1 record, exit 0 |

Full commits, signed-development artifact/archive/key/manifest hashes, pinned
image identity, original result fields and cleanup receipts are preserved in
[the evidence index](2026-10-22-subdomain-mail-phase4.json). All five earlier
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
and Roundcube probes. Earlier Phase 4 repairs changed only the harness; the
child-removal continuation also corrects pinned Stalwart principal-response
decoding in the mail agent, as described below.

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
  the later IMAP rerun passed fixture setup and reached child removal.
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

## IMAP probe repair and historical rerun

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

## IMAP-rerun results and subsequent blocker

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

That attempt left child removal and its downstream preservation checks
unverified. The separately authorized child-removal rerun below resolves this
blocker; the failed original result remains unchanged.

Always-run infrastructure cleanup separately removed the one proven-owned
disposable guest with exit 0. This VM cleanup is not a passing child-removal
gate. Production, existing local VMs and databases were untouched. The tracked
report/evidence update after the run changes documentation only.

## Child-removal diagnosis and one authorized rerun

The user authorized capturing/diagnosing/fixing the child-removal failure and
exactly one further focused hosted run. Source `e856cb1d2e0e0cac4e7b7654e65fcd7610cda205`
passed in [39815224111](https://github.com/Smartqix/nakpanel/actions/runs/39815224111).
No second dispatch is authorized. The previous guest was already deleted and
its precise agent error cannot be recovered from its retained generic failure.

A local component reproduction used the official Stalwart 0.11.8 Darwin ARM64
binary, verified against its GitHub release attestation, and an isolated
current-schema SQL directory. Real IMAP authentication succeeded. The exact
principal sequence returned GET HTTP 200 with the individual, DELETE HTTP 200
with `data:null`, then GET HTTP 200 with `error:"notFound"` and no data member.
The agent expected HTTP 404 and reported `mailbox principal removal has not
converged`. This proves a defect in the pinned-provider integration; it does
not recover the deleted guest's exact original error. The [pinned management
API source](https://github.com/stalwartlabs/stalwart/blob/v0.11.8/crates/jmap/src/api/management/mod.rs)
and [principal handler](https://github.com/stalwartlabs/stalwart/blob/v0.11.8/crates/jmap/src/api/management/principal.rs)
match the observed response. This Darwin component probe is local proof,
not Ubuntu server acceptance. Its temporary server and owned PostgreSQL were
stopped before dispatch; no existing local VM or populated database was used.

The agent now recognizes only the explicit `notFound` error without a data
member as absence. Authorization errors, malformed JSON and contradictory
principal/error envelopes fail closed. Pinned-version, exact principal name
and individual type, loopback endpoint, redirect refusal and response-size
controls remain enforced. The actual API regression failed before the fix
and passed afterward. Staged agent teardown and full control-worker/shared
convergence/finalization fixtures preserve parent, sibling and foreign
resources while deleting only the reviewed child scope.

The harness now writes a bounded, redacted `child-removal.json` receipt before
processing success, failure or timeout, retaining operation identity, state,
stage, safe public message and checkpoints. It omits HTML and request bodies;
nullable initial checkpoints are supported. Final child-denial, zero remaining
child mail-domain rows and exact parent/sibling resource/message checks remain
required. The public API message is intentionally generic; this receipt does
not claim to retain an unavailable raw agent exception.

Local verification passed 28 distinct focused Go test functions without skips,
including real-database removal execution and current subdomain mail cases.
After the last harness-only correction, all six Go harness functions and all
11 Python harness cases passed again. The five unchanged protocol cases pass
through those checks. Vet for the three affected packages, Python syntax,
formatting and diff checks passed. A fresh review found no Critical, Important
or Minor findings and independently passed 11 Python cases and four focused
agent functions. Broader unchanged restore, reboot and PHP maintenance checks
were excluded; no acceptance for those paths is added by this focused run.

## Final hosted result

[Run 39815224111](https://github.com/Smartqix/nakpanel/actions/runs/39815224111)
completed successfully at `2026-10-22T16:56:41Z`, testing exact source
`e856cb1d2e0e0cac4e7b7654e65fcd7610cda205`. Fresh signed installation,
Ubuntu `26.04:resolute` identity and final installed-artifact identity passed.
PHP 8.3.36, 8.4.27 and 8.5.12 were present, with all three FPM services active
both before and after mail acceptance. The signed archive, key, manifest,
pinned image and receipt hashes are retained in the evidence index.

All five gate groups passed: child browser/protocol CRUD and alias delivery;
Roundcube; shared quotas and foreign-resource isolation; disable/suspension/
reactivation with exact message UID/byte preservation; and reviewed child
removal with final parent/sibling resource and message preservation.

Removal operation 1 reached state/stage `completed`. Its retained receipt
contains both child mailbox-removal checkpoints, surviving-mail/access checks,
shared reconciliation, parent-DNS handling and finalization. The child login
was denied and no child mail-domain row remained. Parent/sibling mailbox,
alias and DNS rows matched the immediate pre-removal baseline exactly;
parent/sibling/control message UIDs and byte digests matched the original
message canaries. The original/final aggregate row fingerprints differ across
whole-subscription reactivation because that authorized action reconciles DNS
row identities; the lifecycle check compares restored DNS intent semantically,
and each child-only operation checks its own exact row baseline. This is not a
claim that all row identities stayed constant across owner reactivation.

Child mail disable/re-enable preserved its message before permanent removal.
The confirmed removal intentionally deletes only the reviewed child scope.
No mailbox storage or provider package configuration changed in the fix.
Always-run infrastructure cleanup separately removed one proven-owned guest,
exit 0. The full workflow succeeded. Exactly one new run was dispatched under
this authorization; no retry followed it. Local test services are stopped,
production and existing local VMs/databases remain untouched, and Phase 5 has
not started.

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

Phase 4 is complete for the five focused groups on tested source `e856cb1`.
No PR, merge, deployment or further hosted run was performed. Unchanged
restore/reboot, PHP-maintenance, historical compatibility and full platform
checks were not repeated. No external-inbox or public-DNS acceptance is claimed.
SMTP/IMAP use trusted TLS in the selected probes; the browser uses an explicit
private-lab certificate override, and Roundcube uses its internal HTTP vhost.
The pinned API defect is reproduced locally and its fixed path passes hosted
verification; the deleted previous guest's exact agent error remains unavailable.
