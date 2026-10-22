# Subdomain mail — Phase 4 hosted verification

**Status: incomplete. The mirror repair passed hosted installation; the single
additional run failed during initial message-canary setup.** No complete hosted
mail acceptance gate passed. The additional authorization is exhausted. Stop
before PR, merge or deployment. Main remains `d992462`.

## Results

| Attempt | Tested source | Outcome | Owned cleanup |
| --- | --- | --- | --- |
| [Initial](https://github.com/Smartqix/nakpanel/actions/runs/39781138752) | `0e53e46` | HTTP 400 creating a subdomain; no mail gates reached | 1 record, exit 0 |
| [Repair 1](https://github.com/Smartqix/nakpanel/actions/runs/39785595967) | `6c2c2ab` | Multipass initialization timeout before installation | 0 established records, exit 0 |
| [Repair 2](https://github.com/Smartqix/nakpanel/actions/runs/39788828299) | `8f41eea` | Installation stopped on an Ubuntu mirror index mismatch, exit 100 | 1 record, exit 0 |
| [Authorized mirror rerun](https://github.com/Smartqix/nakpanel/actions/runs/39798543643) | `2de7b5f` | Signed install and all PHP runtimes passed; initial message-canary setup failed before child-mail mutation | 1 record, exit 0 |

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
tests source `2de7b5fe6b82b33ee745edf53e8bdb2e4a7cff52`. No second additional
run is authorized.

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

## Additional hosted result and remaining blocker

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

The result has zero completed mail gates. Browser child CRUD, alias delivery,
Roundcube, quota/isolation, suspension/reactivation and child removal therefore
remain unverified. Cleanup removed the one proven-owned disposable guest with
exit 0. Production and existing local VMs/databases were untouched. No PR,
merge or deployment occurred.

## Previous mirror blocker

The final installation failed fetching
`resolute-updates/main/i18n/Translation-en.xz` from `archive.ubuntu.com`.
APT reported HTTP 404 and an index size mismatch: **175984 bytes received,
176456 expected**, with a signed Release timestamp of
`2026-10-22 13:48:55 UTC`. It reported a mirror synchronization issue and
exited 100. This was a package-index failure before mail fixtures, not a
measured mailbox or subdomain failure. No signature/hash check was bypassed.
The sanitized original diagnostic remains with the run artifacts.

## Outstanding acceptance

All of the following remain unverified on the current hosted feature branch:

- Child browser mailbox/alias CRUD, rotated-password denial, SMTP TLS/STARTTLS,
  local alias delivery and IMAP retrieval.
- Child Roundcube login, compose, delivery and rendered-message read.
- Shared mailbox/alias allowances, finite storage caps and forbidden tenant
  read/write requests under actual runtime conditions.
- Disable/re-enable and subscription suspension/reactivation with actual
  parent/sibling/child message UID and byte canaries.
- Confirmed child removal, denied child login and preserved parent/sibling
  accounts, aliases, DNS and messages.

The one additionally authorized, bounded run has finished. No further hosted
run is authorized. Do not open a PR, merge or deploy based on these
results. Unchanged restore/reboot, PHP maintenance, historical compatibility
and full platform checks were not repeated. No external-inbox or public DNS
acceptance is claimed. SMTP/IMAP require trusted TLS in the selected probes;
the browser uses an explicit private-lab certificate override, and Roundcube
uses its internal HTTP vhost, not public HTTPS acceptance.

## Protection and cleanup

No production server, existing local VM or unrelated PostgreSQL instance was
used. Initial and final guests with established ownership were removed, each
with a one-record/exit-zero receipt. The initialization-timeout attempt had no
ownership record; the cleanup helper made no explicit deletion claim for it.
That disposable GitHub job ended. Mail acceptance fixtures never completed, so
no hosted message-preservation result is claimed. Credentials/private command
logs were excluded from uploaded artifacts. Feature refs were published solely
for authorized hosted execution; main, PRs and production deployment were left
untouched.
