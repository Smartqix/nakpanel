# Synthetic Plesk migration rehearsals R0 and R1

Status: hosted execution in progress. No acceptance verdict yet.

Only R0 and R1 are authorized. The selected dummy customers are S01
(`harbor-cafe.test`, PHP 8.3), S02 (`atlas-studio.test`, PHP 8.4) and S03
(`meadow-blog.test`, PHP 8.5). The guest target is Ubuntu 26.04 AMD64 with
the existing signed Resolute Surý provider and all three hosting runtimes.

## Source and limits

The source is a private synthetic file and logical MariaDB export fixture
inside the owned disposable guest. No installed Plesk source or real customer
server is contacted. Results cannot establish extraction from Plesk or
compatibility with an unexamined customer estate.

R1 includes application workflows, data/permission preservation, tenant
boundaries, three local backups and reboot persistence. S03 uses one local
SMTP/IMAP canary. Full mail import and final catch-up (R3), public DNS/TLS
transition (R4), and fresh-host restore/write-aware rollback (R5) are excluded.
R2, native ARM64 and external mail deliverability are also unexecuted.

## Candidate and local checks

- Candidate: `6c9759be264fd30314404b7504cda2ddb629a5db`.
- [Focused hosted run 40449279762](https://github.com/Smartqix/nakpanel/actions/runs/40449279762).
- Full local `deploy/multipass` Go package tests passed (157.795 seconds).
- The affected workflow/installer selector passed after the private
  bootstrap-file change. Eleven Python harness tests, both Python syntax checks,
  shell syntax and `git diff --check` passed.
- The fresh harness review found six preservation/readiness/policy defects;
  these were fixed before dispatch: Stalwart file interpolation, actual SFTP
  symbolic-link creation, exact ordered SQL content comparison, private
  operator bootstrap credentials, directory metadata and observational boot
  readiness polling. No minor findings were deferred.

## Hosted results

Run 40449279762 failed in R1 subscription provisioning. R0 passed with actual
PHP 8.3.36, 8.4.27 and 8.5.12 plus required CLI/FPM extensions. The fixture
certificate helper supplied a full chain where `panelctl ssl set-custom --cert`
requires exactly one leaf certificate. No application data had been imported.

The helper now produces a single leaf for that CLI. A new local regression
creates a real fixture certificate, checks the single-certificate contract and
validates the hostname/signature against its CA. It was observed failing before
the fix and passing afterward (11 Python tests total).

[Original failed-run evidence](evidence/2026-10-27-plesk-r0-r1/40449279762/result.json)
is retained unchanged. Owned guest deletion and firewall removal passed. A
corrected focused run followed; the failed run remains failed.

Run 40450784211 confirmed trusted site TLS and all three separate customer,
subscription, database and SFTP identities, then failed deleting the uploaded
S01 archive after successful extraction. The HTTP delete handler read
`r.Form["paths"]` before parsing a header-authenticated form, so the agent
received an empty selection. A local HTTP regression reproduced the missing
paths; the handler now explicitly parses the form and rejects malformed input
before calling the agent. Copy/move path regression cases also passed.

[Second failed-run evidence](evidence/2026-10-27-plesk-r0-r1/40450784211/result.json)
is retained unchanged. Guest/firewall cleanup passed. Focused HTTP, file-manager,
agent file operations and workflow-selection checks passed after the fix.
The harness also waits for mail-domain convergence after mailbox/alias changes
and captures bounded, redacted diagnostics from only the verified owned guest
on any later failure. A further corrected R0/R1-only run followed.

Run 40452528733 failed before archive deletion because the outer source-helper
process hit its 180-second timeout. It did not identify the active child command;
the precise cause of that timeout is unresolved in the original evidence.
Owned guest/firewall cleanup passed, with no failed systemd unit at capture time.

The fixture now blocks every WordPress HTTP request at the application hook,
including local loopback checks, retains the host firewall, and uses the existing
WP-CLI no-update/config-isolation settings. WordPress explicitly permits local
requests despite `WP_HTTP_BLOCK_EXTERNAL`; its installer performs loopback
permalink checks ([HTTP implementation](https://raw.githubusercontent.com/WordPress/WordPress/7.1/wp-includes/class-wp-http.php),
[installer](https://raw.githubusercontent.com/WordPress/WordPress/7.1/wp-admin/includes/upgrade.php)).
That is a supported explanation for network waits, not proof of the specific
unrecorded child. The source-helper deadline now encloses its separately bounded
180-second child commands, and failure evidence records the last fixture step,
child output and process wait channels. Composer uses the provisioned tenant
cache subtree. Eleven local harness tests and PHP-template syntax passed.

[Third failed-run evidence](evidence/2026-10-27-plesk-r0-r1/40452528733/result.json)
is retained unchanged. A corrected focused R0/R1 run followed.

Run 40454639549 failed before source creation: S03's PHP 8.5 dedicated FPM
socket did not become ready, with create-site and account-convergence retries.
The original capture omitted the FPM unit/error log and kernel/memory evidence;
it cannot distinguish slow startup from a failed service. Cleanup passed.

The dedicated classic-FPM socket wait used an unconditional three-second
budget after systemd started the simple service. A local real Unix-socket test
reproduced rejection of valid delayed initialization. That candidate increased the budget to 15
seconds, bounded by caller cancellation; regular files and missing sockets still
fail. Focused readiness/provisioning/file-operation tests passed. This corrects
the short readiness budget without proving the original service's precise cause.
The harness now captures FPM unit state/journal/error logs, memory and kernel
messages before owned cleanup if it fails again.

A separate request-construction regression found Run Now issuing GET to the
POST-only scheduled-task endpoint. It was observed RED and is now GREEN with
an actual CSRF-header POST. Twelve Python harness tests pass. The fourth run
never reached that request, so this is an additional preemptive harness fix.

[Fourth failed-run evidence](evidence/2026-10-27-plesk-r0-r1/40454639549/result.json)
is retained unchanged. A corrected R0/R1-only run followed.

Run 40456958081 failed during S03 account convergence despite the longer
socket wait. FPM configuration checks repeatedly took about 20 seconds;
services were then stopped/restarted by convergence. Memory was not exhausted:
about 4 GB was available. The 15-second budget change did not fix this failure
and has been reverted to the original three-second runtime behavior.

The test isolation silently dropped guest DNS and other denied connections.
That can force libraries to exhaust network retry deadlines. The owned firewall
now rejects denied traffic immediately with an administrative prohibition,
while preserving only replies to runner-initiated TCP management and DHCP.
It still denies guest-originated external connections and host DNS, including
previously established UDP DNS. That candidate required a direct UDP DNS probe to fail
immediately and increment the owned rule's counter, in addition to TCP probes.
The seventh-run correction below replaces immediate ICMP receipt as a predicate.
Network waits are the working explanation, not yet a proved PHP root cause.

A firewall regression was RED then GREEN; 13 Python harness tests pass. The
socket cancellation/non-socket guards pass with the original runtime budget.
Any recurring failure will also collect a bounded network syscall trace of a
read-only FPM configuration check. No service repair is used for acceptance.

[Fifth failed-run evidence](evidence/2026-10-27-plesk-r0-r1/40456958081/result.json)
is retained unchanged. Guest/firewall cleanup passed. Corrected hosted R0/R1
validation followed.

Run 40459693972 proved immediate network rejection: a guest-to-host UDP DNS
probe hit the owned rule and returned errno 113 in under one millisecond.
R1 then correctly rejected PHP 8.5 as not ready. The captured FPM syscall trace
identified the delay: repeated resolver queries for `telemetry.sury.org` and its
`multipass` search variant, with five-second waits after DNS SERVFAIL responses.
This is concrete provider-startup evidence; the later missing site-3 config in
the diagnostic occurred because site creation was rejected before it existed.

The provider's [primary source change](https://salsa.debian.org/php-team/php/-/commit/aa12fa4540c8733ab6d68763b2107f39ec48fb37)
invokes telemetry during FPM module initialization and resolves its server
before any request. It returns from that check if address resolution fails.
The isolated fixture now uses its existing BIND service to provide authoritative
negative answers for that exact hostname and its actual DNS search variants.
Root-owned resolved configuration routes local lookup to BIND; specific
negative trust anchors identify these intentionally unsigned fixture zones
([resolver configuration](https://www.freedesktop.org/software/systemd/man/latest/resolved.conf.html),
[private-zone anchors](https://www.freedesktop.org/software/systemd/man/latest/dnssec-trust-anchors.d.html)).
The provider binaries, signatures, required extensions and three-second site
socket budget are unchanged. No external telemetry or customer integration is
allowed by the sandbox. Production DNS/configuration is untouched.

R0 now requires prompt negative resolution and actual FPM configuration checks
for all three minors within their normal startup budget, and repeats those
read-only checks after reboot. Private .test hosts entries are explicit. Fourteen
local Python harness tests pass, including unsafe suffix rejection; native
verification of this corrected private DNS setup is pending.

[Sixth failed-run evidence](evidence/2026-10-27-plesk-r0-r1/40459693972/result.json)
is retained unchanged. Owned guest/firewall cleanup passed.

Run 40462548080 confirmed local authoritative negative answers in its syscall
trace, then failed the separate UDP-denial assertion. That harness version did
not save the probe's errno/response/counters before asserting; its precise
failure cannot be recovered after successful owned cleanup. It remains failed.

The assertion combined an aggregate traffic counter with immediate ICMP-error
receipt. The corrected security proof uses a dedicated DNS-only deny rule and
counter, requires no DNS response, and retains socket errno/timing separately.
A denied packet can legitimately have no returned ICMP error (for example,
when the kernel rate-limits ICMP); this does not relax the required packet-denial
counter. Prompt provider DNS resolution and all three FPM startup budgets are
checked independently against the private authoritative negative answers.
The DNS-specific counter/response proof also runs after reboot. All values and
the actual owned nft table are retained on failure.

A local data check also found the original 1-pixel PNG's invalid IDAT checksum.
The media canary is now a valid PNG with checked chunk CRCs and nonempty pixel
data; WordPress must preserve its actual stored attachment bytes. Both new
regressions were observed RED then GREEN. Sixteen local harness tests pass.

[Seventh failed-run evidence](evidence/2026-10-27-plesk-r0-r1/40462548080/result.json)
is retained unchanged. Guest/firewall cleanup passed. Corrected native R0/R1
validation is pending; no application case has yet completed acceptance.

Run 40464500054 passed R0 with PHP 8.3.36, 8.4.27 and 8.5.12. All three
file/SQL imports passed exact contents, modes, links and mapped-owner checks.
The three application loops also completed, including actual WordPress login,
media bytes, permalink, post update and cron hook, plus the Composer dependency.
The run then timed out waiting for the S02 scheduled task. Mail, backups and
reboot were not reached.

The fixture supplied an absolute working directory, which the agent correctly
rejects. Its original terminal run row was not captured, so the precise original
status/output remains unrecorded. The fixture now submits the normal PHP task
with a site-relative script and working directory. The API rejects absolute or
escaping working directories before mutation, and Run Now records terminal
status/output rather than waiting only for success. A canary counter proves a
fresh execution before and after reboot. New regressions were observed RED then
GREEN; all 18 Python tests, the full local quota package and focused scheduled
provisioning tests passed. These local results do not complete hosted R1.

[Eighth failed-run evidence](evidence/2026-10-27-plesk-r0-r1/40464500054/result.json)
is retained unchanged. Owned guest/firewall cleanup passed. Corrected R0/R1-only
native validation is pending.

## Cleanup and boundary

Pending terminal evidence. Only owned guests and their containment table may
be removed. The task-created encrypted bootstrap secret must be deleted after
the hosted run reaches its final result. No PR, merge, live migration or
production deployment is authorized by this rehearsal.
