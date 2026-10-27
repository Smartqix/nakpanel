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
is retained unchanged. A corrected focused R0/R1 run is pending.

## Cleanup and boundary

Pending terminal evidence. Only owned guests and their containment table may
be removed. The task-created encrypted bootstrap secret must be deleted after
the hosted run reaches its final result. No PR, merge, live migration or
production deployment is authorized by this rehearsal.
