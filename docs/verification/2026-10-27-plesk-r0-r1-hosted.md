# Synthetic Plesk migration rehearsals R0 and R1

Status: R0 has passed; corrected hosted R1 validation is pending. No full R1
acceptance yet. The latest completed [run 40469902668](https://github.com/Smartqix/nakpanel/actions/runs/40469902668)
failed at mail connection readiness. A corrected candidate is being prepared.

Only R0/R1 with S01/S02/S03 are authorized. The target is Ubuntu 26.04 AMD64,
using the existing signed Resolute Surý provider and PHP 8.3/8.4/8.5.

## Workloads and results

The last completed run, 40469902668, verified the following before failing at
mail listener readiness. These partial results do not establish R1 acceptance.

| Case | Workload | Actual PHP | File/SQL import and application workflow | Reboot preservation |
| --- | --- | --- | --- | --- |
| S01 `harbor-cafe.test` | WordPress 7.1/MariaDB | 8.3.36 | PASS | Pending |
| S02 `atlas-studio.test` | Composer/application/MariaDB/cron | 8.4.27 | PASS, including Run Now exit 0 | Pending |
| S03 `meadow-blog.test` | Application/MariaDB; child mail canary | 8.5.12 | Application PASS; mail pending | Pending |

R1 requires exact logical SQL contents, file/directory hashes and modes,
symlinks, mapped ownership, actual FPM identities, authenticated sessions,
uploads, clean URLs, a controlled update, locked Composer code and fresh cron
execution. It also requires one local SMTP/IMAP canary, cross-tenant denials,
three checked backup archives and an unassisted reboot with preservation.

R0 passed signed artifact/image verification, all CLI/FPM extensions, trusted
HTTPS, root/tenant egress denial and the dedicated guest-to-host DNS deny
counter. The signed Ubuntu image serial is `20260927`, SHA256
`8800651811af9a85465ad1d552add729947bb16488dddb4a9b5305a3d97332b2`.
Artifact hashes, trust-key identity and source commit are retained per run.

## Product fixes

- File deletion now explicitly parses the form before reading selected paths.
  Header-authenticated CSRF requests previously reached the agent with no paths.
  A real HTTP regression reproduced this; malformed input is rejected before
  calling the agent. Copy/move regressions also passed.
- Scheduled tasks reject absolute or escaping working directories before SQL
  mutation, matching the existing agent contract. The rehearsal submits a
  site-relative PHP task, records terminal failures immediately and requires
  fresh execution counters before and after reboot.

No OS/PHP provider, required extension, schema, backup-format or FPM startup
budget was changed. The experimental 3-to-15-second FPM wait was reverted after
it failed to fix the measured startup delay.

## Harness corrections and local verification

The initial fresh review found six issues, all fixed: Stalwart certificate-path
interpolation, actual SFTP symlinks, exact ordered SQL comparisons, private
operator credentials, directory metadata and observational boot readiness.
No minor findings were deferred.

Subsequent failed runs corrected leaf-only certificate input, offline WordPress
hooks/CLI settings, Composer cache ownership, diagnostic capture, Run Now POST,
valid PNG media bytes, explicit subdomain allowance and early entitlement
verification. The fixture service plan permits its declared one child domain;
production quota enforcement was not weakened. Mail probes wait for actual TLS
listener readiness after configuration convergence, with no service repair, no
certificate bypass and no retry of message submission.

Provider startup tracing proved DNS requests to `telemetry.sury.org` and its
search variant with repeated five-second waits. The provider's
[primary source](https://salsa.debian.org/php-team/php/-/commit/aa12fa4540c8733ab6d68763b2107f39ec48fb37)
resolves telemetry during FPM initialization. The isolated guest now supplies
authoritative negative answers for only those fixture names, with private
[resolver routing](https://www.freedesktop.org/software/systemd/man/latest/resolved.conf.html)
and [negative trust anchors](https://www.freedesktop.org/software/systemd/man/latest/dnssec-trust-anchors.d.html).
All external traffic remains denied. Production DNS is untouched; this does
not establish provider resilience during a production DNS outage.

DNS containment requires a dedicated deny counter increase and no DNS response.
Returned ICMP errno/timing is diagnostic, because kernel ICMP rate limiting can
prevent receipt. Prompt private resolution and all three FPM startup timings
are checked separately, including after reboot.

Observed local verification: 21 Python harness tests (including real OpenSSL,
PHP cron execution and PNG integrity); full quota package; focused scheduled
provisioning, file-manager/HTTP, agent file operations/readiness and workflow
selection tests. The full multipass package passed earlier (157.795 seconds).
Syntax/whitespace checks passed. New defect regressions were observed failing
before their corrections and passing afterward. Local checks do not substitute
for hosted acceptance. The offline Composer smoke is not a security audit.

## Retained failed runs

Every run below remains FAIL; all ten removed their owned guest and firewall.
Evidence directories contain unchanged public JSON. Original raw source data,
credentials, cookies, private keys and private command logs are not uploaded.

| Run | Failure and correction |
| --- | --- |
| [40449279762](https://github.com/Smartqix/nakpanel/actions/runs/40449279762) | TLS CLI requires one leaf; fixture incorrectly supplied a chain. Corrected leaf input and verified CA/hostname. |
| [40450784211](https://github.com/Smartqix/nakpanel/actions/runs/40450784211) | Archive deletion sent no paths. Fixed HTTP form parsing. |
| [40452528733](https://github.com/Smartqix/nakpanel/actions/runs/40452528733) | Source helper exceeded its aggregate deadline; active child was not captured, so its exact cause remains unknown. Added offline hooks, separate bounded child/aggregate deadlines and progress diagnostics. |
| [40454639549](https://github.com/Smartqix/nakpanel/actions/runs/40454639549) | PHP 8.5 socket not ready; precise original cause unproved without FPM logs. Expanded diagnostics; experimental longer wait was later reverted. |
| [40456958081](https://github.com/Smartqix/nakpanel/actions/runs/40456958081) | FPM checks took about 20 seconds despite the longer wait, with ample memory. Reverted wait change; replaced sandbox DROP with REJECT and added syscall traces. |
| [40459693972](https://github.com/Smartqix/nakpanel/actions/runs/40459693972) | Trace proved provider startup DNS waits. Corrected sandbox-only authoritative negative DNS, keeping signed binaries/extensions. |
| [40462548080](https://github.com/Smartqix/nakpanel/actions/runs/40462548080) | Combined DNS-counter/ICMP assertion failed without retained values; exact original reason unknown. Split security proof from ICMP timing and retained dedicated counters. |
| [40464500054](https://github.com/Smartqix/nakpanel/actions/runs/40464500054) | All imports/application loops completed; cron wait timed out. Fixture absolute CWD violates the existing agent guard; original terminal row was not captured. Corrected PHP task and API guard/diagnostics. |
| [40467944220](https://github.com/Smartqix/nakpanel/actions/runs/40467944220) | R0/all imports/apps/cron passed; child creation correctly rejected the fixture plan's zero subdomain allowance. Explicitly provisioned one child and added early validation. |

| [40469902668](https://github.com/Smartqix/nakpanel/actions/runs/40469902668) | Child/mail provisioning and cron passed. SMTP connection was refused during the observed Stalwart restart, before listeners returned. Added bounded pre-authentication listener readiness; TLS errors remain fatal and message submission is never retried. |

Public evidence: [run directories](evidence/2026-10-27-plesk-r0-r1/).

## Scope decisions and limits

- The source is private synthetic file/logical SQL exports inside the owned
  guest, not installed Plesk. This exercises destination ingress and preservation;
  it cannot prove Plesk extraction or real-customer compatibility.
- Containment is enforced on the disposable runner, bound to the owned guest
  MAC/bridge. Only replies to runner-initiated TCP management and DHCP bypass
  new guest egress denial. Root and tenant probes are required before workload
  execution and after reboot.
- Install-only signed bootstrap precedes fixture-CA trust. All acceptance API,
  application and mail traffic verifies TLS; insecure TLS is not acceptance.
- S03 uses one local mail canary. R3 mail import/catch-up, R4 public DNS/TLS
  transition, R5 fresh-host restore/write-aware rollback, R2 exception workloads,
  ARM64 and external mail deliverability remain unexecuted.
- A temporary encrypted CI secret carries the approved operator credential only
  to the verified owned guest. Its deletion is required after the final result;
  private operator configuration is preserved. No credential value is committed.

No real customers/source servers were contacted. No PR, merge, live migration
or production deployment was performed. The tested development candidate is
not eligible for production promotion from R0/R1 alone.
