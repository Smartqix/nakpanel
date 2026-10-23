# Focused hosted Operations acceptance

Authorization: the owner requested focused hosted Ubuntu 26.04 notifications,
tasks, recovery and both UX fixes, with PHP 8.3/8.4/8.5 retained. Report before a
PR, merge or deployment. No external recipient email was authorized or used.

## Candidate and scope

- Original candidate: `207f4eddf375ad8cff4e266f1d855c10c8bcadd1`.
- Original run: <https://github.com/Smartqix/nakpanel/actions/runs/39976927191>.
- Corrected candidate: `c75b879014c74cb73a959512fe457df460750cd3`.
- Retest: <https://github.com/Smartqix/nakpanel/actions/runs/39980378643>.
- Navigation correction: `40a3faf2334ffb7ef935e759d4bc4e822dd6252f`.
- Passing retest: <https://github.com/Smartqix/nakpanel/actions/runs/39983722531>.
- Selection: `operations_only=true`; unrelated hosted qualification jobs skipped.
- Guest: signed, pinned Ubuntu 26.04 Resolute AMD64 cloud image, serial
  `20260927`, SHA256
  `8800651811af9a85465ad1d552add729947bb16488dddb4a9b5305a3d97332b2`.
- Fresh signed development application; existing signed Resolute Surý provider.
- Owned disposable GitHub-hosted guest; synthetic fixture accounts and loopback
  SMTP capture. No production server changes, external SMTP delivery, PR,
  merge or deployment.

## Implementation correction

Manual scheduled-task **Run now** previously called the agent synchronously and
bypassed durable Operations recording. It now creates its pending run and River
job in one transaction, verifies current ownership, active resource state and
policy, and uses the existing worker. Notifications, Tasks and failure history
therefore observe the same execution path as scheduled runs. UI and audit records
say **queued** rather than claiming execution already completed. The obsolete
synchronous store methods were removed.

The first hosted run timed out waiting for a single incident notification. A real
database/worker regression then reproduced duplicate publication when a second
run is queued before the first failure is dispatched. The issue's latest task
pointer had moved, while the worker notice still belonged to the original event.
Correlation now accepts the original event and the current run (the worker may
already have refreshed its open notice). Three explicit publication timings pass:
delayed dispatch, dispatch between runs and dispatch before the second worker.
No issue acknowledgement, resolution or personal receipts are synthesized.

The second hosted run passed that correction and both UX fixes, then reproduced
loss of twelve consumed terminal results on real SPA navigation. The topbar's
fragment was replaced while the feed correctly retained its consumed cursor.
Results now remain in memory for the current authenticated resource scope and
redraw into a replacement topbar; dismissal and scope changes clear them. Shell
identity is checked even when the URL is unchanged. A new loopback browser test
uses real fragment responses and topbar replacement, rather than only changing
history and calling mount.

## Local verification

- Real RED regression confirmed Run now bypassed the queue before the fix.
- `go test` on provision, quota, HTTP and operations: all four packages passed;
  operations/provision integration tests used an owned loopback PostgreSQL 18
  database with default durability. That database was shut down afterward.
- Focused workflow selection guards passed, including exclusion of unrelated jobs,
  mandatory owned cleanup and upload of public evidence only.
- Two Python protocol/runtime guards passed: missing required hosting PHP
  runtimes/extensions fail acceptance; the loopback SMTP fixture rejects DATA,
  then accepts DATA before a disconnected QUIT.
- Browser probe syntax, affected `go vet` packages and `git diff --check` passed.
- After the correlation fix, the affected provision/operations tests passed,
  including the three timing regressions, domain-notice correlation, dispatcher,
  recorder and incident identity tests. Intermediate failing attempts remain RED
  evidence; only the final targeted run is counted as passing.
- The unrelated full local Multipass script suite was stopped; it is not counted
  as passing or required evidence for this focused run.
- The fragment regression reproduced **0 instead of 12** before the fix and
  passed afterward: twelve results retained, cursor unchanged, dismissed results
  did not return, no script errors. The affected browser acceptance also passed
  cursor preservation, replay dedupe, scope clearing, preference loading and
  mobile overflow checks. Fourteen focused JS tests and Operations Go render
  tests passed; web `go vet` and diff checks passed. Local browser fixtures and
  the owned PostgreSQL instance were stopped after verification.

## Hosted results

The original run failed at the single-notification assertion. Its fresh install
and exact OS check passed with PHP **8.3.36 / 8.4.27 / 8.5.12**, including all
required CLI/FPM extensions. Its owned guest was removed: cleanup recorded one
owned guest and exit code zero. Later scenarios were not reached; this failure
does not establish UX or recovery acceptance.

The second run passed the exact OS/PHP contract, actual Run now/semantic failures,
incident dedupe, independent task identity, foreign issue/task denial, real
disconnected-agent backup failure, and the failed independent check remaining
open. Browser evidence confirms **read-on-open** and **support settings links**
passed, and twelve results appeared after reconnect. It failed the subsequent
navigation preservation assertion. Backup retry success and SMTP acceptance
were not reached. Its owned guest was removed successfully (one, exit zero).

The final run **PASSED** on `40a3faf2334ffb7ef935e759d4bc4e822dd6252f`.
Its signed build took 1m28s; the focused Operations job took 16m21s, including
runner preparation, a fresh installed guest, all scenarios, cleanup and artifact
publication. All six unrelated jobs were skipped. Three focused runs were used;
the first two remain failed evidence and are not relabeled as passes.

| Scenario | Final evidence |
| --- | --- |
| Current supported platform | `ubuntu:26.04:resolute`, AMD64; PHP 8.3.36 / 8.4.27 / 8.5.12 with every required CLI/FPM extension. |
| Task and incident recording | Actual Run now workers, semantic failure despite River completion, repeated incident dedupe, independent task identity, foreign issue/task denial. |
| Failed recovery remains open | Real agent disconnection caused a backup failure; an unsuccessful independent check did not resolve it. |
| Both UX fixes | Opened notification created only the opener's read receipt; another administrator's receipt remained absent; issue acknowledgement and resolution stayed unset. Direct scheduled-task settings link retained customer support context and returned 200. |
| Reconnect/navigation | Twelve real manual tasks completed while the browser was offline; results appeared after reconnection and survived actual fragment navigation without duplicates. Desktop/mobile checks had zero script errors and no horizontal overflow. |
| Backup recovery | Explicit unchecked confirmation blocked retry until selected; real backup succeeded, then independent verification produced an `archive_checksum` receipt with checksum/size. Original failed attempts remained failed. |
| Notification delivery | Eight actual bounded SMTP DATA rejections, no recursive email, private delivery issue, then one DATA acceptance followed by QUIT disconnection verified SMTP recovery only. No external mail sent. |
| Preservation/readiness | Original website file, MariaDB canary and baseline archive checksums remained unchanged. Panel, agent and all three PHP FPM services were active. |
| Owned cleanup | Exactly one owned guest removed; cleanup exit code zero. |

Final artifacts, failed-run evidence, local RED/GREEN logs and browser screenshots
are retained in [the evidence directory](evidence/2026-10-23-operations-hosted/).
`evidence-inspection.json` records the final cross-check of source identity,
workflow selection, six scenario groups, browser assertions, SMTP receipts and
owned cleanup. The mobile results and retry-confirmation screenshots were also
visually inspected. This report and plan update change documentation only after
the tested implementation revision.

## Limits

This is focused Operations acceptance, not full release qualification or required
PR CI/security-gate evidence. Backup recovery requires an independently checked
archive checksum and size; it does not claim a restore rehearsal. SMTP acceptance
does not claim delivery to an external inbox. Ubuntu 24.04 and historical
compatibility matrices are retired requirements.
