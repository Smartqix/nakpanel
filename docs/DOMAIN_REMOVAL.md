# Removing an Add-on Website or Subdomain

Open the website's **Actions > Remove website**. The same action is available
from the subscription's website list. Primary websites, the panel hostname,
and domains required by server mail, DNS or certificates cannot be removed
individually. Use the separate account lifecycle for whole-account termination.

The confirmation lists the exact websites and services that will be removed.
Removing a parent also removes its children and requires explicit consent.
Type the displayed hostname and acknowledge permanent removal. Databases and
backups are **kept by default** under the subscription. Only individually
verified, exclusive databases can be selected for deletion; shared or ambiguous
databases cannot be deleted here. Toolkit databases require a verified recovery
backup before optional deletion.

The dialog waits for completion before navigating to the surviving parent or
subscription. **Continue in background** opens durable progress. Without
JavaScript, the confirmation and progress pages provide the same operation.
If the connection is lost, use the request lookup or progress link: do not
submit a second removal. Expired confirmations require a new impact review.

## Failure and Recovery

Removal freezes mutations for the selected tree and keeps its resource
allocation reserved until completion. A failure remains visible with **Retry**;
retry resumes the same approved scope and completed checkpoints. It does not
delete additional resources. Correct the underlying service or filesystem
problem first. Activity records request, failures, retries and completion.

Kept databases retain their credentials and can be managed from the subscription.
Kept backups remain downloadable. To restore website content, explicitly create
an active replacement using the same domain under the same subscription and
select it as the restore target. A backup never recreates a deleted website
automatically and cannot restore into another customer's or sibling's files.

The agent's protected identity registry at `/var/lib/nakpanel-agent/sites`
prevents old jobs from recreating deleted IDs or touching a same-hostname
replacement. Preserve these records in server backups; never remove tombstones
or ownership markers to force a retry.

## Verification

The current verification target is Ubuntu 26.04 LTS with hosting PHP
8.3/8.4/8.5. The verifier and defaults now target this contract; hosted acceptance remains pending.
`deploy/multipass/domain-removal-verify.sh` must install the current stack and
run Phase 34 in a disposable run-owned guest, then create uniquely named QA
fixtures. Preserve pre-existing lab and soak VMs.
It tests primary protection, child removal, default retention and download,
same-hostname recreation, stale native RPC rejection, fixture-only failure and
retry, CSRF, ownership, and native nginx/DNS/SSH validation.

The final gate is included in `deploy/multipass/deployment-verify.sh`, which
bootstraps using the production installer, then runs current OCI, security,
recovery, PHP, plan, WordPress, statistics and removal acceptance. Historical
phase scripts remain available for debugging their compatibility contracts. These
verifiers are lab tools, not production reset scripts. For optional browser QA,
use `domain-removal-browser-smoke.cjs` with Playwright and Chrome. Destructive
browser mode accepts only the verifier's exact new QA domain naming patterns.
