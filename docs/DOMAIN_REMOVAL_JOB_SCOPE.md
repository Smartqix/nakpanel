# Domain Removal Job Scope

Individual removal is separate from account teardown. PostgreSQL reserves every
approved descendant and keeps it counted until finalization. The queued removal
arguments contain only operation and work-revision IDs.

## Queue Classification

`TargetSiteJobScope` uses fixed SQL predicates and parameter arrays. Unknown job
kinds must be classified before they can be registered. The regression test
checks each control-plane `Kind` declaration.

| Work | Match / Behavior |
| --- | --- |
| Site creation, TLS, hosting state, statistics | Exact site ID; legacy TLS also exact canonical domain |
| Backups and restores | Exact site, backup ID or legacy canonical domain; retained archives are not removed by teardown |
| PHP deployments and workers | Exact PHP application ID |
| WordPress | Exact instance ID; no uninstall placeholder restoration |
| OCI | Exact application ID |
| Scheduled tasks | Run ID resolved through approved task IDs |
| Git, protected directories, access | Shared subscription convergence reloads surviving intent |
| Staging | Exact operation ID when either source or destination is selected; the surviving endpoint is not included in deletion |
| Database creation and administration | Exact site-linked database IDs, even when the database will be retained |
| Webmail and standalone DNS | Exact owned object ID or legacy canonical domain |
| Single-site system reconciliation | Exact site ID; multi-site reconciliation is not cancelled wholesale |
| Global mail, FTPS, DNS templates and account convergence | Not cancelled wholesale; reload current intent and filter tombstones under agent leases |
| Plan/add-on synchronization, usage and scheduler sweeps | Shared intent; reload surviving resources |
| Server operations, notifications, webhooks | Node scope; their existing permissions and fixed-service controls remain required |
| Removal and account termination | Dedicated durable lifecycle guards; never used interchangeably |

Available, pending, scheduled and retryable target jobs are cancelled. Running
target work is drained before irreversible cleanup, without holding the runtime
lock that work may need. Every worker must also recheck current identity before
calling the agent; cancelling a queue entry alone is insufficient.

## Agent Boundary

The dispatcher extracts identity from explicit typed requests, not recursive
JSON-field heuristics. A PHP environment variable or application secret named
`site_id` is not an authorization input.

Positive-ID creation, current account intent and reconciliation may initialize
identities. Other positive-ID operations require a registered identity. Legacy
domain-only requests are rejected for any hostname with removal history. New
hostnames can be reused only with a new positive site ID after cleanup completes.

Root-owned identity records and tombstones use mode 0600 in a mode-0700 directory
under `/var/lib/nakpanel-agent/sites`. Ordered subscription/domain/site leases use
cross-process locks. Nested provisioner calls reuse the validated lease context.
Weaker legacy references cannot replace the positive identity in that context.

Removal keeps the hostname reserved at the agent until cleanup completes. Whole
account teardown has a separate tombstone namespace so replaying an old account
operation cannot erase another subscription's replacement hostname.

Shared mail, DNS, FTPS, task, account and reconciliation payloads exclude removed
identities. DNS owner IDs remain explicit, including records in parent zones.
Server certificate dependencies are read from trusted agent configuration,
including resolved FTPS/webmail certificate links, and independently rechecked
before physical cleanup. Dependency lookup failure blocks approval.

No individual teardown may delete the subscription home, reset its disk quota,
kill processes by UID, remove its system user, prune shared Podman storage, or
remove the subscription Valkey service.
