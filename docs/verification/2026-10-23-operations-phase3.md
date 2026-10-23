# Operations center — phase 3 local evidence

Scope: durable source recording, condition detection and verified recovery.
No hosted environment, production resource or external mailbox was accessed.

- Real local PostgreSQL and River fixtures exercise transactional job capture,
  automatic retry preservation, rollback, duplicate terminal signals and outbox
  delivery. No historical jobs are backfilled.
- Backup recovery reloads ownership, policy, active state, database coverage,
  quotas and conflicting work. It creates a new backup/job under the logical
  operation, preserving failed attempts. Confirmation expires and is invalidated
  by a changed incident or intent. Worker execution reloads current intent again.
- Generic job retry and its obsolete hosted script are removed. Restores and
  other destructive jobs have no automatic retry action.
- Scheduled checks detect overdue backups and certificates within 14 days of
  expiry. Backup deadlines use UTC plus 30 minutes of grace. Repeated identical
  observations do not inflate occurrence counts. Unknown evidence stays open.
- Verifiers check managed archive checksum/size, trusted local TLS, the enabled
  isolated site runtime, or local SMTP/IMAP and configured webmail readiness.
  Archive integrity does not prove a restore. Local mail readiness does not prove
  external delivery. Public DNS is not asserted by local HTTPS probes.
- Resolution is fenced by incident generation, latest event and the current
  full intent hash. A newer failure or changed intent rejects an older result.
- Read-only site probes retain PHP 8.3/8.4/8.5 and tenant execution checks.
- Independent checks use bounded jobs. Heavy probes do not occupy the system
  mutation queue. Check failures do not generate recursive verification jobs.

UI projections are replaced together in phase 4. This is backend evidence only.

Verification: the affected panel, operations, provision and HTTP packages pass,
including real PostgreSQL/River tests. The operations race check passes. The full
local suite exposed an outdated SQL mock (corrected and passing). Its unchanged
Roundcube harness also intermittently failed to write a child-failure receipt;
that targeted harness investigation continues, with no hosted execution. No
claim of complete release acceptance is made at this phase.
