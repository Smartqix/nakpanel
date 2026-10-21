# Development policy

Nakpanel is in active development, before production release. Breaking changes
are allowed. Implement the current design directly.

- Do not preserve old APIs, schemas, configuration formats, or backup formats
  solely for backward compatibility.
- Do not add legacy adapters, compatibility shims, dual-read/write paths,
  backfills, or transitional migrations unless the user explicitly requests them.
- Development databases, fixtures, and test backups may be recreated for the
  current design instead of maintaining historical upgrade or restore paths.
- Remove obsolete code and update its callers, tests, and documentation together.
- Validate current supported behavior. Historical release and archive
  compatibility matrices are not required unless explicitly requested.
- Ubuntu 26.04 LTS (Resolute) is the only supported server OS. Ubuntu 24.04
  support, Noble-specific regression matrices and 24.04-to-26.04 migration are
  retired requirements. Reject unsupported server OS versions before mutation.
- Keep hosting PHP 8.3, 8.4 and 8.5, with their required extensions, isolated
  FPM/CLI execution and readiness checks. Internal tools use validated PHP 8.5.
  A native PHP 8.5-only profile does not satisfy the hosting runtime contract.
- Reuse the existing signed Resolute Surý provider and trusted PHP descriptors;
  do not substitute Noble packages or remove a required runtime to pass a gate.
- Keep current-version Ubuntu 26.04 backup/restore, application update and
  recovery, security and tenant-isolation requirements. Historical evidence
  stays attributed to its original OS/source; retired failures remain failures.
- The Ubuntu 26.04-only transition is phased. Report each phase before moving
  on, and follow the current authorization in the support plan. Code/default
  alignment and focused local verification do not establish hosted acceptance.
  Hosted tests require explicit authorization.

This policy supersedes backward-compatibility and backfill requirements in older
plans and verification documents. Historical reports describe past work; they
do not create continuing legacy-support obligations. A later explicit user
request can require a specific compatibility or migration path.
