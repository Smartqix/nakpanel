# Contributing to Nakpanel

Nakpanel is before production release. Breaking changes are allowed; legacy
compatibility, backfills, and historical upgrade or restore paths are not
required unless explicitly requested. Development databases, fixtures, and test
backups may be recreated for the current design. Update code, callers, tests,
and documentation together while retaining explicitly requested platform support
and current security requirements. See [AGENTS.md](AGENTS.md) for project guidance.

## Workflow

Read [Local development](docs/DEVELOPMENT.md) before setting up a checkout.

Add-on websites and subdomains have a scoped, checkpointed removal workflow.
Databases and backups are retained by default. See
[Domain removal and recovery](docs/DOMAIN_REMOVAL.md) for protection rules,
retry behaviour, retained-data recovery and the single-VM acceptance test.

Contributions are welcome through the normal GitHub fork, branch, and pull
request flow.

Before opening a pull request:

```bash
go test ./... -count=1
go vet ./...
task build
git diff --check
```

If you change shell scripts, also run:

```bash
bash -n deploy/multipass/*.sh
```

Provisioning, deployment, quota, migration, plan, subscription, agent or systemd
changes need the appropriate current-version Ubuntu 26.04 acceptance. Hosted
runs require explicit authorization; see [Verification](docs/VERIFICATION.md).
Documentation-only changes need link, asset and rendering checks, not hosted tests.

Please keep changes focused and include tests for behavior changes. Security and
operationally sensitive areas need extra care:

- Authentication, session, and RBAC logic.
- Privileged agent RPC and Unix socket permissions.
- Linux user creation, SFTP/FTPS confinement, ownership, disk quotas, and
  PHP-FPM/nginx rendering.
- Path-derived File Manager, Git, staging, scheduled-task, and log operations.
- Rootless Podman container generations and Valkey isolation, Unix-socket
  ownership, subordinate-ID allocation, and ACLs.
- Current database schemas and migrations; historical backfills are not required.
- Plan, subscription, entitlement, and oversell behavior.
- Backup, restore, DNS, TLS, and reconciliation jobs.

Do not commit local secrets, production credentials, VM artifacts, database
dumps, or generated junk outside the project’s expected generated files.
