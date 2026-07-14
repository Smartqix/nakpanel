# Nakpanel

Nakpanel is a Go-based hosting control panel for managing sites, databases,
backups, DNS, TLS, customers, service plans, subscriptions, and quotas.

The panel serves its own HTTPS interface directly on port `7443`. Tenant web
traffic remains on nginx ports `80` and `443`, so the control plane stays
reachable even when tenant vhost configuration needs repair.

Nakpanel is in active development. It is suitable for Ubuntu 24.04 lab testing
and contribution work today, but it should be reviewed carefully before any
production use because it includes privileged Linux provisioning, quota
management, and migration-sensitive control-plane behavior.

## What Works Today

- HTTPS panel runtime with self-signed bootstrap TLS certificates.
- Login, Argon2id password verification, secure sessions, and role-aware
  dashboards for admins and customers.
- Customer records, service plans, subscriptions, and entitlement checks.
- Site, database, TLS, backup, restore, DNS, webmail, and reconciliation jobs
  through River.
- `panelctl` operator and recovery commands that work without the web listener,
  while retaining subscription, quota, lifecycle, audit, and River gates.
- ACME, self-signed, and system-trusted custom site certificates with atomic
  agent installation and custom-certificate expiry warnings.
- Privileged Unix-socket agent for Linux provisioning work.
- PHP-FPM pool rendering, Linux users, nginx vhosts, MariaDB databases, and
  per-site disk quota enforcement.
- Adminer SSO for database access from the authenticated panel.
- Single-VM Ubuntu 24.04 Multipass deployment verification.

## Architecture

Nakpanel is intentionally split into a control plane and a privileged agent:

- `cmd/panel`: HTTPS web panel, authentication, dashboards, PostgreSQL access,
  River workers, and job orchestration.
- `cmd/agent`: root-owned Unix-socket service for OS-level provisioning.
- `cmd/panelctl`: local operator/recovery CLI backed by PostgreSQL and the same
  control-plane services as the web panel.
- `internal/control`: HTTP handlers, auth, dashboard loading, quota and plan
  logic, provisioning managers, stores, TLS bootstrap, and embedded web assets.
- `internal/agent`: RPC server, peer credential checks, and Linux operations.
- `migrations`: goose migrations from users/sessions through subscription
  accounts, operator identity, and custom TLS notifications.
- `deploy`: systemd units, install scripts, and Multipass verification scripts.

The panel communicates with the agent over `/run/nakpanel/agent.sock`. On Linux,
the agent enforces peer credentials so only the expected panel UID can dispatch
privileged operations.

## Requirements

For local development:

- Go `1.23+`
- PostgreSQL
- [Task](https://taskfile.dev/)
- A shell environment that can run the Go test suite

For full deployment verification:

- Multipass
- Ubuntu `24.04` VM image
- Enough local disk and memory for PostgreSQL, nginx, PHP-FPM, MariaDB, bind9,
  quota tooling, and Go builds

The realistic end-to-end target is Ubuntu 24.04. Some agent operations are
Linux-specific and cannot be fully exercised on macOS.

## Quick Start

Clone the repository and run the local checks:

```bash
git clone https://github.com/Smartqix/nakpanel.git
cd nakpanel

task goose:up
task river:up
task build
go test ./...
```

By default, local migration tasks use:

```text
postgres://postgres@localhost:5432/nakpanel?sslmode=disable
```

Set `NAKPANEL_DATABASE_URL` when your local database uses a different DSN.

## Full Ubuntu 24.04 Verification

Run the single-VM deployment verifier:

```bash
deploy/multipass/deployment-verify.sh
```

This creates a fresh `nakpanel-lab` Ubuntu 24.04 Multipass VM, removes old
Nakpanel phase VMs, installs the service stack, runs migrations, builds the
panel, agent, and CLI, installs systemd units, and runs the full Phase 18 verification
chain (through mailbox hosting on Stalwart; see `docs/MAIL.md`).

The verifier intentionally refuses to delete Multipass VMs whose names do not
start with `nakpanel-`. Non-Nakpanel VMs such as unrelated local test machines
are left alone.

To override the lab VM name or Ubuntu image:

```bash
NAKPANEL_MULTIPASS_VM=nakpanel-lab NAKPANEL_MULTIPASS_IMAGE=24.04 deploy/multipass/deployment-verify.sh
```

After a successful verification, open:

```text
https://<vm-ip>:7443/login
```

The bootstrap certificate is self-signed, so the browser warning is expected.

Seeded test accounts:

```text
admin@nakpanel.test  / NakpanelAdmin!2026
client@nakpanel.test / NakpanelClient!2026
```

Do not use these seeded credentials as production defaults.

## Configuration

Important environment variables:

| Variable | Purpose |
| --- | --- |
| `NAKPANEL_DATABASE_URL` | PostgreSQL DSN for panel, migrations, and River tasks. |
| `NAKPANEL_TLS_DIR` | Directory for the panel bootstrap TLS certificate and key. Defaults to `/var/lib/nakpanel/tls`. |
| `NAKPANEL_AGENT_ALLOWED_UID` | Optional numeric UID allowed to connect to the agent socket. |
| `NAKPANEL_AGENT_SOCKET` | Agent socket used by `panelctl agent ping`. Defaults to `/run/nakpanel/agent.sock`. |
| `NAKPANEL_MARIADB_DSN` | Optional MariaDB connection string used by the agent database provisioner. |
| `NAKPANEL_ACME_DIRECTORY_URL` | ACME directory URL for certificate issuance. |
| `NAKPANEL_ACME_ACCOUNT_KEY` | Path to the ACME account key. |
| `NAKPANEL_ACME_EMAIL` | ACME account email. |
| `NAKPANEL_MULTIPASS_VM` | Multipass VM name for deployment verification. Defaults to `nakpanel-lab`. |
| `NAKPANEL_MULTIPASS_IMAGE` | Multipass image for deployment verification. Defaults to `24.04`. |

The panel always listens on `:7443` using the configured TLS directory. It must
not bind tenant ports `80` or `443`; those stay reserved for nginx.

## Development Workflow

Common commands:

```bash
task generate      # sqlc, templ, and embedded CSS
task build         # build panel, agent, and panelctl
task test          # run go test ./...
task goose:up      # apply goose migrations
task river:up      # apply River queue migrations
```

Generated code and assets are checked in where the current project expects
them, including sqlc output, templ output, and `internal/control/web/static/app.css`.
Run `task build` after touching SQL queries, templ pages, or Tailwind input.

## Operator CLI

Install `bin/panelctl` as `/usr/local/bin/panelctl` on an Ubuntu host. Commands
use `NAKPANEL_DATABASE_URL`; only `agent ping` contacts the privileged socket.
The default audit label is `SUDO_USER` or the current OS username, and can be
overridden with `--actor`.

```bash
sudo -u nakpanel panelctl create-admin --email admin@example.test
sudo -u nakpanel panelctl user list
sudo -u nakpanel panelctl session list --user admin@example.test
sudo -u nakpanel panelctl site reconcile example.test
sudo -u nakpanel panelctl backup create example.test
sudo -u nakpanel panelctl reconcile --system
sudo -u nakpanel panelctl agent ping
```

Destructive commands require an interactive confirmation or `--yes`. Custom
site certificates can be queued without placing key material in River:

```bash
sudo -u nakpanel panelctl ssl set-custom example.test \
  --cert /secure/example.crt \
  --key /secure/example.key \
  --chain /secure/intermediate.crt
```

The chain must verify to the host system trust store. Arbitrary private roots,
self-signed leaves, encrypted keys, mismatched keys, and wrong-domain or
out-of-date certificates are rejected.

Useful recovery and operations notes live in:

- `docs/RECOVERY.md`
- `IMPLEMENTATION_PLAN.md`
- `deploy/multipass/deployment-verify.sh`

## Contributing

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

If you change provisioning, deployment, quotas, migrations, plans,
subscriptions, the agent, or systemd behavior, run:

```bash
deploy/multipass/deployment-verify.sh
```

Please keep changes focused and include tests for behavior changes. Security and
operationally sensitive areas need extra care:

- Authentication, session, and RBAC logic.
- Privileged agent RPC and Unix socket permissions.
- Linux user creation, ownership, disk quotas, and PHP-FPM/nginx rendering.
- Database migrations and data backfills.
- Plan, subscription, entitlement, and oversell behavior.
- Backup, restore, DNS, TLS, and reconciliation jobs.

Do not commit local secrets, production credentials, VM artifacts, database
dumps, or generated junk outside the project’s expected generated files.

## Project Status

Nakpanel currently covers the core control-plane and provisioning path, but it
does not yet claim full cPanel/Plesk parity. Billing, invoices, mailbox
management, advanced reseller hierarchy, and full production hardening are
future work unless explicitly implemented in the codebase.

## License

No license file is currently declared in this repository. Treat usage and
redistribution rights as unspecified until a license is added.
