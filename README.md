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
- First-class, subscription-scoped Mail workspace for domains, mailboxes,
  aliases, DKIM/DMARC, webmail, and administrator Stalwart controls.
- `panelctl` operator and recovery commands that work without the web listener,
  while retaining subscription, quota, lifecycle, audit, and River gates.
- ACME, self-signed, and system-trusted custom site certificates with atomic
  agent installation and custom-certificate expiry warnings.
- Privileged Unix-socket agent for Linux provisioning work.
- Subscription system accounts with honest account-level disk quotas and
  per-domain document-root usage.
- Domain-centered hosting tools for File Manager, confined SFTP, TLS-only
  FTPS, dedicated PHP-FPM services, structured nginx controls, logs,
  statistics, scheduled tasks, Git, protected directories, and staging.
- Operational OCI containers with digest-pinned images, rootless
  subscription identities, loopback-only nginx ingress, health-gated
  generations, encrypted write-only secrets, rollback, and reboot
  reconciliation.
- One disposable, socket-only Valkey cache per entitled subscription with
  memory/CPU/process ceilings and restricted ACL commands.
- Detailed, readiness-gated PHP 8.3, 8.4, and 8.5 inventory, with PHP 8.4 as
  the default for new eligible sites and explicit older selections preserved.
- Classic PHP hosting for mutable applications, plus native Managed PHP from a
  hosted or remote Git repository with pinned Composer installs, immutable
  health-gated releases, rollback retention, encrypted write-only environment
  secrets, bounded workers, suspension, and reboot reconciliation.
- WordPress 7.1 compatibility on Classic PHP, including trusted custom TLS,
  WP-CLI 2.12.0, backups containing files and tracked MariaDB data, clean
  permalinks, media, cron, sessions, and OPcache.
- Adminer SSO for database access from the authenticated panel.
- Single-VM Ubuntu 24.04 Multipass deployment verification.

WordPress support is compatibility only: Nakpanel is not a WordPress Toolkit
and does not manage plugins, themes, cloning, or WordPress lifecycle through a
dedicated product. Nakpanel does not offer Node.js or Python applications.
Advanced OCI workloads remain separate under the domain's Containers
workspace.

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
  accounts, operator identity, custom TLS, the hosting toolkit, and
  subscription cache services.
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
  quota tooling, Podman, ProFTPD, Valkey, ClamAV signatures, PHP 8.3/8.4/8.5,
  Composer 2, WP-CLI, and Go builds

The realistic end-to-end target is Ubuntu 24.04. Some agent operations are
Linux-specific and cannot be fully exercised on macOS.

## Production Installation (Ubuntu 24.04)

One command from a checkout on the target server:

```bash
sudo deploy/install/install.sh --yes
```

The installer detects fresh installs versus upgrades (`panelctl version` /
`/etc/nakpanel/version`). Upgrades take a full pre-upgrade backup set and
roll back automatically when migrations or the post-upgrade health gate fail;
downgrades are refused without `--allow-downgrade`. To rebuild a server from
an encrypted backup archive:

```bash
sudo deploy/install/install.sh --restore /path/to/archive.nkbk --backup-key-file /path/to/key --yes
```

See `docs/RECOVERY.md` for server backups, disaster recovery, and
administrator recovery, and `docs/SOAK.md` for the long-run soak procedure.

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
panel, agent, and CLI, installs systemd units, and retains the Phase 28 and
adversarial security gates before Phase 29 reliability/disaster recovery.
Phase 30 then installs the current worktree and is the final gate: it proves
the detailed PHP runtime inventory, a real Classic WordPress 7.1 site, native
Managed PHP release/worker behavior, cross-subscription isolation, and reboot
recovery.

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
| `NAKPANEL_FTPS_PUBLIC_ADDRESS` | Public address advertised for FTPS passive data connections. |
| `NAKPANEL_FTPS_TLS_CERT` | Certificate path for the Nakpanel-managed TLS-only ProFTPD service. |
| `NAKPANEL_FTPS_TLS_KEY` | Private-key path for the Nakpanel-managed TLS-only ProFTPD service. |
| `NAKPANEL_VALKEY_IMAGE` | Optional official `docker.io/valkey/valkey` image pinned by SHA-256 digest. The Ubuntu installer resolves and pins `8.1-alpine` when omitted. |
| `NAKPANEL_PUBLIC_URL` | Canonical HTTPS panel origin used for five-minute customer SSO links. |
| `NAKPANEL_BILLING_WEBHOOK_URL` | Optional external billing webhook endpoint; HTTPS is required except for loopback tests. |
| `NAKPANEL_BILLING_WEBHOOK_SECRET` | HMAC-SHA256 webhook secret. Configure it only with the webhook URL. |
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
sudo -u nakpanel panelctl api-key create --name billing --cidrs 203.0.113.0/24
sudo -u nakpanel panelctl api-key list
```

The API key command prints the full `npk_...` value exactly once. Nakpanel stores
only its prefix, per-key salt, and SHA-256 digest. External billing uses the
bearer-authenticated `/api/v1` provisioning API; cookie sessions and CSRF tokens
are intentionally not accepted on those routes. Provider-scoped plans are
discoverable through `/api/v1/plans?provider=admin` or a `reseller:{id}` provider.

Hosting-toolkit verification is split across
`deploy/multipass/phase21-verify.sh` through
`deploy/multipass/phase25-verify.sh`. Each script reuses `nakpanel-lab` and
chains its prerequisite; `deployment-verify.sh` remains the canonical clean
deployment gate. `deploy/multipass/phase30-verify.sh` is the final direct gate
and chains Phase 29 unless `NAKPANEL_SKIP_PRIOR_PHASES=1` is set by the
canonical single-VM runner.

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
- Linux user creation, SFTP/FTPS confinement, ownership, disk quotas, and
  PHP-FPM/nginx rendering.
- Path-derived File Manager, Git, staging, scheduled-task, and log operations.
- Rootless Podman container generations and Valkey isolation, Unix-socket
  ownership, subordinate-ID allocation, and ACLs.
- Database migrations and data backfills.
- Plan, subscription, entitlement, and oversell behavior.
- Backup, restore, DNS, TLS, and reconciliation jobs.

Do not commit local secrets, production credentials, VM artifacts, database
dumps, or generated junk outside the project’s expected generated files.

## Project Status

Nakpanel currently covers the core control-plane, hosting provisioning, mail
workspace, external billing provisioning API, Classic PHP, and Managed PHP,
but it does not yet claim full cPanel/Plesk parity. WordPress Toolkit features,
Node.js/Python application runtimes, billing invoices, advanced reseller
hierarchy, and full production hardening remain external or future work.

## License

No license file is currently declared in this repository. Treat usage and
redistribution rights as unspecified until a license is added.
