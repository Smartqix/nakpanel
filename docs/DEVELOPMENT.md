# Local development

Server provisioning targets Ubuntu 26.04 only. macOS can build the Go commands
and run local checks; a macOS build does not establish Linux provisioning or
native server acceptance.

## Prerequisites

- Go **1.26.9**, pinned in [GO_VERSION](../deploy/release/GO_VERSION).
- A running local PostgreSQL server and an empty development database.
- [Task](https://taskfile.dev/), Git and a shell environment.
- Network access for the pinned Go generation tools and Tailwind CLI.

Create the development database with your local PostgreSQL administration tools.
Use a role permitted to create objects in that database. Set the connection for
your own local credentials before applying migrations; the example below assumes
that the `postgres` role and `nakpanel` database already exist.

```bash
git clone https://github.com/Smartqix/nakpanel.git
cd nakpanel
export NAKPANEL_DATABASE_URL='postgres://postgres@localhost:5432/nakpanel?sslmode=disable'

task goose:up
task river:up
task build
go test ./... -count=1
```

These commands build the panel, agent and `panelctl`; they do not install the
Linux service stack or launch a hosted guest. Use only a disposable development
database. The example DSN is loopback-only and is not a deployment configuration.

Some integration tests require separately configured disposable databases.
The [Operations guide](operations-center.md#development-schema-and-release-validation)
describes `NAKPANEL_OPERATIONS_TEST_DSN`; CI creates its private fixtures.
A local test run with missing optional fixture DSNs is not full database acceptance.

## Generated assets and common commands

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

## Repository map

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

## Working policy

Nakpanel is before production release. Breaking changes are allowed; legacy
compatibility, backfills, and historical upgrade or restore paths are not
required unless explicitly requested. Development databases, fixtures, and test
backups may be recreated for the current design. Update code, callers, tests,
and documentation together while retaining explicitly requested platform support
and current security requirements. See [AGENTS.md](../AGENTS.md) for project guidance.

## Server validation

See [Verification](VERIFICATION.md) for current-version gates, native architecture
qualification and evidence limits. Hosted tests require explicit authorization.
Do not start a Multipass guest just to validate documentation or static images.
