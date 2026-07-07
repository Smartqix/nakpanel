# nakpanel — Implementation Plan

> A cPanel/Plesk-class hosting control panel. Full Go. Ubuntu 24.04+ / nginx + PHP-FPM.
> This document is the spec of record. Hand each **Phase** to the coding agent as a scoped,
> independently testable task. The **Invariants** section is non-negotiable — the agent must
> treat those as hard constraints, not suggestions.

Codename `nakpanel` is a placeholder — rename the module freely.
Module path used throughout: `github.com/nakroteck/nakpanel`.

---

## 0. What this is (and isn't)

A control panel is not a UI. Underneath it is three things repeated across subsystems:

1. A **privileged execution boundary** (something runs as root; everything else does not).
2. A **deterministic config-generation engine** (DB intent → templated config → atomic write → reload).
3. A **state-reconciliation model** (intent lives in the DB; the system is made to match it).

We build **one vertical slice end to end** first (create a hosting account), because that slice
exercises all three pillars. Every later subsystem (mail, DNS, more DB engines) is a repeat of the
same pattern.

Scope for v1 is deliberately narrow: **Ubuntu 24.04+, nginx, PHP-FPM, MariaDB.** One lane, done correctly.

---

## 1. Invariants (the agent must never violate these)

These are the rules that keep the system secure and coherent. A change that breaks one of these is a bug,
regardless of how convenient it seems locally.

**Security boundary**
- The web/API tier (`panel`) runs as an **unprivileged** system user (`nakpanel`). It never runs as root.
- The panel **never** execs a shell command built from user input. Provisioning happens only by sending a
  structured request to the agent.
- The agent (`agent`) is the **only** component that runs as root. It exposes a **fixed, enumerated**
  vocabulary of operations — never a free-form "run this command" op.
- The agent validates **every field** of **every** request at the boundary before acting.
- The agent listens on a **unix domain socket only** (`/run/nakpanel/agent.sock`, root-owned, mode `0660`,
  group `nakpanel`). It **never** binds a TCP port. It is never network-reachable.

**Networking / ports**
- The panel **never binds 80 or 443.** Those belong to client websites (the tenant-serving nginx).
- The panel listens on exactly **one** port: `PanelPort` (default **7443**), **HTTPS only**, and it
  **terminates its own TLS**. No plaintext panel listener exists — not even a redirect.
- The panel is reachable **independently of the client nginx.** If a tenant vhost breaks nginx, the operator
  must still be able to log in and fix it. The panel binary serves its own TLS on its own port; it is not
  required to be reverse-proxied.

**Config generation**
- All system config (nginx vhosts, FPM pools, etc.) is **generated from templates**, written to a temp file,
  `fsync`'d, then **atomically renamed** into place, then the service is reloaded. Config is **never** hand-edited
  in place. Same intent → byte-identical output.

**State**
- **Intent lives in PostgreSQL** and is the single source of truth. The agent is a **stateless executor**.
- Every agent operation is **idempotent**, keyed by an idempotency `ID`. Re-running a request must converge to
  the same state, not error or duplicate.
- Intent row + provisioning job are enqueued in the **same DB transaction** (River). No "intent recorded but no
  job," ever.

**Roles**
- Admin, reseller, and client are **RBAC roles on one listener**, not separate ports/apps. (cPanel's split
  2083/2087 is a historical artifact we do not copy.)

---

## 2. Stack (locked)

| Concern | Choice | Notes |
|---|---|---|
| Language | **Go** (1.22+) | Single language across panel + agent. Static binaries, `go:embed`. |
| Control-plane router | **chi** or stdlib `net/http` | Go 1.22 `ServeMux` has method+pattern routing. Stay stdlib-compatible; **no** fasthttp/Fiber. |
| DB access | **sqlc** | You write SQL, it generates type-checked Go. Auditable. (`ent` is the alt if you want a graph ORM.) |
| Migrations | **goose** | Or golang-migrate. |
| Panel state DB | **PostgreSQL** | Non-negotiable. Source of truth + River backend. |
| Job queue | **River** | Postgres-backed. **Transactional enqueue.** No Redis. |
| Shared contract | `internal/types` | RPC envelope + intent structs, imported by **both** binaries. |
| Agent transport | JSON-over-unix-socket | Shared structs. Upgrade to gRPC-over-socket later only if needed. |
| Templating (UI) | **templ** | Typed Go components, compile-time checked. |
| Interactivity | **HTMX + Alpine** | Server-rendered partials; no SPA build. |
| CSS | **Tailwind standalone CLI** | Single binary. **No node/npm** in the build. |
| JS islands (only where needed) | xterm.js (terminal), uPlot/Chart.js (graphs), file manager | Embedded, targeted, not a framework. |
| Client DB engine (v1) | **MariaDB only** | `DBEngine` interface built for MySQL 8 / Postgres later. |
| DB admin UI | **Adminer** | Single PHP file; MySQL + MariaDB + Postgres behind one SSO. |
| Process mgmt | **systemd** | Units for `panel` and `agent`. |
| Target OS | **Ubuntu 24.04 LTS+** | MariaDB 10.11 LTS in main. |

**Distribution goal:** `templ generate` → Go; Tailwind → one CSS file; `go:embed` bakes templates + assets into
the `panel` binary. Install = drop two binaries + two systemd units. That single-binary property is the moat;
protect it (don't reintroduce a node build step, don't add Redis).

---

## 3. Port & login layout (folded-in spec)

**Constants — define once, in `internal/config`, and reference everywhere:**

```go
const (
    PanelPort   = 7443                         // panel HTTPS listener; the ONLY inbound panel port
    AgentSocket = "/run/nakpanel/agent.sock"   // unix socket; never TCP
    PanelUser   = "nakpanel"                    // unprivileged system user the panel runs as
)
```

`PanelPort = 7443` is a deliberate non-squat: not 2083 (cPanel), not 8443 (Plesk), not 8083 (Hestia), so we
never collide during a migration and never impersonate another panel. It's a single constant — change it in one
place if desired, then it must flow to the firewall rule and docs automatically (derive, don't hardcode twice).

**Login surface (the whole thing):**

- **Canonical:** `https://<server-ip>:7443` and `https://panel.<host>:7443` — served directly by the `panel`
  binary's own TLS listener. Works before DNS propagates, on a fresh box, and **when nginx is down**. This is
  the path documented in recovery procedures.
- **Convenience (optional):** `https://panel.<host>` on 443, reverse-proxied by the client nginx to the panel on
  loopback. Nicer URL, dodges high-port firewalls — but depends on nginx being healthy, so it is **never the
  only** path. If you add it, add it as a bonus, not a dependency.
- **Admin vs client:** same `:7443` listener, routed by **RBAC role**. No second port.
- **Webmail (Roundcube):** per-domain `https://webmail.<clientdomain>` on 443 via nginx. **Not** a panel port.
- **DB tools (Adminer):** a path behind the panel's own auth, e.g. `https://panel.<host>:7443/db`, reached via the
  SSO token handshake. **Not** a separate listener.

**TLS bootstrap for the panel itself:**
1. On first boot, if no panel cert exists, generate a **self-signed** cert and serve on `:7443` immediately
   (operator gets a browser warning — acceptable for a fresh box / IP access).
2. Store it; allow the operator to later attach an **ACME** cert for `panel.<host>` once DNS resolves. The
   listener hot-swaps to the real cert. ACME for the *panel hostname* is separate from ACME for *client sites*
   (Phase 4).

**Firewall (inbound allowlist — the entire attack surface):**

```
22    SSH
80    client sites (nginx)
443   client sites (nginx)
7443  panel (PanelPort)
```

The agent opens **no** inbound port. nftables/ufw rules are generated from the constants above.

---

## 4. Repository layout

```
nakpanel/
  go.mod                         module github.com/nakroteck/nakpanel
  sqlc.yaml
  Taskfile.yml / Makefile        build: templ generate, tailwind, sqlc, go build x2
  cmd/
    panel/main.go                unprivileged control plane (binds :7443)
    agent/main.go                privileged root agent (listens on unix socket)
    panelctl/main.go             (later) operator CLI
  internal/
    config/                      constants (PanelPort, AgentSocket, PanelUser), env loading
    types/                       SHARED CONTRACT: RPC envelope, intent structs, enums
    control/
      http/                      router, handlers, middleware (auth, RBAC, CSRF)
      auth/                      sessions, password hashing (argon2id), RBAC
      store/                     sqlc-generated code + hand-written queries
      jobs/                      River worker definitions
      agentclient/              dials AgentSocket, sends types.Request, decodes types.Response
      web/                       templ components + go:embed'd static assets (css/js islands)
    agent/
      rpc/                       socket listener, framing, dispatch, per-field validation
      ops/                       one file per op: create_site.go, create_database.go, ...
      provisioner/               system users, docroots, FPM pools, nginx render
      dbengine/                  DBEngine interface + mariadb adapter
      tmpl/                      nginx + FPM templates (go:embed'd)
  migrations/                    goose .sql files
  deploy/
    systemd/
      nakpanel.service           panel; User=nakpanel; after network
      nakpanel-agent.service     agent; runs as root; ExecStart before panel
    firewall/                    nftables ruleset generated from config constants
  docs/
    RECOVERY.md                  "log in on :7443 directly when nginx is down"
```

---

## 5. The shared contract (`internal/types`)

This package is the spine. Both binaries import it; it has **no** dependencies on either side.

```go
package types

import "encoding/json"

// Envelope ------------------------------------------------------------
type Request struct {
    Op   string          `json:"op"`   // enumerated; see Op* consts
    ID   string          `json:"id"`   // idempotency key (ULID)
    Data json.RawMessage `json:"data"` // op-specific payload
}

type Response struct {
    ID    string          `json:"id"`
    OK    bool            `json:"ok"`
    Data  json.RawMessage `json:"data,omitempty"`
    Error string          `json:"error,omitempty"`
}

// Enumerated ops (the agent's ENTIRE vocabulary) ----------------------
const (
    OpPing            = "ping"
    OpReloadService   = "reload_service"
    OpCreateSystemUser= "create_system_user"
    OpCreateSite      = "create_site"
    OpIssueCert       = "issue_cert"
    OpCreateDatabase  = "create_database"
    // extend deliberately; each new op is a reviewed addition
)

// Intent payloads -----------------------------------------------------
type CreateSiteReq struct {
    Username   string `json:"username"`    // validated: ^[a-z][a-z0-9]{2,31}$
    Domain     string `json:"domain"`      // validated FQDN
    PHPVersion string `json:"php_version"`  // allowlist: {"8.3","8.2"}
    Docroot    string `json:"docroot"`     // derived server-side, never trusted from client
}

type DBEngine string
const (
    EngineMariaDB DBEngine = "mariadb"
    EngineMySQL   DBEngine = "mysql"     // not implemented v1
    EnginePgSQL   DBEngine = "pgsql"     // not implemented v1
)

type CreateDatabaseReq struct {
    Engine   DBEngine `json:"engine"`   // default mariadb
    DBName   string   `json:"db_name"`
    DBUser   string   `json:"db_user"`
    Password string   `json:"password"` // generated server-side
}
```

Validation lives on the **agent** side and is exhaustive: reject unknown ops, reject any field failing its rule,
never fall through to a default that executes something.

---

## 6. Build order (hand each phase to the agent as one task)

Each phase ends with **acceptance criteria** the agent can verify. Do not start a phase before the previous one's
criteria pass.

### Phase 0 — Scaffold & spine
Set up the monorepo, `go.mod`, `internal/types`, `internal/config` (with the constants), sqlc + goose wired to a
local Postgres, and a Taskfile that builds both binaries. Stub `cmd/panel` and `cmd/agent` mains.
- [ ] `task build` produces `panel` and `agent` binaries.
- [ ] `goose up` runs against a local Postgres; a `users` table exists.
- [ ] `internal/types` compiles and is imported by both binaries.

### Phase 1 — Panel listener, auth, RBAC, nginx-independence
Implement the `:7443` HTTPS listener **in the panel binary** with self-signed bootstrap cert. Session auth
(argon2id passwords), and RBAC roles {admin, reseller, client} on the one listener. No reverse proxy involved.
- [ ] `panel` serves `https://<ip>:7443` with a self-signed cert, **with nginx stopped**.
- [ ] Login works; an admin and a client hit the same URL and get role-appropriate views.
- [ ] There is **no** plaintext listener and **no** bind on 80/443.
- [ ] `docs/RECOVERY.md` documents the direct-port login path.

### Phase 2 — The agent boundary
Root agent binary: systemd unit running as root, listening on `AgentSocket` (0660, group `nakpanel`). Implement
the envelope, dispatch, per-field validation, and two trivial ops: `OpPing` and `OpReloadService`. Panel gets an
`agentclient` that dials the socket.
- [ ] Agent listens on the unix socket; `ss -x` shows **no** TCP port for it.
- [ ] Panel (as `nakpanel`) can `Ping` the agent and reload a named service.
- [ ] Sending an unknown op or a malformed field returns a validation error and performs **no** action.
- [ ] Re-sending the same `ID` is a no-op that returns the same result (idempotency harness in place).

### Phase 3 — Vertical slice: CreateSite (the 60% milestone)
Panel records site intent + enqueues a River job **in one transaction**; a worker calls the agent's
`OpCreateSite`. The agent: creates the system user, creates the docroot (owned by that user), creates a
**per-site PHP-FPM pool** running as that user, renders the nginx vhost from a template (temp → fsync → atomic
rename), and reloads nginx + php-fpm. Fully idempotent.
- [ ] One API call provisions a working site reachable on port 80 serving a placeholder `index.php` as the site user.
- [ ] Killing the worker mid-job and re-running converges to the same state (no duplicate user/pool/vhost).
- [ ] The generated vhost is byte-identical on regeneration from the same intent.
- [ ] FPM pool runs as the site user, not root, not `www-data`-shared.

### Phase 4 — Client TLS (ACME) + MariaDB via DBEngine
`OpIssueCert` (Let's Encrypt for client domains). `OpCreateDatabase` behind the `DBEngine` interface with the
**MariaDB adapter only**; scoped grants (per-DB privileges so tenants are isolated); idempotent create.
- [ ] A client domain gets a valid LE cert and serves HTTPS.
- [ ] Creating a DB yields a MariaDB database + user with privileges scoped to **only** that database.
- [ ] `DBEngine` interface exists with `mysql`/`pgsql` returning "not implemented," so adding them later touches
      only the adapter.

### Phase 5 — UI
templ + HTMX + Alpine, styled with the Tailwind standalone CLI, all `go:embed`'d into the `panel` binary. Wire the
CreateSite and CreateDatabase flows to real screens. Add the terminal (xterm.js) and a resource graph
(uPlot) as embedded islands.
- [ ] `panel` is a single binary with **no external asset files**; deleting the source tree and running the binary
      still serves the full UI.
- [ ] Build has **no** node/npm step (Tailwind standalone only).
- [ ] Create-a-site and create-a-database are fully driveable from the UI.

### Phase 6+ — Later (not v1)
Webmail hostnames (Roundcube autologin), Adminer SSO at `/db`, backups (correctness-critical), local Bind DNS,
reconciliation/drift detection ("regenerate all configs"), additional PHP versions, MySQL 8 + Postgres adapters,
reseller quotas/cgroups. Each is a repeat of the Phase 3 pattern.

---

## 7. How to run this with Codex / Claude Code

- Keep this file at repo root as the spec of record. Point the agent at it at the start of every session.
- Work **one Phase per task**. Each phase has acceptance criteria — tell the agent "implement Phase N; it is done
  only when all checkboxes pass," and have it write the test/verification for each box.
- Re-paste **Section 1 (Invariants)** into any task that touches the agent, ports, or config generation. Coding
  agents will otherwise make locally-reasonable choices (running the panel behind nginx, giving the agent a TCP
  port, editing config in place) that quietly break the architecture. The invariants are the guardrails.
- The riskiest code is `internal/agent/rpc` (the root boundary) and `internal/agent/provisioner`. Ask for tests
  first there — especially the idempotency and validation paths.