# Domain and Subdomain Figma Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for native execution. Steps use checkbox tracking.

**Goal:** Implement the approved Domains/Subdomains design, deploy to nakpanel.com, and verify the changed journeys twice.

**Architecture:** Preserve Go/templ, embedded assets, the shared dialog controller, scoped HTTP handlers, observed-state job polling and domain-removal services. Add a focused domain workspace component and stylesheet; reuse existing Lucide icons and route helpers. No schema or agent change.

**Tech Stack:** Go, templ, vanilla JavaScript, embedded CSS, PostgreSQL/River, Playwright.

**Spec:** https://www.figma.com/design/hMmle03TChlSqaWiubt7IQ (overview 3:294; child 3:295; creation 6:616; removal 10:2749; mobile 8:1915 and 18:8575; acceptance 20:4420).

## Global Constraints
- Databases and backups are kept by default; optional database deletion stays explicit.
- Never remove an existing live site during QA. Use uniquely named new QA roots/children only.
- Maintain server-side ownership, provider scope, CSRF, support prefixes, entitlements and primary-domain protection.
- Redirect creation/removal only after observed completion, never a fixed timer.
- Partial SSL failures preserve hosting and expose retry; protect other hidden files.
- Preserve non-JavaScript routes and forms. No live reset, schema migration or OS installation.
- No external runtime assets; readable 14px text, 20px dialog titles, 26px page titles, 44px controls.

## Review Focus
- Long hostnames and 390px/short viewports must not push actions outside the viewport.
- Missing/disabled plan services must not be advertised as granted.
- Suspended/removing sites must not offer creation or unsafe actions.
- Multiple menus/dialogs must close predictably and restore focus.
- Async acceptance, partial SSL failure and lost responses must not duplicate operations.

### Task 1: Domain context and render contracts
**Files:** create domain_workspace.go, domain_workspace_test.go; modify workspace.templ and helpers only as needed.
**Interfaces:** consume existing dashboard.Site, SubscriptionSummary, DashboardActions, WorkspaceView; produce domainWorkspaceHeader, domainWorkspaceOverview, and shared context helpers.
- [ ] Add failing render tests for grouped header, parent context, single status strip, tools, entitlement states and support paths.
- [ ] Run focused tests and observe the missing UI assertions fail.
- [ ] Implement components with real data, preserving all POST routes.
- [ ] Regenerate templ and run focused tests.

### Task 2: List, mobile navigation and visual system
**Files:** domain_workspace.templ, static/domains.css, static/domains.js, assets.go, workspace.templ.
**Interfaces:** reuse shared dialog controller and existing list filters/sort; emit actual domain tool URLs.
- [ ] Add asset and navigation regression tests, including menu dismissal and active deep tools.
- [ ] Implement compact list, desktop tabs, grouped More, mobile drawer, aligned actions and bundled typography.
- [ ] Verify desktop/mobile screenshots, long names, overflow and controls.

### Task 3: Creation and removal dialogs
**Files:** workspace.templ, site_create.templ, site_removal.templ, static/site-removal.js, domain assets and tests.
**Interfaces:** preserve creation data attributes, setup status JSON and signed removal previews.
- [ ] Add failing tests for single-column field groups, fixed suffix, sticky actions, independent confirmation and retention defaults.
- [ ] Implement readable creation/removal layouts, accurate SSL states and inline errors without bypassing server validation.
- [ ] Run Go and Node regression suites.

### Task 4: Full verification and branch review
- [ ] Run go test ./... -count=1, go vet ./..., task build, Node suites, shell syntax and git diff --check.
- [ ] Run local browser QA at 1440x1000 and 390x844, including keyboard/focus and all domain links.
- [ ] Review the whole patch and fix material findings with regression tests.

### Task 5: Deploy and two live passes
**Files:** deploy/multipass/domain-workspace-browser-smoke.cjs and docs/verification/2026-10-17-domain-workspace.md.
- [ ] Record current binary/version and service state; stage verified binary with rollback available.
- [ ] Atomically install/restart the panel only; verify health, trusted TLS and unchanged hostname services.
- [ ] Pass 1: admin list/detail, create QA add-on and child with SSL, validation, all domain tool links, safe removal and retained DB/backup.
- [ ] Pass 2: repeat on distinct QA names; mobile/keyboard, support/client scope, primary restriction and retained data.
- [ ] Record exact evidence, remaining limitations and final deployed revision. Do not merge/push unless separately authorized.
