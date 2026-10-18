# Domain and Subdomain Design Verification

## Deployment

- Approved design: https://www.figma.com/design/hMmle03TChlSqaWiubt7IQ
- Live panel: https://nakpanel.com:7443/sites
- Deployed version: `29.0.0+55a330b-domain-figma`.
- Panel SHA-256: `565820c6f14c9bedae79780bf2dea954baaee2e19a0689304bb2469c91a169f6`.
- Branch: `ricky/domain-subdomain-figma`. No merge or push was requested for this change.
- Panel-only atomic deployment with a binary rollback retained under `/var/lib/nakpanel/deployments/domain-figma-20261018/`. No schema migration, agent replacement, data reset or OS reinstallation.

## Delivered

Compact domain inventory, grouped object headers and actions, one service-status strip, grouped overview tools, parent context, real subscription usage, bounded creation/removal dialogs, joined subdomain suffix, SSL validation recovery, and a grouped mobile tools drawer. Typography and icons are bundled; no runtime CDN is required.

Existing ownership, CSRF, entitlement, signed removal-preview and observed-state polling services remain authoritative. Creation redirects only after completion. Children never offer nested subdomain creation. Databases and backups remain kept by default; optional database removal is explicit and unchecked.

## Findings Fixed

1. Anchor-based dialog triggers followed their fallback URL after opening. Default navigation is now prevented only in the enhanced dialog path.
2. Long domain names pushed Close controls outside narrow dialogs. Header text now shrinks and wraps without shrinking the control.
3. The removal dialog exposed two Cancel controls and split its confirmation label across grid rows. It now has one contextual Cancel and a coherent label.
4. Literal hyphens in HTML validation patterns were invalid under modern Unicode-set semantics. Account/password patterns now compile and invalid database passwords are caught before submission. Server validation was not relaxed.
5. Long More menus exceeded short desktop viewports. They now choose the available side and scroll within its bounds.
6. Shared dialog geometry depended on being on a domain page. Component styles now remain consistent when the same dialog is rendered elsewhere.

Each material finding has a regression test or a browser assertion observed failing before the fix and passing afterward. A fresh independent review found no further material ownership or retention regressions.

## Automated Gates

- `go test ./... -count=1`: passed.
- `go vet ./...`: passed.
- `task build`: passed.
- `node --test internal/control/web/*test.cjs`: 117 passed.
- `git diff --check`: passed.
- `bash -n deploy/multipass/*.sh`: passed.
- Browser checks: 1440x1000, short 1440x620, 390x844 and 390x620. List filters, primary protection, dialog persistence, initial focus, Escape/focus restoration, independent acknowledgements, long names, mobile navigation, bounded footers, bundled assets and horizontal overflow passed.

The reproducible browser runner is `deploy/multipass/domain-workspace-browser-smoke.cjs`. The mutation runner requires explicit fixture opt-in, trusted SSH configuration and credential-file paths: `deploy/multipass/domain-workspace-live-verify.cjs`. Neither embeds credentials.

## Two Live Passes

| Pass | New QA add-on / child IDs | Retained Database | Retained Backup | Removal |
| --- | --- | --- | --- | --- |
| 1 | 3 / 4 | 2 | 1 | Child individually, then add-on |
| 2 | 5 / 6 | 3 | 2 | Add-on and child together |

Fixture roots were `figma-one-20261018.2-29-45-217.sslip.io` and `figma-two-20261018.2-29-45-217.sslip.io`. Isolated roots were used because the existing server correctly rejects adding a new independent domain beneath an already-hosted parent; that path must use Add subdomain.

Both passes verified:

- UI creation, real setup polling and completion redirects; trusted public HTTPS and HTTP redirects.
- Child creation from a matching full address, invalid-name preservation, and server rejection of nested children.
- Hidden-file denial with the ACME challenge path still reachable.
- All linked domain-tool routes rendered with navigation and no horizontal document overflow: hosting, PHP, mail, DNS, SSL, databases, backups, files, access, logs, tasks, statistics, Git, WordPress, PHP applications, containers, staging and cache.
- Database creation through the dialog, automatic active-state refresh, and phpMyAdmin launch.
- Completed backup creation; removal confirmations, pending state and convergence.
- Retained databases and backups stayed `active` with `site_id IS NULL`. Both retained archives remained downloadable.

Two additional tests used nakpanel.com's own authoritative DNS, rather than the isolated test suffix. QA children 7 and 8 obtained trusted SSL, then were removed. The second used a 63-character DNS label. Full-address normalization, no nested Add subdomain action, mobile tools and long removal headings passed on the final deployment.

Two client-scope passes created isolated empty QA customers 4 and 5. Client login/logout, empty own inventory, ten cross-tenant domain/tool `404` checks, forbidden plan changes, invalid CSRF rejection and support-view prefixes passed. These QA customers were suspended afterward; existing customer ownership was not changed.

## Final State

- Existing sites 1 (`nakpanel.com`) and 2 (`blog.nakpanel.com`) remain active with active TLS.
- All newly created QA websites were removed.
- QA databases 2 and 3 and backups 1 and 2 remain preserved under subscription 3.
- The two original mailboxes are unchanged.
- Panel, agent, nginx, MariaDB, BIND and Stalwart are active. No new retryable, discarded or cancelled River jobs were found in the deployment verification window.
- Local screenshots and machine-readable evidence are under `/tmp/nakpanel-domain-live` and `/tmp/nakpanel-domain-workspace` on the implementation machine.

## Scope

Live mutation testing covers the changed domain/subdomain creation, SSL, database, backup and removal journeys. Other tool pages received link/render checks and the full existing test suite. This is not a claim that every WordPress, Git, container, SMTP, FTPS/SFTP or advanced recovery operation was newly exercised end to end; their engines were not changed in this UI task.
