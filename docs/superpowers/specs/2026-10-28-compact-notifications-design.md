# Compact Notification Preview and Full Inbox

Status: the owner approved this direction and authorized desktop/mobile mockups
and an implementation plan on 28 October 2026. Application implementation,
hosted tests, deployment, merge and push are not authorized by that approval.

## Intent and Evidence

Make account and hosting notifications easy to scan without interrupting a
Service Provider workflow. Compact means fewer competing controls and better
hierarchy, not smaller or lower-contrast text.

The supplied Service Plan screenshot shows a notification body reduced to a
narrow text column beside two large action buttons and a long timestamp. Local
source review confirms that `operations.js:rows` uses the same horizontal row
for a full page and the 480px quick panel. Its client `stamp` formatter also
replaces compact server-rendered times with a full localized datetime. Quick
rows are replaced on every poll, and quick-panel failures use a status target
that is absent on ordinary domain/plan pages. Standalone account alerts have
no full-message opening action.

This is screenshot and source evidence, not a new hosted acceptance result.
The application was not contacted or changed for this design.

Research grounding:

- [Plesk UI notifications](https://docs.plesk.com/en-US/obsidian/administrator-guide/plesk-administration/plesk-ui-notifications.80000/): unread indicators, filters, mark-all-read and persistent notification access.
- [Carbon notification guidance](https://www.carbondesignsystem.com/building-blocks/core/components/notification/guidelines): short previews and a destination for longer information.
- [PatternFly notification drawer guidance](https://www.patternfly.org/components/notification-drawer/design-guidelines/): clear unread states, timestamps, local actions and explicit dismissal semantics.

The exact sizes and interaction decisions below are Nakpanel design decisions,
not claims about those products' implementations.

## Approaches

1. **CSS repair only:** cheapest, but still shares full-page rows with the quick
   panel and leaves message opening, focus loss and silent failures unresolved.
2. **Compact preview plus full inbox — selected by the owner:** a bounded bell
   panel for scanning, with Activity's existing Notifications tab for history
   and search. Dedicated presentation variants share safe data and actions.
3. **Permanent right drawer:** more room for managing history, but obscures
   hosting settings and works against the requested compactness. Not selected.

## Goals and Non-Goals

Goals: readable messages; a short single-alert panel; stable keyboard use;
predictable read/archive actions; full authorized content for standalone
messages; identical scope and unread counts across preview and full inbox.

Do not rebuild the operations engine, add a sidebar destination, change SMTP
policy, create new notification producers, rewrite incident recovery, add
mark-unread or archive-all actions, or introduce a frontend framework. Do not
copy the illustrative service-plan form from the mockup into application code.

## Mockups

The self-contained [interactive artifact](../../assets/compact-notifications-2026-10-28/mockup.html)
uses existing bundled Inter and Lucide assets. All accounts, addresses, domains,
timestamps and event states are fictional. The snapshot anchor is 28 October
2026, 10:40 America/New_York. It has no production API calls or persistence.

| Frame | Viewport | Artifact |
| --- | --- | --- |
| Desktop bell preview | 1440 x 1000 | [JPEG](../../assets/compact-notifications-2026-10-28/desktop-preview.jpg) |
| Desktop full inbox | 1440 x 1000 | [JPEG](../../assets/compact-notifications-2026-10-28/desktop-inbox.jpg) |
| Mobile bell preview | 390 x 844 | [JPEG](../../assets/compact-notifications-2026-10-28/mobile-preview.jpg) |
| Mobile full inbox | 390 x 844 | [JPEG](../../assets/compact-notifications-2026-10-28/mobile-inbox.jpg) |

Single-alert, empty, connection-interrupted and standalone-detail frames are
included with the artifacts. They supplement, rather than replace, the exact
production acceptance cases. An illustrative successful event in the mockup
does not authorize adding a new backend event producer.

## Visual Contract

| Element | Decision |
| --- | --- |
| Typography | Existing bundled Inter. Heading 16px/24px, row title and summary 14px/20px, metadata 12px/18px. No viewport-scaled fonts or negative letter spacing. |
| Colour | Existing graphite/cobalt shell; white surfaces; text `#202936`, secondary `#526176`, timestamp `#637187`, accent `#245ce8`. Verify contrast in the rendered implementation. |
| Surface | One panel, 1px subtle border, 8px radius, restrained shadow. Notification rows share dividers, not individual cards. |
| Desktop preview | Width 400px; viewport inset at least 12px; maximum height 560px or available height, whichever is smaller. Height is content-driven. |
| Mobile preview | Viewport width minus 24px; maximum height 620px or available height, whichever is smaller. No fixed minimum height. |
| Position | Anchor to the actual bell rectangle, including a wrapped/taller mobile topbar. Keep 8px below the trigger and 12px from viewport edges; do not hardcode a topbar height. Recompute on resize and visual-viewport changes. |
| Preview structure | Header, All/Unread selector, independently scrollable list, footer. Header/footer stay visible. Latest five matching notifications, fetched with `limit=5`. |
| Rows | Icon + `minmax(0,1fr)` message + fixed action column. Summary previews clamp to two lines. Titles can wrap. Never reserve a full timestamp column. |
| Controls | Desktop 32px icon targets, mobile at least 44px. The footer's whole link area is a target: 44px desktop, 48px mobile. Bundled Lucide icons and meaningful tooltips/names. |

The desktop single-alert frame must remain below 300px high at the standard
fixture text length. Long inputs may increase it within the bounded panel;
never clip a title or squeeze text to keep an arbitrary row height.

## Interaction and State Contract

### Preview and Inbox

- Bell count is the authorized viewer's unread count, not open issues or active
  jobs. Hide zero; display `99+` visually above 99 and expose the exact count in
  the accessible name.
- Opening the preview does not mark anything read. Default to All. The preview
  and full inbox maintain independent All/Unread selections; full-page search
  must not filter the preview. Resource scope is shared and authoritative.
- `View all notifications` opens the existing scoped `/activity?tab=inbox`
  destination. No new sidebar item. Subscription and support prefixes remain.
- The full inbox uses the same content hierarchy with its wider density,
  search and existing keyset pagination. Search matches only the title,
  authorized safe summary and authorized target label, never hidden raw bodies.
- On mobile, keep All/Unread and Mark all read on one toolbar row, with search
  directly below. Omit redundant eyebrow/count text rather than shrinking
  messages or stacking every control into its own row.
- Group full-page rows by Today, Yesterday and older dates in the browser's
  timezone. Before hydration, use unambiguous absolute UTC date headings.
- Use compact elapsed times below 24 hours and a short date thereafter. Exact
  localized date/time, including timezone, is available in details and a time
  tooltip. SSR/client use the same compact thresholds; no full datetime column.

### Opening a Message

- An issue/task-linked notification opens its current existing details, with
  authorized settings links and recovery rules unchanged.
- A standalone event, such as a new sign-in address, opens a named notification
  detail dialog. Fetch it through a new authorized read endpoint before marking
  it read. Show the complete permitted summary, bounded to 2000 characters by
  the existing safe-summary policy, not raw logs, transport errors or secrets.
- A successful detail load marks only that viewer's selected notification
  read. A failed, denied, superseded or cancelled load does not. A failed read
  receipt leaves the content open and reports that read status was not saved.
- Reading and archiving do not acknowledge, resolve, retry or delete an issue,
  task, resource, audit event or other viewer's receipt.

### Actions and Failures

- Row overflow: Mark as read when unread, and Archive. No delete action.
  Archive hides the viewer's notification only; it is not data deletion.
- Mark all read applies to all currently authorized non-archived messages in
  the current resource scope, not only the latest five or a search result.
  Use the existing scoped service. Show that scope in its accessible label.
- Await receipt success before changing read/archive state. Disable duplicate
  actions while pending. After success refresh authoritative counts; a new
  notification arriving concurrently may leave a nonzero badge.
- Failed requests produce a local row/panel error and retry action. Do not
  rely on the Activity page's status element from a Service Plan or domain page.
- Loading, empty, unread-empty, search-empty, offline/stale, action failure,
  401/session-expired and 404/no-longer-authorized are distinct states. Retain
  last-known rows/counts on connection failure; never replace them with zero.
- No new routine toasts or auto-opening critical modals in this change. Existing
  task-result and issue-recovery behavior remains authoritative.

### Focus, Refresh and Navigation

- Escape closes the topmost action menu, then the preview, returning focus to
  the relevant trigger. Outside click closes the preview without stealing
  focus from the clicked field. Only one Tasks/Notifications quick panel opens.
- A preview is non-modal: Tab is not trapped. A real detail dialog uses the
  existing shared dialog controller for focus trap, nested Escape and restoration.
- Reconcile rows by notification identity. Do not replace a focused button or
  open action menu on polling. Preserve scroll and the visible row anchor.
  Defer poll-driven reorder/removal while interacting; apply deferred ordering
  on close/reopen. A deliberate successful archive focuses the next row, the
  previous row, or the panel heading when empty, in that order.
- Use the existing operations poller and lifecycle. No second notification
  interval. Abort on navigation/scope change and ignore late results. Preserve
  the underlying form's dirty state and unsaved values.

## Backend Boundary

No database migration is expected. Extend the current `Notification` read DTO
with an authorized `target` label. Add:

```go
Notification(ctx context.Context, actor auth.SessionUser, id int64,
    scope operations.Resource) (operations.Notification, error)
```

Expose it as `GET /api/workspace/operations/notifications/{id}` with the current
resource query parameters. Validate identity, resource scope and current
`NotificationVisibilitySQL`; return 404 for cross-tenant/out-of-scope records.
Detail reads have no receipt side effect. Allow an authorized archived record
to be read by its ID; archive is not authorization revocation. Counts/lists
continue to exclude archived receipts. Keep read/archive POSTs and their current
per-user authorization/CSRF contract; these change only personal receipts.

Use a single safe-summary projection for list, detail and search. Update all
current callers and tests directly; no adapters or historical schema paths.

## Constraints and Authorization

- Existing Go/templ, embedded CSS, vanilla JS and stdlib HTTP only.
- No external fonts, CDN scripts, framework rewrite or new browser dependency.
- Do not change mail delivery, retention, access policy or resource lifecycles.
- Ubuntu 26.04 LTS (Resolute) is the only supported server OS. Reject unsupported
  server OS versions before mutation. No Noble packages or retired matrices.
- Preserve hosting PHP 8.3/8.4/8.5, isolated FPM/CLI readiness and validated
  internal PHP 8.5, using the signed Resolute Sury provider/descriptors.
- Local mockup/fixture verification is authorized. Hosted tests and deployment
  require separate explicit authorization and a phase report before proceeding.

## Acceptance and Deliberate Limits

Validate the screenshot's single long sign-in event plus 0, 1, 5 and 50 events;
long account/domain names; unknown kinds; stale results after scope changes;
slow/failing read/archive/detail requests; and rapid repeated clicks.

Run desktop/mobile visual and keyboard checks twice at 1440x1000 and 390x844,
plus 320px width and 200% zoom. Require no horizontal document overflow,
intersecting controls, truncated title, silent failure or lost form edits.

The mockup demonstrates local, in-memory interactions and is not evidence of
implemented authorization, production notification sources or hosted readiness.
Production implementation and its two-pass evidence remain pending approval.

## Design Review Record

The local mockup/source review and measured layout evidence are recorded in the
[artifact notes](../../assets/compact-notifications-2026-10-28/README.md).
The independent read-only builder check reported no important unresolved design
questions. This is design review only; authorization and integration still need
the application tests in the implementation plan.
