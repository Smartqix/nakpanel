# Notifications, Tasks and Issues — proposed design

Status: research and design proposal, 23 October 2026. Implementation, hosted
tests, PR creation and deployment are not authorized by this document.

**Figma:** [editable designs and flows](https://www.figma.com/design/xKb9jZ6VvLAWEwwsKRZeG5).
**Primary flow:** [notifications to recovery](https://www.figma.com/proto/xKb9jZ6VvLAWEwwsKRZeG5?node-id=3-1711).
**Plan:** [phased implementation](../plans/2026-10-23-notifications-tasks-issues.md).

All Figma scenarios use fictional `.example` resources. The example overdue
backup is a designed failure scenario, not a finding about nakpanel.com.

## What we have today

Fresh authenticated inspection covered Home, the Tasks tray and Activity.
The live server was healthy during inspection; no failure, retry or destructive
operation was triggered. The following code findings explain the visible UX:

| Existing foundation | Evidence and gap |
| --- | --- |
| Global Tasks tray | `dashboard/tasks.go`, `web/tasks.go`, `web/static/tasks.js`: at most eight recent jobs, a separately calculated active count, polling and completion toasts. Completed maintenance can dominate the tray. A transition outside the bounded list can be missed. |
| Activity | `web/workspace.templ:routedActivity`: alerts, raw job rows and audit events are stacked together. The captured job list included blank DNS targets and machine names such as `configure_dns_zone`. |
| Health and grouping | `web/attention.go`: useful severity, site health and duplicate grouping already exist. Some grouping keys use kind/title or job kind rather than an explicit resource incident. These are UI projections rather than durable issue lifecycles. |
| Notifications | `quota/usage.go` and the notification schema: durable rows, dedupe keys, resolution timestamps and SMTP delivery records exist. A shared notification `read_at` is insufficient for independent read state across multiple viewers. |
| Recovery | `provision/recovery.go`, `http/server.go`: administrator-only retry of selected discarded jobs. The current retry resets the same River row; the proposed UX needs preserved logical attempt outcomes and explicit capabilities. |
| Navigation | Existing fragment navigation and a single task poller can be reused. The new design does not require a frontend rewrite or a separate message broker. |

Screenshots are retained privately with this design task. They were not uploaded
to Figma because Activity contains real account and sign-in metadata. The design
does not claim that failure states were exercised on the live server.

## What to learn from Plesk

These are documented patterns, followed by our own recommendations. The new
Nakpanel issue model is a proposal, not a claim about Plesk's internal schema.

- Plesk provides a notification pane with unread indication, search, filters,
  mark-all-read and retention controls; critical events can also appear as
  pop-outs. Adopt a persistent inbox and selective interruptions.
  [Plesk UI notifications](https://docs.plesk.com/en-US/obsidian/administrator-guide/plesk-administration/plesk-ui-notifications.80000/).
- Plesk separates email notification recipients and customization from UI
  notifications. Give Nakpanel channel preferences and administrator delivery
  health, rather than assuming every in-app message should become an email.
  [Automatic email notifications](https://docs.plesk.com/en-US/obsidian/administrator-guide/59422/).
- Plesk Monitoring can notify when a threshold is exceeded and when the resource
  returns to normal. Pair incident detection with observed recovery.
  [Monitoring](https://docs.plesk.com/en-US/obsidian/administrator-guide/statistics-and-monitoring/monitoring.68886/).
- Plesk's official **Onyx-era** background-task UI guide describes progress that
  remains accessible while users work elsewhere. Use that historical UX pattern
  as inspiration, not as evidence of current Obsidian behavior or OS support.
  [Background tasks](https://docs.plesk.com/en-US/onyx/extensions-guide/ui-design-guide/background-tasks.79787/).

## Recommended information architecture

Keep **Activity** in the sidebar. Give it **Issues**, **Tasks** and **History**
tabs, shared across global, subscription and domain scopes. Default to Issues
when action is needed. A scoped view keeps its resource filter and return path.
Do not add another sidebar destination or duplicate history below an Overview.

| Surface | Answers | Badge | State belongs to |
| --- | --- | --- | --- |
| Notification bell/inbox | What changed that I need to know? | My unread messages | The viewer |
| Tasks button/quick panel | What is still happening? | Authorized active operations | The operation |
| Activity → Issues | What currently needs action? | Authorized open incidents, including acknowledged ones | The affected resource |
| Activity → History | What happened, who acted, and what was verified? | None | Immutable event/attempt history |

Only one quick panel is open at a time. Returning from an issue preserves the
previous resource, filters and scroll position. Routine reconciliation goes to
History, not a stream of completion interruptions.

## State and interaction contracts

**Notifications:** unread → read → optionally archived, independently per user.
Reading, marking all read, archiving or changing email preferences cannot resolve
or acknowledge an issue. Critical alerts remain available in-app. Opening an
unread item marks that item read and follows its authorized deep link.

**Tasks:** queued → running → waiting to retry/running → succeeded, failed or
cancelled. Group attempts under one logical operation; preserve every terminal
attempt result. Show a real stage and elapsed time. Show percentages or estimated
completion times only when the worker supplies reliable measurements. Ordinary
worker completion does not establish a verified recovery.

**Issues:** open → acknowledged/investigating → checking recovery → resolved.
Acknowledgement records the actor and time while leaving the issue open. Dedup
by incident kind, resource identity and condition, not display text. Repeated
failures update occurrences and evidence. A recurrence after verified resolution
opens a new incident linked to the previous one.

**Recovery:** explain impact, likely cause, affected scope, last observation and
the next safe action. Recheck current permissions, ownership, resource intent,
worker capability and prerequisites at mutation time. A safe retry creates a new
attempt from current intent. Disable the action with a reason if it cannot be
performed. Do not expose generic retry, force-cancel or repair-all for restores,
removal, updates, credential changes or other destructive operations.

The prototype's running-to-resolved transition compresses time for demonstration.
The implemented product must wait for a verifier receipt, never a timer. Archive
verification establishes archive integrity and freshness; it does **not** claim
a full restore rehearsal or prove application recovery.

For webmail, for example, configured intent is not sufficient recovery evidence:
the expected HTTPS hostname and applicable readiness checks must pass. Public
DNS uncertainty must be shown as uncertainty. Unknown or stale observations must
never be presented as healthy.

## Role and scope boundaries

| Role | Sees | Can do in the first release |
| --- | --- | --- |
| Administrator | Authorized server and tenant issues; personal notification receipts; redacted technical diagnostics | Acknowledge, manage delivery policy, run allowlisted safe recovery after preflight |
| Reseller | Its customers/subscriptions and their allowed resource details | Read and acknowledge in scope; open permitted resource settings; request provider action for restricted recovery |
| Customer | Its own subscriptions/sites and relevant messages | Read and acknowledge own issues; open permitted settings; contact the provider when administrator action is required |

Retain the current administrator-only retry boundary initially. Expanding a
specific recovery action to reseller/customer roles requires a separate typed
capability and tests; do not make every retry available because a user can view
the operation. Filter counts, cursor feeds, detail routes and action endpoints
with the same ownership rules. Recheck after role changes, transfers, suspension
or deletion. Preserve historical labels without reviving access to removed data.

## Backend design using existing foundations

Keep Go, PostgreSQL, River, templ and the existing navigation lifecycle. Add a
small `internal/control/operations` package for the shared read model and domain
contracts; keep each provisioning worker responsible for its actual mutation.

- `operations` stores logical operation identity, typed resource scope, trigger,
  summary state, timestamps and correlation ID.
- `operation_attempts` stores immutable attempt outcomes, River job links,
  sanitized error codes and optional verification receipts.
- `issues` stores incident identity, severity, condition, scope, acknowledgement,
  occurrence counts, last observation, a monotonic incident generation and
  recovery evidence tied to the observed resource intent revision.
- A transactionally recorded event/outbox connects operation, issue and
  notification changes. A durable dispatcher replays undispatched events after
  restart; River insertion and dispatch acknowledgement share a PostgreSQL
  transaction where supported. Consumers deduplicate by event identity. Cover
  crashes after source commit, during enqueue and before acknowledgement so
  neither a process crash nor duplicate delivery loses a transition. Do not add
  another queue product.
- Reuse notification/delivery concepts. Replace the shared read-state contract
  with unique `(notification_id, user_id)` receipts and role-aware preferences.
  Update callers, fixtures and schemas directly; no old/new dual paths or backfill.
- Cursor-based updates deliver every relevant transition, even when an operation
  starts and ends between polls. Keep the current backoff, hidden-tab abort and
  navigation lifecycle. Avoid a second independent poller for each badge.

Some issues have no failed job. Define scheduled, idempotent detectors for
certificate expiry and overdue backups, alongside worker-driven observations.
Each condition owns its threshold, grace period, observation freshness, cadence
and recovery predicate. Re-observe open incidents and after relevant changes;
unknown/stale checks keep the issue open with uncertainty. A renewed certificate
needs current certificate/readiness evidence; an overdue backup needs a verified
fresh archive. Replace the corresponding transient attention projections with
the durable issue query so one condition cannot vanish or appear twice.

A verification receipt names the incident generation, latest occurrence and
resource intent revision it checked. Resolve with a conditional update against
all three. A newer failure, changed intent or stale receipt invalidates that
resolution and schedules a fresh check. Completion timestamps alone cannot
establish ordering or close a newer incident.

An SMTP acceptance is labeled **Accepted by SMTP**, not Delivered. The inbox is
durable when SMTP is unavailable. Delivery retries are bounded; the delivery
failure issue must not recursively generate unlimited failed emails. Digests and
preferences must respect current authorization at send time as well as enqueue.

Proposed retention defaults: personal notifications 30 days, resolved operations
and issues 90 days, open issues until resolved, audit events under a separate
administrator policy. These are product defaults for review, not legal retention
claims. Expiring detailed diagnostics must leave a safe outcome summary.

## Designed flows and edge states

1. **Discovery:** sidebar issue count → prioritized Issues list → scoped detail.
2. **Notification:** unread inbox → failed task or issue; mark-all-read leaves
   the issue count and open condition unchanged.
3. **Task:** active-first list → stage/progress; a terminal failure links to an
   incident rather than creating repeated independent alerts.
4. **Recovery:** failed attempt → issue impact → prerequisite check → confirmation
   of scope/preservation → new attempt → verification → resolved receipt.
5. **History:** original failure, acknowledgement, retry and verified result stay
   linked. Successful recovery never rewrites the original failure as success.
6. **Preferences:** personal channels/digests are separate from administrator
   sender/delivery configuration and mandatory in-app categories.
7. **Mobile:** the same scope and state vocabulary, stacked rows, usable touch
   targets and independently scrollable content.
8. **Exceptions:** loading, offline/stale, empty, permission denied, retry blocked,
   missing resource and email degraded. Keep old data during disconnection; do
   not flash zero counts or show an unsupported success state.

Use Inter, the existing dark sidebar and blue controls. Use words/icons as well
as color. Require visible focus, meaningful accessible names, 44px primary touch
targets, Escape/close behavior, focus return and restrained live announcements.
Trap focus only in genuinely modal confirmations; respect reduced motion.

The first Figma preference screen specifies policy values and layout. Implementing
its switches, selectors, save errors and role variants is included in phase 4/5;
the Figma prototype demonstrates the primary recovery path, not every setting.

## Acceptance and limits

- A failed operation creates one correctly scoped incident, including after
  multiple attempts. Independent resources are never merged by title.
- Counts and lists agree across roles and do not depend on the last eight jobs.
- Per-user read/acknowledgement/recovery semantics remain distinct.
- Queued work, stale observations and SMTP acceptance cannot produce false
  recovery/delivery claims. Secret-bearing logs are never exposed to tenants.
- Retry is idempotent, authorized against current intent and retains the failed
  attempt. Recovery is verified independently of worker completion.
- Conditions without failed jobs are detected and re-observed; dispatcher
  restarts lose no transitions. Out-of-order verification cannot resolve a newer
  failure or a changed resource intent.
- No change to hosting PHP 8.3/8.4/8.5, validated internal PHP 8.5, signed Resolute
  providers, backup/restore isolation or supported OS rules is part of this work.
- Figma artifacts are editable native nodes and shared component instances.
  Designs and proposed schemas are not evidence of implemented behavior.

Design-review decisions still open: retention defaults, digest schedule and the
event categories each role may mute by email. They do not block reviewing the
proposed interaction flow. No project code should be implemented from this draft
until the user authorizes a phase.
