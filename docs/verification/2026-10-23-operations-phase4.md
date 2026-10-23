# Operations center — phase 4 local UI evidence

Implemented the reviewed Figma flow using the existing sidebar and design tokens:
Activity Issues/Tasks/History/Notifications, personal unread counts, active task
quick view, scoped lists, details/attempts, acknowledgement, independent recovery
checks and explicit backup retry confirmation. Read, acknowledged and resolved
remain distinct. Original failures remain visible after a retry.

One lifecycle controls live updates. It retains the feed cursor, aborts stale
navigation requests, pauses hidden tabs and preserves last-known data on failure.
Paging does not reset while background updates arrive. Unsupported recovery
buttons remain absent. A native dialog supplies focus containment and Escape;
closing restores focus. Counts and initial HTML use the durable scoped read model.
The old raw dashboard jobs, competing aggregate attention and task poller were
removed. Resource-specific readiness displays remain.

Local verification:

- Focused web, HTTP, dashboard and panel tests pass.
- All 250 JavaScript tests pass; operations tests cover scope races, reconnect
  cursors, aborted results and bodyless CSRF-protected acknowledgements.
- A fresh headless Chrome profile used the loopback-only fictional fixture at
  1440×1000 and 390×844. Recovery requires a checked confirmation, the dialog
  closes, Escape restores quick-panel focus, and mobile has no horizontal overflow.
  No browser script errors were recorded. Screenshots were visually inspected.
- The visual pass found author CSS overriding `hidden` on pagination buttons;
  the operations stylesheet now enforces hidden state. Active tabs and severity
  styling persist after live refresh.

Preferences controls are wired; phase 5 implements their persisted policy and
email delivery. No SMTP or hosted acceptance is asserted here. The broader local
suite is recorded separately in the final acceptance report.
