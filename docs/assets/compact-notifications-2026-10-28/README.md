# Compact Notification Design Review

Prepared 28 October 2026 on `ricky/compact-notifications-design`, isolated from
the ongoing service-plan changes. This is a design artifact, not an application
implementation, hosted acceptance result or deployment.

## Review

- [Four-frame review gallery](review.html)
- [Interactive mockup](mockup.html)
- [Detailed design](../../superpowers/specs/2026-10-28-compact-notifications-design.md)
- [Implementation plan](../../superpowers/plans/2026-10-28-compact-notifications.md)

The gallery and mockup are self-contained HTML. The mockup embeds existing
bundled Inter and Lucide assets; it makes no external requests. The gallery's
links open the adjacent mockup. Use the bell, All/Unread, message titles,
overflow actions, search, Mark all read and View all notifications. Reload to
reset all fictional state. No login or server is required.

Open `mockup.html` with these query parameters for specific states:

| Parameters | State |
| --- | --- |
| `?view=preview` | Five-entry bell preview over an illustrative plan page |
| `?view=inbox` | Searchable full inbox in Activity |
| `?view=preview&state=single` | One alert; content-sized panel |
| `?view=preview&state=empty` | No notifications |
| `?view=preview&state=long` | Long domain and email text |
| `?view=preview&state=offline` | Retained last-known rows and connection note |
| `?view=preview&state=error` | Click Mark all read to show a failed receipt |

The mockup uses six fictional events and a fixed snapshot time of 28 October
2026, 10:40 America/New_York. It demonstrates layout and in-memory actions,
not live authorization, pagination, polling, network retries, issue recovery or
notification production. Issue/task detail is illustrative; the application
plan keeps the existing authorized linked detail views. Unrelated sidebar,
plan and Tasks controls are context only. Do not copy this shell into the app.

## Frames

| Frame | Viewport | Image |
| --- | --- | --- |
| Desktop preview | 1440 x 1000 | [JPEG](desktop-preview.jpg) |
| Desktop inbox | 1440 x 1000 | [JPEG](desktop-inbox.jpg) |
| Mobile preview | 390 x 844 | [JPEG](mobile-preview.jpg) |
| Mobile inbox | 390 x 844 | [JPEG](mobile-inbox.jpg) |
| Desktop one alert | 1440 x 1000 | [JPEG](desktop-single.jpg) |
| Mobile one alert | 390 x 844 | [JPEG](mobile-single.jpg) |
| Desktop empty | 1440 x 1000 | [JPEG](desktop-empty.jpg) |
| Connection interrupted | 1440 x 1000 | [JPEG](desktop-offline.jpg) |
| Failed action | 1440 x 1000 | [JPEG](desktop-action-error.jpg) |
| Standalone details | 390 x 844 | [JPEG](mobile-detail.jpg) |
| Unread empty | 390 x 844 | [JPEG](mobile-unread-empty.jpg) |
| Narrow long message | 320 x 844 | [JPEG](mobile-narrow-long.jpg) |

Supplemental screenshots show the same design; later refinements affected only
local action focus and the mobile inbox toolbar. The four primary frames and
standalone detail frame were recaptured after those refinements.

## Local Evidence

Checked the fictional prototype in the in-app browser, then inspected saved
desktop/mobile screenshots. Measured the rendered DOM rather than inferring
sizes from source CSS:

- Desktop preview: 400px wide; one-alert panel 259.5px high.
- Mobile preview: 366px wide at a 390px viewport; one-alert panel 270px high;
  populated panel capped at 620px with a 48px footer target.
- Narrow preview: 296px wide at a 320px viewport, no horizontal document
  overflow or overlapping header controls; 14px summary and 44px icon targets.
- The bottom-row overflow menu remained inside the scrollable list bounds.
- After a read action, focus returns to the row action trigger. After archive,
  it advances to the next visible message. Escape closes the menu before the
  preview; detail Escape returns to the bell if the opener was removed.
- All/Unread and search are independent between the inbox and preview.
- Read-all removes the badge and Unread shows All caught up. Error state keeps
  the unread count unchanged. Connection failure retains the last-known rows.
- Mobile inbox toolbar was tightened; first message begins at 420.5px rather
  than approximately 500px. Filter and read-all controls do not overlap at 320px.
- No warning/error console entries were returned during the final check.

The clean worktree's baseline `go test ./... -count=1` completed successfully
before design edits. Opt-in PostgreSQL/browser cases were not run; this is not
evidence that the proposed application changes have been implemented or tested.
The implementation plan defines two independent integrated acceptance passes,
including delayed requests, role/scope authorization, 200% zoom and real
PostgreSQL tests. Those remain future work.

## Rebuild

From the repository root:

```sh
node docs/assets/compact-notifications-2026-10-28/build.cjs
```

`mockup.template.html` is the editable source. `build.cjs` embeds the existing
font/icon assets into `mockup.html` and, when the primary JPEGs exist, rebuilds
the embedded-image `review.html`. Screenshots are captured separately from the
rendered prototype; rebuilding does not invent or update evidence.

Inter and Lucide remain subject to their existing license notices in the
repository's bundled asset directories. No external fonts or CDN assets were
introduced. No production credential, preview token or private runtime file is
part of this artifact.
