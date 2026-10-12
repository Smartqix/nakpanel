# Panel Interactions

The embedded `interaction.js` loads before the main UI and Git scripts.
Existing AJAX workflows use `NakpanelUI.fetch` for same-origin requests,
JSON negotiation, mutation CSRF headers, a bounded timeout, and consistent
session/error messages. Non-JSON partial refreshes explicitly request HTML.
Mutation requests are never automatically replayed after network uncertainty.

Busy-state helpers restore each submit control's previous disabled state.
Domain database and Git workflows keep their scoped polling and partial refresh;
server tools retain operation polling. Plain server forms and normal page links
remain supported; this change does not turn every route into SPA navigation.

For new enhanced forms, use the shared request helper and the existing server
JSON contract. Keep validation feedback inside the active form/dialog, preserve
non-secret values on failure, prevent duplicate submissions, and distinguish
accepted work from completed work. Refresh only the affected resource view,
without replacing a dirty form. Keep CSRF, authorization, and idempotency checks
server-side. Do not automatically retry mutations or persist secrets in browser
storage.

Tests: `node --test internal/control/web/*test.cjs` and `go test ./...`.
