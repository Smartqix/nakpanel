# Subscription Site Form Fix Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task by task. Track steps with the checkboxes below.

**Goal:** Make Add website submit the selected subscription correctly without changing the user's chosen UX deployment.

**Architecture:** Correct the browser encoding for the non-upload site form, and defensively parse bounded multipart requests at the site endpoint. Keep the existing provisioning manager, entitlement checks, ownership checks, and normal form fallback authoritative.

**Tech Stack:** Go net/http, embedded vanilla JavaScript, existing Go handler tests, Playwright, Ubuntu 24.04 Multipass.

**Spec:** User-approved investigation in this task: subscription 39 (`kofik`) is active, its customer is active, its entitlement snapshot exists, and its system account is in sync. The rendered dialog selects ID 39. Identical invalid-domain probes recognize the subscription when URL-encoded, but return `no active subscription` when multipart.

## Global Constraints

- Preserve the selected UX; do not deploy the separate Phase 34 worktree wholesale.
- Do not recreate subscriptions, modify quotas, bypass RBAC, or disable CSRF.
- Do not create the domain from the screenshot without authorization.
- No migration, package update, VM reset, broad installer run, commit, or push.
- Preserve every existing unrelated local change and the lab's current data.
- Subscription IDs, limits, PHP availability, and ownership remain server-validated.

## 1. Establish the Deployment Baseline

- [ ] Record the running panel binary checksum and Go build metadata, service configuration, and current source revision. Identify the source of `/tmp/np-panel-ux`, not merely the most recent `/tmp/nakpanel-src` directory.
- [ ] Compare the current rendered subscription page and embedded JavaScript with that source. Save desktop/mobile baseline screenshots and checksums.
- [ ] Ensure no other deployment is running. If the exact UX source cannot be established, stop before binary replacement and report the source mismatch.
- [ ] Capture the active status and entitlement IDs for subscription 39 using read-only queries. Do not log session cookies or CSRF tokens.

## 2. Regression Tests and Transport Correction

**Files:** `internal/control/web/static/app.js`, `internal/control/http/server_test.go`; create `internal/control/http/site_form_test.go` for focused parsing cases if the existing test file would become unwieldy.

- [ ] Add a handler regression using `mime/multipart.Writer`, an authenticated session, a valid CSRF header, and fields `subscription_id=39`, `domain=example.test`, and `php_version=8.5`. Assert the fake provisioner receives subscription 39, not zero, and only one call occurs. Run it before implementation and confirm failure.
- [ ] Add a browser regression that opens the real Add website dialog and intercepts POST `/sites` before it reaches the server. Assert the encoded request contains the selected subscription ID and PHP version. Fulfill the intercepted request with a controlled JSON response; do not provision a domain.
- [ ] In `submitSite`, serialize before changing busy state:

```javascript
var body = new URLSearchParams(new FormData(form));
if (submit) submit.disabled = true;
fetch(form.action, {
  method: "POST",
  body: body,
  credentials: "same-origin",
  headers: { "X-Nakpanel-SPA": "true", "X-Nakpanel-CSRF": csrfToken() }
});
```

- [ ] Preserve the existing success redirect and inline failure behavior. URLSearchParams supplies the URL-encoded content type; do not manually construct multipart boundaries.
- [ ] Audit other enhanced non-upload forms for the same `FormData` plus `ParseForm()` mismatch. Fix only independently reproduced instances, with their own tests. Keep file uploads multipart.

## 3. Defensive Server Parsing and Errors

**Files:** `internal/control/http/server.go`, focused tests above.

- [ ] Reuse the existing body-size middleware where it is stricter. For POST `/sites`, impose a 64 KiB total body maximum with `http.MaxBytesReader`; a multipart memory threshold alone is not a request-size limit.
- [ ] Inspect the content type using `mime.ParseMediaType`. For `multipart/form-data`, call `ParseMultipartForm(64 << 10)` and defer `r.MultipartForm.RemoveAll()` whenever allocated. Reject any uploaded files because this route accepts text only. Otherwise retain `ParseForm()` for ordinary URL-encoded forms.
- [ ] Return HTTP 400 for malformed encoding or forbidden file parts and HTTP 413 for an oversized body, using the existing JSON/error rendering conventions. These failures must not call provisioning.
- [ ] Require a positive subscription ID for the modern SPA flow. A missing or invalid selection must say `Select an active subscription.` rather than falling into the legacy owner-based path. Preserve explicitly supported legacy non-SPA behavior and test it separately.
- [ ] Do not replace legitimate entitlement, suspended-account, quota, PHP-version, or cross-tenant errors with success. Preserve 404 ownership denial and CSRF rejection.

## 4. Verification

- [ ] Test URL-encoded and multipart success paths, malformed body, file part rejection, oversized body, missing/invalid subscription ID, CSRF failure, cross-tenant denial, inactive subscription, quota rejection, and no-JavaScript fallback.
- [ ] Verify inline errors preserve selected subscription/domain/PHP, re-enable the submit button, and prevent duplicate requests while pending.
- [ ] Browser-test desktop and 390px mobile: select subscription, submit with request interception, inspect the request body, and verify success/error rendering without changing the chosen layout.
- [ ] Run `go test ./... -count=1`, `go vet ./...`, `task build`, and `git diff --check` in the confirmed UX source workspace. Review generated asset changes for unrelated drift.

## 5. Deploy and Confirm

- [ ] Build only the panel from the confirmed UX source including this patch. Keep the agent, database, and other services unchanged.
- [ ] Retain the current panel binary as a rollback artifact; atomically install the candidate and restart only `nakpanel.service`.
- [ ] Verify HTTPS health, login, existing UX screenshots, and new embedded JavaScript. Confirm the running binary checksum matches the candidate.
- [ ] Run the real dialog flow with an invalid-domain fixture, removing browser validation only in the automated test. It must reach domain validation instead of returning `no active subscription`; confirm site count is unchanged.
- [ ] If health or UX compatibility fails, restore the captured binary and restart the panel. Do not use an unrelated older build as rollback.
- [ ] Report the exact tests and deployment performed, and explicitly identify any remaining unrelated critical alert or version mismatch. This fix does not resolve the separate reconciliation schema-version error observed in the lab.

## Acceptance

The selected subscription reaches provisioning intact, multipart clients cannot silently lose fields, ordinary forms still work, no access control is weakened, and the chosen UX remains unchanged. No user hosting data is created or modified by the verification probes.

## Execution Record

- Implemented on the existing `ricky/erp-ux-implementation` branch at baseline
  `96586af`, preserving its feedback and layout changes. No Phase 34 worktree
  content was imported.
- The multipart regression failed before the fix with subscription ID zero.
  It now passes alongside URL-encoded, CSRF, file rejection, malformed form,
  missing-selection, and known/unknown-length body-limit checks.
- Passed the complete Go suite, vet, Task build, and whitespace checks.
- Added `deploy/multipass/site-form-browser-smoke.cjs` for repeatable invalid-domain
  checks at 1440px and 390px. Both passed on subscription 39 with inline recovery,
  preserved input, no document overflow, and no JavaScript errors.
- Deployed only the panel on `192.168.252.68`. Its SHA-256 matches the candidate:
  `dc08e9e48531342e3ae22e44e80a8c0054529a10deec5fb8f5268b63e76e440c`.
  The embedded CSS checksum matched the previous deployed UX exactly.
- Rollback binary retained at `/var/lib/nakpanel/panel-before-site-form-fix`.
  Health and login passed; site count remained zero and subscription 39 remained
  active/in_sync. No agent, schema, quota, or customer data changes were made.
- The unrelated critical reconciliation alert remains outside this fix.
  Other enhanced upload/administration forms were not changed without a
  separately reproduced failure. No commit or push was performed.
