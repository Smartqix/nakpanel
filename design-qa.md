# Phase 11 Design QA

## Visual Truth

- Source: `/Users/rickynkansah/Downloads/Building a custom control panel from scratch - Claude.png`
- Implemented desktop: `/tmp/nakpanel-ui-audit/phase11-subscriptions-desktop-final.png`
- Implemented mobile: `/tmp/nakpanel-ui-audit/phase11-subscriptions-mobile-final.png`
- Full comparison: `/tmp/nakpanel-ui-audit/phase11-reference-comparison-final.png`
- Focused comparison: `/tmp/nakpanel-ui-audit/phase11-focused-comparison-final.png`

## State And Viewports

- Desktop: administrator, Subscriptions, 2048 x 993.
- Mobile: administrator, Subscriptions, 390 x 844.
- The implementation preserves the reference's graphite rail, white topbar, light content canvas, compact bordered surfaces, and dense subscription rows.
- Capacity and overselling controls intentionally live under Tools & Settings in Phase 11 instead of remaining above the subscription table.

## Comparison History

### Pass 1

- The navigation rail was too narrow and the content column was centered too aggressively.
- Subscription rows expanded into very tall mobile table stacks.
- A few controls used text or custom-drawn symbols instead of the selected icon library.

Fixes:

- Matched the source's wide graphite rail and left-aligned workspace proportions.
- Reworked mobile resource tables into compact disclosure-friendly summaries.
- Bundled an official Lucide sprite and replaced text/custom-drawn control icons.

### Pass 2

- Full-page and focused comparison images showed consistent rail geometry, topbar height, title scale, table density, borders, radii, and status treatment.
- Desktop and mobile layouts remained readable with no overlaps, clipping, or horizontal page overflow.
- No unresolved P1 or P2 visual findings remained.

## Design Surface

- Typography: self-contained system stacks with compact UI sizing and monospace treatment for technical values; no external font dependency.
- Spacing: 304px desktop rail, compact topbar, restrained panel padding, and stable responsive gutters.
- Color: graphite navigation, light neutral canvas, cobalt primary actions, amber brand mark, and restrained semantic status colors.
- Assets: official bundled Lucide icon subset with the upstream license included; no placeholder imagery or hand-drawn SVG icons.
- Copy: task-oriented labels, real object names, ownership context, status text, and conservative empty states.

## Interaction Verification

- Mobile menu opens with a scrim, updates `aria-expanded`, closes with Escape, and does not overlap the final content state.
- Add Website dialog traps focus, wraps Shift+Tab correctly, closes with Escape, and restores focus to its trigger.
- Scoped global search returned an owned site, navigated to its detail route, and browser Back restored the sites page.
- Routed links, onboarding controls, subscription context, and server forms work without client-side view switching.
- Browser console errors: none.

final result: passed

# Phase 12 Design QA

## Visual Truth

- Reference: `/Users/rickynkansah/Downloads/Building a custom control panel from scratch - Claude.png`
- Desktop provider workspace: `/tmp/nakpanel-ui-audit/phase12-resellers-desktop-final.png`
- Mobile provider workspace: `/tmp/nakpanel-ui-audit/phase12-resellers-mobile-final.png`
- Matched comparison: `/tmp/nakpanel-ui-audit/phase12-reference-comparison-final.png`

## State And Viewports

- Desktop: administrator, Resellers, 1256 x 608.
- Mobile: administrator, Resellers, 390 x 844.
- The administrator navigation is now the Service Provider workspace: Home, Customers, Resellers, Domains, Subscriptions, Service Plans, Activity, and Tools & Settings.
- Provider rows preserve field labels on mobile and keep account names, emails, plans, allocations, and lifecycle status readable without horizontal page overflow.

## Interaction Verification

- Mobile navigation opens with a scrim and closes with Escape.
- Selecting a reseller enables the bulk activate and suspend controls; clearing the selection disables them again.
- Responsive table labels remain present for reseller, customer, DNS, certificate, audit, and reseller-plan rows.
- Desktop document width equals the 1256px viewport; mobile document width equals the 390px viewport.
- Browser console errors and warnings: none.

final result: passed

## ERP Restyle Design QA (2026-08-29)

### Visual Truth
The workspace now follows a Plesk-calibrated ERP scale. Single theme in `:root`
(cobalt `#2563eb` primary; the purple theme is retired). All grayscale, border,
and surface colors resolve through `--np-*` tokens; status tints remain literal.

- Type: 13px/1.45 base, 22px/500 page titles, 15px/600 h2, 14px/600 panel
  titles, 12px/500 quiet table headers, 11px tracked kickers and pills.
  Font weights are capped at 600 (regular 400 / medium 500 / semibold 600);
  the system font stack is unchanged and intentional.
- Density: 256px graphite rail, 34px nav rows, 52px topbar, 24px content
  padding, 44px panel titles, 52px object rows, 8px/10px table cells, 32px
  controls (buttons, inputs, selects), 30px icon buttons, 18px icons at
  stroke-width 1.5.
- Geometry: one corner radius token `--np-radius: 4px` (pills stay 999px);
  spacing snapped to a 2px sub-grid below 16px and a 4px grid above
  (`--np-space-1` … `--np-space-10`), 16px rhythm between stacked panels.

### Comparison History
- Restyle pass: verified live against the lab VM (nakpanel-lab) at the
  documented viewports (2048x993 desktop, 390x844 mobile) — login, Home,
  Websites & Domains, domain workspace, Subscriptions, Tools & Settings,
  mail workspace, and the frozen `/?legacy=1` shell all render on the new
  scale. Captures: `artifacts/restyle-*.png`.
- Test contract: the three pinned minified CSS assertions in
  `internal/control/http/server_test.go` were updated in lockstep
  (`--np-ink:#1f2733`, table td 13px, page-head p 13px). All verifier-grepped
  class names and the `content:attr(data-label)` responsive-table pattern are
  unchanged.
