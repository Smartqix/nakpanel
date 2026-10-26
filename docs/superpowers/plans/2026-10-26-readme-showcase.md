# README Showcase Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan inline. Steps use checkbox syntax for tracking.

**Goal:** Make Nakpanel's README a distinctive, accurate product introduction.

**Architecture:** GitHub-compatible Markdown and repository-owned static assets.
Detailed material moves into linked guides; existing application templates supply
fictional-data screenshots without connecting to a database or agent.

**Tech Stack:** Markdown, SVG, PNG and a temporary local rendering preview.

**Spec:** [Approved design](../specs/2026-10-26-readme-showcase-design.md).

## Global Constraints

- Ubuntu 26.04 only; hosting PHP 8.3/8.4/8.5 and internal PHP 8.5.
- Keep development/experimental status and unspecified license truthful.
- Preserve source-bound historical verification; never imply broader acceptance.
- Documentation/assets only; no hosted tests, runtime changes or publication.

## Review Focus

- Existing recovery links to README installation anchors continue to work.
- Installation clearly requires an explicit private administrator password file.
- Native 8.5-only diagnostics are not presented as full product support.
- Screenshots use fictional identities and current application templates.
- Images and tables remain readable in light/dark and narrow layouts.

## Task 1: README and linked documentation

**Files:** README.md; CONTRIBUTING.md; docs/INSTALLATION.md;
docs/DEVELOPMENT.md; docs/CONFIGURATION.md; docs/FEATURES.md;
docs/VERIFICATION.md; docs/assets/readme/; this design and plan.

**Interfaces:** Consumes current templates, the approved outline and original
README procedures. Produces the root introduction and its relative doc/asset links.

- [x] Reconcile the old README and move detailed procedures into focused guides.
- [x] Add banner/badges and fictional-data product screenshots.
- [x] Write the shorter overview, six feature groups and architecture diagram.
- [x] Validate local files/anchors, SVG content and Git diff whitespace.
- [x] Inspect local rendering on light/dark and narrow layouts; correct defects.
- [x] Obtain one focused final documentation review and address material findings.
- [x] Record verification and commit the documentation locally; do not publish.

Verification uses link/asset inspection and visual rendering, not new application
tests. The owner authorized implementation of the proposed design; no further
approval handoff is needed for this local documentation work.

## Execution notes

Pre-flight: documentation links and asset paths are the only shared interfaces.
No runtime code or workflow is changed.

Ruling: use a vertical five-node architecture diagram and explain `panelctl` in
prose. The original horizontal graph scaled 16 px labels to roughly 4 px in the
390 px preview. The simpler diagram keeps the same control/queue/agent boundary
legible; the CLI's database and ping behavior remains explicit in the prose.

Final review: one fresh documentation reviewer identified a disabled seeded
customer login still advertised in moved material and a misleading final-gate
label. Both are corrected against the current verifier sources. The old
`nakpanel-lab` reuse description is also replaced with current ownership wording.

Ruling: treat the final-gate finding as material rather than cosmetic: calling
Phase 34 the final canonical gate could omit domain-removal/data-preservation
acceptance. The current runner's actual call order is the authority. No material
findings or deferred polish remain after these source-checked corrections.

## Verification result

- 70 local documentation/asset references resolve, including moved-guide links
  and the existing README installation anchor used by Recovery.
- Four SVGs parse without scripts, event handlers or external references; both
  PNGs validate. Hosting is 65,172 bytes; Operations is 115,157 bytes and is an
  exact unchanged copy of its attributed source.
- Local GitHub-like rendering inspected in light/dark themes and a 390 px
  content column. Seven images loaded; no content-column overflow. Mermaid
  renders without an error; the final graph has a 324.8 px natural width and
  displays at 324 px, keeping labels legible.
- The temporary fictional-data template renderer was removed. No runtime,
  migration, installer, workflow or private credential was changed. No hosted
  tests, remote publication, merge or deployment were performed.
- One focused fresh review completed; the source-checked corrections above are
  applied. `git diff --check` passes. Documentation is committed locally only.
