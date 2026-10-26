# README showcase design

Approved in the conversation on 2026-10-26: implement the researched product
introduction, using Nakpanel's navy/amber identity, real interface previews,
six capability groups and short installation/development paths.

## Intent and audience

Help server operators and prospective contributors understand the product,
its current limits and their next step without reading a phase-by-phase log.

## Approach

Use a product showcase with a concise technical entry point. A command-first
handbook was considered; its detailed reference material belongs in linked
guides. The owner approved the showcase direction with “proceed”.

## Design

- A repository-owned static SVG banner and three platform/status badges, plus
  the real CI badge. No license or production-ready badge.
- A current hosting workspace rendered with fictional data, followed by an
  existing Operations Center demonstration. Captions identify demonstration data.
- Six capability groups, a small Mermaid architecture diagram and clear links
  for installation, development, configuration, recovery and contribution.
- Move detailed procedures into focused guides; retain historical evidence with
  its original source and scope. Target roughly 180–220 README lines.
- Keep Ubuntu 26.04 only, signed Surý hosting PHP 8.3/8.4/8.5, internal PHP 8.5,
  experimental release qualification and unspecified project licensing explicit.

## Boundaries and verification

Documentation and static assets only. No runtime behavior, installers, workflows,
license selection, hosted tests, PR, merge or deployment changes. Check local
links and anchors, SVG safety and image sizes; inspect light/dark and narrow
rendering. No application test suite is needed for this reversible docs change.
