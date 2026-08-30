# Phase 30 live fix 1: legacy verifier PHP installation order

## Status

Implemented in `c03d64c` (`fix: install Phase 30 PHP before legacy provisioning`).

Phase 3 now runs the canonical Ubuntu 24.04 Phase 30 installer before starting the Nakpanel agent and panel and before its first legacy site-provisioning request. The existing explicit PHP 8.3 fixture remains in place for the legacy one-VM chain.

## Root cause

The production installer already invoked `deploy/install/phase30-install.sh`, but the legacy Multipass chain bootstraps its VM manually. Its earliest PHP provisioning step, `deploy/multipass/phase3-verify.sh`, installed only `php8.3-fpm` and then started the agent and panel.

Current capability detection correctly requires the production PHP extension set. On a fresh deployment the resulting PHP 8.3 runtime lacked bcmath, curl, DOM/XML, GD, Imagick, Intl, mbstring, MySQLi, Redis, SOAP, and ZIP support, so it remained unready and the first legacy UI site creation failed with HTTP 400: `PHP 8.3 is not installed on the server`.

This was an installation-order defect, not a readiness-policy defect. The repair invokes `deploy/install/phase30-install.sh` immediately after Phase 3's legacy base-package fixture, allowing the canonical installer to install and validate all PHP runtimes and extensions before Nakpanel services consume capability data.

## Red/green evidence

- RED: `go test ./deploy/multipass -run '^TestPhase3RunsCanonicalPhase30InstallerBeforeServicesAndProvisioning$' -count=1` failed with `Phase 3 must run the canonical phase30-install.sh`.
- GREEN: the same focused test passed after adding `sudo bash "${REMOTE_SRC}/deploy/install/phase30-install.sh"` before service startup and site provisioning.
- Regression contract: the static test checks the exact canonical installer call and its ordering relative to both Nakpanel service restarts and the first `POST /sites` request.

## Verification

- Focused Phase 3 ordering test: pass.
- `go test ./...`: pass.
- `go vet ./...`: pass.
- `task build`: pass; templ, sqlc, Tailwind, panel, agent, and panelctl completed without tracked generator churn.
- `bash -n deploy/**/*.sh`: pass.
- `git diff --check`: pass.

## Remaining concerns

The repair was verified through static ordering coverage, the complete local Go suite, build, vet, and shell parsing. A fresh Ubuntu 24.04 Multipass deployment was not rerun during this repair, so the live Ondrej PPA, Composer/WP-CLI downloads, and ClamAV signature refresh remain dependent on external service availability; the canonical installer continues to fail closed when any of those production prerequisites are unavailable.
