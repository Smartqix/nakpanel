# Phase 30 live fix 1: legacy verifier PHP installation order

## Status

Implementation commits:

- `c03d64c` (`fix: install Phase 30 PHP before legacy provisioning`) repairs direct Phase 3 verification.
- `474a944` (`fix: install Phase 30 PHP in shared verifier bootstrap`) repairs the Phase 5 UI bootstrap used by the full chained deployment verifier.
- `bcb2451` (`test: require one active legacy PHP installer call`) hardens the static contract against commented-out or duplicate installer calls.

Both legacy bootstrap paths now run the canonical Ubuntu 24.04 Phase 30 installer before building or starting Nakpanel and before their first site-provisioning request. Their existing explicit PHP 8.3 fixtures remain in place.

## Root cause

The production installer already invoked `deploy/install/phase30-install.sh`, but the legacy Multipass verifiers bootstrap their VM manually. The initial trace incorrectly treated `deploy/multipass/phase3-verify.sh` as the shared bootstrap. Phase 3 does install only `php8.3-fpm`, so `c03d64c` correctly repairs direct Phase 3 runs, but the full production verification chain never invokes it.

The actual chained call graph is `deployment-verify.sh` -> Phase 28 -> Phase 27 -> Phase 26 -> Phase 25 through Phase 8 -> Phase 7 -> Phase 6 -> `phase5-ui-verify.sh`. Phase 5 UI is the shared bootstrap. It also installed only `php8.3-fpm`, then built and started Nakpanel and issued the first site request without ever running Phase 3 or the canonical Phase 30 installer.

Current capability detection correctly requires the production PHP extension set. On a fresh deployment the resulting PHP 8.3 runtime lacked bcmath, curl, DOM/XML, GD, Imagick, Intl, mbstring, MySQLi, Redis, SOAP, and ZIP support, so it remained unready and the first legacy UI site creation failed with HTTP 400: `PHP 8.3 is not installed on the server`.

The same HTTP 400 repeated on the fresh live deployment after `c03d64c`, proving that the direct Phase 3 repair did not affect the chained path. This remains an installation-order defect, not a readiness-policy defect. Phase 3 and Phase 5 UI now invoke `deploy/install/phase30-install.sh` immediately after their legacy base-package fixtures, allowing the canonical installer to install and validate all PHP runtimes and extensions before Nakpanel consumes capability data.

## Red/green evidence

- Round 1 RED: the Phase 3-only contract failed with `Phase 3 must run the canonical phase30-install.sh`.
- Round 1 GREEN: the Phase 3-only contract passed after `c03d64c` added the canonical installer to the direct verifier.
- Round 2 RED: `go test ./deploy/multipass -run '^TestLegacyBootstrapsRunCanonicalPhase30InstallerBeforeBuildServicesAndProvisioning$' -count=1` passed its Phase 3 subtest and failed `Phase_5_shared_bootstrap` with `must run the canonical phase30-install.sh`.
- Round 2 GREEN: the same focused contract passed after `474a944` added the canonical installer to Phase 5 UI.
- Round 3 review finding: the original `strings.Index` contract could count a commented-out command and did not reject duplicate active commands.
- Round 3 RED: `TestSingleActiveCommandPositionRejectsCommentedAndDuplicateCommands` failed to compile with `undefined: singleActiveCommandPosition`, demonstrating the active-line scanner did not exist.
- Round 3 GREEN: the helper and both-script ordering tests passed after adding a non-comment executable-line scanner. Comment-only and duplicate-active fixtures fail, while a comment plus exactly one active command returns the active command's later byte position.
- Regression contract: the table-driven static test requires both direct Phase 3 and shared Phase 5 to contain the exact canonical installer command on a non-comment executable line exactly once, before `task build`, both Nakpanel service restarts, and each script's first site `POST`.

## Verification

- Focused active-command helper and two-bootstrap ordering tests: pass.
- `go test ./... -count=1`: pass.
- `go vet ./...`: pass.
- `task build`: pass; templ, sqlc, Tailwind, panel, agent, and panelctl completed without tracked generator churn.
- `bash -n deploy/**/*.sh`: pass.
- `git diff --check`: pass.

## Remaining concerns

Per the round-two repair instructions, Multipass was not rerun after `474a944`. The corrected shared call path is covered statically and by the complete local Go/build/vet/syntax suite, but still needs the next fresh Ubuntu 24.04 deployment to prove the live chain. The Ondrej PPA, Composer/WP-CLI downloads, and ClamAV signature refresh remain external dependencies; the canonical installer continues to fail closed when any production prerequisite is unavailable.
