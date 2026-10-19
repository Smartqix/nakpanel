# Stalwart v0.11.8 supply evidence — 2026-10-18

The existing installer uses the GNU builds from the official
[v0.11.8 release](https://github.com/stalwartlabs/stalwart/releases/tag/v0.11.8),
published 2025-04-30, release ID 215704930. Version and installed path remain
unchanged. This narrow verification does not claim that this old release is the
latest supported or security-qualified Stalwart version.

The official GitHub release API's digest fields are null for these older assets;
the release has no checksum-file asset. It does publish individual Sigstore
signature bundles and links to signed build provenance. Downloaded archive bytes
match both independently signed records:

| GNU asset | GitHub asset ID | Bytes | SHA256 |
| --- | --- | --- | --- |
| stalwart-mail-x86_64-unknown-linux-gnu.tar.gz | 250703435 | 28160752 | `17ace571b012ff0228b276e09c83f28114824596279f86234f7a55e3773ad7df` |
| stalwart-mail-aarch64-unknown-linux-gnu.tar.gz | 250703443 | 26412751 | `1e85521e44f1347336ad90235fa18c701616798bd2837d2dfdd6e9f082fcde3d` |

Both archives contain exactly one regular member named `stalwart-mail`. Its ELF64
little-endian machine is 62 (amd64) or 183 (arm64); uncompressed sizes are
66656272 / 57979160 bytes. No downloaded binary was executed during this check.

## Actual signature and provenance verification

An isolated `/tmp/nakpanel-stalwart-sigstore-venv` installed Sigstore Python 4.1.0.
For **each** actual tar archive, this command succeeded using its published
`.sigstore.json` bundle, including certificate-chain and transparency-log policy:

```sh
python -m sigstore verify identity --bundle ARCHIVE.sigstore.json \
  --cert-identity 'https://github.com/stalwartlabs/mail-server/.github/workflows/ci.yml@refs/tags/v0.11.8' \
  --cert-oidc-issuer 'https://token.actions.githubusercontent.com' ARCHIVE
```

Its signed message SHA256 equals each actual archive hash. Rekor entries are
204726269 (amd64) and 204726275 (arm64), integrated 2025-04-30.

GitHub CLI additionally verified the official SLSA build provenance:

```sh
gh attestation verify ARCHIVE --repo stalwartlabs/mail-server \
  --cert-identity 'https://github.com/stalwartlabs/mail-server/.github/workflows/ci.yml@refs/tags/v0.11.8' \
  --source-ref refs/tags/v0.11.8 \
  --source-digest 7dc620816f355a09830691af495b2a63c05fe971 \
  --deny-self-hosted-runners --format json
```

The saved authenticated statement lists **both** target asset names and hashes;
verified timestamp is 2025-04-30T10:54:02Z, builder is GitHub-hosted, workflow/source
commit is `7dc620816f355a09830691af495b2a63c05fe971`, invocation
[14751869465](https://github.com/stalwartlabs/mail-server/actions/runs/14751869465/attempts/1).
The historical `mail-server` identity is intentional: the renamed `stalwart`
repository identity fails the expected SourceRepositoryURI check. The separate
release signature bundles are message signatures, not SLSA statements; passing
them to `gh attestation verify --bundle` correctly finds no SLSA predicate.

Evidence directory `/tmp/nakpanel-stalwart-v0.11.8-assessment` contains the API
response, exact archives/bundles, tagged upstream CI workflow, per-architecture
Sigstore success logs and verified GitHub provenance JSON. The official tagged
workflow uses `actions/attest-build-provenance@v2` and
`sigstore/gh-action-sigstore-python@v3.0.0` before release upload.

## Installer interface

Source `deploy/install/stalwart.sh` (inert). The full installer invokes
`nakpanel_prepare_stalwart_artifact` **before installed application-file changes**.
It exports `NAKPANEL_STALWART_STAGE`, a private current-user-owned directory. The
parent owns cleanup of this inherited stage across success/failure exits.

Preparation derives architecture from the actual host and rejects any selected
platform mismatch. It downloads only the pinned v0.11.8 HTTPS GNU URL. An inherited
stage is revalidated and rejected if missing, nonprivate, symlinked or tampered;
invalid supplied bytes are never silently replaced. Verification pins size and
SHA256, opens the archive without following symlinks, permits only the exact one
regular member and checks ELF architecture. It executes no archive code.

Phase 18 invokes `nakpanel_install_stalwart` after sourcing the helper. It checks
root, revalidates the stage, then validates the same opened bytes again while
extracting to a new file in a private directory on `/usr/local/bin`'s filesystem.
It sets mode0755 and fsyncs the complete file before atomic rename to the existing
`/usr/local/bin/stalwart-mail` path. Standalone use cleans its self-created stage;
the parent retains ownership of an inherited preflight stage. Production install
does not require Sigstore tooling/network: reviewed authenticated hashes are
pinned in source and checked with Python stdlib.

Regression tests first failed for the missing helper/validator, then passed for
valid extraction/mode, tampering, size, traversal, extra members, symlink/device
members, wrong ELF architecture, symlinked archive and reused unverified stage.
Both actual upstream archives also passed the production validator. No parent
installer or phase18 file and no VM was modified by this task.
