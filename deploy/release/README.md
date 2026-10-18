# Portable application bundles

`GO_VERSION` pins Go **1.26.9**, a maintained release including the 2026-10-08
security fixes. Module minimum remains 1.23.0; CI, release builder and source
installer consume this pin. Refresh it when Go publishes security fixes.
Official policy/history: https://go.dev/doc/devel/release and checksums:
https://go.dev/dl/?mode=json&include=all . Never install an unchecked Go archive.

From a clean release checkout with that exact compiler, Python 3, OpenSSL, make
and generation dependencies available:

```sh
NAKPANEL_RELEASE_SIGNING_KEY=/secure/release-rsa-key.pem make release
```

For a single-architecture qualification runner, set
`NAKPANEL_RELEASE_ARCHITECTURES=amd64` or `arm64`. The default remains
`amd64 arm64`; a space-separated pair in either order is also accepted. Empty,
unknown, duplicate and malformed selections fail before generation or key access.

The key must already exist and be managed by the release owner. This command
never generates a production key or publishes artifacts. Generation runs once,
checks generated templ/sqlc/CSS files against Git, and then cross-builds all
three existing commands for `linux/amd64` (`GOAMD64=v1`) and `linux/arm64`
(`GOARM64=v8.0`) with `CGO_ENABLED=0`. Existing version/commit ldflags and embedded
assets are preserved. Every ELF must have the expected machine and no
`PT_INTERP` or `PT_DYNAMIC`; its Go build information is included in the bundle.

The versioned directory/tarball includes binaries, matching deployment/config
assets, VERSION, Makefile, go.mod/go.sum and SQL migrations. `manifest.json`
schema 1 records full Git commit, application version, exact Go version, CGO,
architecture/CPU baseline, development state and SHA256 for **every** asset.
`manifest.sig` is the detached OpenSSL RSA/SHA256 signature of the exact JSON
bytes. The trusted public key must be distributed independently of the bundle.

Verify an already extracted, root-controlled staging directory before any
installed-file replacement:

```sh
python3 deploy/release/verify.py --bundle /staging/nakpanel-29.0.0-linux-arm64 \
  --public-key /etc/nakpanel/release-public-key.pem --version 29.0.0 \
  --architecture arm64
```

The verifier accepts only amd64/v1 or arm64/v8.0, the requested exact version,
valid signed manifests, regular files, a complete digest inventory and static
ELFs. It rejects extra/missing/tampered files, symlinks and unsafe paths.
Extract archives into a fresh private staging directory using a safe extraction
routine; never extract an unverified archive over the installed filesystem.
Do not permit concurrent writers between verification and installation. A
bundle-supplied verifier or public key cannot establish trust by itself: invoke
the verifier from your trusted checkout/installer and use an existing trust key.
The installer retains its version/no-op/downgrade/backup/rollback decisions.

For local qualification only, `NAKPANEL_RELEASE_ALLOW_DIRTY=1` allows an
uncommitted checkout and marks its manifest `development:true`. Such bundles
are rejected unless `--allow-development` is explicitly passed. Development
snapshots still run generation, but include its results without requiring a
comparison to committed generated files; production builds enforce that gate. CI uses an
ephemeral key to exercise signing and discards it; CI does not publish a release.

**The bundle is not compiler-free.** Goose 3.24.0 and River 0.19.0 migrations
still run through the existing pinned `go run` Makefile targets. A compatible Go
compiler, module downloads/cache and the migration assets are prerequisites.
Prebuilt migration tools, ordering and failure recovery need a separate review.

Static linkage alone does not establish runtime parity. The same artifact digest
must pass native Noble/Resolute tests for DNS/TLS, Unix credentials, local user
and supplementary-group lookup and DB access under the hardened units before
rollout. No CGO/NSS assumptions or security checks are disabled here.
