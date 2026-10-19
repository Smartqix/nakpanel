# Native Ubuntu qualification

Ubuntu 24.04 remains the default. Native qualification runs four cells:
24.04/amd64, 24.04/arm64, 26.04/amd64 and 26.04/arm64. The Resolute native
profile advertises PHP 8.5; it does not imply PHP 8.3/8.4 parity.

The experimental Resolute profiles require a booted systemd server, an ext4
filesystem backing `/home`, and cgroup v2 CPU, memory and PID controllers.
Installer preflight reports actual mount information, available bytes/inodes
and writable storage before package preparation or application replacement.
It does not invent a minimum disk or memory capacity. Existing Noble filesystem
and controller eligibility is preserved; its report identifies anything that
still needs quota or OCI verification. This is separate from the native runner
capacity needed to run several disposable guests below.

New tenant accounts use system UID/GID range 10000–59999. Existing marked
accounts retain their IDs. A legacy archive whose numeric identities collide
with target OS accounts remains incompatible; qualification never remaps it or
reassigns an OS account to make the restore pass.

The ordinary `unit`, `security-suite` and `release-build` CI jobs remain
required. The security suite creates unique owned source/DR guests and always
attempts ownership-validated cleanup. It does not reuse a fixed CI VM name.

## Native runners

Register dedicated self-hosted runners with these custom labels:

- `self-hosted`, `multipass`, `nakpanel-qualification`, `amd64` on native x86-64;
- `self-hosted`, `multipass`, `nakpanel-qualification`, `arm64` on native arm64.

These architecture labels are intentional custom labels, separate from GitHub's
built-in X64/ARM64 labels. The harness also checks the actual host and guest
architecture, so assigning a label cannot make an emulated cell count as native.
Use dedicated trusted runners for privileged VM qualification. Do not run
untrusted pull-request code on runners holding production signing credentials.
Only public verification keys are needed for this workflow.

Install Multipass and grant the runner account access to its daemon. Provide
Git, Bash, Python 3, OpenSSL, curl, dig, jq, tar, Make and the build dependencies
used by the verifier scripts. `actions/setup-go` installs the exact toolchain
from `deploy/release/GO_VERSION`. Mail workspace qualification requires Node.js, Playwright and Chrome on the
runner. Set `PLAYWRIGHT_MODULE` to an absolute module path when it is not
resolvable as `playwright`; optional database-manager coverage uses the same
browser dependency. The hosted workflow provisions pinned Playwright1.64.1.

Allow approximately 20 GB of free RAM and 150 GB of free disk per active cell:
a source guest, historical-upgrade guest and short-lived DR guest may coexist.
Jobs have a six-hour limit, a matrix parallelism cap of two, and one concurrency
group per architecture. This permits one cell on each native architecture at a
time. Avoid overlapping manual qualification dispatches for the same runners.

The runner must reach configured Ubuntu package sources and the external
registries/download endpoints used by the real product gates. Cached bundles
and local cloud images must be readable by the runner account and must not be
modified during a qualification run.

## Required signed artifact configuration

Pre-stage a signed current bundle and a genuine prior release bundle for each
architecture on the corresponding native runner. Supply their independently
managed public keys and exact application versions. Both Ubuntu releases of an
architecture use the same current bundle directory and therefore the same
signed payload; do not rebuild separately for each OS cell.

After staging, every modern gate requires the guest's release directory,
manifest, signature, public key and all three executables. A missing or unsafe
guest artifact fails the run; it cannot trigger a working-tree build while a
signed release is selected. Source-development runs without a selected release
retain their existing workflow. Fresh bootstrap explicitly creates a MariaDB
fixture and writes/reads a canary in its physical schema before later upgrade
or recovery checks use it.

Set repository variable `NAKPANEL_QUALIFICATION_ARTIFACTS` to JSON with this
shape, or pass the same JSON in the `qualification_artifacts` dispatch input.
The following paths and versions are examples and must be replaced with actual
pre-staged artifacts:

```json
{
  "amd64": {
    "current": {
      "bundle": "/srv/nakpanel/releases/current-amd64",
      "public_key": "/srv/nakpanel/trust/current-public.pem",
      "version": "29.0.0"
    },
    "prior": {
      "bundle": "/srv/nakpanel/releases/prior-amd64",
      "public_key": "/srv/nakpanel/trust/prior-public.pem",
      "version": "28.0.0"
    }
  },
  "arm64": {
    "current": {
      "bundle": "/srv/nakpanel/releases/current-arm64",
      "public_key": "/srv/nakpanel/trust/current-public.pem",
      "version": "29.0.0"
    },
    "prior": {
      "bundle": "/srv/nakpanel/releases/prior-arm64",
      "public_key": "/srv/nakpanel/trust/prior-public.pem",
      "version": "28.0.0"
    }
  }
}
```

A missing configuration, architecture, path, trust anchor, version, signature or
compatible executable fails before native VM work. Required prior-release gates
are never skipped because configuration is absent. Production historical and
current releases must have distinct commits and different signed payloads. An
explicit development candidate may share HEAD while containing a different
signed payload; its evidence cannot promote.

No signing secret is assumed or created by native qualification. The separate
`release-build` policy job exercises both architecture builds using an ephemeral
test signing key and a CI-only tracked README marker. This marks its manifests
`development:true`. Those test outputs are not automatically fed into native
qualification. If deliberately staging them for a test run, also stage their
public key, configure their exact application version and enable the
`allow_development_artifacts` input. Development opt-in applies to current and
prior artifacts and makes the resulting report nonpromotion.

## Pinned cloud images

The default launch sources remain the `24.04` and `26.04` Multipass aliases.
When an alias is unavailable, download the appropriate official cloud image
separately, independently verify its published SHA256, and pre-stage that local
file. Add an optional `images` object to the architecture's configuration:

```json
{
  "images": {
    "24.04": {
      "source": "/srv/nakpanel/images/noble-server-cloudimg-arm64.img",
      "sha256": "REPLACE_WITH_THE_INDEPENDENTLY_VERIFIED_64_HEX_SHA256"
    }
  }
}
```

This fragment belongs inside `arm64` in the preceding example. Use the correct
architecture's image in each architecture entry. The harness rejects a missing
or mismatching digest before launch, and still validates actual guest release,
architecture and ownership before sync/install/delete. The image source changes
only the launch argument. A Resolute cell's historical24 guest uses the separate
24.04 image entry, never its26.04 image implicitly. Reports preserve requested
image inputs and verified launch source/hash evidence.

## Running and reading results

Dispatch the **CI** workflow with `qualify_native=true`. Optionally set
`verify_database_manager=true` to require the real database-manager FastCGI and
restricted browser workflow. Missing optional browser dependencies then fail
that requested gate; they do not silently skip it.

The wrapper executes the clean signed installation, genuine populated prior24
upgrade, native26 same-profile update where applicable, rootless OCI and rootful
Valkey boundaries/cgroup/reboot checks, security, rollback/reboot/DR, native PHP,
service plans, WordPress Toolkit, webmail, uninstall, GoAccess and domain removal.
The DR leg includes real message contents and a second reboot. It finishes by
checking installed application digests against the signed artifact.

Every matrix job always uploads its configuration preflight JSON and any cell
report/logs produced, including failures. A final summary job requires all four
complete cell reports, passing baseline jobs and byte-identical current signed
release manifests across the two releases of each architecture. Missing reports
or differing artifacts fail the summary; development evidence remains
nonpromotion. Read `report.json` together with
`gates.tsv`, gate logs, signed release manifest and inventory log. A failure
preserves pending gates and cannot become a passing qualification report.
`qualification_passed`, `promotion_eligible`, profile and `full_php_parity` are
separate fields. A complete production native8.5 profile can qualify without
claiming full PHP parity. Development artifacts cannot promote.

Cleanup enumerates only the current run's host ownership records and calls
`destroy_owned_vm` for each candidate. Both guest and host ownership must match;
protected lab/soak and unrelated guests cannot be deleted. A cleanup failure
fails the step and leaves the durable host ownership records for diagnosis.
Long-running soak evidence remains a separate 30–60-day requirement described
in [SOAK.md](SOAK.md); a successful fast workflow is not that elapsed soak.

For a direct optional Sury run on Ubuntu 26.04, explicitly export
`NAKPANEL_QUALIFICATION_PHP_PROVIDER=sury` before invoking the wrapper. Fresh
source and DR installers receive `--php-provider sury`; populated hosts retain
their trusted installed profile. All PHP 8.3/8.4/8.5 gates run and reports use
`profile=ubuntu-26.04-sury`, `php_provider=sury`, and `full_php_parity=true`.
The default remains native 8.5 and the required four-cell CI matrix is unchanged.
The historical 24.04 upgrade guest always resets the provider to its original
profile. Unsupported provider/release combinations fail before VM mutation.

The required `mail-workspace` gate creates fresh synthetic mailboxes and aliases
through the real browser, rotates a password, proves old-password denial,
validates IMAP plus SMTP TLS/STARTTLS and alias delivery, tests an unrelated
customer boundary, then removes only its QA objects. Protocol verification
runs in the owned guest with its installed Stalwart certificate as the explicit
trust anchor and matching hostname; TLS verification remains enabled. Browser
lab self-signed HTTPS and `.test` DNS overrides require an explicit guest IPv4;
production QA defaults retain normal trust and DNS. Private credential state
is kept in a0700 temporary directory outside uploaded cell reports and removed.
The public-HTTPS webmail popup stage requires a separately configured public
webmail TLS hostname; this gate does not claim that stage. The mandatory
`internal-tools` gate separately proves actual Roundcube FastCGI and IMAP login.
