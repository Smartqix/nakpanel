# Domain Git Workspace

Open **Domains > selected domain > Git**. Nakpanel manages one remote
repository per domain. Existing hosted repositories remain supported, but new
hosted push access is not offered in this workspace.

## Connect and Publish

1. Enter a repository URL. For a new SSH repository, leaving the URL field
   automatically saves a manual-mode draft and prepares access without fetching
   or publishing. The settings screen displays its public key as preparation
   completes. Without JavaScript, Save repository performs the same preparation.
   Public HTTPS repositories use normal saving. Embedded credentials are rejected.
2. For private SSH repositories, copy the generated public key to the repository
   provider with read-only access. Verify the host fingerprint against a trusted
   provider source before saving the host key. A scan alone is not verification.
   Copy the generated key title (domain, repository and site ID) into the provider's
   deploy-key title field. Public-key copy/download and its SHA-256 fingerprint
   are separate from the Git server's host fingerprint. Repeated saves reuse the
   existing key; the title is display metadata, not a private key or filename.
3. Pull updates to fetch branches and commit history. Choose a branch and a
   directory below `public_html`. `.` means `public_html` itself.
4. Check the destination, then confirm Deploy. Publication uses the selected
   fetched SHA, not a branch name resolved again later.

Manual is the default. Test connection fetches metadata without publishing,
including in automatic mode. Automatic mode fetches and publishes after an
authenticated webhook or a confirmed Pull updates action, but stops when existing files conflict. Disabled mode
allows fetch/inspection but prevents publication. Saving settings does not
publish files in any mode.

Once code is published, changing the source or target requires disconnecting
first. Disconnect removes managed repository access and disables its webhook;
published website files remain. Reconnect intentionally to establish a new
source/target. Rollback restores tracked code only, not databases or uploads.

## Webhooks

Automatic settings can rotate a once-visible webhook URL. This URL contains a
bearer credential: keep it private and use HTTPS with a trusted certificate.
The endpoint authenticates that token, requires a unique delivery identifier,
and accepts only the configured `refs/heads/<branch>` push. Duplicate delivery
IDs do not enqueue duplicate operations. Supported delivery headers are
`X-GitHub-Delivery` and `X-Gitlab-Event-UUID`. This is token authentication, not
provider HMAC-signature verification.

The private Multipass address is not reachable from public GitHub. Configure a
deliberate public HTTPS endpoint before using external webhooks; Nakpanel does
not open one automatically. Never disable certificate verification to compensate.

## Limits and Recovery

Git subprocesses have a two-minute timeout and 8 MiB output cap. Transfers have
512 MiB per-file and 1 GiB address-space limits; these are not aggregate
repository limits. Aggregate disk use remains subject to the subscription UID's
filesystem quota. Fetches exclude pull-request refs and use shallow branch
history. File-change snapshots are bounded to 256 MiB and fail before applying
an oversized change.

Before a failed deployment is rolled back, original affected files are restored
from a snapshot. Exact operation retries retain their immutable revision and
rollback pointer. Ordinary confirmed redeploys can restore changed tracked files.
Git is a code publication tool, not a replacement for site/database backups.

## Deployment and Verification

Apply `20260909000046_git_workspace.sql` before deploying matching panel/agent
binaries. Migrations should run as the schema owner. When run as PostgreSQL
administrator, the panel role needs SELECT/INSERT/UPDATE/DELETE on the new
`git_webhook_deliveries` table. Existing pending legacy deployments are failed
with a requeue message because they did not record an immutable commit.

The non-resetting verifier requires an existing disposable domain:

```sh
NAKPANEL_TEST_BASE_URL=https://<vm-ip>:7443 \
NAKPANEL_TEST_SITE_ID=<id> \
NAKPANEL_TEST_DOMAIN=git-workspace-<unique>.test \
deploy/multipass/git-workspace-verify.sh
```

It publishes GitHub's public Hello-World example only to that disposable site,
tests modes, branch switching, rollback, webhook deduplication and disconnect,
then leaves the disconnected test domain and published files for inspection.
Do not point it at a real website. Private SSH authentication has automated
test coverage but requires acceptance with a real provider deploy key before
claiming that specific provider integration has been verified in production.
