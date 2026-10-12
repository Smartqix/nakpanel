#!/usr/bin/env bash
set -euo pipefail
# An existing disposable domain is mandatory. Never point this at a real site.
: "${NAKPANEL_TEST_BASE_URL:?Set the panel HTTPS URL}"
: "${NAKPANEL_TEST_SITE_ID:?Set a disposable site ID}"
: "${NAKPANEL_TEST_DOMAIN:?Set its domain, starting git-workspace-}"
[[ "$NAKPANEL_TEST_DOMAIN" == git-workspace-*.test ]] || { echo 'Only disposable git-workspace-*.test domains are accepted' >&2; exit 1; }
command -v jq >/dev/null
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/deploy/multipass/common.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
base="$NAKPANEL_TEST_BASE_URL"
site="$NAKPANEL_TEST_SITE_ID"
for _ in $(seq 1 30); do
  if curl -ksSf "$base/healthz" -o /dev/null 2>/dev/null; then break; fi
  sleep 1
done
curl -ksSf -c "$tmp/cookies" --data-urlencode "email=${NAKPANEL_TEST_EMAIL:-admin@nakpanel.test}" --data-urlencode "password=${NAKPANEL_TEST_PASSWORD:-NakpanelAdmin!2026}" "$base/login" -o /dev/null
csrf="$(csrf_token "$tmp/cookies")"
status(){ curl -ksSf -b "$tmp/cookies" "$base/sites/$site/git/status"; }
post(){ local action="$1"; shift; curl -ksSf -b "$tmp/cookies" -H "X-Nakpanel-CSRF: $csrf" -H 'X-Nakpanel-SPA: true' "$@" "$base/sites/$site/git$action"; }
wait_done(){
 for _ in $(seq 1 90); do
  status > "$tmp/status"
  state="$(jq -r '.repository.convergence_status // "disconnected"' "$tmp/status")"
  [[ "$state" == in_sync || "$state" == disconnected ]] && return 0
  if [[ "$state" == failed ]]; then jq -r '.repository.last_error' "$tmp/status"; return 1; fi
  sleep 2
 done
 echo 'Timed out waiting for Git operation' >&2; return 1
}
revision(){ jq -r '.repository.operation_revision' "$tmp/status"; }
operation(){ local action="$1"; shift; post "/$action" --data-urlencode "expected_revision=$(revision)" --data-urlencode "idempotency_key=verify-$action-$(date +%s)-$RANDOM" "$@" >/dev/null; wait_done; }
status > "$tmp/status"
[[ "$(jq -r '.repository' "$tmp/status")" == null || "$(jq -r '.repository.connection_status' "$tmp/status")" == disconnected ]] || { echo 'Disposable domain must not have a connected repository' >&2; exit 1; }
initial_revision="$(jq -r '.repository.operation_revision // 0' "$tmp/status")"
post '' --data-urlencode 'mode=remote' --data-urlencode 'remote_url=https://github.com/octocat/Hello-World.git' --data-urlencode 'branch=master' --data-urlencode 'deploy_target=.' --data-urlencode 'deployment_mode=manual' --data-urlencode "expected_revision=$initial_revision" >/dev/null
wait_done
operation fetch
first="$(jq -r '.repository.fetched_revision' "$tmp/status")"
[[ "$first" =~ ^[a-f0-9]{40}$ ]]
[[ "$(jq -r '.repository.deployed_revision' "$tmp/status")" == '' ]]
operation preview --data-urlencode "revision=$first"
operation deploy --data-urlencode "revision=$first" --data-urlencode 'confirm=yes'
[[ "$(jq -r '.repository.deployed_revision' "$tmp/status")" == "$first" ]]
ip="${NAKPANEL_TEST_VM_IP:-$(vm_ip)}"
curl -fsS -H "Host: $NAKPANEL_TEST_DOMAIN" "http://$ip/README" > "$tmp/published"
echo 'PASS prepare/fetch/preview/immutable deployment and HTTP publication'
post '' --data-urlencode 'mode=remote' --data-urlencode 'remote_url=https://github.com/octocat/Hello-World.git' --data-urlencode 'branch=test' --data-urlencode 'deploy_target=.' --data-urlencode 'deployment_mode=manual' --data-urlencode "expected_revision=$(revision)" >/dev/null
wait_done
operation fetch
second="$(jq -r '.repository.fetched_revision' "$tmp/status")"
[[ "$second" != "$first" ]]
operation deploy --data-urlencode "revision=$second" --data-urlencode 'confirm=yes'
operation rollback --data-urlencode "revision=$first" --data-urlencode 'confirm=yes'
[[ "$(jq -r '.repository.deployed_revision' "$tmp/status")" == "$first" ]]
echo 'PASS branch selection and code rollback'
post '' --data-urlencode 'mode=remote' --data-urlencode 'remote_url=https://github.com/octocat/Hello-World.git' --data-urlencode 'branch=test' --data-urlencode 'deploy_target=.' --data-urlencode 'deployment_mode=disabled' --data-urlencode "expected_revision=$(revision)" >/dev/null
wait_done
operation fetch
code=$(curl -ksS -o "$tmp/rejected" -w '%{http_code}' -b "$tmp/cookies" -H "X-Nakpanel-CSRF: $csrf" -H 'X-Nakpanel-SPA: true' --data-urlencode "expected_revision=$(revision)" --data-urlencode "revision=$second" -d 'confirm=yes' "$base/sites/$site/git/deploy")
[[ "$code" == 400 || "$code" == 409 ]]
[[ "$(jq -r '.repository.deployed_revision' "$tmp/status")" == "$first" ]]
echo 'PASS disabled mode allows fetching but rejects publication'
post '' --data-urlencode 'mode=remote' --data-urlencode 'remote_url=https://github.com/octocat/Hello-World.git' --data-urlencode 'branch=test' --data-urlencode 'deploy_target=.' --data-urlencode 'deployment_mode=automatic' --data-urlencode "expected_revision=$(revision)" >/dev/null
wait_done
curl -fsS -H "Host: $NAKPANEL_TEST_DOMAIN" "http://$ip/README" > "$tmp/before-test"
operation test
[[ "$(jq -r '.repository.fetched_revision' "$tmp/status")" == "$second" ]]
[[ "$(jq -r '.repository.deployed_revision' "$tmp/status")" == "$first" ]]
curl -fsS -H "Host: $NAKPANEL_TEST_DOMAIN" "http://$ip/README" > "$tmp/after-test"
cmp "$tmp/before-test" "$tmp/after-test"
echo 'PASS connection test in automatic mode never publishes code'
post '/webhook' -d '' > "$tmp/webhook"
hook="$(jq -r '.webhook_path' "$tmp/webhook")"
[[ "$hook" == /git/hooks/* ]]
delivery="git-verify-$(date +%s)-$RANDOM"
code=$(curl -ksS -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -H "X-GitHub-Delivery: $delivery-wrong" -H 'X-GitHub-Event: push' -d '{"ref":"refs/heads/wrong"}' "$base$hook")
[[ "$code" == 404 ]]
curl -ksSf -H 'Content-Type: application/json' -H "X-GitHub-Delivery: $delivery" -H 'X-GitHub-Event: push' -d '{"ref":"refs/heads/test"}' "$base$hook" -o /dev/null
wait_done
[[ "$(jq -r '.repository.deployed_revision' "$tmp/status")" == "$second" ]]
before_replay="$(revision)"
curl -ksSf -H 'Content-Type: application/json' -H "X-GitHub-Delivery: $delivery" -H 'X-GitHub-Event: push' -d '{"ref":"refs/heads/test"}' "$base$hook" -o /dev/null
status > "$tmp/status"
[[ "$(revision)" == "$before_replay" ]]
echo 'PASS automatic publication, configured branch gate and delivery replay deduplication'
curl -fsS -H "Host: $NAKPANEL_TEST_DOMAIN" "http://$ip/README" > "$tmp/published"
operation disconnect --data-urlencode 'confirm=yes'
curl -fsS -H "Host: $NAKPANEL_TEST_DOMAIN" "http://$ip/README" > "$tmp/retained"
cmp "$tmp/published" "$tmp/retained"
echo 'PASS disconnect preserved published files; disposable domain retained for inspection'
