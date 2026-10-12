#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "Git key verification failed at line $LINENO" >&2' ERR
: "${NAKPANEL_TEST_BASE_URL:?Set panel URL}"
: "${NAKPANEL_TEST_SITE_ID:?Set disposable site ID}"
: "${NAKPANEL_TEST_DOMAIN:?Set disposable domain}"
[[ "$NAKPANEL_TEST_DOMAIN" == git-workspace-*.test ]] || exit 1
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/deploy/multipass/common.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
base="$NAKPANEL_TEST_BASE_URL"
site="$NAKPANEL_TEST_SITE_ID"
curl -ksSf -c "$tmp/cookies" --data-urlencode "email=${NAKPANEL_TEST_EMAIL:-admin@nakpanel.test}" --data-urlencode "password=${NAKPANEL_TEST_PASSWORD:-NakpanelAdmin!2026}" "$base/login" -o /dev/null
csrf="$(csrf_token "$tmp/cookies")"
status(){ curl -ksSf -b "$tmp/cookies" "$base/sites/$site/git/status" > "$tmp/status"; }
wait_done(){
 for _ in $(seq 1 60); do
  status
  state="$(jq -r '.repository.convergence_status' "$tmp/status")"
  [[ "$state" == in_sync ]] && return 0
  [[ "$state" == failed ]] && { echo 'Git preparation failed' >&2; return 1; }
  sleep 2
 done
 return 1
}
status
if [[ "$(jq -r '.repository.connection_status // "disconnected"' "$tmp/status")" != disconnected ]]; then
 jq -e '.repository.remote_url == "ssh://git@github.com/octocat/Hello-World.git" and (.repository.deployed_revision // "") == "" and (.repository.fetched_revision // "") == ""' "$tmp/status" >/dev/null || { echo 'Use a disconnected disposable repository' >&2; exit 1; }
fi
prepare(){
 curl -ksSf -b "$tmp/cookies" -H "X-Nakpanel-CSRF: $csrf" -H 'X-Nakpanel-SPA: true' \
  --data-urlencode "expected_revision=$(jq -r '.repository.operation_revision // 0' "$tmp/status")" \
  -d 'mode=remote&branch=main&deploy_target=.&deployment_mode=manual' \
  --data-urlencode 'remote_url=git@github.com:octocat/Hello-World.git' "$base/sites/$site/git" -o /dev/null
 wait_done
}
prepare
jq -e '.repository.deploy_public_key | startswith("ssh-ed25519 ")' "$tmp/status" >/dev/null
jq -e '.key_title | contains("Hello-World")' "$tmp/status" >/dev/null
jq -e '.key_fingerprint | startswith("SHA256:")' "$tmp/status" >/dev/null
jq -e '(.repository.fetched_revision // "") == "" and (.repository.deployed_revision // "") == ""' "$tmp/status" >/dev/null
jq -r '.repository.deploy_public_key' "$tmp/status" > "$tmp/key"
prepare
jq -r '.repository.deploy_public_key' "$tmp/status" > "$tmp/reused"
cmp "$tmp/key" "$tmp/reused"
echo 'PASS SSH preparation generated a named key without fetching or publishing; repeated save reused it'
curl -ksSf -b "$tmp/cookies" -H "X-Nakpanel-CSRF: $csrf" -H 'X-Nakpanel-SPA: true' \
 --data-urlencode "expected_revision=$(jq -r '.repository.operation_revision' "$tmp/status")" -d 'confirm=yes' "$base/sites/$site/git/disconnect" -o /dev/null
wait_done
echo 'PASS disposable repository disconnected'
