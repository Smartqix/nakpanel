#!/usr/bin/env bash
# Sourced by the Phase31 gate after its owned plan/subscription fixtures converge.
# All mutations use authenticated product routes; SQL is an independent oracle.

phase31_php_json(){
  python3 -I -B - "$1" "$2" "$3" "$4" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        value = json.load(stream)
    kind, plan_id, revision = sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
    if value.get("ok") is not True or type(value.get("plan_id")) is not int or value["plan_id"] != plan_id:
        raise ValueError("identity")
    if type(value.get("revision")) is not int or value["revision"] != revision:
        raise ValueError("revision")
    if kind == "preview":
        preview = value.get("preview", {})
        changes = preview.get("changes")
        if value.get("no_change") is not False or preview.get("allowed") is not True or value.get("blockers") != []:
            raise ValueError("preview admission")
        if type(changes) is not list or not changes or any(change.get("path") not in {"php.allowed_versions", "php.default_version"} for change in changes):
            raise ValueError("preview writes")
    elif kind in {"apply", "noop"}:
        if value.get("changed") is not (kind == "apply") or value.get("sync_state") not in {"pending", "in_sync"}:
            raise ValueError("commit outcome")
    else:
        raise ValueError("mode")
except Exception:
    raise SystemExit("phase31: invalid PHP-only API response")
PY
}

phase31_php_error(){
  python3 -I -B - "$1" "$2" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    value = json.load(stream)
if value.get("ok") is not False or value.get("code") != sys.argv[2]:
    raise SystemExit("phase31: PHP-only rejection did not match the requested boundary")
PY
}

phase31_php_digest(){
  local mode="$1" id="$2" subscription="$3" plan_expr='to_jsonb(p)' preset_expr='to_jsonb(ps)' snapshot_expr='to_jsonb(e)'
  [[ "${id}" =~ ^[1-9][0-9]*$ && "${subscription}" =~ ^[0-9]+$ ]] || fail "invalid PHP-only oracle identity"
  if [[ "${mode}" == nonphp ]]; then
    plan_expr="(to_jsonb(p)-'revision'-'updated_at'-'php_allowlist'-'default_php_version'-'hosting_policy')||jsonb_build_object('hosting_policy',p.hosting_policy #- '{php,allowed_versions}' #- '{php,default_version}')"
    preset_expr="(to_jsonb(ps)-'hosting'-'php')||jsonb_build_object('hosting',ps.hosting-'allowed_php_versions'-'default_php_version','php',ps.php-'allowed_versions'-'default_version')"
    snapshot_expr="(to_jsonb(e)-'source_revision'-'updated_at'-'php_allowlist'-'default_php_version'-'hosting_policy'-'service_presets')||jsonb_build_object('hosting_policy',e.hosting_policy #- '{php,allowed_versions}' #- '{php,default_version}','service_presets',e.service_presets #- '{hosting,allowed_php_versions}' #- '{hosting,default_php_version}' #- '{php,allowed_versions}' #- '{php,default_version}')"
  elif [[ "${mode}" != full ]]; then
    fail "invalid PHP-only oracle mode"
  fi
  db "SELECT encode(sha256(convert_to(jsonb_build_object('plan',${plan_expr},'presets',${preset_expr},'snapshot',${snapshot_expr})::text,'UTF8')),'hex') FROM plans p LEFT JOIN plan_service_presets ps ON ps.plan_id=p.id LEFT JOIN subscription_entitlements e ON e.subscription_id=${subscription} WHERE p.id=${id}"
}

phase31_php_wait(){
  local id="$1"
  wait_for 'PHP-only snapshot and service convergence' "SELECT (s.sync_status='in_sync' AND s.sync_error='' AND s.plan_revision=p.revision AND e.source_revision=GREATEST(p.revision,COALESCE((SELECT MAX(a.revision) FROM subscription_addons sa JOIN addon_plans a ON a.id=sa.addon_plan_id WHERE sa.subscription_id=s.id),0)) AND account.convergence_status='in_sync' AND account.desired_revision=account.applied_revision AND account.last_error='')::text FROM subscriptions s JOIN plans p ON p.id=s.plan_id JOIN subscription_entitlements e ON e.subscription_id=s.id JOIN subscription_system_accounts account ON account.subscription_id=s.id WHERE s.id=${id}" true
}

phase31_php_history(){
  local id="$1" previous="$2" audit_before="$3" writes="$4"
  [[ "$(db "SELECT (count(*)=${writes} AND bool_and(COALESCE(definition#>>'{_operation,kind}'='php_versions_only' AND definition_hash=encode(sha256(convert_to(definition::text,'UTF8')),'hex') AND actor_user_id IS NOT NULL AND btrim(actor_label)<>'' AND btrim(change_reason)<>'',false)))::text FROM plan_revisions WHERE plan_id=${id} AND revision>${previous}")" == true ]] || fail "PHP-only immutable raw revision proof failed"
  [[ "$(db "SELECT count(*) FROM audit_events WHERE action='plan.saved' AND target_type='plan' AND target_id=${id}")" == "$((audit_before+writes))" ]] || fail "PHP-only save did not produce exactly one atomic audit per write"
}

phase31_php_ready(){
  multipass_exec_short "${VM_NAME}" -- sudo -u nakpanel python3 - <<'PY'
import json, re, socket
request = {"id": "phase31-php-only-capabilities", "op": "runtime_capabilities", "data": {}}
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(10)
    client.connect("/run/nakpanel/agent.sock")
    client.sendall(json.dumps(request).encode() + b"\n")
    data = bytearray()
    while True:
        chunk = client.recv(65536)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > 2 * 1024 * 1024:
            raise SystemExit("phase31: capability response exceeds its bound")
response = json.loads(data)
if response.get("ok") is not True or response.get("id") != request["id"]:
    raise SystemExit("phase31: authoritative capability observation failed")
capabilities = response["data"]
runtimes = capabilities.get("php_runtimes")
versions = [item["version"] for item in runtimes if item.get("ready") is True] if runtimes else capabilities.get("php_versions", [])
if type(versions) is not list or not versions or len(versions) > 32 or any(type(item) is not str or re.fullmatch(r"[1-9][0-9]*\.[0-9]+", item) is None for item in versions):
    raise SystemExit("phase31: no bounded ready PHP inventory")
print(",".join(sorted(set(versions))))
PY
}

verify_phase31_php_versions(){
  local ready_csv alternate='' version revision original_revision audit_before before full_before original_versions original_default
  local -a versions php_form
  ready_csv="$(phase31_php_ready)" || fail "could not observe ready PHP runtimes"
  IFS=',' read -r -a versions <<<"${ready_csv}"
  [[ ",${ready_csv}," == *",${NAKPANEL_FIXTURE_PHP},"* ]] || fail "fixture PHP is not authoritatively ready"
  for version in "${versions[@]}"; do
    if [[ "${version}" != "${NAKPANEL_FIXTURE_PHP}" ]]; then alternate="${version}"; break; fi
  done

  echo 'phase31: preview and update PHP-only intent without normalizing the stored draft'
  revision="$(db "SELECT revision FROM plans WHERE id=${draft_id}")"
  original_revision="${revision}"
  audit_before="$(db "SELECT count(*) FROM audit_events WHERE action='plan.saved' AND target_type='plan' AND target_id=${draft_id}")"
  before="$(phase31_php_digest nonphp "${draft_id}" 0)"
  full_before="$(phase31_php_digest full "${draft_id}" 0)"
  php_form=(-d "expected_revision=${revision}" -d "php_versions=${NAKPANEL_FIXTURE_PHP}" -d "default_php_version=${NAKPANEL_FIXTURE_PHP}" -d 'change_reason=Phase31 PHP-only draft qualification')
  post_expect 200 phase31-php-draft-preview "plans/${draft_id}/php-versions/preview" "${php_form[@]}"
  phase31_php_json "${tmpdir}/phase31-php-draft-preview.out" preview "${draft_id}" "${revision}"
  [[ "$(phase31_php_digest full "${draft_id}" 0)" == "${full_before}" ]] || fail "PHP-only preview changed its stored plan"
  post_expect 200 phase31-php-draft-update "plans/${draft_id}/php-versions" "${php_form[@]}"
  revision=$((revision+1))
  phase31_php_json "${tmpdir}/phase31-php-draft-update.out" apply "${draft_id}" "${revision}"
  [[ "$(phase31_php_digest nonphp "${draft_id}" 0)" == "${before}" ]] || fail "PHP-only draft update changed non-PHP intent or readiness metadata"
  [[ "$(db "SELECT lifecycle_status||':'||is_active::text FROM plans WHERE id=${draft_id}")" == draft:false ]] || fail "PHP-only update activated its draft"
  post_expect 409 phase31-php-stale "plans/${draft_id}/php-versions" "${php_form[@]}"
  phase31_php_error "${tmpdir}/phase31-php-stale.out" stale_revision
  full_before="$(phase31_php_digest full "${draft_id}" 0)"
  php_form=(-d "expected_revision=${revision}" -d "php_versions=${NAKPANEL_FIXTURE_PHP}" -d "default_php_version=${NAKPANEL_FIXTURE_PHP}" -d 'change_reason=Phase31 explicit no-op')
  post_expect 200 phase31-php-noop "plans/${draft_id}/php-versions" "${php_form[@]}"
  phase31_php_json "${tmpdir}/phase31-php-noop.out" noop "${draft_id}" "${revision}"
  post_expect 400 phase31-php-unready "plans/${draft_id}/php-versions" -d "expected_revision=${revision}" -d php_versions=9.9 -d default_php_version=9.9 -d 'change_reason=Phase31 unready refusal'
  phase31_php_error "${tmpdir}/phase31-php-unready.out" php_version_unready
  [[ "$(phase31_php_digest full "${draft_id}" 0)" == "${full_before}" ]] || fail "PHP-only no-op or refusal changed its stored plan"
  phase31_php_history "${draft_id}" "${original_revision}" "${audit_before}" 1

  # Even a single-runtime native profile must prove the active zero-write path.
  phase31_php_wait "${subscription_id}"
  revision="$(db "SELECT revision FROM plans WHERE id=${plan_id}")"
  IFS='|' read -r original_versions original_default <<<"$(db "SELECT php_allowlist||'|'||default_php_version FROM plans WHERE id=${plan_id}")"
  local active_metadata_before active_metadata_after
  active_metadata_before="$(db "SELECT (SELECT count(*) FROM plan_revisions WHERE plan_id=${plan_id})||':'||(SELECT count(*) FROM audit_events WHERE action='plan.saved' AND target_type='plan' AND target_id=${plan_id})||':'||a.desired_revision||':'||a.applied_revision||':'||(SELECT count(*) FROM river_job WHERE kind='sync_plan_subscriptions' AND args->>'plan_id'='${plan_id}') FROM subscription_system_accounts a WHERE a.subscription_id=${subscription_id}")"
  full_before="$(phase31_php_digest full "${plan_id}" "${subscription_id}")"
  IFS=',' read -r -a versions <<<"${original_versions}"
  php_form=(-d "expected_revision=${revision}" -d "default_php_version=${original_default}" -d 'change_reason=Phase31 active zero-write qualification')
  for version in "${versions[@]}"; do php_form+=(-d "php_versions=${version}"); done
  post_expect 200 phase31-php-active-noop "plans/${plan_id}/php-versions" "${php_form[@]}"
  phase31_php_json "${tmpdir}/phase31-php-active-noop.out" noop "${plan_id}" "${revision}"
  post_expect 400 phase31-php-active-unready "plans/${plan_id}/php-versions" -d "expected_revision=${revision}" -d php_versions=9.9 -d default_php_version=9.9 -d 'change_reason=Phase31 active unready refusal'
  phase31_php_error "${tmpdir}/phase31-php-active-unready.out" php_version_unready
  [[ "$(phase31_php_digest full "${plan_id}" "${subscription_id}")" == "${full_before}" ]] || fail "active PHP-only no-op or refusal changed raw intent"
  active_metadata_after="$(db "SELECT (SELECT count(*) FROM plan_revisions WHERE plan_id=${plan_id})||':'||(SELECT count(*) FROM audit_events WHERE action='plan.saved' AND target_type='plan' AND target_id=${plan_id})||':'||a.desired_revision||':'||a.applied_revision||':'||(SELECT count(*) FROM river_job WHERE kind='sync_plan_subscriptions' AND args->>'plan_id'='${plan_id}') FROM subscription_system_accounts a WHERE a.subscription_id=${subscription_id}")"
  [[ "${active_metadata_before}" == "${active_metadata_after}" ]] || fail "active zero-write request created history, audit, convergence or jobs"

  if [[ -z "${alternate}" ]]; then
    echo 'phase31: single ready runtime; actual draft write and active zero-write boundaries passed; alternate-runtime write is unavailable'
    return 0
  fi
  echo 'phase31: propagate PHP-only offers and preserve synced raw snapshots across manual retry'
  phase31_php_wait "${subscription_id}"
  revision="$(db "SELECT revision FROM plans WHERE id=${plan_id}")"
  original_revision="${revision}"
  IFS='|' read -r original_versions original_default <<<"$(db "SELECT php_allowlist||'|'||default_php_version FROM plans WHERE id=${plan_id}")"
  audit_before="$(db "SELECT count(*) FROM audit_events WHERE action='plan.saved' AND target_type='plan' AND target_id=${plan_id}")"
  before="$(phase31_php_digest nonphp "${plan_id}" "${subscription_id}")"
  php_form=(-d "expected_revision=${revision}" -d "default_php_version=${alternate}" -d 'change_reason=Phase31 preserve selected runtime while adding a ready offer')
  IFS=',' read -r -a versions <<<"${original_versions}"
  for version in "${versions[@]}" "${alternate}"; do php_form+=(-d "php_versions=${version}"); done
  post_expect 200 phase31-php-active-preview "plans/${plan_id}/php-versions/preview" "${php_form[@]}"
  phase31_php_json "${tmpdir}/phase31-php-active-preview.out" preview "${plan_id}" "${revision}"
  post_expect 200 phase31-php-active-update "plans/${plan_id}/php-versions" "${php_form[@]}"
  revision=$((revision+1))
  phase31_php_json "${tmpdir}/phase31-php-active-update.out" apply "${plan_id}" "${revision}"
  phase31_php_wait "${subscription_id}"
  [[ "$(phase31_php_digest nonphp "${plan_id}" "${subscription_id}")" == "${before}" ]] || fail "PHP-only synchronization changed non-PHP data"
  post_as phase31-php-manual-retry "subscriptions/${subscription_id}/sync" -d 'retry=explicit'
  phase31_php_wait "${subscription_id}"
  [[ "$(phase31_php_digest nonphp "${plan_id}" "${subscription_id}")" == "${before}" ]] || fail "same-revision manual synchronization erased raw preservation"
  php_form=(-d "expected_revision=${revision}" -d "default_php_version=${original_default}" -d 'change_reason=Phase31 restore original PHP intent through a second narrow revision')
  for version in "${versions[@]}"; do php_form+=(-d "php_versions=${version}"); done
  post_expect 200 phase31-php-restore "plans/${plan_id}/php-versions" "${php_form[@]}"
  revision=$((revision+1))
  phase31_php_json "${tmpdir}/phase31-php-restore.out" apply "${plan_id}" "${revision}"
  phase31_php_wait "${subscription_id}"
  [[ "$(phase31_php_digest nonphp "${plan_id}" "${subscription_id}")" == "${before}" ]] || fail "second PHP-only revision changed non-PHP data"
  phase31_php_history "${plan_id}" "${original_revision}" "${audit_before}" 2
}
