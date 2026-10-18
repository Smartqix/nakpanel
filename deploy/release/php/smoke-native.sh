#!/usr/bin/env bash
# Isolated candidate CLI and FastCGI smoke. Only disposable Resolute builders.
set -euo pipefail
[[ "${NAKPANEL_ISOLATED_PHP_BUILDER:-}" == 1 ]] || { echo 'requires disposable isolated native builder' >&2; exit 1; }
source /etc/os-release
[[ "${ID}" == ubuntu && "${VERSION_ID}" == 26.04 ]] || exit 1
[[ "$(id -u)" == 0 ]] || { echo 'requires builder root for isolated FPM users/unit' >&2; exit 1; }
minor="${1:?usage: smoke-native.sh 8.3|8.4 OUTPUT}"
[[ "${minor}" == 8.3 || "${minor}" == 8.4 ]] || exit 1
output="${2:?evidence output required}"
mkdir -p "${output}"; output="$(cd "${output}" && pwd)"
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
prefix="/opt/nakpanel/php/${minor}"
unit="nakpanel-php-smoke-${minor//./}"
account="npsmoke${minor//./}"
document_root="/srv/${unit}"
config="/etc/${unit}.conf"
if id "${account}" >/dev/null 2>&1; then echo 'smoke account already exists; fresh smoke required' >&2; exit 1; fi
useradd --system --home-dir "${document_root}" --shell /usr/sbin/nologin "${account}"
mkdir -p "${document_root}"
chown "${account}:${account}" "${document_root}"
chmod 0700 "${document_root}"
cp "${here}/sources.lock.json" "${document_root}/sources.lock.json"
cat > "${document_root}/index.php" <<'PHP'
<?php
$required=json_decode(file_get_contents(__DIR__.'/sources.lock.json'),true)['required_extensions'];
$missing=array_values(array_filter($required,fn($extension)=>!extension_loaded($extension)));
header('Content-Type: application/json');
echo json_encode(['version'=>PHP_VERSION,'sapi'=>PHP_SAPI,'uid'=>posix_geteuid(),
 'ini'=>php_ini_loaded_file(),'scanned'=>php_ini_scanned_files(),'missing'=>$missing,
 'outside_readable'=>@file_get_contents('/etc/passwd')!==false,
 'shell_exec_enabled'=>function_exists('shell_exec'),'inside_readable'=>is_readable(__FILE__)]);
PHP
chmod 0644 "${document_root}/index.php" "${document_root}/sources.lock.json"
cat > "${config}" <<EOF
[global]
pid = /run/${unit}/master.pid
error_log = /run/${unit}/error.log
[smoke]
user = ${account}
group = ${account}
listen = /run/${unit}/fpm.sock
listen.owner = root
listen.group = root
listen.mode = 0600
pm = ondemand
pm.max_children = 2
pm.process_idle_timeout = 5s
clear_env = yes
catch_workers_output = yes
security.limit_extensions = .php
php_admin_value[open_basedir] = ${document_root}:/tmp
php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen
EOF
chmod 0600 "${config}"
trap 'journalctl -u "${unit}" --no-pager > "${output}/fpm-journal-${minor}.log"; if [[ -f "/run/${unit}/error.log" ]]; then cp "/run/${unit}/error.log" "${output}/fpm-error-${minor}.log"; fi; systemctl stop "${unit}.service" >/dev/null 2>&1 || true' EXIT
install -d -m0755 "/run/${unit}"
PHP_INI_SCAN_DIR="${prefix}/etc/cli/conf.d" "${prefix}/bin/php" -c "${prefix}/etc/cli/php.ini" -r '
$lock=json_decode(file_get_contents($argv[1]),true);$required=$lock["required_extensions"];
foreach($required as $ext) {if(!extension_loaded($ext)){fwrite(STDERR,"missing $ext\n");exit(1);}}
if(PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION!==$argv[2])exit(2);
if(php_ini_loaded_file()!==$argv[3]."/etc/cli/php.ini")exit(3);
echo json_encode(["version"=>PHP_VERSION,"sapi"=>PHP_SAPI,"ini"=>php_ini_loaded_file(),"scanned"=>php_ini_scanned_files(),"extensions"=>get_loaded_extensions()]),PHP_EOL;
' "${here}/sources.lock.json" "${minor}" "${prefix}" | tee "${output}/cli-${minor}.json"
PHP_INI_SCAN_DIR="${prefix}/etc/fpm/conf.d" "${prefix}/sbin/php-fpm" -c "${prefix}/etc/fpm/php.ini" -y "${config}" -tt > "${output}/fpm-config-${minor}.log" 2>&1
systemd-run --unit "${unit}" --property=Type=simple --property=NoNewPrivileges=yes \
 --property=ProtectSystem=strict --property=ProtectHome=true --property=PrivateTmp=true \
 --property="RuntimeDirectory=${unit}" --property="ReadWritePaths=${document_root}" \
 /usr/bin/env "PHP_INI_SCAN_DIR=${prefix}/etc/fpm/conf.d" "${prefix}/sbin/php-fpm" \
 -F -c "${prefix}/etc/fpm/php.ini" -y "${config}"
for attempt in $(seq 1 30); do [[ ! -S "/run/${unit}/fpm.sock" ]] || break; sleep 1; done
systemctl is-active "${unit}" > "${output}/fpm-unit-${minor}.state"
env -i SCRIPT_FILENAME="${document_root}/index.php" REQUEST_METHOD=GET SERVER_PROTOCOL=HTTP/1.1 \
 /usr/bin/cgi-fcgi -bind -connect "/run/${unit}/fpm.sock" > "${output}/fastcgi-${minor}.response"
python3 - "${output}/fastcgi-${minor}.response" "${prefix}" "$(id -u "${account}")" <<'PY'
import json,pathlib,sys
response=pathlib.Path(sys.argv[1]).read_text();data=json.loads(response.split('\n\n',1)[1])
assert data['version'].startswith(pathlib.Path(sys.argv[2]).name+'.'),data
assert data['sapi']=='fpm-fcgi' and data['uid']==int(sys.argv[3]) and data['uid']!=0,data
assert data['ini']==sys.argv[2]+'/etc/fpm/php.ini',data
assert data['missing']==[] and data['inside_readable'] is True,data
assert data['outside_readable'] is False and data['shell_exec_enabled'] is False,data
assert '/etc/fpm/conf.d/' in data['scanned'] and '/etc/cli/' not in data['scanned'],data
print(json.dumps(data,sort_keys=True))
PY
journalctl -u "${unit}" --no-pager > "${output}/fpm-journal-${minor}.log"
printf 'NATIVE_CLI_FPM_FASTCGI_SMOKE_PASSED %s\n' "${minor}"
