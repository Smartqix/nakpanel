#!/usr/bin/env python3
"""Explicit disposable Surý maintenance rehearsal. Importing this module is inert.

Same-version delivery and failed-configuration recovery are distinct from a
version advance, package-version rollback, application rollback or production update.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import io
import json
import lzma
import os
from pathlib import Path
import re
import shlex
import signal
from urllib.parse import unquote, urlsplit
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

MODE = 'SAME_VERSION_REINSTALL_AND_FAILED_CONFIGURATION_RECOVERY'
MINORS = ('8.3', '8.4', '8.5')
KEY_SHA = 'b486fd5488185c4c46467960fa69c53d5085fec492cf76b9eaf3db33561c9d7c'
FINGERPRINT = '15058500A0235D97F5D10063B188E2B695BD4743'
GATES = {'bundle','fresh-install','inventory','phase28','valkey-platform','security','phase29','phase30','phase31','phase32','internal-tools','mail-workspace','phase33','phase34','domain-removal','release-artifacts'}
BINDING = ('source_vm','run_token','release','architecture','profile','php_provider','app_version','runtime_commit','manifest_sha256','installed_binary_sha256')
SERVICES = ('nakpanel.service', 'nakpanel-agent.service')
HEX = re.compile(r'^[a-f0-9]{64}$')
PHP_NAME = re.compile(r'^php(?:-common|8\.[345]-[a-z0-9-]+)$')
REQUIRED_EXTENSIONS = ('bcmath','curl','dom','exif','fileinfo','gd','imagick','intl','mbstring','mysqli','openssl','redis','SimpleXML','soap','xml','zip','Zend OPcache')
QUALIFIER_FILES = {'deploy/multipass/internal-tools-verify.sh','deploy/multipass/roundcube-send-read.py','deploy/multipass/roundcube_send_read_test.go','deploy/multipass/roundcube_send_read_test.py'}


class MaintenanceTermination(KeyboardInterrupt):
    pass


def controlled_termination(signum, frame):
    raise MaintenanceTermination('controlled SIGTERM cancellation')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii') + b'\n'


def sha_value(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def bound(actual, expected):
    require(type(actual) is dict and type(expected) is dict, 'receipt bindings must be objects')
    require(all(actual.get(k) == expected[k] for k in BINDING), 'receipt source/profile/payload binding differs')


def validate_authorization(config, report, supplement, retention, handoff):
    require(all(type(item) is dict for item in (config,report,supplement,retention,handoff)), 'authorization inputs must be JSON objects')
    require(config['operation'] == MODE, 'only same-version reinstall/configuration recovery is supported; removal/provider switch/version rollback are unsupported')
    require(config['release'] == '26.04' and config['profile'] == 'ubuntu-26.04-sury' and config['php_provider'] == 'sury', 'existing Surý Resolute profile required')
    require(config['architecture'] in ('amd64', 'arm64'), 'unsupported architecture')
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{5,63}', config['run_token']) is not None, 'unsafe token')
    require(config['source_vm'].startswith('nakpanel-26-04-' + config['architecture'] + '-') and config['source_vm'].endswith(config['run_token']), 'VM identity differs from selected run')
    require(re.fullmatch(r'[a-f0-9]{40}', config['runtime_commit']) is not None, 'invalid selected commit')
    require(sha_value(config['manifest_sha256']) and type(config['installed_binary_sha256']) is dict and set(config['installed_binary_sha256']) == {'panel','agent','panelctl'} and all(sha_value(x) for x in config['installed_binary_sha256'].values()), 'invalid selected release hashes')
    require(report.get('qualification_scope') == 'CURRENT_VERSION_ONLY' and report.get('excluded_gates') == ['real-upgrade'], 'current-version qualification scope required')
    require(report.get('schema_version') == 1 and type(report.get('schema_version')) is int and report.get('qualification_passed') is True and report.get('pending_gates') == [], 'all canonical qualification gates must have passed')
    require(report.get('full_php_parity') is True and type(report.get('php_contract')) is list and len(report['php_contract']) == 3 and set(report['php_contract']) == set(MINORS), 'the complete qualified Surý PHP8.3/8.4/8.5 contract is required')
    for key in ('source_vm','run_token','release','architecture','profile','php_provider'):
        require(report.get(key) == config[key], 'qualification report source binding differs')
    gates = report.get('gates')
    require(type(gates) is list and len(gates) == len(GATES) and all(type(g) is dict and type(g.get('name')) is str for g in gates) and {g.get('name') for g in gates} == GATES, 'exactly current16 canonical gates are required')
    require(all(g.get('status') == 'PASS' and type(g.get('exit_code')) is int and g['exit_code'] == 0 for g in gates), 'a canonical gate did not pass')
    require(supplement.get('schema') == 'nakpanel-roundcube-supplement-v1' and supplement.get('success') is True, 'real Roundcube supplemental receipt required')
    bound(supplement, config)
    for key in ('qualifier_wrapper_sha256','qualifier_helper_sha256'):
        require(sha_value(config[key]) and supplement.get(key) == config[key], 'Roundcube qualifier differs from reviewed source')
    raw = supplement.get('raw_receipt', {})
    require(type(raw) is dict, 'raw Roundcube receipt must be an object')
    require(raw.get('schema') == 'nakpanel-roundcube-send-read-v1' and raw.get('success') is True and raw.get('status') == 'PASS', 'Roundcube raw result is not a passing actual flow')
    require(type(raw.get('send_attempts')) is int and raw['send_attempts'] == 1, 'Roundcube send was missing/retried/uncertain')
    require(all(raw.get(k) is True for k in ('http_send_completed','self_recipient_verified','imap_arrival_verified','imap_message_id_verified','roundcube_body_verified')), 'actual Roundcube send/self-recipient/IMAP/body proof is incomplete')
    require(type(raw.get('message_id')) is str and re.fullmatch(r'<[^<>\s]+@[^<>\s]+>', raw['message_id']) is not None, 'actual server-generated message ID required')
    require(type(raw.get('uid')) is str and re.fullmatch(r'[1-9][0-9]*', raw['uid']) is not None, 'actual positive IMAP UID required')
    require(all(sha_value(raw.get(k)) for k in ('subject_sha256','body_sha256','recipient_sha256','qualifier_helper_sha256','certificate_sha256')), 'invalid raw Roundcube hashes')
    require(raw['qualifier_helper_sha256'] == config['qualifier_helper_sha256'] and digest(canonical(raw)) == supplement.get('raw_receipt_sha256'), 'raw Roundcube bytes/helper hash differ')
    require(retention.get('schema') == 'nakpanel-sury-maintenance-retention-v1' and retention.get('status') == 'PASS', 'actual cold retention receipt required')
    bound(retention, config)
    require(retention.get('snapshot_name') == config['retention_snapshot'] and retention.get('snapshot_id') == config['source_vm']+'.'+config['retention_snapshot'] and sha_value(retention.get('snapshot_info_sha256')), 'actual retained snapshot identity/metadata hash required')
    require(all(retention.get(k) is True for k in ('cold_snapshot','running_revalidated','ownership_verified')), 'cold snapshot restart/identity proof required')
    require(handoff.get('schema') == 'nakpanel-sury-maintenance-handoff-v1' and handoff.get('exclusive_source_handoff') is True and handoff.get('allowed_operations') == [MODE], 'exclusive qualified-source handoff is pending')
    bound(handoff, config)
    for k in ('qualification_report_sha256','roundcube_receipt_sha256','retention_receipt_sha256'):
        require(sha_value(config[k]) and handoff.get(k) == config[k], 'handoff receipt hash differs')


def check_apt_plan(text, versions, expected):
    seen = set()
    for line in text.splitlines():
        require(not line.startswith('Remv '), 'APT removals are unsupported, including mandatory internal PHP8.5')
        if not line.startswith(('Inst ', 'Conf ')):
            continue
        match = re.match(r'^(Inst|Conf) (\S+?)(?::(?:arm64|amd64))?(?: \[[^\]]+\])? \((\S+)', line)
        require(match is not None, 'unrecognized APT package operation')
        operation, package, version = match.groups()
        require(PHP_NAME.fullmatch(package) is not None and package in versions and version == versions[package], 'APT plan changes an unapproved package/version')
        if operation == 'Inst':
            require(package in expected, 'APT plan installs beyond the exact requested PHP packages')
            seen.add(package)
    require(seen == set(expected), 'APT did not plan the exact same-version reinstall')


def check_candidate(policy, version):
    candidate = re.search(r'^\s*Candidate:\s*(\S+)\s*$', policy, re.M)
    require(candidate is not None and candidate[1] == version, 'current APT candidate differs from captured original version')
    selected = False
    found = False
    for line in policy.splitlines():
        match = re.fullmatch(r'\s*(?:\*\*\*\s+)?(\S+)\s+-?\d+\s*', line)
        if match:
            selected = match[1] == version
        if selected and re.fullmatch(r'\s*-?\d+\s+https://packages\.sury\.org/php/?\s+resolute/main\s+(?:arm64|amd64|all)\s+Packages\s*', line):
            found = True
    require(found, 'selected PHP candidate must use exact signed Surý HTTPS Resolute source')


class FaultFile:
    def __init__(self, pool, token):
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{5,63}', token) is not None, 'unsafe fault token')
        self.path = Path(pool) / ('zz-nakpanel-maintenance-' + token + '.conf')
        self.data = b'[nakpanel_owned_drill]\nnakpanel_owned_drill_invalid = yes\n'
        self.identity = None

    def create(self):
        info = self.path.parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o022, 'unsafe FPM pool directory')
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(self.data)
            stream.flush()
            os.fsync(stream.fileno())
            info = os.fstat(stream.fileno())
        self.identity = (info.st_dev, info.st_ino)

    def remove(self):
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and (info.st_dev, info.st_ino) == self.identity and stream.read() == self.data, 'fault path inode/owner/hash changed; refusing removal')
        current = self.path.lstat()
        require((current.st_dev, current.st_ino) == self.identity, 'fault path changed before removal')
        self.path.unlink()


def check_expected_failure(minor, path, config_test, transaction, status):
    require(minor in MINORS, 'unsupported PHP minor')
    check_fault_config(path, config_test)
    text = transaction.stdout + transaction.stderr
    package = 'php' + minor + '-fpm'
    postinst_errors = ('installed ' + package + ' package post-installation script subprocess returned error exit status 1', 'old ' + package + ' package postinst maintainer script subprocess failed with exit status 1')
    require(transaction.returncode == 100 and 'error processing package ' + package + ' (--configure)' in text and any(re.search(re.escape(message) + r'(?:\n|$)', text) for message in postinst_errors), 'APT failure was not the expected real FPM postinst failure')
    require(status.strip() == 'install ok half-configured', 'real dpkg half-configured state required')


def check_fault_config(path, config_test):
    diagnostic = config_test.stdout + config_test.stderr
    require(config_test.returncode != 0 and str(path) in diagnostic and "unknown entry 'nakpanel_owned_drill_invalid'" in diagnostic, 'owned injected FPM configuration did not cause the exact expected failure')


def restore_service_actions(before):
    require(set(before) == set(SERVICES) and all(v in ('active','inactive') for v in before.values()), 'unknown mutation-worker service/state')
    return [('start' if before[unit] == 'active' else 'stop', unit) for unit in SERVICES]


def tree_state(root):
    root = Path(root)
    result = {}
    for p in sorted(root.rglob('*')):
        info = p.lstat()
        require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode), 'unexpected configuration special file')
        result[str(p.relative_to(root))] = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid, 'kind': stat.S_IFMT(info.st_mode), 'value': os.readlink(p) if p.is_symlink() else digest(p.read_bytes()) if p.is_file() else None}
    return result


def drill_minor(minor, token, pool, backend, record):
    require(minor in MINORS, 'unsupported minor')
    before = tree_state(pool)
    fault = FaultFile(pool, token)
    fault.create()
    record('injected', {'minor': minor, 'path': str(fault.path), 'inode': fault.identity, 'sha256': digest(fault.data)})
    # No automatic blind repair on unexpected failure. The exact owned file and
    # durable receipt remain for operator inspection/cold-snapshot fallback.
    config_test = backend.config_test(minor)
    check_fault_config(fault.path, config_test)
    transaction = backend.reinstall(minor)
    status = backend.package_status(minor)
    record('failed_transaction_observed', {'minor': minor, 'config_test': vars(config_test), 'transaction': vars(transaction), 'dpkg_status': status})
    check_expected_failure(minor, fault.path, config_test, transaction, status)
    record('expected_configuration_failure', {'minor': minor})
    fault.remove()
    require(tree_state(pool) == before, 'preexisting FPM pool settings changed')
    recovery = backend.reinstall(minor)
    require(recovery.returncode == 0 and backend.package_status(minor).strip() == 'install ok installed' and backend.config_test(minor).returncode == 0, 'exact cached package configuration recovery failed')
    require(tree_state(pool) == before, 'FPM pool settings differ after recovery')
    record('recovered', {'minor': minor})


def private_bytes(path, expected=None, private=True):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o022, 'unsafe input type/owner/mode: ' + str(path))
        if private:
            require(stat.S_IMODE(info.st_mode) == 0o600, 'private control input must have mode0600')
        value = stream.read()
    if expected is not None:
        require(sha_value(expected) and digest(value) == expected, 'bound input hash differs: ' + str(path))
    return value


def write_private(path, value):
    path = Path(path)
    data = value if isinstance(value, bytes) else canonical(value)
    fd,temporary = tempfile.mkstemp(prefix='.'+path.name+'.',suffix='.next',dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:os.unlink(temporary)
        except FileNotFoundError:pass


def check_native_gpgv(proof, config, release_sha):
    require(proof.get('native_gpgv') is True and type(proof.get('exit_code')) is int and proof['exit_code'] == 0, 'native gpgv verification is required before retained baseline use')
    expected = {'vm':config['source_vm'],'run_token':config['run_token'],'release':'26.04','architecture':config['architecture'],'key_sha256':KEY_SHA,'inrelease_sha256':release_sha,'validsig_fingerprint':FINGERPRINT,'guest_mutation':False,'package_transaction':False}
    require(all(proof.get(k) == v and (type(proof.get(k)) is bool if type(v) is bool else True) for k,v in expected.items()), 'native gpgv receipt identity/key/Release binding differs')


def check_roundcube_execution(receipt, config, envelope):
    require(receipt.get('schema') == 'nakpanel-roundcube-supplement-execution-v1' and receipt.get('success') is True and type(receipt.get('exit_code')) is int and receipt['exit_code'] == 0, 'passing real Roundcube execution receipt required')
    require(all(receipt.get(k) == config[k] for k in ('source_vm','run_token','release','architecture','profile','php_provider','runtime_commit','qualifier_commit')), 'Roundcube execution runtime/qualifier identity differs')
    expected = config['qualifier_files_sha256']
    require(set(expected) == QUALIFIER_FILES and all(sha_value(v) for v in expected.values()) and receipt.get('qualifier_files_sha256') == expected, 'all four reviewed qualifier file hashes are required')
    require(receipt.get('envelope_sha256') == digest(canonical(envelope)), 'real execution receipt does not bind the exact canonical envelope')
    times = []
    for key in ('started_at','finished_at'):
        require(type(receipt.get(key)) is str, 'real UTC execution times required')
        value = datetime.fromisoformat(receipt[key].replace('Z','+00:00'))
        require(value.utcoffset() is not None and value.utcoffset().total_seconds() == 0, 'execution time must be UTC')
        times.append(value)
    require(times[1] >= times[0], 'execution finished before it started')


def release_body(data):
    text = data.decode('utf-8').replace('\r\n', '\n')
    require(text.startswith('-----BEGIN PGP SIGNED MESSAGE-----\n') and '\n-----BEGIN PGP SIGNATURE-----\n' in text, 'signed Release framing required')
    body = text.split('\n\n', 1)[1].split('\n-----BEGIN PGP SIGNATURE-----\n', 1)[0]
    body = '\n'.join(line[2:] if line.startswith('- ') else line for line in body.splitlines())
    fields = {}
    checksums = {}
    section = False
    for line in body.splitlines():
        if line == 'SHA256:':
            section = True
        elif line.startswith(' ') and section:
            parts = line.split()
            require(len(parts) == 3 and sha_value(parts[0]), 'invalid signed Release digest')
            require(parts[2] not in checksums, 'duplicate Release digest path')
            checksums[parts[2]] = (parts[0], int(parts[1]))
        elif not line.startswith((' ', '\t')) and ':' in line:
            section = False
            key, value = line.split(':', 1)
            require(key not in fields, 'duplicate Release field')
            fields[key] = value.strip()
    require(fields.get('Origin') == 'deb.sury.org' and fields.get('Suite') == 'resolute' and fields.get('Codename') == 'resolute', 'wrong signed provider/suite')
    return fields, checksums


def deb822(data):
    for block in data.decode('utf-8').strip().split('\n\n'):
        row = {}
        key = None
        for line in block.splitlines():
            if line.startswith((' ', '\t')):
                require(key is not None, 'invalid Debian continuation')
                row[key] += '\n' + line
            else:
                key, separator, value = line.partition(':')
                require(separator and key not in row, 'invalid/duplicate Debian field')
                row[key] = value.strip()
        yield row


def check_index_packages(release, compressed, architecture, packages):
    fields, checksums = release_body(release)
    require(architecture in fields.get('Architectures', '').split(), 'architecture missing from signed Release')
    name = 'main/binary-' + architecture + '/Packages'
    require((digest(compressed),len(compressed)) == checksums.get(name + '.xz'), 'compressed index differs from signed Release')
    plain = lzma.decompress(compressed)
    require((digest(plain),len(plain)) == checksums.get(name), 'plain index differs from signed Release')
    rows = list(deb822(plain))
    seen = set()
    for entry in packages:
        require(PHP_NAME.fullmatch(entry['Package']) and entry['Package'] not in seen and entry['Architecture'] in (architecture,'all'), 'unexpected or duplicate PHP package/architecture')
        seen.add(entry['Package'])
        matches = [row for row in rows if all(row.get(k) == str(entry[k]) for k in ('Package','Version','Architecture','Filename','SHA256','Size'))]
        require(len(matches) == 1, 'retained package must exactly match one authenticated index row')
        require('..' not in Path(entry['Filename']).parts and entry['Filename'].startswith('pool/main/') and Path(entry['Filename']).suffix == '.deb', 'unsafe authenticated package filename')
    return packages


def command(args, *, check=True, env=None, timeout=180, data=None, cwd=None):
    result = subprocess.run(args, input=data, capture_output=True, text=True, timeout=timeout, env=env, cwd=cwd)
    if check and result.returncode:
        raise RuntimeError('command failed (' + str(result.returncode) + '): ' + ' '.join(map(str,args[:3])) + '\n' + result.stdout + result.stderr)
    return result


def host_main(path):
    os.umask(0o077)
    config = json.loads(private_bytes(path))
    refs = config['references']
    names = {'qualification_report','roundcube_receipt','roundcube_execution_receipt','retention_receipt','exclusive_handoff','native_gpgv_receipt','baseline_inventory'}
    require(type(refs) is dict and set(refs) == names, 'all explicit private receipt references are required')
    receipts = {name:json.loads(private_bytes(refs[name]['path'],refs[name]['sha256'])) for name in names}
    for field, ref in [('qualification_report_sha256','qualification_report'),('roundcube_receipt_sha256','roundcube_receipt'),('retention_receipt_sha256','retention_receipt')]:
        require(config[field] == refs[ref]['sha256'], 'receipt reference/hash differs')
    validate_authorization(config, receipts['qualification_report'], receipts['roundcube_receipt'], receipts['retention_receipt'], receipts['exclusive_handoff'])
    check_roundcube_execution(receipts['roundcube_execution_receipt'],config,receipts['roundcube_receipt'])
    require(config['roundcube_execution_sha256'] == refs['roundcube_execution_receipt']['sha256'] == receipts['exclusive_handoff'].get('roundcube_execution_sha256'), 'handoff real-flow execution receipt hash differs')
    require(refs['roundcube_receipt']['sha256'] == digest(canonical(receipts['roundcube_receipt'])), 'initial envelope bytes are not the exact canonical producer output')
    require(type(config['allow_development']) is bool, 'release class must be explicit')
    require(re.fullmatch(r'[a-f0-9]{40}', config['qualifier_commit']) is not None, 'explicit reviewed qualifier commit required')
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{5,63}', config['maintenance_id']) is not None, 'unsafe maintenance identifier')
    require(re.fullmatch(r'maintenance-sury-[A-Za-z0-9-]{6,80}', config['retention_snapshot']) is not None, 'unbound retention snapshot')
    helper = Path(__file__).resolve()
    private_bytes(helper,config['maintenance_helper_sha256'],private=False)
    driver = Path(config['driver_source'])
    qualifier = Path(config['qualifier_source'])
    driver_required = {'deploy/multipass/common.sh','deploy/multipass/qualification-artifacts.sh','deploy/multipass/qualification_artifacts.py','deploy/release/verify.py','deploy/install/stage_bundle.py'}
    qualifier_required = driver_required | QUALIFIER_FILES | {'deploy/multipass/sury-maintenance-drill.py','deploy/multipass/sury-maintenance-verify.sh','deploy/multipass/sury_maintenance_test.py','deploy/multipass/sury_maintenance_test.go'}
    for directory,mapping,required in [(driver,config['driver_source_sha256'],driver_required),(qualifier,config['qualifier_source_sha256'],qualifier_required)]:
        require(required <= set(mapping), 'all frozen helper dependencies are required')
        for relative,expected in mapping.items():
            require(not Path(relative).is_absolute() and '..' not in Path(relative).parts, 'unsafe frozen helper path')
            private_bytes(directory/relative,expected,private=False)
    check_frozen_checkout(driver,config['driver_source_sha256'],config['runtime_commit'])
    check_frozen_checkout(qualifier,config['qualifier_source_sha256'],config['qualifier_commit'])
    require(config['qualifier_wrapper_sha256'] == config['qualifier_source_sha256']['deploy/multipass/internal-tools-verify.sh'] and config['qualifier_helper_sha256'] == config['qualifier_source_sha256']['deploy/multipass/roundcube-send-read.py'], 'qualifier receipt/source hashes differ')
    require(all(config['qualifier_files_sha256'][k] == config['qualifier_source_sha256'][k] for k in QUALIFIER_FILES) and config['maintenance_helper_sha256'] == config['qualifier_source_sha256']['deploy/multipass/sury-maintenance-drill.py'], 'committed qualifier/maintenance file maps differ')
    bundle = Path(config['bundle'])
    manifest = json.loads(private_bytes(bundle/'manifest.json',config['manifest_sha256'],private=False))
    private_bytes(bundle/'manifest.sig',config['signature_sha256'],private=False)
    private_bytes(config['public_key'],config['public_key_sha256'],private=False)
    require((manifest.get('commit'),manifest.get('version'),manifest.get('architecture'),manifest.get('development')) == (config['runtime_commit'],config['app_version'],config['architecture'],config['allow_development']), 'selected signed release metadata differs')
    for name, expected in config['installed_binary_sha256'].items():
        require(manifest['files'].get('bin/'+name) == expected, 'binary map differs from signed manifest')
        private_bytes(bundle/'bin'/name,expected,private=False)
    baseline = Path(config['baseline_directory'])
    inventory = receipts['baseline_inventory']
    release = private_bytes(baseline/'InRelease')
    require(digest(release) == inventory['trust']['inrelease_sha256'], 'retained Release differs')
    check_native_gpgv(receipts['native_gpgv_receipt'],config,digest(release))
    packages = inventory['architectures'][config['architecture']]['packages']
    compressed = private_bytes(baseline/(config['architecture']+'-Packages.xz'))
    check_index_packages(release,compressed,config['architecture'],packages)
    for entry in packages:
        retained = Path(entry['retained_file'])
        require(retained.resolve().is_relative_to((baseline/'retained-baseline'/config['architecture']).resolve()) if sys.version_info >= (3,9) else False, 'package retention path escaped its architecture')
        value = private_bytes(retained,entry['SHA256'])
        require(len(value) == int(entry['Size']), 'retained package size differs')
    require(set(inventory['derivation']['profile_required_packages']) <= {x['Package'] for x in packages}, 'profile PHP package retention is incomplete')
    verify_args = [sys.executable,str(driver/'deploy/release/verify.py'),'--bundle',str(bundle),'--public-key',config['public_key'],'--version',config['app_version'],'--architecture',config['architecture']]
    if config['allow_development']:
        verify_args.append('--allow-development')
    command(verify_args,timeout=180)
    evidence = Path(config['evidence_directory'])
    evidence.mkdir(mode=0o700,parents=False,exist_ok=False)
    write_private(evidence/'selected-inputs.json',config)
    host_execute(config,packages,release,compressed,receipts,evidence,helper,driver,qualifier)


def clean_environment(config):
    env = {k:v for k,v in os.environ.items() if not k.startswith('NAKPANEL_')}
    env.update({'LC_ALL':'C','NAKPANEL_RUN_TOKEN':config['run_token'],'NAKPANEL_MULTIPASS_VM':config['source_vm'],'NAKPANEL_MULTIPASS_SOURCE_VM':config['source_vm'],'NAKPANEL_MULTIPASS_DR_VM':config['source_vm']+'-maintenance-unallocated','NAKPANEL_MULTIPASS_IMAGE':'26.04','NAKPANEL_MULTIPASS_ARCH':config['architecture'],'NAKPANEL_OWNERSHIP_DIR':config['ownership_directory'],'NAKPANEL_RELEASE_BUNDLE':config['bundle'],'NAKPANEL_RELEASE_PUBLIC_KEY':config['public_key'],'NAKPANEL_RELEASE_VERSION':config['app_version'],'NAKPANEL_RELEASE_ALLOW_DEVELOPMENT':'1' if config['allow_development'] else '0','NAKPANEL_QUALIFICATION_PHP_PROVIDER':'sury','NAKPANEL_BASELINE_PHP':'8.5','NAKPANEL_REMOTE_SRC':'/var/lib/nakpanel-qualification/'+config['run_token']+'/source','NAKPANEL_CELL_REPORT_DIR':config['cell_report_directory']})
    if 'mailbox_password' in config:
        require(type(config['mailbox_password']) is str and '\n' not in config['mailbox_password'], 'invalid private mailbox credential')
        env['NAKPANEL_INTERNAL_TOOLS_PASSWORD'] = config['mailbox_password']
    return env


def host_identity(config, driver, env):
    return command(['bash','-c','set -euo pipefail; source "$1"; assert_vm_identity "$2" 26.04 "$3" "$4"; assert_qualification_installed_release "$2"','_',str(driver/'deploy/multipass/common.sh'),config['source_vm'],config['architecture'],config['run_token']],env=env,timeout=120).stdout


def host_record(config):
    path = Path(config['ownership_directory'])/config['run_token']/config['source_vm']
    raw = private_bytes(path)
    require(raw.decode().strip() == '26.04\t'+config['architecture']+'\t'+config['run_token'], 'host ownership differs')
    return digest(raw)


def check_snapshot_info(value, config, retention):
    require(type(value) is dict and set(value)=={'errors','info'} and value['errors']==[] and type(value['errors']) is list, 'snapshot query returned errors or an unsupported shape')
    info=value['info']
    require(type(info) is dict and set(info)=={config['source_vm']}, 'snapshot query did not identify the exact owned VM')
    instance=info[config['source_vm']]
    require(type(instance) is dict and set(instance)=={'snapshots'} and type(instance['snapshots']) is dict and set(instance['snapshots'])=={config['retention_snapshot']}, 'snapshot query did not return exactly the retained snapshot')
    metadata=instance['snapshots'][config['retention_snapshot']]
    fields={'children','comment','cpu_count','created','disk_space','memory_size','mounts','parent','size'}
    require(type(metadata) is dict and set(metadata)==fields and type(metadata['children']) is list and all(type(x) is str for x in metadata['children']) and type(metadata['mounts']) is dict and all(type(metadata[k]) is str for k in fields-{'children','mounts'}) and bool(metadata['created']), 'snapshot metadata is incomplete or malformed')
    require(retention['snapshot_id']==config['source_vm']+'.'+config['retention_snapshot'] and digest(canonical(metadata))==retention['snapshot_info_sha256'], 'snapshot was replaced or its retained metadata differs')
    return metadata


def host_execute(config, packages, release, compressed, receipts, evidence, helper, driver, qualifier):
    env = clean_environment(config)
    ownership = host_record(config)
    host_identity(config,driver,env)
    state = {'schema':'nakpanel-sury-maintenance-result-v1','operation':MODE,'source_vm':config['source_vm'],'run_token':config['run_token'],'runtime_commit':config['runtime_commit'],'qualifier_commit':config['qualifier_commit'],'maintenance_helper_sha256':config['maintenance_helper_sha256'],'genuine_version_advance':False,'apt_version_rollback':False,'application_rollback':False,'status':'STARTED','guest_state':'identity_verified','reboots':[]}
    write_private(evidence/'result.json',state)
    mutated = False
    code = private_bytes(helper,config['maintenance_helper_sha256'],private=False).decode('utf-8')
    remote_code = remote_program(code)
    guest_config = guest_configuration(config)
    message_ids = {receipts['roundcube_receipt']['raw_receipt']['message_id']}
    message_uids = {receipts['roundcube_receipt']['raw_receipt']['uid']}
    def remote(action, **values):
        request = dict(action=action,config=guest_config,**values)
        result = command(['multipass','exec',config['source_vm'],'--','sudo','python3','-c',remote_code],env=env,data=json.dumps(request),timeout=1800,check=False)
        write_private(evidence/(action+'-'+str(values.get('phase','stage'))+'.stdout'),result.stdout.encode())
        write_private(evidence/(action+'-'+str(values.get('phase','stage'))+'.stderr'),result.stderr.encode())
        require(result.returncode == 0, 'guest '+action+' failed; inspect retained stdout/stderr and cold snapshot')
        return json.loads(result.stdout)
    def product_check(phase):
        for relative,expected in config['qualifier_source_sha256'].items():
            private_bytes(qualifier/relative,expected,private=False)
        output = evidence/('roundcube-'+phase+'.json')
        run_env = dict(env,NAKPANEL_INTERNAL_TOOLS_RECEIPT=str(output))
        started = datetime.now(timezone.utc).isoformat()
        result = command(['bash',str(qualifier/'deploy/multipass/internal-tools-verify.sh'),'--roundcube-only'],env=run_env,timeout=600,check=False)
        write_private(evidence/('roundcube-'+phase+'.log'),(result.stdout+result.stderr).encode())
        require(result.returncode == 0, 'actual Roundcube flow failed; uncertain sends are never retried')
        proof = json.loads(private_bytes(output))
        validate_authorization(config,receipts['qualification_report'],proof,receipts['retention_receipt'],receipts['exclusive_handoff'])
        original = receipts['roundcube_receipt']['raw_receipt']
        require(all(proof['raw_receipt'][k] == original[k] for k in ('recipient_sha256','certificate_sha256')), 'Roundcube mailbox/certificate binding changed')
        raw = proof['raw_receipt']
        require(raw['message_id'] not in message_ids and raw['uid'] not in message_uids, 'Roundcube receipt reused an earlier message; a fresh actual flow is required')
        message_ids.add(raw['message_id']);message_uids.add(raw['uid'])
        execution = {k:config[k] for k in ('source_vm','run_token','release','architecture','profile','php_provider','runtime_commit','qualifier_commit')}
        execution.update(schema='nakpanel-roundcube-supplement-execution-v1',success=True,exit_code=0,qualifier_files_sha256=config['qualifier_files_sha256'],envelope_sha256=digest(private_bytes(output)),started_at=started,finished_at=datetime.now(timezone.utc).isoformat())
        check_roundcube_execution(execution,config,proof)
        write_private(output.with_suffix('.execution.json'),execution)
    original_sigterm=signal.signal(signal.SIGTERM,controlled_termination)
    original_sigint=signal.getsignal(signal.SIGINT)
    try:
        # Receipt booleans alone are not a backup: freshly inspect the exact
        # qualified source snapshot before the first guest write. Multipass
        # exposes VM.SNAPSHOT plus metadata, rather than an opaque snapshot ID.
        snapshot=command(['multipass','info',receipts['retention_receipt']['snapshot_id'],'--format','json'],env=env,timeout=120,check=False)
        write_private(evidence/'snapshot-info.stdout',snapshot.stdout.encode())
        write_private(evidence/'snapshot-info.stderr',snapshot.stderr.encode())
        require(snapshot.returncode==0,'retained snapshot query failed before guest writes')
        metadata=check_snapshot_info(json.loads(snapshot.stdout),config,receipts['retention_receipt'])
        write_private(evidence/'snapshot-current.json',{'snapshot_id':receipts['retention_receipt']['snapshot_id'],'snapshot_info_sha256':digest(canonical(metadata)),'metadata':metadata})
        # Archive transfer and private staging are the first guest writes. All
        # qualification, real-flow, native signature and cold-retention inputs
        # have already passed host validation before this function is entered.
        archive = evidence/'retained-baseline.tar'
        archive_items = {'config.json':canonical(guest_config),'InRelease':release,'Packages.xz':compressed}
        for entry in packages:
            archive_items[Path(entry['Filename']).name] = private_bytes(entry['retained_file'],entry['SHA256'])
        with tarfile.open(archive, 'x') as stream:
            for name,data in archive_items.items():
                entry = tarfile.TarInfo(name);entry.size=len(data);entry.mode=0o600;entry.uid=entry.gid=0
                stream.addfile(entry,io.BytesIO(data))
        archive.chmod(0o600)
        remote_archive = '/tmp/nakpanel-sury-maintenance-'+config['maintenance_id']+'.tar'
        mutated = True
        command(['multipass','transfer',str(archive),config['source_vm']+':'+remote_archive],env=env,timeout=300)
        guest_packages = [{k:entry[k] for k in ('Package','Version','Architecture','Filename','SHA256','Size')} for entry in packages]
        guest_receipts = {k:receipts[k] for k in ('qualification_report','roundcube_receipt','roundcube_execution_receipt','retention_receipt','exclusive_handoff')}
        staged = remote('stage',archive=remote_archive,archive_sha256=digest(archive.read_bytes()),archive_size=archive.stat().st_size,packages=guest_packages,receipts=guest_receipts)
        require(staged.get('status') == 'STAGED', 'private guest staging was not confirmed')
        original = remote('run')
        require(original.get('status') == 'RECOVERED' and original.get('operation') == MODE, 'actual same-version failed-configuration recovery did not complete')
        write_private(evidence/'recovery.json',original)
        product_check('recovered')
        previous_boot = original['boot_id']
        for number in (1,2):
            host_identity(config,driver,env)
            command(['multipass','restart',config['source_vm']],env=env,timeout=300)
            command(['bash','-c','set -euo pipefail; source "$1"; wait_for_cloud_init "$2"','_',str(driver/'deploy/multipass/common.sh'),config['source_vm']],env=env,timeout=300)
            host_identity(config,driver,env)
            proof = remote('health',phase='reboot-'+str(number))
            require(proof.get('service_repair_performed') is False and sha_value(proof.get('observation_sha256')), 'unassisted postboot service observation is required')
            require(proof.get('status') == 'HEALTHY' and proof.get('boot_id') not in {previous_boot,*state['reboots']}, 'real new boot identity and complete health proof required')
            previous_boot = proof['boot_id'];state['reboots'].append(previous_boot)
            write_private(evidence/('reboot-'+str(number)+'.json'),proof)
            product_check('reboot-'+str(number))
        host_identity(config,driver,env)
        state.update(status='PASS',guest_state='running_revalidated',same_version_delivery=True,failed_configuration_recovery=True,two_reboots_verified=True,roundcube_send_read_steps=3)
        write_private(evidence/'result.json',state)
        print(evidence/'result.json')
    except BaseException as error:
        # Ctrl-C/SIGTERM after transfer must not leave a live faulted guest and
        # a misleading STARTED receipt. During bounded cleanup, a second signal
        # cannot interrupt the exact known-owner stop or its failure receipt.
        signal.signal(signal.SIGINT,signal.SIG_IGN)
        signal.signal(signal.SIGTERM,signal.SIG_IGN)
        state.update(status='FAIL',error_type=type(error).__name__,diagnostic=str(error),guest_state='unchanged_before_guest_write')
        if mutated:
            state['guest_state']='failure_stop_unconfirmed'
            write_private(evidence/'result.json',state)
            try:
                require(host_record(config) == ownership, 'host ownership changed; stop not authorized')
                command(['multipass','stop',config['source_vm']],env=env,timeout=120)
                state['guest_state'] = 'stopped_after_failure'
            except Exception as stop_error:
                state['stop_error_type'] = type(stop_error).__name__
        write_private(evidence/'result.json',state)
        raise
    finally:
        signal.signal(signal.SIGTERM,original_sigterm)
        signal.signal(signal.SIGINT,original_sigint)


def guest_directory(config):
    return Path('/var/lib/nakpanel-qualification')/config['run_token']/'maintenance-drills'/config['maintenance_id']


def guest_configuration(config):
    # The transfer archive must contain no host credential, environment, private
    # input paths or unrelated extensible fields. Credentials stay on the host
    # and reach only the reviewed real-flow wrapper through its private env.
    keys = (*BINDING,'operation','maintenance_id','allow_development','public_key_sha256','signature_sha256','qualifier_commit','qualifier_files_sha256','qualifier_wrapper_sha256','qualifier_helper_sha256','maintenance_helper_sha256','retention_snapshot','qualification_report_sha256','roundcube_receipt_sha256','roundcube_execution_sha256','retention_receipt_sha256')
    return {key:config[key] for key in keys}


def root_regular(path, expected=None):
    # All guest entrypoints require EUID0; private_bytes then requires root owner.
    return private_bytes(path,expected,private=False)


def guest_identity(config):
    require(os.geteuid() == 0, 'guest rehearsal requires root after explicit host handoff')
    require(config['operation'] == MODE and config['profile'] == 'ubuntu-26.04-sury' and config['php_provider'] == 'sury', 'removal/provider switches and non-Surý profiles are unsupported')
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{5,63}',config['run_token']) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{5,63}',config['maintenance_id']), 'unsafe guest identifiers')
    os_release = {}
    for line in os_identity_bytes().decode().splitlines():
        key,sep,value = line.partition('=')
        if sep:
            os_release[key] = value.strip('"\'')
    require(tuple(os_release.get(k) for k in ('ID','VERSION_ID','VERSION_CODENAME')) == ('ubuntu','26.04','resolute'), 'actual guest must be Ubuntu26.04/resolute')
    require(command(['dpkg','--print-architecture']).stdout.strip() == config['architecture'], 'actual guest architecture differs')
    require(root_regular('/etc/nakpanel-qualification-owner').decode().strip() == config['run_token'], 'guest ownership marker differs')
    profile = json.loads(root_regular('/etc/nakpanel/platform.json'))
    require(profile.get('profile') == 'ubuntu-26.04-sury' and profile.get('internal_php_version') == '8.5' and profile.get('hosting_php_versions') == list(MINORS) and profile.get('architecture') == config['architecture'] and profile.get('bootstrap_pending',False) is False, 'trusted installed Surý profile is incomplete or differs')
    release = Path('/var/lib/nakpanel-qualification')/config['run_token']/'release'
    manifest = json.loads(root_regular(release/'manifest.json',config['manifest_sha256']))
    require((manifest.get('commit'),manifest.get('version'),manifest.get('architecture'),manifest.get('development')) == (config['runtime_commit'],config['app_version'],config['architecture'],config['allow_development']), 'actual staged signed release differs')
    key = release.parent/'public.pem'
    root_regular(key,config['public_key_sha256']);root_regular(release/'manifest.sig',config['signature_sha256'])
    command(['openssl','dgst','-sha256','-verify',str(key),'-signature',str(release/'manifest.sig'),str(release/'manifest.json')])
    for artifact,binary in [('panel','nakpanel-panel'),('agent','nakpanel-agent'),('panelctl','panelctl')]:
        require(manifest['files']['bin/'+artifact] == config['installed_binary_sha256'][artifact], 'staged selected binary map differs')
        root_regular(Path('/usr/local/bin')/binary,config['installed_binary_sha256'][artifact])
    root_regular('/usr/share/keyrings/nakpanel-sury-php.gpg',KEY_SHA)


def ensure_root_directory(path, *, exclusive=False):
    path = Path(path)
    if not path.exists() or exclusive:
        path.mkdir(mode=0o700)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, 'unsafe root-private staging directory')


def verify_gpgv(root):
    result = command(['gpgv','--status-fd','1','--keyring','/usr/share/keyrings/nakpanel-sury-php.gpg',str(root/'InRelease')],check=False)
    statuses = result.stdout.splitlines()
    require(result.returncode == 0 and not any(line.startswith('[GNUPG:] '+bad+' ') for line in statuses for bad in ('BADSIG','ERRSIG','EXPSIG','EXPKEYSIG','REVKEYSIG')), 'native Surý signature verification failed')
    valid = [line.split() for line in statuses if line.startswith('[GNUPG:] VALIDSIG ')]
    require(valid and all(len(parts)>=12 and parts[-1] == FINGERPRINT for parts in valid), 'native signature fingerprint differs')
    return {'native_gpgv':True,'validsig_fingerprint':FINGERPRINT,'inrelease_sha256':digest(root_regular(root/'InRelease')),'status':result.stdout,'stderr':result.stderr}


def stage_guest(request):
    config = request['config'];root=guest_directory(config)
    validate_authorization(config,request['receipts']['qualification_report'],request['receipts']['roundcube_receipt'],request['receipts']['retention_receipt'],request['receipts']['exclusive_handoff'])
    check_roundcube_execution(request['receipts']['roundcube_execution_receipt'],config,request['receipts']['roundcube_receipt'])
    archive = Path(request['archive'])
    require(str(archive) == '/tmp/nakpanel-sury-maintenance-'+config['maintenance_id']+'.tar', 'unexpected transfer archive')
    fd = os.open(archive,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno());data=stream.read()
        require(stat.S_ISREG(info.st_mode) and len(data)==request['archive_size'] and digest(data)==request['archive_sha256'], 'transferred archive bytes differ')
    ensure_root_directory(root.parent.parent)
    ensure_root_directory(root.parent)
    ensure_root_directory(root,exclusive=True)
    packages = request['packages'];expected={'config.json','InRelease','Packages.xz'}|{Path(p['Filename']).name for p in packages}
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as tar:
        members=tar.getmembers()
        require(len(members)==len(expected) and {m.name for m in members}==expected and all(m.isfile() and m.name==Path(m.name).name for m in members), 'unexpected archive member/type')
        for member in members:
            content=tar.extractfile(member).read();write_private(root/member.name,content)
    require(json.loads(root_regular(root/'config.json')) == config, 'staged configuration differs')
    native=verify_gpgv(root)
    check_index_packages(root_regular(root/'InRelease'),root_regular(root/'Packages.xz'),config['architecture'],packages)
    for entry in packages:
        data=root_regular(root/Path(entry['Filename']).name,entry['SHA256']);require(len(data)==int(entry['Size']), 'staged package size differs')
        meta=command(['dpkg-deb','-f',str(root/Path(entry['Filename']).name),'Package','Version','Architecture']).stdout
        observed={k:v.strip() for k,_,v in (line.partition(':') for line in meta.splitlines())}
        require(all(observed.get(k)==entry[k] for k in ('Package','Version','Architecture')), 'actual Debian control identity differs from signed index')
    write_private(root/'packages.json',packages);write_private(root/'native-gpgv.json',native)
    # Transfer path is user-owned; it is never executed and not blindly removed.
    return {'status':'STAGED','root':str(root),'package_count':len(packages),'native_gpgv':native}


def remote_program(source):
    return "import json,sys\nscope={'__name__':'maintenance_guest','__file__':'reviewed-maintenance-helper'}\nexec(compile("+repr(source)+",'reviewed-maintenance-helper','exec'),scope)\nrequest=json.load(sys.stdin)\ntry:\n print(json.dumps(scope['guest_action'](request),sort_keys=True))\nexcept Exception as error:\n print('maintenance guest failed: '+str(error),file=sys.stderr)\n sys.exit(1)\n"


def check_frozen_checkout(directory, mapping, commit):
    require(re.fullmatch(r'[a-f0-9]{40}',commit) is not None, 'invalid frozen source commit')
    require(command(['git','-C',str(directory),'rev-parse','HEAD']).stdout.strip()==commit, 'frozen source HEAD differs')
    for relative,expected in mapping.items():
        blob=subprocess.run(['git','-C',str(directory),'show',commit+':'+relative],capture_output=True,check=True).stdout
        require(digest(blob)==expected,'frozen helper bytes do not belong to the selected commit')


def os_identity_bytes(root=Path('/')):
    root = Path(root)
    path = root/'etc/os-release'
    if path.is_symlink():
        require(os.readlink(path) in ('../usr/lib/os-release','/usr/lib/os-release'), 'unexpected OS metadata symlink')
        path = root/'usr/lib/os-release'
    return root_regular(path)


def archive_targets(text, packages):
    expected = {entry['Filename']:entry for entry in packages}
    result = {}
    for line in text.splitlines():
        if not line.startswith("'"):
            continue
        parts = shlex.split(line)
        require(len(parts) == 4, 'unrecognized APT archive request')
        uri, destination, size, unused_hash = parts
        parsed = urlsplit(uri)
        require(parsed.scheme == 'https' and parsed.netloc == 'packages.sury.org' and not parsed.query and not parsed.fragment and unquote(parsed.path).startswith('/php/'), 'APT requested a foreign/unauthenticated archive URI')
        relative = unquote(parsed.path)[len('/php/'):]
        require(relative in expected, 'APT requested an artifact outside retained signed package inventory')
        entry = expected[relative]
        require(int(size) == int(entry['Size']) and Path(destination).name == destination and re.fullmatch(r'[A-Za-z0-9_+~.:%-]+\.deb', destination), 'APT archive name/size differs')
        require(entry['Package'] not in result and destination not in result.values(), 'duplicate APT archive mapping')
        result[entry['Package']] = destination
    require(set(result) == {entry['Package'] for entry in packages}, 'APT did not request the complete explicit PHP package set')
    return result


def package_inventory():
    raw = command(['dpkg-query','-W','-f=${binary:Package}\t${Version}\t${Status}\n']).stdout
    return {parts[0]:parts[1:] for line in raw.splitlines() if (parts:=line.split('\t')) and len(parts)==3}


def intent_state():
    sql = """SELECT json_build_object(
'sites',(SELECT json_agg(json_build_array(id,status,desired_status,php_version,desired_php_version) ORDER BY id) FROM sites),
'applications',(SELECT json_agg(json_build_array(id,site_id,php_version,desired_state,desired_revision,active_deployment_id,hosting_mode) ORDER BY id) FROM php_applications),
'workers',(SELECT json_agg(json_build_array(id,application_id,name,script,arguments,processes,desired_state,desired_revision) ORDER BY id) FROM php_workers))"""
    return json.loads(command(['runuser','-u','postgres','--','psql','-XqAt','-d','nakpanel','-v','ON_ERROR_STOP=1','-c',sql]).stdout)


def service_state(unit):
    return command(['systemctl','show','--property=ActiveState','--value',unit]).stdout.strip()


def managed_state():
    names = set()
    for pattern in ('nakpanel-php-fpm@*.service','nakpanel-php-worker@*.service'):
        for path in Path('/etc/systemd/system').glob(pattern):
            if re.fullmatch(r'nakpanel-php-(?:fpm|worker)@[0-9][0-9-]*\.service',path.name):
                root_regular(path)
                names.add(path.name)
    return {name:service_state(name) for name in sorted(names)}


def assert_managed_services(states, intent):
    require(type(states) is dict and all(type(name) is str and re.fullmatch(r'nakpanel-php-(?:fpm|worker)@[1-9][0-9]*(?:-(?:[2-9]|[1-9][0-9]+))?\.service',name) and state in ('active','inactive') for name,state in states.items()), 'managed PHP service state is failed, unknown or unsafe')
    require(type(intent) is dict,'managed PHP desired intent is missing')
    sites={row[0]:row for row in (intent.get('sites') or [])}
    applications={row[0]:row for row in (intent.get('applications') or [])}
    expected={}
    for site_id,row in sites.items():
        unit='nakpanel-php-fpm@'+str(site_id)+'.service'
        if unit in states:expected[unit]='active' if row[1]=='active' and row[2]=='active' else 'inactive'
    enabled={}
    for app_id,row in applications.items():
        require(len(row)==7 and row[1] in sites and row[3] in ('active','suspended') and row[6] in ('managed','classic'),'managed PHP application intent is unknown')
        active=row[6]=='managed' and row[3]=='active' and sites[row[1]][1]=='active' and sites[row[1]][2]=='active'
        require(not active or (type(row[5]) is int and row[5]>0),'managed active application has no selected deployment')
        enabled[app_id]=active
        if row[6]=='managed':expected['nakpanel-php-fpm@'+str(row[1])+'.service']='active' if active else 'inactive'
    for row in intent.get('workers') or []:
        require(len(row)==8 and row[1] in applications and type(row[5]) is int and 1<=row[5]<=64 and row[6] in ('running','stopped'),'managed PHP worker intent is unknown')
        for process in range(1,row[5]+1):
            unit='nakpanel-php-worker@'+str(row[0])+('' if process==1 else '-'+str(process))+'.service'
            expected[unit]='active' if enabled[row[1]] and row[6]=='running' else 'inactive'
    require(all(name in expected and state==expected[name] for name,state in states.items()) and all(states.get(name)==state for name,state in expected.items() if state=='active'),'managed PHP active/stopped state differs from effective desired state')


def guarded_settings():
    alternatives = {}
    for directory in ('/etc/alternatives','/var/lib/dpkg/alternatives'):
        for pattern in ('php*','phar*'):
            for path in Path(directory).glob(pattern):
                info=path.lstat()
                require(info.st_uid==0 and (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)), 'unsafe PHP alternatives state')
                alternatives[str(path)] = {'mode':stat.S_IMODE(info.st_mode),'value':os.readlink(path) if path.is_symlink() else digest(root_regular(path))}
    tools={name:digest(root_regular(name)) for name in ('/usr/local/lib/nakpanel/composer.phar','/usr/local/lib/nakpanel/wp-cli.phar','/usr/local/bin/composer','/usr/local/bin/wp','/etc/wp-cli/config.yml')}
    return {'php':tree_state('/etc/php'),'apt_sources':tree_state('/etc/apt/sources.list.d'),'apt_preferences':tree_state('/etc/apt/preferences.d'),'platform':digest(root_regular('/etc/nakpanel/platform.json')),'sury_key':digest(root_regular('/usr/share/keyrings/nakpanel-sury-php.gpg')),'php_alternatives':alternatives,'tools':tools}


def package_files(packages):
    text = command(['dpkg-query','-L',*[entry['Package'] for entry in packages]]).stdout
    result = {}
    for name in sorted(set(text.splitlines())):
        if name == '':
            continue
        path=Path(name)
        require(path.is_absolute() and '..' not in path.parts, 'unexpected package file path')
        info=path.lstat()
        if stat.S_ISREG(info.st_mode):
            result[name]={'mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid,'value':digest(root_regular(path))}
        elif stat.S_ISLNK(info.st_mode):
            result[name]={'mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid,'link':os.readlink(path)}
    return result


class GuestBackend:
    def __init__(self, root, config, packages):
        self.root, self.config, self.packages = root, config, packages
        self.versions={entry['Package']:entry['Version'] for entry in packages}
        self.cache=root/'apt-archives'
        self.env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DEBIAN_FRONTEND':'noninteractive','UCF_FORCE_CONFFOLD':'1'}
        self.sequence=0

    def record(self, step, data):
        self.sequence+=1
        write_private(self.root/('step-'+str(self.sequence).zfill(3)+'-'+step+'.json'),data)

    def apt(self, packages, *, simulate=False, print_uris=False):
        args=['apt-get','-o','Dir::Cache::archives='+str(self.cache),'-o','APT::Keep-Downloaded-Packages=true','--no-remove','--reinstall','--fix-broken']
        if simulate:args+=['--simulate']
        elif print_uris:args+=['--print-uris','--download-only','--yes']
        else:args+=['--no-download','--yes']
        args+=['install',*[package+'='+self.versions[package] for package in sorted(packages)]]
        return command(args,check=False,env=self.env,timeout=600)

    def prepare(self):
        require(command(['dpkg','--audit']).stdout.strip() == '', 'preexisting pending/broken dpkg state cannot enter this drill')
        observed=package_inventory()
        actual_php={k.removesuffix(':'+self.config['architecture']) for k,v in observed.items() if PHP_NAME.fullmatch(k.removesuffix(':'+self.config['architecture'])) and v[1]=='install ok installed'}
        require(actual_php == set(self.versions), 'installed PHP set differs from retained exact profile dependency closure')
        for entry in self.packages:
            name=entry['Package'];current=observed.get(name,observed.get(name+':'+self.config['architecture']))
            require(current == [entry['Version'],'install ok installed'], 'captured original PHP version/state differs from retained artifact')
            check_candidate(command(['apt-cache','policy',name]).stdout,entry['Version'])
        for minor in MINORS:
            require(service_state('php'+minor+'-fpm.service')=='active' and self.config_test(minor).returncode==0, 'all original PHP FPM services must work before maintenance')
            control=subprocess.run(['dpkg-deb','--ctrl-tarfile',str(self.root/Path(next(e['Filename'] for e in self.packages if e['Package']=='php'+minor+'-fpm')).name)],capture_output=True,check=True,env=self.env)
            with tarfile.open(fileobj=io.BytesIO(control.stdout),mode='r:') as archive:
                members=[m for m in archive if m.name.lstrip('./')=='postinst' and m.isfile()]
                require(len(members)==1,'signed FPM postinst missing')
                expected=archive.extractfile(members[0]).read()
            require(root_regular('/var/lib/dpkg/info/php'+minor+'-fpm.postinst')==expected,'installed FPM postinst differs from signed package')
        self.cache.mkdir(mode=0o700);(self.cache/'partial').mkdir(mode=0o700)
        uris=self.apt(set(self.versions),print_uris=True)
        require(uris.returncode==0,'cannot derive exact authenticated APT archive requests')
        destinations=archive_targets(uris.stdout,self.packages)
        for entry in self.packages:
            source=self.root/Path(entry['Filename']).name
            data=root_regular(source,entry['SHA256'])
            fd=os.open(self.cache/destinations[entry['Package']],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as stream:stream.write(data)
        require(Path('/usr/bin/cgi-fcgi').is_file(),'real FastCGI client is required before mutation')

    def config_test(self, minor):
        return command(['/usr/sbin/php-fpm'+minor,'-t'],check=False,env=self.env)

    def package_status(self,minor):
        return command(['dpkg-query','-W','-f=${Status}','php'+minor+'-fpm'],env=self.env).stdout

    def reinstall(self,minor=None):
        packages={'php'+minor+'-fpm'} if minor else set(self.versions)
        plan=self.apt(packages,simulate=True)
        require(plan.returncode==0,'APT simulation failed; no package mutation attempted')
        check_apt_plan(plan.stdout,self.versions,packages)
        self.record('apt-plan',{'packages':sorted(packages),'stdout':plan.stdout,'stderr':plan.stderr})
        result=self.apt(packages)
        self.record('apt-result',{'packages':sorted(packages),'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
        return result


def php_smoke(root, config, phase):
    result={}
    for minor in MINORS:
        tag=config['maintenance_id']+'-'+phase+'-'+minor.replace('.','')
        require(re.fullmatch(r'[A-Za-z0-9-]+',tag),'unsafe smoke name')
        public=Path('/run')/('nakpanel-maintenance-probe-'+tag);public.mkdir(mode=0o755)
        public.chmod(0o755)
        runtime='nakpanel-maintenance-'+tag;runtime_path=Path('/run')/runtime
        script=public/'index.php'
        script.write_text("<?php header('Content-Type: application/json'); echo json_encode(['version'=>PHP_VERSION,'uid'=>posix_geteuid(),'ini'=>php_ini_loaded_file(),'extensions'=>get_loaded_extensions(),'own_read'=>is_readable(__FILE__),'other_denied'=>@file_get_contents('/etc/passwd')===false,'shell_disabled'=>!function_exists('shell_exec')]);")
        script.chmod(0o644)
        pool=public/'fpm.conf'
        pool.write_text('[global]\ndaemonize = no\nerror_log = '+str(runtime_path/'error.log')+'\npid = '+str(runtime_path/'fpm.pid')+'\n[canary]\nlisten = '+str(runtime_path/'fpm.sock')+'\nlisten.mode = 0600\npm = static\npm.max_children = 1\nclear_env = yes\nsecurity.limit_extensions = .php\nphp_admin_value[open_basedir] = '+str(public)+':/tmp\nphp_admin_value[disable_functions] = shell_exec\n')
        pool.chmod(0o644)
        cli=command(['/usr/bin/php'+minor,'-c','/etc/php/'+minor+'/cli/php.ini','-r',"echo json_encode(['version'=>PHP_VERSION,'ini'=>php_ini_loaded_file(),'extensions'=>get_loaded_extensions()]);"],env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        cli_proof=json.loads(cli.stdout)
        require(cli_proof['version'].startswith(minor+'.') and cli_proof['ini']=='/etc/php/'+minor+'/cli/php.ini' and set(REQUIRED_EXTENSIONS)<=set(cli_proof['extensions']),'actual CLI version/INI/extensions failed')
        unit='nakpanel-maintenance-'+tag+'.service';started=False
        try:
            command(['systemd-run','--quiet','--collect','--unit',unit,'--property=User=nobody','--property=Group=nogroup','--property=RuntimeDirectory='+runtime,'--property=RuntimeDirectoryMode=0700','--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=PrivateTmp=yes','--property=NoNewPrivileges=yes','/usr/sbin/php-fpm'+minor,'-F','-c','/etc/php/'+minor+'/fpm/php.ini','-y',str(pool)])
            started=True;deadline=time.monotonic()+90
            while not (runtime_path/'fpm.sock').exists() and time.monotonic()<deadline:time.sleep(.25)
            require((runtime_path/'fpm.sock').is_socket(),'real isolated nonroot FPM socket did not become ready')
            response=command(['/usr/bin/cgi-fcgi','-bind','-connect',str(runtime_path/'fpm.sock')],env={'PATH':'/usr/bin:/bin','LC_ALL':'C','SCRIPT_FILENAME':str(script),'REQUEST_METHOD':'GET','SCRIPT_NAME':'/index.php','SERVER_PROTOCOL':'HTTP/1.1','SERVER_NAME':'localhost','SERVER_PORT':'80','GATEWAY_INTERFACE':'CGI/1.1','REDIRECT_STATUS':'200'})
            body=re.split(r'\r?\n\r?\n',response.stdout,maxsplit=1)
            require(len(body)==2,'FastCGI response headers missing')
            fpm=json.loads(body[1])
            require(fpm['version']==cli_proof['version'] and type(fpm['uid']) is int and fpm['uid']>0 and fpm['ini']=='/etc/php/'+minor+'/fpm/php.ini' and set(REQUIRED_EXTENSIONS)<=set(fpm['extensions']) and all(fpm.get(k) is True for k in ('own_read','other_denied','shell_disabled')),'actual isolated FPM/INI/modules/UID/confinement proof failed')
            tool_env={'PATH':'/usr/local/bin:/usr/bin:/bin','LC_ALL':'C','HOME':str(runtime_path),'COMPOSER_HOME':str(runtime_path/'composer'),'COMPOSER_CACHE_DIR':str(runtime_path/'composer-cache'),'COMPOSER_DISABLE_NETWORK':'1','WP_CLI_DISABLE_AUTO_CHECK_UPDATE':'1','WP_CLI_CONFIG_PATH':'/dev/null','WP_CLI_CACHE_DIR':str(runtime_path/'wp-cache')}
            interpreter=['/usr/sbin/runuser','-u','nobody','--','/usr/bin/php'+minor]
            composer=command(interpreter+['/usr/local/lib/nakpanel/composer.phar','--no-plugins','--no-scripts','--no-interaction','--version'],env=tool_env,cwd=public)
            wp=command(interpreter+['/usr/local/lib/nakpanel/wp-cli.phar','--info','--no-color'],env=tool_env,cwd=public)
            worker_code="echo 'NAKPANEL_MAINTENANCE_WORKER='.json_encode(['version'=>PHP_VERSION,'uid'=>posix_geteuid()]).PHP_EOL;"
            project=public/'composer.json';project.write_text(json.dumps({'name':'nakpanel/maintenance-canary','scripts':{'maintenance':'@php -r '+shlex.quote(worker_code)}}));project.chmod(0o644)
            worker=command(interpreter+['/usr/local/lib/nakpanel/composer.phar','--no-plugins','--no-interaction','run-script','maintenance'],env=tool_env,cwd=public)
            tools=parse_tool_results(minor,fpm['uid'],composer,wp,worker)
            result[minor]={'cli':cli_proof,'fastcgi':fpm,'tools':tools}
        finally:
            if started:command(['systemctl','stop',unit])
    write_private(root/('php-smoke-'+phase+'.json'),result)
    return result


def parse_tool_results(minor, uid, composer, wp, worker):
    require(all(result.returncode==0 for result in (composer,wp,worker)), 'actual Composer/WP-CLI/@php worker failed')
    composer_version=re.search(r'Composer version (\d+\.\d+\.\d+)',composer.stdout+composer.stderr)
    wp_version=re.search(r'^WP-CLI version:\s*(\d+\.\d+\.\d+)',wp.stdout,re.M)
    lines=[line.removeprefix('NAKPANEL_MAINTENANCE_WORKER=') for line in worker.stdout.splitlines() if line.startswith('NAKPANEL_MAINTENANCE_WORKER=')]
    require(composer_version is not None and wp_version is not None and len(lines)==1, 'actual tool version/worker output missing')
    observed=json.loads(lines[0])
    require(observed.get('version','').startswith(minor+'.') and type(observed.get('uid')) is int and observed['uid']==uid and uid>0, 'Composer @php worker used the wrong interpreter/UID')
    return {'composer_version':composer_version[1],'wp_cli_version':wp_version[1],'worker':observed}


def manager_remaining(deadline):
    remaining=deadline-time.monotonic()
    if remaining<=0:raise ValueError('post-maintenance service/DB-manager readiness timed out')
    return remaining


def manager_key(deadline):
    manager_remaining(deadline)
    try:
        fd=os.open('/etc/nakpanel/database-manager.key',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)&0o137 or info.st_size>4096:
                raise ValueError('database-manager key metadata invalid')
            data=os.read(fd,4097)
        finally:os.close(fd)
        key=data.strip().decode('ascii')
    except (OSError,UnicodeError):
        raise ValueError('database-manager private key unavailable') from None
    manager_remaining(deadline)
    if not 32<=len(key)<=4096 or len(data)!=info.st_size or any(ord(c)<32 or ord(c)>126 for c in key):
        raise ValueError('database-manager key format invalid')
    return key


def manager_bridge():
    try:
        info=os.lstat('/run/nakpanel-db-manager/bridge.sock')
    except OSError:return None
    return {'socket':stat.S_ISSOCK(info.st_mode),'uid':info.st_uid,'gid':info.st_gid,'mode':oct(stat.S_IMODE(info.st_mode))}


def manager_http(deadline):
    key=manager_key(deadline)
    connection=http.client.HTTPConnection('127.0.0.1',9082,timeout=min(2,manager_remaining(deadline)))
    response=None
    try:
        connection.request('GET','/__nakpanel_health',headers={'X-Nakpanel-Manager-Key':key})
        remaining=manager_remaining(deadline)
        if connection.sock is not None:connection.sock.settimeout(min(2,remaining))
        response=connection.getresponse()
        manager_remaining(deadline)
        return {'status':response.status,'transport':'connected'}
    except ConnectionRefusedError:
        manager_remaining(deadline);return {'status':None,'transport':'refused'}
    except (TimeoutError,OSError,http.client.HTTPException):
        manager_remaining(deadline);return {'status':None,'transport':'unavailable'}
    finally:
        cleanup_failed=False
        try:
            if response is not None:
                try:response.close()
                except (OSError,http.client.HTTPException):cleanup_failed=True
        finally:
            try:connection.close()
            except (OSError,http.client.HTTPException):cleanup_failed=True
        if cleanup_failed:raise ValueError('database-manager connection cleanup failed') from None


def service_wait(before, db_manager):
    deadline=time.monotonic()+120
    expected={**{'php'+minor+'-fpm.service':'active' for minor in MINORS},**before}
    if db_manager:expected.update({'nakpanel-database-manager.service':'active','nakpanel-database-manager-http.service':'active'})
    while True:
        ready=True
        for unit,state in expected.items():
            remaining=manager_remaining(deadline)
            try:
                result=command(['systemctl','show','--property=ActiveState','--value',unit],check=False,timeout=min(5,remaining))
            except (OSError,UnicodeError,subprocess.SubprocessError):
                raise ValueError('post-maintenance service inspection unavailable') from None
            manager_remaining(deadline)
            ready=(result.returncode==0 and result.stdout.strip()==state) and ready
        if db_manager:
            bridge=manager_bridge();manager_remaining(deadline)
            if bridge is None or not bridge['socket']:ready=False
            check=manager_http(deadline) if ready else None
            ready=ready and check is not None and check['status']==204
        manager_remaining(deadline)
        if ready:return
        time.sleep(min(1,manager_remaining(deadline)))


def guest_health(root, config, phase, *, reboot=False):
    baseline=json.loads(root_regular(root/'baseline.json'))
    packages=json.loads(root_regular(root/'packages.json'))
    units=sorted(set(SERVICES)|{'php'+minor+'-fpm.service' for minor in MINORS}|set(baseline['managed_services'])|({'nakpanel-database-manager.service','nakpanel-database-manager-http.service'} if baseline['database_manager'] else set()))
    # Preserve unassisted postboot state before any wait or smoke operation.
    # Service restoration belongs only to the controlled fault recovery path;
    # a reboot persistence failure must never be repaired by this verifier.
    observed={'reboot':reboot,'boot_id':root_regular('/proc/sys/kernel/random/boot_id').decode().strip(),'mutation_services':{unit:service_state(unit) for unit in SERVICES},'fpm_services':{minor:service_state('php'+minor+'-fpm.service') for minor in MINORS},'managed_services':managed_state(),'unit_details':command(['systemctl','show','--property=ActiveState,SubState,UnitFileState,Result,ExecMainStatus',*units]).stdout,'package_inventory':package_inventory(),'settings':guarded_settings(),'package_files':package_files(packages),'intent':intent_state(),'dpkg_audit':command(['dpkg','--audit']).stdout}
    write_private(root/('observed-'+phase+'.json'),observed)
    assert_managed_services(baseline['managed_services'],baseline['intent'])
    assert_managed_services(observed['managed_services'],observed['intent'])
    require(observed['package_inventory']==baseline['package_inventory'],'package versions or states changed outside same-version recovery')
    require(observed['settings']==baseline['settings'],'preexisting PHP/APT/profile/key settings differ')
    require(observed['package_files']==baseline['package_files'],'original installed PHP package bytes/modes differ')
    require(observed['intent']==baseline['intent'],'original site/application/worker desired state changed')
    require(observed['dpkg_audit'].strip()=='','pending/broken dpkg state remains')
    service_wait(baseline['mutation_services'],baseline['database_manager'])
    current_managed=managed_state();assert_managed_services(current_managed,observed['intent'])
    require(current_managed==baseline['managed_services'],'managed PHP service active/stopped state changed')
    smoke=php_smoke(root,config,phase)
    original_smoke=json.loads(root_regular(root/'php-smoke-before.json'))
    require(all(smoke[minor]['tools']==original_smoke[minor]['tools'] for minor in MINORS),'tool versions or actual @php worker interpreter/UID changed')
    return {'status':'HEALTHY','operation':MODE,'boot_id':observed['boot_id'],'php':smoke,'settings_restored':True,'package_bytes_restored':True,'package_versions_unchanged':True,'desired_and_active_state_unchanged':True,'database_manager_fastcgi':baseline['database_manager'],'service_repair_performed':False,'observation_sha256':digest(root_regular(root/('observed-'+phase+'.json')))}


def run_guest(root, config):
    require(not (root/'baseline.json').exists(),'maintenance attempt already exists; preserve its evidence')
    packages=json.loads(root_regular(root/'packages.json'));backend=GuestBackend(root,config,packages)
    verify_gpgv(root);backend.prepare()
    before={unit:service_state(unit) for unit in SERVICES};restore_service_actions(before)
    db_manager=Path('/etc/nakpanel-database-manager/health.php').exists()
    baseline={'package_inventory':package_inventory(),'settings':guarded_settings(),'package_files':package_files(packages),'mutation_services':before,'managed_services':managed_state(),'intent':intent_state(),'database_manager':db_manager}
    write_private(root/'baseline.json',baseline)
    assert_managed_services(baseline['managed_services'],baseline['intent'])
    service_wait(before,db_manager);php_smoke(root,config,'before')
    for unit in SERVICES:
        if before[unit]=='active':command(['systemctl','stop',unit])
    require(all(service_state(unit)=='inactive' for unit in SERVICES),'panel/agent mutation workers did not quiesce')
    require(intent_state()==baseline['intent'],'desired state drifted while quiescing')
    delivery=backend.reinstall()
    require(delivery.returncode==0,'initial real same-version delivery failed')
    backend.record('same-version-delivered',{'returncode':delivery.returncode,'genuine_version_advance':False})
    for minor in MINORS:
        require(all(service_state(unit)=='inactive' for unit in SERVICES),'a background mutation worker resumed during fault sequence')
        drill_minor(minor,config['maintenance_id'],Path('/etc/php')/minor/'fpm/pool.d',backend,backend.record)
    require(guarded_settings()==baseline['settings'] and package_inventory()==baseline['package_inventory'],'settings or package state differ before mutation workers resume')
    # Restart only previously active PHP resources; desired-stopped workers and
    # previously stopped resources are never explicitly started by this tool.
    for unit,state in baseline['managed_services'].items():
        if state=='active':command(['systemctl','restart',unit])
    if db_manager:command(['systemctl','restart','nakpanel-database-manager.service'])
    for operation,unit in restore_service_actions(before):command(['systemctl',operation,unit])
    result=guest_health(root,config,'recovered');result['status']='RECOVERED'
    write_private(root/'recovery-result.json',result)
    return result


def guest_action(request):
    require(request.get('action') in ('stage','run','health'),'unsupported guest operation; no removal/provider switch exists')
    config=request['config'];guest_identity(config)
    if request['action']=='stage':return stage_guest(request)
    root=guest_directory(config);ensure_root_directory(root)
    require(json.loads(root_regular(root/'config.json'))==config,'guest operation input differs from staged binding')
    if request['action']=='run':return run_guest(root,config)
    require(request.get('phase') in ('reboot-1','reboot-2'),'unexpected reboot health phase')
    result=guest_health(root,config,request['phase'],reboot=True);write_private(root/(request['phase']+'.json'),result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['same-version'])
    parser.add_argument('spec', type=Path)
    args = parser.parse_args()
    return host_main(args.spec)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt as error:
        print('Surý maintenance rehearsal cancelled; inspect retained failure receipt',file=sys.stderr)
        sys.exit(143 if isinstance(error,MaintenanceTermination) else 130)
    except (ValueError, RuntimeError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print('Surý maintenance rehearsal refused/failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
