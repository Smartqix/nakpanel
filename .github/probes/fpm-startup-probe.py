"""Diagnostic only: selected FPM configuration under real hosted systemd."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import time

BASE = 'fbcf634e11318af85a14c1cae0e10b256e220d50'
REF = 'refs/heads/ricky/fpm-startup-probe-20261019-v1'
CONFIG = 'deploy/database-manager/php-fpm.conf'
UNIT = 'deploy/systemd/nakpanel-database-manager.service.tmpl'
EXPECTED = {CONFIG: 'f43fd8861ab9d805e791d765fafe356ccb4b805c48ba22126ac951a50b8e180b',
            UNIT: 'dbb572f351e53298c62cd35e92c5a385589bce01e68dce7d538b3fd15ad98ce5'}
COMMAND_EVIDENCE = None
COMMAND_NUMBER = 0


def run(args, timeout=20):
    global COMMAND_NUMBER
    started = time.monotonic()
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        record_command(args, started, None, error.stdout or b'', error.stderr or b'', True)
        raise
    record_command(args, started, result.returncode, result.stdout, result.stderr, False)
    return result


def record_command(args, started, exit_code, stdout, stderr, timed_out):
    global COMMAND_NUMBER
    if COMMAND_EVIDENCE is None:
        return
    COMMAND_NUMBER += 1
    prefix = 'command-' + str(COMMAND_NUMBER).zfill(4)
    (COMMAND_EVIDENCE / (prefix + '.stdout')).write_bytes(stdout)
    (COMMAND_EVIDENCE / (prefix + '.stderr')).write_bytes(stderr)
    with (COMMAND_EVIDENCE / (prefix + '.json')).open('x') as handle:
        json.dump(dict(args=args, exit_code=exit_code, timed_out=timed_out,
                       elapsed_seconds=time.monotonic() - started), handle, indent=2)
        handle.write('\n')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    global COMMAND_EVIDENCE
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
    assert os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
    assert os.environ.get('RUNNER_OS') == 'Linux'
    assert os.environ.get('GITHUB_REPOSITORY') == 'Smartqix/nakpanel'
    assert os.environ.get('GITHUB_EVENT_NAME') == 'push'
    assert os.environ.get('GITHUB_REF') == REF
    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    ident, attempt = os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT']
    assert re.fullmatch(r'[0-9]{5,16}', ident) and re.fullmatch(r'[1-9][0-9]?', attempt)
    root = Path(__file__).resolve().parents[2]
    assert run(['git', '-C', str(root), 'rev-parse', 'HEAD^']).stdout.decode().strip() == BASE
    changed = run(['git', '-C', str(root), 'diff', '--name-only', BASE, 'HEAD'])
    assert changed.returncode == 0
    assert set(changed.stdout.decode().splitlines()) == {
        '.github/workflows/fpm-startup-probe.yml', '.github/probes/fpm-startup-probe.py'}
    assert run(['git', '-C', str(root), 'status', '--porcelain']).stdout == b''
    for name, expected in EXPECTED.items():
        assert digest((root / name).read_bytes()) == expected, name
    runner = pwd.getpwnam('runner')
    assert runner.pw_uid > 0 and int(os.environ['SUDO_UID']) == runner.pw_uid
    output = Path(args.output).resolve()
    expected_output = Path(os.environ['RUNNER_TEMP']).resolve() / ('fpm-startup-probe-' + ident + '-' + attempt)
    assert output == expected_output
    output.mkdir(mode=0o700)
    COMMAND_EVIDENCE = output

    def save(name, value):
        path = output / name
        with path.open('x') as handle:
            json.dump(value, handle, indent=2)
            handle.write('\n')

    def retain(name, data):
        with (output / name).open('xb') as handle:
            handle.write(data)

    prefix = 'np-fpm-' + ident + '-' + attempt
    username = 'npfpm' + ident + 'a' + attempt
    assert len(username) < 32 and run(['getent', 'passwd', username]).returncode == 2
    assert run(['getent', 'group', username]).returncode == 2
    etc, state, runtime = (Path('/etc') / prefix, Path('/var/lib') / prefix, Path('/run') / prefix)
    assert all(not p.exists() and not p.is_symlink() for p in (etc, state, runtime))
    binary = Path('/usr/sbin/php-fpm8.3')
    assert binary.is_file()
    version = run([str(binary), '--version'])
    assert version.returncode == 0 and re.search(rb'PHP 8\.3\.', version.stdout + version.stderr)
    policy = run(['apt-cache', 'policy', 'php8.3-fpm'])
    save('host.json', dict(base_commit=BASE, probe_commit=os.environ['GITHUB_SHA'],
                          run_id=ident, attempt=attempt, uname=run(['uname', '-a']).stdout.decode(),
                          systemd=run(['systemd', '--version']).stdout.decode(),
                          php_version=(version.stdout + version.stderr).decode(),
                          php_binary_sha256=digest(binary.read_bytes()),
                          configured_authenticated_APT_policy=policy.stdout.decode(),
                          selected_source_sha256=EXPECTED, diagnostic_only=True))
    unit_paths, units, results = [], [], []
    created_user = False
    account = None
    cleanup_errors = []
    observation_errors = []
    causal_errors = []
    failure = None
    try:
        created = run(['useradd', '--system', '--no-create-home', '--user-group',
                       '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', username])
        assert created.returncode == 0
        created_user = True
        account = pwd.getpwnam(username)
        for path in (etc, state, runtime):
            path.mkdir(mode=0o700)
            os.chown(path, account.pw_uid, account.pw_gid)
        os.chown(etc, 0, account.pw_gid)
        etc.chmod(0o750)
        for child in ('grants', 'tmp'):
            path = state / child
            path.mkdir(mode=0o700)
            os.chown(path, account.pw_uid, account.pw_gid)
        launcher = etc / 'launch.py'
        launcher.write_text('''import errno,json,os,stat,sys
v=os.fstat(2)
d=dict(stderr_socket=stat.S_ISSOCK(v.st_mode),stderr_uid=v.st_uid,stderr_inode=v.st_ino)
try:
 f=os.open('/proc/self/fd/2',os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600);os.close(f);d['reopen_errno']=0
except OSError as error:d['reopen_errno']=error.errno
os.write(2,('NAKPANEL_PROBE_FD '+json.dumps(d,sort_keys=True)+'\\n').encode())
os.execv(sys.argv[1],[sys.argv[1],'--nodaemonize','--fpm-config',sys.argv[2]])
''')
        os.chown(launcher, 0, account.pw_gid)
        launcher.chmod(0o640)
        mappings = {'nakpanel-dbmgr': username,
                    '/run/nakpanel-database-manager': str(runtime),
                    '/var/lib/nakpanel-database-manager': str(state),
                    '/etc/nakpanel-database-manager': str(etc),
                    '/opt/nakpanel-database-manager': '/opt/' + prefix,
                    '/run/nakpanel-db-manager': '/run/' + prefix + '-bridge'}
        selected = (root / CONFIG).read_text()
        assert selected.count('error_log = /proc/self/fd/2\n') == 1
        for old, new in mappings.items():
            selected = selected.replace(old, new)
        for label, destination in [('original-procfd', '/proc/self/fd/2'),
                                   ('inherited-null-control', '/dev/null'),
                                   ('syslog-candidate', 'syslog')]:
            config_text = selected.replace('error_log = /proc/self/fd/2\n', 'error_log = ' + destination + '\n')
            config = etc / (label + '.conf')
            config.write_text(config_text)
            os.chown(config, 0, account.pw_gid)
            config.chmod(0o640)
            retain(label + '.fpm.conf', config.read_bytes())
            check = run([str(binary), '--test', '--fpm-config', str(config)])
            retain(label + '.root-test.stdout', check.stdout)
            retain(label + '.root-test.stderr', check.stderr)
            unit_name = prefix + '-' + label + '.service'
            unit_path = Path('/run/systemd/system') / unit_name
            assert not unit_path.exists() and not unit_path.is_symlink()
            unit = (root / UNIT).read_text()
            for old, new in mappings.items():
                unit = unit.replace(old, new)
            unit = unit.replace('RuntimeDirectory=nakpanel-database-manager', 'RuntimeDirectory=' + prefix)
            unit = unit.replace('StateDirectory=nakpanel-database-manager', 'StateDirectory=' + prefix)
            old_exec = 'ExecStart=@PHP_FPM_BINARY@ --nodaemonize --fpm-config ' + str(etc) + '/php-fpm.conf'
            assert unit.count(old_exec) == 1
            unit = unit.replace(old_exec, 'ExecStart=/usr/bin/python3 ' + str(launcher) + ' ' + str(binary) + ' ' + str(config))
            unit = unit.replace('Restart=on-failure', 'Restart=no')
            unit += '\n[Service]\nStandardOutput=journal\nStandardError=journal\n'
            unit_path.write_text(unit)
            unit_path.chmod(0o644)
            units.append(unit_name)
            unit_paths.append(unit_path)
            retain(label + '.unit', unit.encode())
            reload_result = run(['systemctl', 'daemon-reload'])
            assert reload_result.returncode == 0
            assert not (runtime / 'fpm.sock').exists() and not (runtime / 'fpm.sock').is_symlink()
            started = run(['systemctl', 'start', unit_name])
            properties = {}
            listener = False
            healthy = 0
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                inspected = run(['systemctl', 'show', unit_name, '--property=ActiveState,SubState,Result,ExecMainStatus,ExecMainPID,MainPID,InvocationID,NRestarts,FragmentPath'])
                assert inspected.returncode == 0
                properties = dict(line.split('=', 1) for line in inspected.stdout.decode().splitlines() if '=' in line)
                socket_path = runtime / 'fpm.sock'
                listener = socket_path.exists() and stat.S_ISSOCK(socket_path.lstat().st_mode)
                healthy = healthy + 1 if properties.get('ActiveState') == 'active' and listener else 0
                if properties.get('ActiveState') == 'failed' or healthy >= 3:
                    break
                time.sleep(0.2)
            run(['journalctl', '--sync'])
            journal = run(['journalctl', '-u', unit_name, '--no-pager', '--output=cat'])
            assert journal.returncode == 0
            retain(label + '.master-journal.log', journal.stdout)
            invocation = properties.get('InvocationID', '')
            assert re.fullmatch(r'[a-f0-9]{32}', invocation), properties
            invocation_journal = run(['journalctl', '_SYSTEMD_INVOCATION_ID=' + invocation, '--no-pager', '--output=json'])
            assert invocation_journal.returncode == 0
            retain(label + '.invocation-journal.jsonl', invocation_journal.stdout)
            entries = [json.loads(line) for line in invocation_journal.stdout.decode().splitlines()]
            master_pid = properties.get('ExecMainPID', '')
            assert master_pid.isdecimal() and int(master_pid) > 0
            master_entries = [entry for entry in entries
                              if entry.get('_SYSTEMD_INVOCATION_ID') == invocation
                              and entry.get('_SYSTEMD_UNIT') == unit_name
                              and str(entry.get('_PID')) == master_pid]
            messages = [entry.get('MESSAGE', '') for entry in master_entries]
            fd_rows = [json.loads(message.removeprefix('NAKPANEL_PROBE_FD '))
                       for message in messages if isinstance(message, str) and message.startswith('NAKPANEL_PROBE_FD ')]
            assert len(fd_rows) == 1 and fd_rows[0].get('stderr_socket') is True
            result = dict(case=label,root_config_test_exit=check.returncode,
                          unit_start_command_exit=started.returncode,properties=properties,
                          real_listener=listener,consecutive_healthy_polls=healthy,
                          stderr_descriptor=fd_rows,
                          configuration_sha256=digest(config.read_bytes()),unit_sha256=digest(unit.encode()),
                          journal_sha256=digest(journal.stdout),
                          actual_master_pid=master_pid,invocation_id=invocation,
                          actual_master_ready_logged=any('ready to handle connections' in message for message in messages if isinstance(message, str)),
                          actual_log_open_error=any('failed to open error_log (/proc/self/fd/2)' in message for message in messages if isinstance(message, str)),
                          invocation_journal_sha256=digest(invocation_journal.stdout))
            save(label + '.json', result)
            results.append(result)
            stopped = run(['systemctl', 'stop', unit_name])
            assert stopped.returncode == 0
            run(['systemctl', 'reset-failed', unit_name])
        by_case = {result['case']: result for result in results}
        baseline = by_case['original-procfd']
        if not (baseline['root_config_test_exit'] == 0
                and baseline['properties'].get('ActiveState') == 'failed'
                and baseline['properties'].get('ExecMainStatus') == '78'
                and baseline['actual_log_open_error']
                and baseline['stderr_descriptor'][0]['reopen_errno'] != 0):
            causal_errors.append('baseline-does-not-confirm-log-open-hypothesis')
        for label in ('inherited-null-control', 'syslog-candidate'):
            result = by_case[label]
            properties = result['properties']
            if not (result['root_config_test_exit'] == 0
                    and properties.get('ActiveState') == 'active'
                    and properties.get('MainPID') == result['actual_master_pid']
                    and result['real_listener'] and result['consecutive_healthy_polls'] >= 3):
                causal_errors.append(label + '-not-healthy')
        if not by_case['syslog-candidate']['actual_master_ready_logged']:
            causal_errors.append('syslog-master-readiness-journal-missing')
    except Exception as error:
        failure = type(error).__name__ + ': ' + str(error)
    finally:
        if failure:
            for name in units:
                for command in ([ 'systemctl', 'show', name,
                                  '--property=ActiveState,SubState,Result,ExecMainStatus,ExecMainPID,MainPID,InvocationID'],
                                ['journalctl', '-u', name, '--no-pager', '--output=json']):
                    try:
                        observed = run(command)
                        if observed.returncode != 0:
                            observation_errors.append('failure-snapshot-exit:' + repr(command))
                    except Exception as error:
                        observation_errors.append('failure-snapshot-error:' + type(error).__name__ + ':' + repr(command))
        def cleanup_run(command):
            try:
                completed = run(command)
                if completed.returncode != 0:
                    cleanup_errors.append('command-exit:' + str(completed.returncode) + ':' + repr(command))
                return completed
            except Exception as error:
                cleanup_errors.append('command-error:' + repr(command) + ':' + type(error).__name__)
                return None

        for name in reversed(units):
            cleanup_run(['systemctl', 'stop', name])
            inspected = cleanup_run(['systemctl', 'show', name, '--property=MainPID', '--value'])
            if inspected is None or inspected.stdout.strip() != b'0':
                cleanup_errors.append('live-process:' + name)
        if not cleanup_errors:
            for path in unit_paths:
                try:
                    path.unlink()
                except Exception as error:
                    cleanup_errors.append('unlink:' + str(path) + ':' + type(error).__name__)
            cleanup_run(['systemctl', 'daemon-reload'])
            if created_user:
                if account is None:
                    try:
                        account = pwd.getpwnam(username)
                    except KeyError:
                        cleanup_errors.append('created-account-not-found')
                try:
                    no_processes = account is not None and run(['pgrep', '-u', str(account.pw_uid)]).returncode == 1
                except Exception as error:
                    no_processes = False
                    cleanup_errors.append('account-process-check:' + type(error).__name__)
                if not no_processes:
                    cleanup_errors.append('account-processes-remain')
                else:
                    cleanup_run(['userdel', username])
                    try:
                        group = run(['getent', 'group', username])
                        if group.returncode == 0:
                            cleanup_run(['groupdel', username])
                        elif group.returncode != 2:
                            cleanup_errors.append('group-inspection')
                    except Exception as error:
                        cleanup_errors.append('group-inspection:' + type(error).__name__)
            if not cleanup_errors:
                for path in (etc, state, runtime):
                    try:
                        if path.exists():
                            assert not path.is_symlink() and path.name == prefix
                            shutil.rmtree(path)
                    except Exception as error:
                        cleanup_errors.append('owned-directory:' + str(path) + ':' + type(error).__name__)
        save('result.json',dict(diagnostic_only=True,production_source_unchanged=True,
                               base_commit=BASE,probe_commit=os.environ['GITHUB_SHA'],
                               results=results,failure=failure,cleanup_errors=cleanup_errors,
                               observation_errors=observation_errors,causal_errors=causal_errors,
                               controlled_mechanism_confirmed=not failure and not causal_errors and len(results) == 3,
                               platform_or_fix_acceptance=False))
        for path in output.rglob('*'):
            assert not path.is_symlink()
            os.chown(path, runner.pw_uid, runner.pw_gid, follow_symlinks=False)
        os.chown(output, runner.pw_uid, runner.pw_gid)
    if failure or cleanup_errors or observation_errors or causal_errors or len(results) != 3:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
