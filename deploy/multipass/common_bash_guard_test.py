"""Actual-shell admission tests; no Bash version override or guest operation.

The macOS control runs the real /bin/bash3.2 when present. Supported admission
uses the actual Bash executable selected from PATH/by --bash5, never a shell
version mock. Ubuntu CI already provides Bash5. Source setup uses owned command
sentinels; all Multipass and other operational calls would fail the test.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).resolve().with_name('common.sh')
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--bash5')
options, remaining = parser.parse_known_args()
sys.argv = [sys.argv[0], *remaining]


def major(shell):
    result = subprocess.run([str(shell), '--noprofile', '--norc', '-c',
                             'builtin printf "%s" "${BASH_VERSINFO[0]}"'],
                            env={'PATH': '/usr/bin:/bin'}, capture_output=True, text=True, timeout=5)
    if result.returncode or not result.stdout.isdigit():
        raise AssertionError('an actual GNU Bash executable is required')
    return int(result.stdout)


class BashAdmissionTests(unittest.TestCase):
    def old_shell(self):
        shell = Path('/bin/bash')
        if not shell.is_file() or major(shell) >= 5:
            self.skipTest('real pre5 /bin/bash control is unavailable on this host')
        return shell

    def run_common(self, shell, caller, *, extra=None):
        with tempfile.TemporaryDirectory(prefix='nakpanel-bash-admission-') as directory:
            root = Path(directory)
            commands = root / 'commands'
            commands.mkdir()
            log = root / 'external-calls'
            for name in ('uname', 'dirname', 'multipass', 'python3', 'date', 'openssl', 'mkdir'):
                path = commands / name
                if name == 'uname':
                    body = 'printf "uname\\n" >>"$BASH_ADMISSION_CALLS"\nprintf "arm64\\n"\n'
                elif name == 'dirname':
                    body = 'printf "dirname\\n" >>"$BASH_ADMISSION_CALLS"\nprintf "%s\\n" "$BASH_ADMISSION_COMMON_DIR"\n'
                else:
                    body = 'printf "FORBIDDEN\\n" >>"$BASH_ADMISSION_CALLS"\nexit 93\n'
                path.write_text('#!/bin/sh\n' + body)
                path.chmod(0o755)
            env = dict(PATH=str(commands), HOME=str(root), TMPDIR=str(root), LC_ALL='C',
                       BASH_ADMISSION_CALLS=str(log), BASH_ADMISSION_COMMON_DIR=str(SOURCE.parent))
            env.update(extra or {})
            argv = [str(shell), '--noprofile', '--norc']
            if caller is None:
                argv += [str(SOURCE)]
            else:
                argv += ['-c', caller, 'admission-test', str(SOURCE)]
            result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=5)
            calls = log.read_text().splitlines() if log.exists() else []
            return result, calls

    def assert_refused(self, result, calls):
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('GNU Bash 5', result.stderr)
        self.assertIn('explicit', result.stderr)
        self.assertEqual(result.stdout, '', 'unsupported shell continued qualification')
        self.assertEqual(calls, [], 'unsupported shell reached external setup/operational commands')

    def test_old_shell_direct_execution_refuses_before_any_setup(self):
        self.assert_refused(*self.run_common(self.old_shell(), None))

    def test_old_shell_source_refuses_even_when_errexit_is_suppressed(self):
        for caller in ('set -e; source "$1"; printf CONTINUED',
                       'if source "$1"; then printf CONTINUED; fi; printf CONTINUED',
                       'load(){ source "$1"; printf CONTINUED; }; load "$1" || :; printf CONTINUED',
                       'trap \'if [[ ${NAKPANEL_MULTIPASS_VM+x} ]]; then builtin printf SETUP; fi\' EXIT; source "$1"'):
            with self.subTest(caller=caller):
                self.assert_refused(*self.run_common(self.old_shell(), caller))

    def test_old_shell_cannot_spoof_readonly_version_through_environment(self):
        forged = {'BASH_VERSION': '99.0', 'BASH_VERSINFO': '99', 'SHELL': '/pretend/bash5'}
        self.assert_refused(*self.run_common(self.old_shell(), 'source "$1"; printf CONTINUED', extra=forged))

    def test_old_shell_refusal_uses_builtins_even_with_shadowing_functions(self):
        caller = 'exit(){ return 0; }; printf(){ :; }; if source "$1"; then :; fi; builtin printf CONTINUED'
        self.assert_refused(*self.run_common(self.old_shell(), caller))

    def test_real_bash5_preserves_all_supported_profile_setup_without_vm_calls(self):
        shell = options.bash5 or shutil.which('bash')
        self.assertTrue(shell, 'put a real GNU Bash5+ executable first in PATH')
        self.assertGreaterEqual(major(shell), 5, 'qualification requires actual GNU Bash5+ first in PATH')
        for image, provider, profile, php in (
                ('26.04', 'native', 'ubuntu-26.04-native', '8.5'),
                ('26.04', 'sury', 'ubuntu-26.04-sury', '8.4')):
            with self.subTest(image=image, provider=provider):
                result, calls = self.run_common(shell, 'source "$1"; builtin printf "%s %s" "$NAKPANEL_QUALIFICATION_PROFILE" "$NAKPANEL_FIXTURE_PHP"',
                    extra={'NAKPANEL_MULTIPASS_IMAGE': image, 'NAKPANEL_QUALIFICATION_PHP_PROVIDER': provider})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, profile + ' ' + php)
                self.assertEqual(calls, ['uname', 'dirname'])

    def test_real_bash5_direct_common_execution_succeeds_without_vm_calls(self):
        shell = options.bash5 or shutil.which('bash')
        self.assertTrue(shell, 'real GNU Bash5+ is required')
        self.assertGreaterEqual(major(shell), 5)
        result, calls = self.run_common(shell, None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ['uname', 'dirname'])


if __name__ == '__main__':
    unittest.main()
