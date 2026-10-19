"""Run the Resolute installer with the observed uutils 0.10 parent semantics.

The real Native17 primitive (receipt SHA256 35a0c740686bfbc35f6ab034a48ebef6
28ca24e7817251fb674d3757fcd2f624) produced an implicit 0700 ancestor under
umask 077, while each explicitly named directory became 0755. Directory
creation models that primitive; artifact preparation, account ownership,
SQLite and PHP/runuser are external boundaries. Real archive validation,
extraction and the remaining installer filesystem effects run.
"""
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest


SOURCE = Path(__file__).resolve().with_name('roundcube.sh')


class RoundcubePermissionsTests(unittest.TestCase):
    def fixture(self, directory, *, restrictive=False, fail_lint=False):
        root = Path(directory).resolve()
        root.chmod(0o755)
        for path in ('opt', 'usr', 'usr/share', 'etc', 'var', 'var/lib', 'var/log', 'tmp', 'bin', 'stage'):
            target = root / path
            target.mkdir(parents=True, exist_ok=True)
            target.chmod(0o755)
        prefix = root / 'opt/nakpanel'
        if restrictive:
            prefix.mkdir(mode=0o700)
        private = prefix / 'private'
        if restrictive:
            private.mkdir(mode=0o700)
            (private / 'secret').write_bytes(b'keep existing private bytes\n')
            (private / 'secret').chmod(0o600)
        # Keep the real archive policy and extraction in the exercised path.
        archive = root / 'stage/roundcube.tar.gz'
        with tarfile.open(archive, 'w:gz') as stream:
            for name in ('config', 'SQL', 'program', 'program/lib', 'program/lib/Roundcube', 'installer'):
                info = tarfile.TarInfo('roundcubemail-1.6.19/' + name)
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                stream.addfile(info)
            for name, data in (('program/lib/Roundcube/bootstrap.php', b'<?php // public bootstrap\n'),
                               ('SQL/sqlite.initial.sql', b'CREATE TABLE fixture (id INTEGER);\n')):
                info = tarfile.TarInfo('roundcubemail-1.6.19/' + name)
                info.size = len(data)
                info.mode = 0o644
                stream.addfile(info, io.BytesIO(data))
        shutil.copyfile(SOURCE.with_name('archive_policy.py'), root / 'archive_policy.py')
        source = SOURCE.read_text()
        for original, mapped in (
            ('/tmp/nakpanel', str(root / 'tmp/nakpanel')),
            ('/opt/nakpanel', str(prefix)), ('/usr/share', str(root / 'usr/share')),
            ('/etc/roundcube', str(root / 'etc/roundcube')),
            ('/var/lib/roundcube', str(root / 'var/lib/roundcube')),
            ('/var/log/roundcube', str(root / 'var/log/roundcube')),
            ('/usr/bin/php', str(root / 'bin/php')),
        ):
            source = source.replace(original, mapped)
        (root / 'roundcube.sh').write_text(source)
        scripts = {
            'install': '''import os, pathlib, sys
a=sys.argv[1:]
if len(a)<8 or a[0]!='-d' or a[1]!='-o' or a[2] not in ('root','www-data') or a[3]!='-g' or a[4] not in ('root','www-data') or a[5]!='-m':
 sys.exit('unexpected install boundary')
mode=int(a[6],8)
for value in a[7:]:
 p=pathlib.Path(value)
 # uutils 0.10 directory(): create_dir_all, then chmod only the operand.
 p.mkdir(parents=True,exist_ok=True)
 p.chmod(mode)
''',
            'chown': '''import sys
a=sys.argv[1:]
if a and a[0]=='-R':a=a[1:]
if len(a)!=2 or a[0] not in ('root:root','root:www-data','www-data:www-data'):
 sys.exit('unexpected ownership boundary')
''',
            'sqlite3': '''import pathlib,sys
if len(sys.argv)!=2 or not sys.stdin.read().startswith('CREATE TABLE fixture'):
 sys.exit('unexpected SQLite boundary')
pathlib.Path(sys.argv[1]).write_bytes(b'fixture database')
''',
            'php8.5': '''import os,pathlib,stat,sys
r=pathlib.Path(os.environ['ROUNDCUBE_TEST_ROOT']);p=pathlib.Path(sys.argv[-1])
if sys.argv[1:]!=['-l',str(r/'opt/nakpanel/roundcube/1.6.19/program/lib/Roundcube/bootstrap.php')]:
 sys.exit('unexpected PHP lint boundary')
reader=os.environ.get('ROUNDCUBE_TEST_READER','root')
if reader=='www-data':
 if os.environ.get('ROUNDCUBE_TEST_FAIL_LINT')=='1':sys.exit(37)
 for parent in p.parents:
  if parent==r.parent:break
  if not stat.S_IMODE(parent.stat().st_mode)&1:sys.exit('www-data cannot traverse public program ancestor')
 if not stat.S_IMODE(p.stat().st_mode)&4:sys.exit('www-data cannot read bootstrap')
(r/(reader+'-lint')).write_bytes(p.read_bytes())
''',
        }
        for name, body in scripts.items():
            path = root / 'bin' / name
            path.write_text('#!' + sys.executable + '\n' + body)
            path.chmod(0o755)
        runuser = root / 'bin/runuser'
        runuser.write_text('''#!/bin/sh
[ "$1" = -u ] && [ "$2" = www-data ] && [ "$3" = -- ] || exit 91
shift 3
export ROUNDCUBE_TEST_READER=www-data
exec "$@"
''')
        runuser.chmod(0o755)
        env = dict(os.environ, PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'],
                   ROUNDCUBE_TEST_ROOT=str(root), ROUNDCUBE_TEST_FAIL_LINT='1' if fail_lint else '0',
                   NAKPANEL_ROUNDCUBE_STAGE=str(root / 'stage'))
        return root, env

    def install(self, root, env):
        driver = root / 'run-installer.sh'
        driver.write_text('''set -euo pipefail
umask 077
source "$ROUNDCUBE_TEST_ROOT/roundcube.sh"
nakpanel_prepare_roundcube_artifact(){ export NAKPANEL_ROUNDCUBE_STAGE="$ROUNDCUBE_TEST_ROOT/stage"; }
NAKPANEL_INTERNAL_PHP_VERSION=8.5
nakpanel_install_roundcube
umask >"$ROUNDCUBE_TEST_ROOT/caller-umask"
''')
        return subprocess.run(['bash', str(driver)], env=env, capture_output=True, text=True, timeout=20)

    def assert_public_install(self, root, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for path in ('opt/nakpanel', 'opt/nakpanel/roundcube', 'opt/nakpanel/roundcube/1.6.19'):
            self.assertEqual(stat.S_IMODE((root / path).stat().st_mode), 0o755, path)
        self.assertEqual((root / 'caller-umask').read_text().strip(), '0077')
        self.assertTrue((root / 'www-data-lint').is_file(), 'installer skipped the nonroot lint')
        self.assertEqual((root / 'www-data-lint').read_bytes(), b'<?php // public bootstrap\n')
        self.assertFalse((root / 'root-lint').exists(), 'root lint cannot prove public traversal')
        self.assertEqual((root / 'usr/share/roundcube').resolve(), root / 'opt/nakpanel/roundcube/1.6.19')
        self.assertEqual(stat.S_IMODE((root / 'etc/roundcube').stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE((root / 'etc/roundcube/debian-db-roundcube.php').stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE((root / 'var/lib/roundcube/roundcube.sqlite').stat().st_mode), 0o660)

    def test_fresh_public_program_is_reachable_under_restrictive_caller_umask(self):
        with tempfile.TemporaryDirectory(prefix='nakpanel-roundcube-perms-', dir='/tmp') as directory:
            root, env = self.fixture(directory)
            self.assert_public_install(root, self.install(root, env))

    def test_explicit_ancestors_repair_restrictive_prefix_without_widening_private_children(self):
        with tempfile.TemporaryDirectory(prefix='nakpanel-roundcube-perms-', dir='/tmp') as directory:
            root, env = self.fixture(directory, restrictive=True)
            private = root / 'opt/nakpanel/private'
            original = [(path, path.read_bytes() if path.is_file() else None, path.stat())
                        for path in (private, private / 'secret')]
            self.assert_public_install(root, self.install(root, env))
            for path, data, before in original:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), stat.S_IMODE(before.st_mode))
                self.assertEqual((path.stat().st_uid, path.stat().st_gid), (before.st_uid, before.st_gid))
                if data is not None:
                    self.assertEqual(path.read_bytes(), data)

    def test_repeated_install_preserves_existing_program_database_and_private_configuration(self):
        with tempfile.TemporaryDirectory(prefix='nakpanel-roundcube-perms-', dir='/tmp') as directory:
            root, env = self.fixture(directory, restrictive=True)
            self.assert_public_install(root, self.install(root, env))
            preserved = [root / path for path in ('opt/nakpanel/private/secret',
                         'opt/nakpanel/roundcube/1.6.19/program/lib/Roundcube/bootstrap.php',
                         'etc/roundcube/debian-db-roundcube.php', 'var/lib/roundcube/roundcube.sqlite')]
            before = [(p.read_bytes(), p.stat().st_ino, stat.S_IMODE(p.stat().st_mode)) for p in preserved]
            self.assert_public_install(root, self.install(root, env))
            self.assertEqual([(p.read_bytes(), p.stat().st_ino, stat.S_IMODE(p.stat().st_mode)) for p in preserved], before)
            self.assertEqual(stat.S_IMODE((root / 'opt/nakpanel/private').stat().st_mode), 0o700)

    def test_failed_nonroot_lint_fails_installer_and_propagates_exit_status(self):
        with tempfile.TemporaryDirectory(prefix='nakpanel-roundcube-perms-', dir='/tmp') as directory:
            root, env = self.fixture(directory, fail_lint=True)
            result = self.install(root, env)
            self.assertEqual(result.returncode, 37, result.stdout + result.stderr)
            self.assertFalse((root / 'caller-umask').exists(), 'installer continued after failed lint')
            self.assertFalse((root / 'root-lint').exists())


if __name__ == '__main__':
    unittest.main()
