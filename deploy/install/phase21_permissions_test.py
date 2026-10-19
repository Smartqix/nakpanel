"""Exercise the real Phase21 directory/setup block on a mapped filesystem.

Native17's actual uutils0.10 primitive (SHA35a0c740...) creates unnamed
ancestors0700 under077. The independent Surý17 receipt SHAa598fc88... shows
both nginx ancestors root:root0700 and real UID33 traversal/write denial.
Directory effects and modes below are real. Root/www-data account ownership
and runuser are modeled external boundaries, permitting an unprivileged host
test; no system directory, account, service or guest is changed.
"""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).resolve().with_name('phase21-25-install.sh')
CHECKS = [('-x', 'etc/nginx/nakpanel/protected'),
          ('-x', 'var/cache/nginx/nakpanel'), ('-w', 'var/cache/nginx/nakpanel')]


class Phase21PermissionsTests(unittest.TestCase):
    def fixture(self, directory, *, semantics='uutils', ancestors=None, deny=''):
        root = Path(directory).resolve()
        root.chmod(0o755)
        for name in ('etc/nginx', 'etc/tmpfiles.d', 'var/cache', 'var/lib/nakpanel',
                     'var/log', 'usr/lib', 'run', 'bin'):
            path = root / name
            path.mkdir(parents=True, exist_ok=True)
            for parent in (path, *path.parents):
                if parent == root.parent:
                    break
                parent.chmod(0o755)
        for name in ('etc/nginx/nakpanel', 'var/cache/nginx'):
            if ancestors is not None:
                path = root / name
                path.mkdir(mode=ancestors)
                path.chmod(ancestors)
        private = ['etc/nakpanel/ssh', 'etc/nakpanel/ssh/authorized_keys',
                   'var/lib/nakpanel/tls', 'var/lib/nakpanel/git']
        if ancestors is not None:
            private += ['etc/nginx/nakpanel/private', 'var/cache/nginx/private']
        for name in private:
            path = root / name
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o700)
            (path / 'private-canary').write_bytes(b'existing private bytes\n')
            (path / 'private-canary').chmod(0o600)
        (root / 'owners.json').write_text('{}')
        common = '''import json,os,pathlib,stat,sys
r=pathlib.Path(os.environ['PHASE21_TEST_ROOT'])
owners=json.loads((r/'owners.json').read_text())
def target(value):
 p=pathlib.Path(value)
 if not p.is_relative_to(r):sys.exit('path escaped mapped fixture')
 return p
def owner(p,uid,gid):owners[str(p)]=[uid,gid]
def save():(r/'owners.json').write_text(json.dumps(owners))
'''
        scripts = {
            'install': common + '''a=sys.argv[1:]
if len(a)<8 or a[:2]!=['-d','-o'] or a[3]!='-g' or a[5]!='-m':sys.exit('unexpected install boundary')
ids={'root':0,'www-data':33}
uid,gid=ids[a[2]],ids[a[4]];mode=int(a[6],8)
for value in a[7:]:
 p=target(value);missing=[];parent=p.parent
 while not parent.exists():missing.append(parent);parent=parent.parent
 p.mkdir(parents=True,exist_ok=True)
 for parent in missing:
  owner(parent,0,0)
  if os.environ['PHASE21_TEST_SEMANTICS']=='gnu':parent.chmod(0o755)
 p.chmod(mode);owner(p,uid,gid)
save()
''',
            'chown': common + '''a=sys.argv[1:]
if len(a)!=2 or a[0]!='root:root':sys.exit('unexpected ownership boundary')
owner(target(a[1]),0,0);save()
''',
            'systemd-tmpfiles': common + '''if sys.argv[1:]!=['--create',str(r/'etc/tmpfiles.d/nakpanel-containers.conf')]:sys.exit('unexpected tmpfiles boundary')
''',
            'runuser': common + '''a=sys.argv[1:]
if len(a)!=6 or a[:4]!=['-u','www-data','--','test'] or a[4] not in ('-x','-w'):sys.exit('unexpected reader boundary')
perm,p=a[4],target(a[5]);relative=str(p.relative_to(r));allowed=True
for parent in (p.parent,*p.parents):
 if parent==r.parent:break
 uid,gid=owners.get(str(parent),[0,0]);bits=(parent.stat().st_mode>>(6 if uid==33 else 3 if gid==33 else 0))&7
 if not bits&1:allowed=False
uid,gid=owners.get(str(p),[0,0]);bits=(p.stat().st_mode>>(6 if uid==33 else 3 if gid==33 else 0))&7
allowed=allowed and bool(bits&(1 if perm=='-x' else 2))
forced=os.environ.get('PHASE21_TEST_DENY','')==perm+':'+relative
with (r/'reader-checks.jsonl').open('a') as f:f.write(json.dumps([perm,relative,allowed,forced])+'\\n')
sys.exit(37 if forced else 0 if allowed else 1)
''',
        }
        for name, body in scripts.items():
            path = root / 'bin' / name
            path.write_text('#!' + sys.executable + '\n' + body)
            path.chmod(0o755)
        env = dict(os.environ, PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'],
                   PHASE21_TEST_ROOT=str(root), PHASE21_TEST_SEMANTICS=semantics,
                   PHASE21_TEST_DENY=deny)
        canaries = [p for name in private for p in (root / name, root / name / 'private-canary')]
        return root, env, canaries

    def snapshot(self, paths):
        return [(str(p), p.read_bytes() if p.is_file() else None, p.stat().st_ino,
                 stat.S_IMODE(p.stat().st_mode), p.stat().st_uid, p.stat().st_gid) for p in paths]

    def install(self, root, env, source=None):
        source = SOURCE.read_text() if source is None else source
        start = source.index('install -d -o root -g root -m 0755 /etc/nakpanel\n')
        end = source.index('if [[ ! -f /etc/nakpanel/mysql-agent.cnf ]]', start)
        block = source[start:end]
        # Only the actual setup block runs; package/network/daemon operations
        # outside this block are not invoked.
        for prefix in ('/etc', '/var', '/usr', '/run'):
            block = block.replace(prefix + '/', str(root / prefix[1:]) + '/')
        driver = root / 'installer-block.sh'
        driver.write_text('set -euo pipefail\numask 077\n' + block +
                          '\numask >"$PHASE21_TEST_ROOT/caller-umask"\n')
        return subprocess.run(['bash', str(driver)], env=env, capture_output=True, text=True, timeout=10)

    def assert_ready(self, root, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        owners = json.loads((root / 'owners.json').read_text())
        for name, mode, owner in [('etc/nginx/nakpanel', 0o755, [0, 0]),
                                 ('var/cache/nginx', 0o755, [0, 0]),
                                 ('etc/nginx/nakpanel/protected', 0o710, [0, 33]),
                                 ('etc/nginx/nakpanel/applications', 0o755, [0, 0]),
                                 ('var/cache/nginx/nakpanel', 0o750, [33, 33])]:
            path = root / name
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode, name)
            self.assertEqual(owners.get(str(path), [0, 0]), owner, name)
        self.assertEqual((root / 'caller-umask').read_text().strip(), '0077')
        checks = root / 'reader-checks.jsonl'
        self.assertTrue(checks.exists(), 'installer skipped the nonroot permission readiness boundary')
        observed = [json.loads(line) for line in checks.read_text().splitlines()]
        self.assertEqual(observed[-3:], [[perm, path, True, False] for perm, path in CHECKS])

    def test_missing_shared_ancestors_are_traversable_under_uutils_and_077(self):
        with tempfile.TemporaryDirectory(prefix='nakpanel-phase21-perms-', dir='/tmp') as directory:
            root, env, canaries = self.fixture(directory)
            before = self.snapshot(canaries)
            self.assert_ready(root, self.install(root, env))
            self.assertEqual(self.snapshot(canaries), before)

    def test_restrictive_existing_shared_ancestors_and_reinstall_preserve_private_children(self):
        with tempfile.TemporaryDirectory(prefix='nakpanel-phase21-perms-', dir='/tmp') as directory:
            root, env, canaries = self.fixture(directory, ancestors=0o700)
            before = self.snapshot(canaries)
            for _ in range(2):
                self.assert_ready(root, self.install(root, env))
                self.assertEqual(self.snapshot(canaries), before)

    def test_gnu_creation_and_existing_public_parents_keep_private_modes(self):
        for ancestors in (None, 0o755):
            with self.subTest(ancestors=ancestors), tempfile.TemporaryDirectory(prefix='nakpanel-phase21-perms-', dir='/tmp') as directory:
                root, env, canaries = self.fixture(directory, semantics='gnu', ancestors=ancestors)
                before = self.snapshot(canaries)
                self.assert_ready(root, self.install(root, env))
                self.assertEqual(self.snapshot(canaries), before)

    def test_each_failed_nonroot_permission_check_stops_installer(self):
        for perm, path in CHECKS:
            with self.subTest(permission=perm, path=path), tempfile.TemporaryDirectory(prefix='nakpanel-phase21-perms-', dir='/tmp') as directory:
                root, env, _ = self.fixture(directory, deny=perm + ':' + path)
                result = self.install(root, env)
                self.assertEqual(result.returncode, 37, result.stdout + result.stderr)
                self.assertFalse((root / 'caller-umask').exists(), 'installer continued after failed reader check')


if __name__ == '__main__':
    unittest.main()
