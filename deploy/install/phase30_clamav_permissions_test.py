"""Execute the actual installer scanner boundary under a restrictive caller umask."""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

SOURCE=Path(__file__).resolve().with_name('phase30-install.sh')


class ClamAVPermissionsTests(unittest.TestCase):
    def run_fixture(self,root,*,release='24.04',layout='cvd',existing=False,unsafe=None,renew=False,updater_needs_read=False):
        root=Path(root).resolve();root.chmod(0o755)
        database=root/'var/lib/clamav';database.mkdir(parents=True,exist_ok=True)
        units=root/'etc/systemd/system';units.mkdir(parents=True,exist_ok=True)
        for path in (root/'var',root/'var/lib',database,root/'etc',root/'etc/systemd',units):path.chmod(0o755)
        conf=root/'freshclam.conf';conf.write_bytes(b'private existing configuration\n');conf.chmod(0o600)
        log=root/'freshclam.log';log.write_bytes(b'private existing log\n');log.chmod(0o600)
        dat=database/'freshclam.dat';dat.write_bytes(b'keep updater state');dat.chmod(0o600)
        custom=database/'custom.ndb';custom.write_bytes(b'keep custom database');custom.chmod(0o600)
        if existing:
            for name in ('main','daily','bytecode'):
                path=database/(name+'.'+layout);path.write_bytes(b'existing public signature');path.chmod(0o600)
        outside=root/'outside';outside.write_bytes(b'private outside target');outside.chmod(0o600)
        target=database/('main.'+layout)
        if unsafe=='signature-symlink':
            target.unlink(missing_ok=True);target.symlink_to(outside)
        elif unsafe=='hardlink':
            target.unlink(missing_ok=True);os.link(outside,target)
        elif unsafe=='fifo':
            target.unlink(missing_ok=True);os.mkfifo(target,0o600)
        elif unsafe=='world-writable':
            target.write_bytes(b'untrusted');target.chmod(0o666)
        elif unsafe=='database-symlink':
            replacement=root/'other-database';database.rename(replacement);database.symlink_to(replacement,target_is_directory=True)
        dropin=units/'clamav-freshclam.service.d';dropin.mkdir()
        local=dropin/'local.conf';local_data=b'[Service]\nUMask=0077\n' if unsafe=='unit-umask' else b'[Service]\nRestart=on-failure\n'
        local.write_bytes(local_data);local.chmod(0o600)
        managed=dropin/'nakpanel-signatures.conf'
        if unsafe=='dropin-symlink':managed.symlink_to(outside)
        elif unsafe=='foreign-dropin':managed.write_bytes(b'[Service]\nEnvironment=KEEP_CUSTOM\n');managed.chmod(0o600)
        binary=root/'bin';binary.mkdir()
        scripts={
            'timeout':'#!/bin/sh\nshift\nexec "$@"\n',
            'freshclam':f'''#!{sys.executable}
import os,pathlib,sys
r=pathlib.Path(os.environ['CLAMAV_TEST_ROOT']);d=r/'var/lib/clamav'
(r/'freshclam-called').write_text('actual external boundary')
if os.environ.get('CLAMAV_TEST_NEED_EXISTING_READ')=='1':
 for p in d.iterdir():
  if p.suffix in ('.cvd','.cld') and p.stat().st_mode&4!=4:sys.exit('updater cannot read existing root-owned definitions')
for n in ('main','daily','bytecode'):
 p=d/(n+'.'+os.environ['CLAMAV_TEST_LAYOUT'])
 if p.exists() and os.environ.get('CLAMAV_TEST_RENEW')!='1':continue
 t=p.with_name(p.name+'.next')
 with t.open('wb') as f:f.write(b'fresh public signature')
 t.replace(p)
''',
            'clamscan':f'''#!{sys.executable}
import os,pathlib,stat,sys
r=pathlib.Path(os.environ['CLAMAV_TEST_ROOT']);d=r/'var/lib/clamav'
if '--version' in sys.argv:sys.exit(0)  # old root-only proof misses unreadability
if os.environ.get('CLAMAV_TEST_READER')!='nobody':sys.exit('scan did not use unprivileged identity')
for p in d.iterdir():
 if p.suffix in ('.cvd','.cld') and (not stat.S_ISREG(p.lstat().st_mode) or p.stat().st_mode&4!=4):
  sys.exit('unprivileged scanner cannot read definitions')
(r/'nonroot-scanner-proved').write_text('loaded signatures as nonroot boundary')
''',
            'runuser':'#!/bin/sh\n[ "$1" = -u ] && [ "$2" = nobody ] && [ "$3" = -- ] || exit 91\nshift 3\nexport CLAMAV_TEST_READER=nobody\nexec "$@"\n',
            'systemctl':f'''#!{sys.executable}
import os,pathlib,subprocess,sys
r=pathlib.Path(os.environ['CLAMAV_TEST_ROOT'])
with (r/'systemctl-calls').open('a') as f:f.write(' '.join(sys.argv[1:])+'\\n')
if sys.argv[1]=='show':print('0077' if os.environ.get('CLAMAV_TEST_UNIT_OVERRIDE')=='1' else '0022')
if sys.argv[1]=='enable' and os.environ.get('CLAMAV_TEST_DAEMON_RENEW')=='1':
 p=r/'etc/systemd/system/clamav-freshclam.service.d/nakpanel-signatures.conf'
 os.umask(0o022 if p.exists() and 'UMask=0022' in p.read_text() else 0o077)
 e=dict(os.environ,CLAMAV_TEST_RENEW='1');subprocess.run(['freshclam','--stdout'],env=e,check=True)
''',
            'python3':f'''#!{sys.executable}
import os,pwd,sys,types
lookup=pwd.getpwnam
pwd.getpwnam=lambda name: types.SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid()) if name=='clamav' else lookup(name)
program=sys.stdin.read().replace('ROOT_UID = 0','ROOT_UID = '+('99999999' if os.environ.get('CLAMAV_TEST_WRONG_OWNER')=='1' else 'os.getuid()'))
if os.environ.get('CLAMAV_TEST_WRONG_OWNER')=='1':pwd.getpwnam=lambda name:types.SimpleNamespace(pw_uid=99999998,pw_gid=os.getgid())
sys.argv=sys.argv[1:]
exec(compile(program,'actual-installer-clamav-boundary','exec'))
'''}
        for name,body in scripts.items():
            path=binary/name;path.write_text(body);path.chmod(0o755)
        source=SOURCE.read_text();start=source.index('# Managed releases scan');end=source.index('\nif [[ "${NAKPANEL_PLATFORM_ID}"',start)
        block=source[start:end].replace('/var/lib/clamav',str(database)).replace('/etc/systemd/system',str(units))
        env=dict(os.environ,PATH=str(binary)+os.pathsep+os.environ['PATH'],CLAMAV_TEST_ROOT=str(root),CLAMAV_TEST_LAYOUT=layout,
                 CLAMAV_TEST_DAEMON_RENEW='1' if renew else '0',CLAMAV_TEST_WRONG_OWNER='1' if unsafe=='wrong-owner' else '0',
                 CLAMAV_TEST_NEED_EXISTING_READ='1' if updater_needs_read else '0',
                 CLAMAV_TEST_UNIT_OVERRIDE='1' if unsafe=='unit-umask' else '0',NAKPANEL_OS_VERSION=release)
        result=subprocess.run(['bash','-c','set -euo pipefail; umask 077\n'+block+'\numask >"$CLAMAV_TEST_ROOT/caller-umask"'],env=env,capture_output=True,text=True,timeout=20)
        if result.returncode==0:self.assertEqual((root/'caller-umask').read_text().strip(),'0077')
        for path,data in ((conf,b'private existing configuration\n'),(log,b'private existing log\n'),(dat,b'keep updater state'),(custom,b'keep custom database'),(local,local_data)):
            self.assertEqual(path.read_bytes(),data)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
        self.assertEqual(outside.read_bytes(),b'private outside target');self.assertEqual(stat.S_IMODE(outside.stat().st_mode),0o600)
        return result,database

    def test_fresh_and_existing_noble_resolute_signature_layouts_are_nonroot_readable(self):
        for release in ('24.04','26.04'):
            for layout in ('cvd','cld'):
                for existing in (False,True):
                    with self.subTest(release=release,layout=layout,existing=existing),tempfile.TemporaryDirectory(prefix='nakpanel-clamav-',dir='/tmp') as td:
                        result,database=self.run_fixture(td,release=release,layout=layout,existing=existing)
                        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                        for name in ('main','daily','bytecode'):
                            self.assertEqual(stat.S_IMODE((database/(name+'.'+layout)).stat().st_mode),0o644)
                        self.assertTrue((Path(td)/'nonroot-scanner-proved').exists(),'actual nonroot scanner boundary was not used')

    def test_normal_update_unit_keeps_new_replacement_signatures_public(self):
        with tempfile.TemporaryDirectory(prefix='nakpanel-clamav-',dir='/tmp') as td:
            result,database=self.run_fixture(td,existing=True,renew=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            for path in database.glob('*.cvd'):self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o644)
            self.assertIn('daemon-reload',(Path(td)/'systemctl-calls').read_text())

    def test_trusted_legacy_signatures_are_readable_before_dropping_to_the_updater_owner(self):
        with tempfile.TemporaryDirectory(prefix='nakpanel-clamav-',dir='/tmp') as td:
            result,_=self.run_fixture(td,existing=True,updater_needs_read=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_later_custom_service_umask_override_fails_without_enabling_or_rewriting_it(self):
        with tempfile.TemporaryDirectory(prefix='nakpanel-clamav-',dir='/tmp') as td:
            result,_=self.run_fixture(td,existing=True,unsafe='unit-umask')
            self.assertNotEqual(result.returncode,0)
            self.assertIn('required public signature creation mask',result.stderr)
            self.assertNotIn('enable --now',(Path(td)/'systemctl-calls').read_text())

    def test_untrusted_path_type_owner_links_and_foreign_dropin_fail_closed(self):
        for unsafe in ('signature-symlink','hardlink','fifo','world-writable','database-symlink','wrong-owner','dropin-symlink','foreign-dropin'):
            with self.subTest(unsafe=unsafe),tempfile.TemporaryDirectory(prefix='nakpanel-clamav-',dir='/tmp') as td:
                result,_=self.run_fixture(td,existing=True,unsafe=unsafe)
                self.assertNotEqual(result.returncode,0,'unsafe installer state passed: '+unsafe)
                if unsafe not in ('dropin-symlink','foreign-dropin'):
                    self.assertFalse((Path(td)/'freshclam-called').exists(),'updater ran before validating unsafe database path')

    def test_actual_distinct_unprivileged_reader_where_passwordless_sudo_is_available(self):
        if not shutil.which('sudo') or subprocess.run(['sudo','-n','true'],capture_output=True).returncode:
            self.skipTest('actual distinct UID requires passwordless sudo; mode and external scanner checks still execute')
        with tempfile.TemporaryDirectory(prefix='nakpanel-clamav-',dir='/tmp') as td:
            root=Path(td).resolve();root.chmod(0o755);before_file=root/'before-private.cvd';before_file.write_bytes(b'public signature');before_file.chmod(0o600)
            program='import os,pwd,sys; u=pwd.getpwnam("nobody"); os.setgroups([]); os.setgid(u.pw_gid); os.setuid(u.pw_uid); [open(p,"rb").read(1) for p in sys.argv[1:]]'
            before=subprocess.run(['sudo','-n',sys.executable,'-c',program,str(before_file)],capture_output=True,text=True)
            self.assertNotEqual(before.returncode,0,'the distinct UID unexpectedly read owner-only definitions')
            result,database=self.run_fixture(td,existing=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            files=[str(database/(name+'.cvd')) for name in ('main','daily','bytecode')]
            after=subprocess.run(['sudo','-n',sys.executable,'-c',program,*files],capture_output=True,text=True)
            self.assertEqual(after.returncode,0,after.stdout+after.stderr)


if __name__=='__main__':unittest.main()
