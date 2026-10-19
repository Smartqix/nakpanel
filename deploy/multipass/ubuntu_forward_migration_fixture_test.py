import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import hashlib
import json
import os
import tempfile
import ast
import subprocess
import sys
import struct

path = Path(__file__).with_name('ubuntu-forward-migration-fixture.py')
spec = importlib.util.spec_from_file_location('forward_fixture', path)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
probe_spec = importlib.util.spec_from_file_location('forward_probe', path.with_name('ubuntu-forward-migration-probe.py'))
probe = importlib.util.module_from_spec(probe_spec)
probe_spec.loader.exec_module(probe)

class ForwardFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keydir=tempfile.TemporaryDirectory()
        cls.private=Path(cls.keydir.name)/'private.pem';cls.public=Path(cls.keydir.name)/'public.pem'
        subprocess.run(['openssl','genrsa','-out',str(cls.private),'2048'],check=True,capture_output=True)
        subprocess.run(['openssl','pkey','-in',str(cls.private),'-pubout','-out',str(cls.public)],check=True,capture_output=True)

    @classmethod
    def tearDownClass(cls):cls.keydir.cleanup()

    def signed_bundle(self,directory,development=False):
        root=Path(directory)/'release';root.mkdir()
        elf=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+b'\0'*9,2,183,1,0,64,0,0,64,56,1,0,0,0)+struct.pack('<IIQQQQQQ',1,5,0,0,0,120,120,4096)
        files={'VERSION':b'29.0.0\n','go.mod':b'module example\n','go.sum':b'checksums\n','Makefile':b'build:\n','migrations/00001.sql':b'-- migration\n','deploy/install/install.sh':b'#!/bin/sh\nexit 0\n'}
        files.update({'bin/'+name:elf for name in ('panel','agent','panelctl')})
        for name,data in files.items():
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        manifest=dict(schema_version=1,version='29.0.0',commit='a'*40,go_toolchain='go1.26.9',cgo_enabled=False,os='linux',architecture='arm64',cpu_baseline='v8.0',development=development,files={name:hashlib.sha256(data).hexdigest() for name,data in files.items()})
        (root/'manifest.json').write_text(json.dumps(manifest))
        subprocess.run(['openssl','dgst','-sha256','-sign',str(self.private),'-out',str(root/'manifest.sig'),str(root/'manifest.json')],check=True,capture_output=True)
        return root

    def test_host_staging_authenticates_signature_version_arch_and_development_before_vm_access(self):
        for case in ('tampered','wrong-version','wrong-arch','development','valid'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as directory:
                bundle=self.signed_bundle(directory,case=='development')
                if case=='tampered':(bundle/'bin/panel').write_bytes(b'tampered')
                version='28.0.0' if case=='wrong-version' else '29.0.0'
                architecture='amd64' if case=='wrong-arch' else 'arm64'
                if case=='valid':
                    staged=Path(fixture.stage_target_bundle(bundle,self.public,version,architecture,'0'))
                    try:
                        self.assertEqual(staged.stat().st_mode&0o777,0o700)
                        (bundle/'bin/panel').write_bytes(b'changed after authentication')
                        self.assertNotEqual((staged/'bundle/bin/panel').read_bytes(),b'changed after authentication')
                    finally:fixture.discard_target_bundle(staged)
                else:
                    with self.assertRaisesRegex(ValueError,'bundle verification'):fixture.stage_target_bundle(bundle,self.public,version,architecture,'0')
                if case=='development':
                    staged=fixture.stage_target_bundle(bundle,self.public,version,architecture,'1');fixture.discard_target_bundle(staged)

    def test_private_spec_requires_owned_source_and_real_inputs(self):
        with self.assertRaises(ValueError): fixture.validate_spec({})
        item = fixture.example_spec()
        item['source_vm'] = 'nakpanel-lab'
        with self.assertRaises(ValueError): fixture.validate_spec(item)

    def test_preparation_rejects_unsupported_webmail_before_seed_or_local_state(self):
        with tempfile.TemporaryDirectory() as directory:
            c=fixture.example_spec();c.update(run_token='fixture-test',source_vm='nakpanel-source-fixture-test')
            spec=Path(directory)/'spec.json';fixture.private_write(spec,json.dumps(c))
            output=Path(directory)/'prepared'
            stages=[]
            def check(config,vm,stage):
                stages.append(stage)
                raise RuntimeError('configured non-SQLite webmail')
            with patch.object(fixture,'identity'),patch.object(fixture,'probe',side_effect=check),patch.object(fixture,'run') as execute:
                with self.assertRaisesRegex(RuntimeError,'non-SQLite'): fixture.prepare(spec,output)
                execute.assert_not_called()
            self.assertEqual(stages,['source-preflight'])
            self.assertFalse(output.exists())

    def test_seed_refuses_non_sqlite_before_any_php_or_database_changes(self):
        with patch.object(probe,'roundcube_preflight',side_effect=RuntimeError('configured non-SQLite')),patch.object(probe,'discover') as discover,patch.object(probe,'pg') as pg:
            with self.assertRaisesRegex(RuntimeError,'non-SQLite'):probe.seed({})
            discover.assert_not_called();pg.assert_not_called()

    def test_source_roundcube_preflight_reads_config_without_executing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            config=Path(directory)/'debian-db.php'
            config.write_text("<?php\n$dbtype='mysql';\n$dbpass='secret-canary';\nfile_put_contents('/tmp/unsafe','bad');\n")
            with patch.object(probe,'command') as execute:
                with self.assertRaisesRegex(RuntimeError,'configured non-SQLite') as failure:probe.roundcube_preflight({},Path(directory))
                self.assertNotIn('secret-canary',str(failure.exception));execute.assert_not_called()

    def test_every_durable_contract_must_survive(self):
        original = {'intent': 'a', 'identities': ['1001:1001'], 'files': {'key': 'digest'},
                    'mariadb': {'rows': 'canary', 'collation': 'utf8mb4_unicode_520_ci', 'routine': 'body', 'event': 'DISABLED', 'trigger': 'body'},
                    'grants': ['SELECT', 'EXECUTE'], 'roundcube': 'hash'}
        fixture.compare_snapshots(original, dict(original))
        for field in original:
            changed = dict(original)
            changed[field] = None
            with self.subTest(field=field), self.assertRaises(ValueError): fixture.compare_snapshots(original, changed)

    def test_new_engine_grants_may_add_but_never_remove_source_privileges(self):
        base = {'grants': ['SELECT', 'EXECUTE']}
        fixture.compare_snapshots(base, {'grants': ['SELECT', 'EXECUTE', 'SHOW CREATE ROUTINE']})
        with self.assertRaises(ValueError): fixture.compare_snapshots(base, {'grants': ['SELECT']})

    def test_preflight_refuses_incomplete_contract_before_guest_access(self):
        called = []
        with patch.object(fixture,'run',side_effect=lambda *a, **k: called.append(a)):
            with self.assertRaises(ValueError): fixture.validate_spec({'source_vm': 'nakpanel-bad'})
        self.assertEqual(called, [])

    def prepared(self, directory):
        c = fixture.example_spec()
        c.update(run_token='fixture-test', source_vm='nakpanel-source-fixture-test',
                 baseline={'intent':{'sites':'hash'},'identities':[{'name':'npfixture','uid':1001,'gid':1001,'subuid':'','subgid':''}],'files':{'tenant':'digest'},'mariadb':{'rows':'canary'},'roundcube':'digest','grants': ['SELECT']}, archive_sha256=hashlib.sha256(b'archive').hexdigest())
        c.update(oci_digest='sha256:'+'c'*64,oci_image_id='d'*64,site_id=1, worker_id=2, subscription_id=3, oci_id=4, username='npfixture', domain='phase30-managed.test', marker='forward-canary-fixture-test', database='np_forward_fixture', database_user='np_forward_fixture', image_ref='docker.io/library/nginx@sha256:'+'a'*64, guest_ca='/etc/nakpanel/forward-fixture-ca.crt', volume_file='/var/lib/nakpanel/containers/sub-3/apps/4/volumes/forward/forward-canary',tenant_file='/home/npfixture/forward-canary.txt',worker_secret_sha256='b'*64,valkey_image='',ftp_username='forwardfixture',mailbox='forwardfixture@phase30-managed.test',images=[{'subscription_id':3,'username':'npfixture','image_ref':'docker.io/library/nginx@sha256:'+'a'*64}])
        for key, name, data in [('archive_file','source.nkbk',b'archive'), ('backup_key_file','archive.key',b'key'), ('ssh_identity_file','sftp-key',b'private'), ('ca_file','ca.crt',b'public')]:
            p = Path(directory) / name
            p.write_bytes(data)
            p.chmod(0o600)
            c[key] = str(p)
        return c

    def test_prepared_contract_binds_archive_and_private_inputs_before_vm_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            c = self.prepared(directory)
            with patch.object(fixture, 'run', side_effect=AssertionError('VM access')):
                fixture.validate_prepared(c)
                Path(c['archive_file']).write_bytes(b'different archive')
                with self.assertRaises(ValueError): fixture.validate_prepared(c)

    def test_every_advertised_assertion_dispatches_real_probe_and_propagates_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            c = self.prepared(directory)
            path = Path(directory) / 'fixture.json'
            fixture.private_write(path, json.dumps(c))
            with patch.dict(os.environ, {'NAKPANEL_FORWARD_FIXTURE_JSON': str(path)}), patch.object(fixture, 'identity'), patch.object(fixture, 'probe', side_effect=RuntimeError('actual assertion failed')):
                for stage in ['assert-source-readonly','assert-baseline','assert-migration-data','assert-services','assert-trusted-tls','assert-no-source-writes']:
                    with self.subTest(stage=stage), self.assertRaisesRegex(RuntimeError, 'actual assertion failed'):
                        fixture.driver(stage,'nakpanel-target',c['source_vm'],c['run_token'],directory,directory)

    def test_reboot_stage_requires_new_actual_boot_id(self):
        with tempfile.TemporaryDirectory() as directory:
            c = self.prepared(directory)
            fixture.private_write(Path(directory) / 'fixture.json', json.dumps(c))
            fixture.private_write(Path(directory) / 'initial-target-boot-id', 'same-boot')
            with patch.dict(os.environ, {'NAKPANEL_FORWARD_FIXTURE_JSON': str(Path(directory) / 'fixture.json')}), patch.object(fixture, 'identity'), patch.object(fixture, 'probe', return_value={'boot_id':'same-boot'}), patch.object(fixture, 'assert_ssh') as ssh:
                with self.assertRaisesRegex(ValueError, 'did not actually reboot'):
                    fixture.driver('assert-reboot','nakpanel-target',c['source_vm'],c['run_token'],directory,directory)
                ssh.assert_not_called()

    def test_readonly_source_rejects_active_worker_or_timer(self):
        from types import SimpleNamespace
        def status(args):
            return SimpleNamespace(returncode=0 if 'nakpanel-php-worker@7.service' in args else 3)
        with patch.object(probe, 'pg', return_value='on'), patch.object(probe, 'maria', return_value='1'), patch.object(probe, 'command', return_value='nakpanel-php-worker@7.service loaded active running worker'), patch.object(probe.subprocess, 'run', side_effect=status):
            with self.assertRaisesRegex(RuntimeError, 'writer'):
                probe.frozen()

    def test_complete_source_image_inventory_rejects_mutable_reference(self):
        rows = [{'subscription_id':2,'username':'npfixture','image_ref':'docker.io/library/nginx:latest'}]
        with patch.object(probe, 'pg', return_value=json.dumps(rows)):
            with self.assertRaisesRegex(RuntimeError, 'immutable'):
                probe.image_inventory()

    def test_worker_secret_digest_requires_actual_nonempty_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = Path(directory) / 'environ'
            environment.write_bytes(b'OTHER=value\x00PHASE30_SECRET=private-canary\x00')
            with patch.object(probe, 'Path', return_value=environment):
                self.assertEqual(probe.worker_secret_digest(42), hashlib.sha256(b'private-canary').hexdigest())
                environment.write_bytes(b'OTHER=value\x00')
                with self.assertRaisesRegex(RuntimeError, 'secret environment'):
                    probe.worker_secret_digest(42)

    def test_embedded_guest_programs_compile_before_any_vm_use(self):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node,ast.Constant) and isinstance(node.value,str) and node.value.lstrip().startswith('import '):
                compile(node.value,str(path),'exec')

    def test_prepared_source_requires_complete_durable_and_runtime_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            c = self.prepared(directory)
            for field in ['images','worker_secret_sha256','baseline','domain','oci_id']:
                changed = dict(c)
                changed.pop(field)
                with self.subTest(field=field), self.assertRaises(ValueError): fixture.validate_prepared(changed)

    def test_target_system_identities_preserve_exact_ids_and_subordinate_rows(self):
        from types import SimpleNamespace
        users=[{'name':'npfirst','uid':997,'gid':982,'subuid':'npfirst:165339392:65536','subgid':'npfirst:165339392:65536'},
               {'name':'npsecond','uid':982,'gid':981,'subuid':'','subgid':''}]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'etc').mkdir()
            for name in ('subuid','subgid'):
                (root/'etc'/name).write_text('other:200000:65536\nnpfirst:400000:65536\nnpsecond:500000:65536\n')
            accounts={};groups={};calls=[]
            def execute(args,*a,**kw):
                calls.append(args)
                if args[0]=='groupadd': groups[args[-1]]=int(args[args.index('--gid')+1])
                if args[0]=='useradd':
                    accounts[args[-1]]=SimpleNamespace(pw_name=args[-1],pw_uid=int(args[args.index('--uid')+1]),pw_gid=int(args[args.index('--gid')+1]))
                return ''
            with patch.object(probe,'command',side_effect=execute),patch.object(probe.pwd,'getpwall',return_value=[]),patch.object(probe.grp,'getgrall',return_value=[]),patch.object(probe.pwd,'getpwnam',side_effect=lambda n:accounts[n]):
                probe.install_target_identities({'baseline':{'identities':users}},root)
            self.assertEqual([(accounts[u['name']].pw_uid,accounts[u['name']].pw_gid) for u in users],[(997,982),(982,981)])
            for name in ('subuid','subgid'):
                self.assertEqual((root/'etc'/name).read_text(),'other:200000:65536\nnpfirst:165339392:65536\n')
            for args in calls:
                if args[0]=='useradd':
                    self.assertIn('--system',args)
                    self.assertIn('--no-user-group',args)
                    self.assertEqual(args[args.index('--shell')+1],'/usr/sbin/nologin')

    def test_target_identity_collisions_and_root_reject_before_commands(self):
        from types import SimpleNamespace
        user={'name':'npfirst','uid':997,'gid':982,'subuid':'npfirst:200000:65536','subgid':'npfirst:200000:65536'}
        cases=[([SimpleNamespace(pw_name='other',pw_uid=997,pw_gid=999)],[], 'other:400000:65536\n'),
               ([],[SimpleNamespace(gr_name='other',gr_gid=982)],'other:400000:65536\n'),
               ([],[],'other:200001:65536\n')]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'etc').mkdir()
            for passwd,groups,rows in cases:
                for name in ('subuid','subgid'): (root/'etc'/name).write_text(rows)
                with patch.object(probe,'command') as execute,patch.object(probe.pwd,'getpwall',return_value=passwd),patch.object(probe.grp,'getgrall',return_value=groups):
                    with self.assertRaisesRegex(ValueError,'collision|overlap'):
                        probe.install_target_identities({'baseline':{'identities':[user]}},root)
                    execute.assert_not_called()
            rootuser=dict(user,uid=0)
            with patch.object(probe,'command') as execute:
                with self.assertRaisesRegex(ValueError,'nonroot'):
                    probe.install_target_identities({'baseline':{'identities':[rootuser]}},root)
                execute.assert_not_called()

    def test_native_install_uses_signed_bundle_and_matching_installer_with_private_admin(self):
        program=fixture.target_install_program()
        for fail,allow in ((False,False),(False,True),(True,False),(True,True)):
            with self.subTest(fail=fail,allow_development=allow),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);repo=root/'bundle';repo.mkdir();installer=repo/'deploy/install/install.sh';installer.parent.mkdir(parents=True)
                evidence=root/'observed.json'
                installer.write_text('#!/bin/sh\nexec "'+sys.executable+'" -c '+"'"+"import json,os,sys;from pathlib import Path;a=sys.argv[1:];actual=os.environ.get(\"NAKPANEL_RELEASE_ALLOW_DEVELOPMENT\",\"0\");expected=os.environ[\"INSTALL_EXPECT_ALLOW\"];assert actual==expected;assert (\"--allow-development-bundle\" in a)==(actual==\"1\");assert (Path(a[a.index(\"--bundle\")+1])/\"host-verified\").exists();p=Path(a[a.index(\"--admin-password-file\")+1]);Path(os.environ[\"INSTALL_OBSERVED\"]).write_text(json.dumps({\"args\":a,\"password\":p.read_text(),\"mode\":p.stat().st_mode&0o777,\"path\":str(p)}));sys.exit(int(os.environ[\"INSTALL_FAIL\"]))"+"'"+' "$@"\n')
                import tarfile
                archive=root/'bundle.tar'
                with tarfile.open(archive,'w') as stream:stream.add(repo,arcname='.')
                # The guest preflight verifier must run before even the signed installer.
                verifier="import sys\nfrom pathlib import Path\na=sys.argv[1:];Path(a[a.index('--bundle')+1]+'/host-verified').write_text('verified')\n"
                c={'admin_email':'operator@example.test','admin_password':'private-admin-canary','target_profile':'ubuntu-26.04-native','architecture':'arm64'}
                payload={'config':c,'archive':str(archive),'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'public_key':'test-public-key','verifier_program':verifier,'version':'29.0.0','allow_development':allow}
                result=subprocess.run([sys.executable,'-c',program],input=json.dumps(payload),text=True,capture_output=True,env=dict(os.environ,TMPDIR=directory,INSTALL_OBSERVED=str(evidence),INSTALL_FAIL='9' if fail else '0',INSTALL_EXPECT_ALLOW='1' if allow else '0',NAKPANEL_RELEASE_ALLOW_DEVELOPMENT='0' if allow else '1'))
                self.assertEqual(result.returncode!=0,fail,result.stderr)
                observed=json.loads(evidence.read_text())
                self.assertEqual(observed['password'],c['admin_password']);self.assertEqual(observed['mode'],0o600)
                self.assertFalse(Path(observed['path']).exists());self.assertNotIn(c['admin_password'],observed['args'])
                self.assertEqual(observed['args'][observed['args'].index('--admin-email')+1],c['admin_email'])
                self.assertIn('--bundle',observed['args']);self.assertIn('--release-public-key',observed['args']);self.assertEqual('--allow-development-bundle' in observed['args'],allow)
                self.assertNotIn('--bin-dir',observed['args'])

    def test_guest_refuses_correctly_transferred_but_unsigned_payload_before_installer(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);bundle=self.signed_bundle(directory)
            (bundle/'bin/panel').write_bytes(b'tampered before transfer')
            import tarfile
            archive=root/'bundle.tar'
            with tarfile.open(archive,'w') as stream:
                for path in sorted(bundle.rglob('*')):
                    if path.is_file():stream.add(path,arcname=path.relative_to(bundle).as_posix(),recursive=False)
            payload={'config':{'architecture':'arm64'},'archive':str(archive),'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'public_key':self.public.read_text(),'verifier_program':(fixture.HERE.parent/'release/verify.py').read_text(),'version':'29.0.0','allow_development':False}
            result=subprocess.run([sys.executable,'-c',fixture.target_install_program()],input=json.dumps(payload),text=True,capture_output=True,env=dict(os.environ,TMPDIR=directory))
            self.assertNotEqual(result.returncode,0)
            self.assertIn('SHA256 mismatch',result.stderr)
            self.assertFalse(list(root.glob('nakpanel-forward-install-*')))

    def test_native_install_refuses_changed_archive_before_installer_or_password_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);archive=root/'bad.tar';archive.write_bytes(b'changed')
            payload={'config':{'admin_password':'secret'},'archive':str(archive),'archive_sha256':'0'*64}
            result=subprocess.run([sys.executable,'-c',fixture.target_install_program()],input=json.dumps(payload),text=True,capture_output=True,env=dict(os.environ,TMPDIR=directory))
            self.assertNotEqual(result.returncode,0);self.assertIn('archive digest mismatch',result.stderr)
            self.assertEqual(sorted(p.name for p in root.iterdir()),['bad.tar'])

if __name__ == '__main__': unittest.main()
