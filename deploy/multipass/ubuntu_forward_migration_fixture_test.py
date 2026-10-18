import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import hashlib
import json
import os
import tempfile
import ast

path = Path(__file__).with_name('ubuntu-forward-migration-fixture.py')
spec = importlib.util.spec_from_file_location('forward_fixture', path)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
probe_spec = importlib.util.spec_from_file_location('forward_probe', path.with_name('ubuntu-forward-migration-probe.py'))
probe = importlib.util.module_from_spec(probe_spec)
probe_spec.loader.exec_module(probe)

class ForwardFixtureTests(unittest.TestCase):
    def test_private_spec_requires_owned_source_and_real_inputs(self):
        with self.assertRaises(ValueError): fixture.validate_spec({})
        item = fixture.example_spec()
        item['source_vm'] = 'nakpanel-lab'
        with self.assertRaises(ValueError): fixture.validate_spec(item)

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

if __name__ == '__main__': unittest.main()
