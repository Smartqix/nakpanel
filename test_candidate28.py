"""Direct candidate28 source qualification; every product boundary is fake."""
import ast
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import test_rootless_pull as R
APP=R.APP
COMMIT='6378b0ae9d15f17481b080926af7fb0bf0761724'
TREE='e0971772916ef3aee3ee7cb23b65645a2b2272fc'
PROBE_SHA=R.SOURCE_PROBE_SHA
TEST_SHA='9c0e75dda3e8e03990ed36eaaf889da40a8a2f9d181c440c97f30dd86ab0ac16'


class Candidate28Tests(unittest.TestCase):
    def setUp(self):self.m=R.module()

    def test_direct_probe_and_reviewed_tests_come_only_from_current_application(self):
        loader=getattr(self.m,'in_tree_probe',None)
        self.assertTrue(callable(loader),'direct current-source probe loader is missing')
        with patch.object(self.m,'qualifier_blob',wraps=self.m.qualifier_blob) as reads:
            source=loader(APP)
        self.assertEqual(hashlib.sha256(source.encode()).hexdigest(),PROBE_SHA)
        self.assertEqual([str(call.args[0]) for call in reads.call_args_list],[str(APP/'deploy/multipass/ubuntu-forward-migration-fixture.py'),str(APP/'deploy/multipass/ubuntu-forward-migration-probe.py'),str(APP/'deploy/multipass/ubuntu_forward_migration_fixture_test.py')])
        self.assertFalse(hasattr(self.m,'qualifier_artifacts'));self.assertFalse(hasattr(self.m,'QUALIFIER_FILES'));self.assertFalse(hasattr(self.m,'QUALIFIER_IDENTITY'));self.assertFalse(hasattr(self.m,'QUALIFIER_GIT_BLOBS'))

    def test_candidate28_source_tree_and_exact175_helper_scope(self):
        data=json.loads((HERE/'SOURCE-INPUTS.json').read_text());helpers=data['app_helpers']
        self.assertEqual((self.m.COMMIT,self.m.TREE),(COMMIT,TREE));self.assertEqual(len(helpers),175)
        self.assertEqual(self.m.digest(self.m.canonical(helpers)),self.m.APP_HELPERS_SHA)
        for name,digest in helpers.items():self.assertEqual(self.m.sha(APP/name),digest)
        self.assertEqual(helpers['deploy/multipass/ubuntu-forward-migration-probe.py'],PROBE_SHA)
        self.assertEqual(helpers['deploy/multipass/ubuntu_forward_migration_fixture_test.py'],TEST_SHA)

    def test_pending_tuple_refuses_before_external_and_before_credential_reads(self):
        for value in (json.loads((HERE/'admission.pending.json').read_text()),):
            with tempfile.TemporaryDirectory() as td:
                p=Path(td)/'a.json';p.write_text(json.dumps(value));p.chmod(0o600)
                with patch.object(subprocess,'run',side_effect=AssertionError('no external operation')),patch.object(subprocess,'Popen',side_effect=AssertionError('no external operation')),patch.dict(os.environ,{},clear=True):
                    with self.assertRaises(self.m.Refusal) as error:self.m.read_admission(p,self.m.sha(p))
                self.assertIn('PENDING',str(error.exception))

    def test_workflow_has_current_source_and_no_separate_qualifier_materialization(self):
        workflow=json.loads((HERE/'workflow.yml').read_text());steps=workflow['jobs']['forward']['steps']
        refs=[row['with']['ref'] for row in steps if row.get('uses','').startswith('actions/checkout@')]
        self.assertEqual(refs,['${{ env.CONTROLLER_SHA }}',COMMIT])
        env=workflow['jobs']['forward']['env'];self.assertEqual(env['CONTROLLER_SHA'],'PENDING');self.assertEqual(env['ROOT_ADMISSION_SHA256'],'PENDING')
        self.assertEqual(json.loads(env['ROOT_ADMISSION_JSON'])['state'],'PENDING');self.assertNotIn('qualifier',json.loads(env['ROOT_ADMISSION_JSON']))
        self.assertEqual(workflow['permissions'],{'contents':'read','actions':'read'});self.assertFalse(workflow['concurrency']['cancel-in-progress'])
        self.assertEqual(workflow['jobs']['forward']['timeout-minutes'],360)

    def isolated_app(self,root):
        directory=root/'deploy/multipass';directory.mkdir(parents=True)
        for name in ('ubuntu-forward-migration-fixture.py','ubuntu-forward-migration-probe.py','ubuntu_forward_migration_fixture_test.py'):
            shutil.copyfile(APP/'deploy/multipass'/name,directory/name)
        return directory

    def test_wrong_current_source_test_blob_and_alias_refuse_without_a_command(self):
        for name in ('ubuntu-forward-migration-fixture.py','ubuntu-forward-migration-probe.py','ubuntu_forward_migration_fixture_test.py'):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as td:
                root=Path(td);directory=self.isolated_app(root);p=directory/name;p.write_bytes(p.read_bytes()+b'\n')
                with patch.object(subprocess,'run',side_effect=AssertionError('no command')):
                    with self.assertRaises((self.m.Refusal,OSError)):self.m.in_tree_probe(root)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);directory=self.isolated_app(root);p=directory/'ubuntu-forward-migration-probe.py';backup=directory/'probe.backup';p.rename(backup);p.symlink_to(backup)
            with self.assertRaises((self.m.Refusal,OSError)):self.m.in_tree_probe(root)

    def test_budget_custody_and_canonical_action_constants_preserved(self):
        old=R.module(original=True)
        for name in ('CAPS','TOTAL_SECONDS','IMAGES','BOUNDARIES','PREDICATES'):
            self.assertEqual(getattr(self.m,name),getattr(old,name))
        self.assertEqual(self.m.QUALIFIER_ACTIONS,dict(old.QUALIFIER_ACTIONS,live=('live',4),tls=('tls',5)))
        before=ast.parse((HERE.parent/'forward-hosted-candidate26-v7/forward_hosted.py').read_text());after=ast.parse((HERE/'forward_hosted.py').read_text())
        for name in ('Runner','Budget','owned_action','public_bytes','verify_positive','check_paths'):
            a=next((n for n in before.body if getattr(n,'name',None)==name),None);b=next((n for n in after.body if getattr(n,'name',None)==name),None)
            self.assertEqual(ast.dump(a,include_attributes=False) if a else None,ast.dump(b,include_attributes=False) if b else None)


    def admission_fixture(self):
        reviews={key:'1'*64 for key in ('native24','native26','required_ci','payload')}
        payload={'archive':'candidate/nakpanel-29.0.0-linux-amd64.tar.gz','archive_size':80,'archive_sha256':'2'*64,'manifest_sha256':'3'*64,'public_key_sha256':'4'*64,'binaries':{key:'5'*64 for key in ('panel','agent','panelctl')}}
        value={'schema':'nakpanel-hosted-forward-admission-v1','state':'AUTHORIZED','source_commit':COMMIT,'source_tree':TREE,'controller_commit':'a'*40,'valid_from':'2026-10-20T00:00:00Z','expires_at':'2026-10-20T02:00:00Z','nonce':'b'*32,'repository':'Smartqix/nakpanel','baseline_reviews':reviews,'artifact':{'id':123,'run_id':456,'name':'offline-fixture','size':100,'sha256':'6'*64,'expires_at':'2026-10-21T00:00:00Z'},'payload':payload,'oci_image_ref':'docker.io/library/nginx@sha256:'+'5'*64,'authority':{'scope':'fresh-synthetic-native-forward-only','maximum_guests':2,'cpus':2,'memory':'5G','disk':'32G','production':False},'controller_files':{'forward_hosted.py':'7'*64,self.m.QUALIFIER_PROBE_BLOB:self.m.QUALIFIER_PROBE_SHA},'app_helpers':json.loads((HERE/'SOURCE-INPUTS.json').read_text())['app_helpers']}
        return value,reviews,{key:payload[key] for key in ('manifest_sha256','public_key_sha256','binaries')}

    def checked_fixture_admission(self,value,reviews,payload):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'offline-admission.json';path.write_text(json.dumps(value));path.chmod(0o600)
            with patch.object(self.m,'ROOT_BASELINES',reviews),patch.object(self.m,'ACCEPTED_PAYLOAD',payload),patch.object(subprocess,'Popen',side_effect=AssertionError('no external action')):
                return self.m.read_admission(path,self.m.sha(path),now=datetime(2026,10,20,1,tzinfo=timezone.utc))

    def test_existing_complete_admission_guards_accept_only_bound_current_fixture(self):
        value,reviews,payload=self.admission_fixture()
        self.assertEqual(self.checked_fixture_admission(value,reviews,payload),value)
        self.assertNotIn('qualifier',value)
        for edit in (lambda a:a.update(source_commit='1627bba3c681a884255eb91452dbba74a43ebbdc'),lambda a:a.update(source_tree='fc003d27bc7e0fc13d095a4ebc464b17471dc26f'),lambda a:a.update(qualifier={}),lambda a:a['app_helpers'].update({'deploy/multipass/ubuntu-forward-migration-probe.py':'0'*64}),lambda a:a['app_helpers'].pop('deploy/multipass/ubuntu_forward_migration_fixture_test.py'),lambda a:a['authority'].update(maximum_guests=3),lambda a:a['authority'].update(production=True),lambda a:a['payload']['binaries'].update(panel='0'*64),lambda a:a['baseline_reviews'].update(native24='0'*64),lambda a:a['artifact'].update(id=True),lambda a:a.update(expires_at='2026-10-20T00:30:00Z')):
            modified=copy.deepcopy(value);edit(modified)
            with self.subTest(keys=sorted(modified)),self.assertRaises(self.m.Refusal):self.checked_fixture_admission(modified,reviews,payload)


    def test_direct_observation_keeps_exact_program_action_vm_private_and_kwargs_binding(self):
        helper=R.ComponentTests(methodName='runTest');helper.setUp();config=helper.config
        source=(APP/'deploy/multipass/ubuntu-forward-migration-probe.py').read_text()
        argv=['multipass','exec',config['source_vm'],'--','sudo','python3','-c',source]
        kw={'input':json.dumps({'action':'source-preflight','config':config}),'text':True,'capture_output':True,'env':None,'timeout':3600}
        self.assertEqual(self.m.qualifier_invocation((argv,),kw,source,config['source_vm'],config['run_token'])['action'],'source-preflight')
        cases=[]
        for index,value in ((2,'foreign-vm'),(7,source+'\n')):
            changed=list(argv);changed[index]=value;cases.append((changed,kw))
        for key,value in (('timeout',600),('env',{}),('input','{}'),('text',False)):
            changed=dict(kw);changed[key]=value;cases.append((argv,changed))
        for request in ({'action':'snapshot','config':config},{'action':'source-preflight','config':dict(config,source_vm='foreign-vm')},{'action':'source-preflight','config':dict(config,run_token='foreign-token')},{'action':'source-preflight','config':config,'raw':'PRIVATE'}):
            cases.append((argv,dict(kw,input=json.dumps(request))))
        for args,kwargs in cases:self.assertIsNone(self.m.qualifier_invocation((args,),kwargs,source,config['source_vm'],config['run_token']))

    def test_actual_prepare_authenticates_source_and_uses_qualified_blob_for_both_actions(self):
        import sqlite3
        from pathlib import PurePosixPath
        helper=R.ComponentTests(methodName='runTest');helper.setUp();helper.m=self.m
        parsed=ast.parse((APP/'deploy/multipass/ubuntu_forward_migration_fixture_test.py').read_text())
        cls=next(n for n in parsed.body if isinstance(n,ast.ClassDef) and n.name=='RoundcubePreflightTests')
        wrapper=ast.literal_eval(next(n.value for n in cls.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='DEBIAN_WRAPPER' for t in n.targets)))
        files={'debian-db-roundcube.php':wrapper,'debian-db.php':"<?php\n$dbtype='sqlite3';\n$basepath='/var/lib/roundcube';\n$dbname='roundcube.sqlite';\n"}
        sql_checks=[]
        class MockPath(PurePosixPath):
            def exists(self):return self.name in files
            def read_text(self):return files[self.name]
            def is_file(self):return str(self)=='/var/lib/roundcube/roundcube.sqlite'
            def is_symlink(self):return False
        class Connection:
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def execute(self,query):
                self_outer.assertEqual(query,'PRAGMA quick_check');sql_checks.append(query);return self
            def fetchall(self):return [('ok',)]
        self_outer=self
        def canonical_roundcube(namespace):
            namespace['Path']=MockPath;namespace['roundcube_preflight']=namespace['_offline_original_roundcube'];namespace['roundcube_preflight'].__defaults__=(MockPath('/etc/roundcube'),)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);spec=root/'spec.json';out=root/'prepared';companion=root/'companion.json';ns={'__name__':'offline_fixture_declarations','__file__':str(APP/'deploy/multipass/ubuntu-forward-migration-fixture.py')}
            exec(compile((APP/'deploy/multipass/ubuntu-forward-migration-fixture.py').read_bytes(),ns['__file__'],'exec'),ns)
            config=ns['example_spec']();config.update(helper.config,architecture='amd64',version=1,ftp_password=R.PRIVATE,mailbox_password=R.PRIVATE)
            spec.write_text(json.dumps(config));spec.chmod(0o600);calls=[];guest_rows=[];objects=[]
            def transport(args,**kwargs):
                calls.append((list(args),dict(kwargs)))
                if args[0]=='bash':result=subprocess.CompletedProcess(args,0,'','')
                elif args[0]=='ssh-keygen':Path(args[-1]+'.pub').write_text('ssh-ed25519 OFFLINE');result=subprocess.CompletedProcess(args,0,'','')
                else:
                    self.assertEqual(args[:7],['multipass','exec',config['source_vm'],'--','sudo','python3','-c'])
                    request=json.loads(kwargs['input']);self.assertIn(request['action'],('source-preflight','seed'))
                    row=helper.guest(config=request['config'],action=request['action'],program_override=args[-1],inject=canonical_roundcube);guest_rows.append(row)
                    result=subprocess.CompletedProcess(args,row.rc,row.out,row.err)
                objects.append((result,copy.deepcopy(vars(result))));return result
            stdout,stderr=io.StringIO(),io.StringIO();code=0
            with patch.object(sqlite3,'connect',return_value=Connection()) as connect,patch.object(subprocess,'run',side_effect=transport),patch.dict(os.environ,{},clear=True),contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
                try:self.m.observed_qualifier_prepare(str(APP/'deploy/multipass/ubuntu-forward-migration-fixture.py'),str(spec),str(out),str(companion),R.NONCE,'224',R.KEY,str(HERE),config['source_vm'],config['run_token'])
                except SystemExit as error:code=error.code
            self.assertEqual(connect.call_args_list,[unittest.mock.call('file:///var/lib/roundcube/roundcube.sqlite?mode=ro',uri=True)]*2);self.assertEqual(sql_checks,['PRAGMA quick_check']*2)
            self.assertEqual(code,1);self.assertEqual(stdout.getvalue(),'');self.assertEqual(stderr.getvalue(),'forward fixture failed: fixture command failed: multipass\n')
            self.assertEqual([a[0] for a,k in calls],['bash','multipass','ssh-keygen','multipass'])
            self.assertEqual([row.observation['action'] for row in guest_rows],['UNKNOWN','seed'])
            for a,k in calls:
                if a[0]=='multipass':
                    self.assertIn("'probe_sha256': '"+self.m.QUALIFIER_PROBE_SHA,a[-1]);self.assertEqual(k['timeout'],3600);self.assertIsNone(k['env'])
            record=self.m.qualifier_companion(companion,R.NONCE,224,R.KEY,config['source_vm'],config['run_token'])
            self.assertEqual(record['chain'],R.CHAIN);self.assertEqual(record['rootless_pull'],R.diagnostic());self.assertEqual(record['probe_sha256'],R.PROBE_SHA)
            raw=json.loads(companion.read_text());self.assertEqual(raw['schema'],'nakpanel-forward-probe-companion-v1');self.assertEqual(set(raw),{'schema','helper_sha256','probe_sha256','matches','guest_returncode','marker'})
            self.assertNotIn(R.PRIVATE,companion.read_text());self.assertNotIn('original_probe_sha256',companion.read_text())
            for result,original in objects:self.assertEqual(vars(result),original)


if __name__=='__main__':
    suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(Candidate28Tests),unittest.defaultTestLoader.loadTestsFromTestCase(R.ComponentTests)])
    # Execute the nine reviewed 9c0 regressions against its actual imported in-tree1fa probe.
    path=APP/'deploy/multipass/ubuntu_forward_migration_fixture_test.py';spec=importlib.util.spec_from_file_location('actual_candidate28_fixture_tests',path);tests=importlib.util.module_from_spec(spec);spec.loader.exec_module(tests)
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(tests.RoundcubePreflightTests))
    result=unittest.TextTestRunner(verbosity=1).run(suite);raise SystemExit(0 if result.wasSuccessful() else 1)
