"""Offline actual-probe/wrapper tests; no controller admission or product commands."""
import ast
import builtins
import contextlib
import copy
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
APP=Path('/Users/rickynkansah/.codex/worktrees/ubuntu-26-php-maintenance/nakpanel')
INPUTS = APP/'deploy/multipass'
SOURCE_PROBE_SHA = '1fa03999f12fc7a3f0bc4bd07ee0afc04d5371c53824538e9496bf31fb6b68f8'
PROBE_SHA = '8f6352a46ce53750cefb4233542fc72f74a92252c6272cd8bdbc675e314706cd'
CONTROLLER_SHA = '682f3351e38c22a0038cdaa03f157e225ee9028dd9b721464187805ef3fcf065'
CHAIN = [{'function': n, 'line': l} for n,l in [('seed',705),('create_fixture_container',569),('rootless',115),('command',31)]]
LABELS = ('STATE_PARENT','CONTAINER_PARENT','SUBSCRIPTION_PARENT','RUNTIME_PARENT')
PATHS = ('/var/lib/nakpanel','/var/lib/nakpanel/containers','/var/lib/nakpanel/containers/sub-3','/run/nakpanel-containers')
NONCE='c7'*16
KEY='e9'*32
PRIVATE='PRIVATE_SENTINEL'
PULL_STDERR='Error: fixed public nginx pull failed\n'
PULL_CWD='/home/ubuntu'


def module(original=False):
    path=HERE.parent/'forward-hosted-candidate26-v7/forward_hosted.py' if original else HERE/'forward_hosted.py'
    if not path.exists():path=HERE.parent/'forward-hosted-candidate26-v7/forward_hosted.py'
    source=path.read_text()
    if original and hashlib.sha256(source.encode()).hexdigest()!=CONTROLLER_SHA:raise AssertionError('original controller input changed')
    m=types.ModuleType('offline_marker_component');m.__file__=str(path);sys.modules[m.__name__]=m
    exec(compile(source,str(path),'exec'),m.__dict__)
    return m


def fact(kind='DIRECTORY',mode=0o755,owner=True,uid=0,gid=0):
    if kind!='DIRECTORY':uid=gid='UNKNOWN'
    return {'kind':kind,'mode':mode,'owner_is_root':owner,'uid':uid,'gid':gid}


def diagnostic(rc=19,cwd=False):
    return {'site':'ROOTLESS_PULL','returncode':rc,'cwd_is_root':cwd,'cwd':PULL_CWD,'execution_cwd':'/','stderr':{'text':PULL_STDERR,'truncated':False},'parents':{k:fact() for k in LABELS}}


class ComponentTests(unittest.TestCase):
    def setUp(self):
        self.m=module()
        self.original_source=(INPUTS/'ubuntu-forward-migration-probe.py').read_text()
        self.assertEqual(hashlib.sha256(self.original_source.encode()).hexdigest(),SOURCE_PROBE_SHA)
        self.source=(HERE/'ubuntu-forward-migration-probe.py').read_text()
        self.assertEqual(hashlib.sha256(self.source.encode()).hexdigest(),PROBE_SHA)
        self.config={'source_vm':'nakpanel-offline','run_token':'offline-test-token','subscription_id':3,'username':PRIVATE,'site_id':1,'worker_id':2,'worker_php_version':'8.5','domain':'offline.test','target_profile':'ubuntu-26.04-native','normalize_php85':True,'oci_image_ref':'docker.io/library/nginx@sha256:'+'5'*64,'database_password':PRIVATE,'marker':PRIVATE,'application_secret':PRIVATE}

    def guest(self,wrapped=True,returncode=19,config=None,action='seed',stats=None,cwd=PULL_CWD,inject=None,trace=False,process_transform=None,program_override=None):
        c=copy.deepcopy(self.config if config is None else config)
        binding=self.m.qualifier_binding(NONCE,224,action,self.m.QUALIFIER_ACTIONS[action][1],c)
        program=self.m.qualifier_guest_program(self.source,binding,KEY) if wrapped else self.source
        if program_override is not None:program=program_override
        calls=[];posts=[];objects=[];exceptions=[];namespaces=[];out=io.StringIO();err=io.StringIO()
        stats={} if stats is None else stats
        def lstat(path):
            value=stats.get(str(path),types.SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0,st_gid=0))
            if isinstance(value,BaseException):raise value
            return value
        def boundary(args,**kwargs):
            calls.append((copy.deepcopy(args),copy.deepcopy(kwargs)))
            if args[0]=='install':result=subprocess.CompletedProcess(args,0,'','')
            else:
                self.assertEqual(args[0:2],['runuser','-u']);self.assertEqual(args[-3:-1],['podman','pull'])
                result=subprocess.CompletedProcess(args,returncode,PRIVATE,PULL_STDERR)
            if process_transform is not None and args[0]!='install':result=process_transform(result,namespaces[-1])
            objects.append((result,copy.deepcopy(vars(result))))
            return result
        class AfterPull(Exception):pass
        def post(route,data):
            posts.append((route,copy.deepcopy(data)))
            if route.endswith('/applications'):raise AfterPull('offline stop after successful pull')
        real_exec=builtins.exec
        def execute(code,namespace=None,*args,**kwargs):
            value=real_exec(code,namespace,*args,**kwargs)
            if type(namespace) is dict and namespace.get('__name__') in ('nakpanel_qualifier_probe','offline_original_probe') and 'seed' in namespace and not namespace.get('_offline_configured'):
                namespace['_offline_configured']=True
                namespaces.append(namespace)
                namespace['_offline_original_roundcube']=namespace['roundcube_preflight']
                namespace['subprocess']=types.SimpleNamespace(run=boundary,CompletedProcess=subprocess.CompletedProcess)
                for name in ('roundcube_preflight','normalize_active_plans','refresh_synced_php_snapshots','assert_fixture_entitlements','normalize_site_php','assert_snapshot_only_php_changed','prepare_fixture_capabilities','wait','maria'):
                    namespace[name]=lambda *a,**k:None
                namespace['roundcube_preflight']=lambda *a,**k:{}
                namespace['assert_fixture_php_inventory']=lambda *a,**k:{'subscriptions':[],'selected':[]}
                namespace['discover']=lambda value:value
                namespace['login']=lambda value:post
                namespace['pg']=lambda *a,**k:'[]'
                if action=='source-preflight':namespace['source_preflight'].__globals__['discover']=lambda value:dict(value,worker_php_version='8.5',domain='offline.test')
                if inject is not None:inject(namespace)
            return value
        def tracer(frame,event,arg):
            if event=='exception' and frame.f_code.co_name in ('command','rootless','create_fixture_container','seed','observed'):
                exceptions.append((frame.f_code.co_name,arg[0],arg[1]))
            return tracer
        previous=sys.gettrace();rc=0
        cwd_mock=patch.object(os,'getcwd',side_effect=cwd if isinstance(cwd,BaseException) else None,return_value=cwd)
        with patch.object(builtins,'exec',execute),patch.object(os,'lstat',side_effect=lstat) as ls,cwd_mock as cw,patch.object(os,'chdir',side_effect=AssertionError('chdir forbidden')),patch.object(subprocess,'run',side_effect=AssertionError('external call forbidden')),patch.object(sys,'stdin',io.StringIO(json.dumps({'action':action,'config':c}))),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            try:
                if trace:sys.settrace(tracer)
                if wrapped:execute(compile(program,'<offline-wrapper>','exec'),{'__name__':'__main__'})
                else:
                    ns={'__name__':'offline_original_probe','__file__':'<offline-original>'};execute(compile(self.source,'<offline-original>','exec'),ns)
                    ns['__name__']='__main__';tree=ast.parse(self.source);execute(compile(ast.Module(body=[tree.body[-1]],type_ignores=[]),'<offline-original>','exec'),ns)
            except SystemExit as error:rc=error.code
            finally:
                if trace:sys.settrace(previous)
        for result,old in objects:self.assertEqual(vars(result),old)
        marker=self.m.qualifier_marker_record(err.getvalue(),binding,KEY)
        observation=self.m.qualifier_projection(dict(marker['payload'],action=action)) if marker else self.m.qualifier_projection(None)
        return types.SimpleNamespace(rc=rc,out=out.getvalue(),err=err.getvalue(),calls=calls,posts=posts,ls=ls,cw=cw,binding=binding,marker=marker,observation=observation,exceptions=exceptions,namespaces=namespaces)

    def assert_unknown_metadata(self,row):
        self.assertEqual(row['cwd_is_root'],'UNKNOWN')
        self.assertEqual(row['parents'],{k:fact('UNKNOWN','UNKNOWN','UNKNOWN') for k in LABELS})

    def test_red_original_wrapper_has_no_pull_metadata(self):
        self.m=module(original=True);self.source=self.original_source;row=self.guest()
        self.assertEqual(row.observation['chain'],CHAIN)
        self.assertNotIn('rootless_pull',row.observation)
        self.assertEqual(row.ls.call_count,0);self.assertEqual(row.cw.call_count,0)

    def test_existing_completed_process_status_and_fixed_failure_facts(self):
        row=self.guest()
        self.assertEqual(row.rc,1);self.assertEqual(row.observation['chain'],CHAIN)
        self.assertEqual(row.observation.get('rootless_pull'),diagnostic())
        self.assertEqual([x.args[0] for x in row.ls.call_args_list],list(PATHS))
        self.assertEqual(row.cw.call_count,1);self.assertEqual(len(row.calls),5)
        self.assertLessEqual(len(json.dumps(row.observation['rootless_pull'])),1024)
        self.assertNotIn(PRIVATE,json.dumps(row.observation));self.assertNotIn('/private',json.dumps(row.observation))

    def test_identical_original_calls_stdin_timeout_outputs_exception_object(self):
        original=self.guest(wrapped=False,trace=True);row=self.guest(trace=True)
        self.assertEqual(row.calls,original.calls);self.assertEqual(row.posts,original.posts)
        self.assertEqual((row.rc,row.out),(original.rc,original.out))
        stripped=''.join(x+'\n' for x in row.err.splitlines() if not x.startswith(self.m.QUALIFIER_PREFIX))
        self.assertEqual(stripped,original.err)
        self.assertEqual(original.err,'forward fixture probe failed: guest operation failed: runuser\n')
        failures=[e for n,t,e in row.exceptions if t is RuntimeError and str(e)=='guest operation failed: runuser']
        self.assertGreaterEqual(len(failures),4);self.assertTrue(all(x is failures[0] for x in failures));self.assertEqual(failures[0].args,('guest operation failed: runuser',))
        for args,kwargs in row.calls:self.assertEqual(kwargs,dict({'input':None,'text':True,'capture_output':True,'env':None,'timeout':600},**({'cwd':'/'} if args[0]=='runuser' else {})))

    def test_successful_pull_does_zero_metadata_reads(self):
        old=self.guest(wrapped=False,returncode=0);row=self.guest(returncode=0)
        self.assertEqual(row.calls,old.calls);self.assertEqual(row.posts,old.posts)
        self.assertNotIn('rootless_pull',row.observation);self.assertEqual(row.ls.call_count,0);self.assertEqual(row.cw.call_count,0)
        self.assertEqual(row.observation['chain'],[{'function':'seed','line':705},{'function':'create_fixture_container','line':570}])

    def test_malformed_subscription_ids_never_read_namespace_metadata(self):
        for value in (None,True,False,0,-1,1.5,'3','../../../secret',[],{},2**63):
            with self.subTest(value=repr(value)):
                row=self.guest(config=dict(self.config,subscription_id=value))
                self.assertEqual(row.observation['rootless_pull']['returncode'],19);self.assert_unknown_metadata(row.observation['rootless_pull'])
                self.assertEqual(row.ls.call_count,0);self.assertEqual(row.cw.call_count,0)
                self.assertNotIn(PRIVATE,json.dumps(row.observation))

    def test_returncode_boundary_and_unknown_invalid_types(self):
        for rc in (-255,-9,1,255):
            with self.subTest(rc=rc):self.assertEqual(self.guest(returncode=rc).observation['rootless_pull']['returncode'],rc)
        for rc in (True,'private status',256,-256,1.5):
            with self.subTest(rc=repr(rc)):
                row=self.guest(returncode=rc);self.assertEqual(row.observation['rootless_pull']['returncode'],'UNKNOWN')
                self.assert_unknown_metadata(row.observation['rootless_pull']);self.assertEqual(row.ls.call_count,0);self.assertEqual(row.cw.call_count,0)

    def test_cwd_boolean_and_failure_is_unknown_without_correction(self):
        self.assertIs(self.guest(cwd='/').observation['rootless_pull']['cwd_is_root'],True)
        row=self.guest(cwd=PermissionError(PRIVATE));self.assertEqual(row.observation['rootless_pull']['cwd_is_root'],'UNKNOWN');self.assertEqual(row.ls.call_count,4)

    def test_symlink_missing_and_nondirectory_stop_descendant_reads(self):
        for bad,kind in [(types.SimpleNamespace(st_mode=stat.S_IFLNK|0o777,st_uid=42,st_gid=42),'SYMLINK'),(FileNotFoundError(PRIVATE),'MISSING'),(types.SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_uid=42,st_gid=42),'UNKNOWN'),(PermissionError(PRIVATE),'UNKNOWN')]:
            with self.subTest(kind=kind):
                row=self.guest(stats={PATHS[0]:bad})
                self.assertEqual([x.args[0] for x in row.ls.call_args_list],[PATHS[0],PATHS[3]])
                self.assertEqual(row.observation['rootless_pull']['parents']['STATE_PARENT'],fact(kind,'UNKNOWN','UNKNOWN'))
                self.assertEqual(row.observation['rootless_pull']['parents']['CONTAINER_PARENT'],fact('UNKNOWN','UNKNOWN','UNKNOWN'))
                self.assertEqual(row.observation['rootless_pull']['parents']['SUBSCRIPTION_PARENT'],fact('UNKNOWN','UNKNOWN','UNKNOWN'))
        row=self.guest(stats={PATHS[1]:FileNotFoundError(PRIVATE)})
        self.assertEqual([x.args[0] for x in row.ls.call_args_list],[PATHS[0],PATHS[1],PATHS[3]])

    def test_only_bounded_permission_bits_and_root_owner_boolean(self):
        row=self.guest(stats={PATHS[0]:types.SimpleNamespace(st_mode=stat.S_IFDIR|0o2770,st_uid=123456,st_gid=42)})
        self.assertEqual(row.observation['rootless_pull']['parents']['STATE_PARENT'],fact(mode=0o2770,owner=False,uid=123456,gid=42))
        for mode,uid in [(True,0),(-1,0),(stat.S_IFDIR,True),(stat.S_IFDIR,-1),('PRIVATE',0),(stat.S_IFDIR,'PRIVATE'),(0x10000,0),(stat.S_IFDIR,2**32)]:
            row=self.guest(stats={PATHS[0]:types.SimpleNamespace(st_mode=mode,st_uid=uid)})
            self.assertEqual(row.observation['rootless_pull']['parents']['STATE_PARENT'],fact('UNKNOWN','UNKNOWN','UNKNOWN'))
            self.assertEqual(row.ls.call_count,2)

    def test_unrelated_failures_do_zero_metadata_reads(self):
        def failure(namespace):
            def pg(*a,**k):return namespace['command'](['runuser','PRIVATE'])
            namespace['pg']=pg
        row=self.guest(inject=failure)
        self.assertNotIn('rootless_pull',row.observation);self.assertEqual(row.ls.call_count,0);self.assertEqual(row.cw.call_count,0)

    def test_same_filename_foreign_rootless_code_never_gets_metadata(self):
        def foreign(namespace):
            source="def rootless(c, *args):\n    return command(['runuser','PRIVATE'])\n"
            code=compile(source,'<nakpanel-forward-reviewed-qualifier>','exec');ns=dict(namespace);exec(code,ns);namespace['rootless']=ns['rootless']
        row=self.guest(inject=foreign)
        self.assertIsNone(row.marker);self.assertEqual(row.ls.call_count,0);self.assertEqual(row.cw.call_count,0)

    def test_strict_closed_schema_rejects_bad_modes_types_labels_and_raw_fields(self):
        projection=getattr(self.m,'rootless_pull_projection',None);self.assertTrue(callable(projection),'closed rootless metadata validator missing')
        self.assertEqual(projection(diagnostic()),diagnostic())
        mutations=[lambda d:d.update(raw=PRIVATE),lambda d:d.update(site=PRIVATE),lambda d:d.update(returncode=True),lambda d:d.update(returncode=0),lambda d:d.update(returncode=256),lambda d:d.update(cwd_is_root=1),lambda d:d['parents'].update(PRIVATE=fact()),lambda d:d['parents']['STATE_PARENT'].update(raw=PRIVATE),lambda d:d['parents']['STATE_PARENT'].update(mode=True),lambda d:d['parents']['STATE_PARENT'].update(mode=0o10000),lambda d:d['parents']['STATE_PARENT'].update(kind=PRIVATE),lambda d:d['parents']['STATE_PARENT'].update(owner_is_root=1),lambda d:d['parents']['STATE_PARENT'].update(kind='SYMLINK'),lambda d:d.update(returncode='x'*10000)]
        for mutate in mutations:
            value=diagnostic();mutate(value)
            with self.subTest(value=str(value)[:100]):self.assertIsNone(projection(value))

    def resigned(self,row,mutate):
        value=copy.deepcopy(row.marker);mutate(value['payload']);value['mac']=hmac.new(bytes.fromhex(KEY),self.m.canonical(value['payload']),hashlib.sha256).hexdigest()
        return self.m.QUALIFIER_PREFIX+json.dumps(value)

    def test_optional_metadata_requires_authenticated_exact_seed_pull_chain(self):
        row=self.guest();self.assertIn('rootless_pull',row.marker['payload'])
        for mutate in (lambda p:p['rootless_pull'].update(returncode=True),lambda p:p['rootless_pull'].update(raw=PRIVATE),lambda p:p['chain'][-2].update(line=114),lambda p:p['chain'].pop(1),lambda p:p.update(rootless_pull=PRIVATE),lambda p:p.update(error_category='value')):
            self.assertIsNone(self.m.qualifier_marker_record(self.resigned(row,mutate),row.binding,KEY))
        self.assertIsNone(self.m.qualifier_marker_record(row.err.replace('"returncode":19','"returncode":18'),row.binding,KEY))
        self.assertIsNone(self.m.qualifier_marker_record(row.err+row.err,row.binding,KEY))
        self.assertIsNone(self.m.qualifier_marker_record(row.err,dict(row.binding,command_ordinal=225),KEY))
        self.assertIsNone(self.m.qualifier_marker_record(row.err,row.binding,'a1'*32))

    def companion(self,path,row,**changes):
        data={'schema':'nakpanel-forward-probe-companion-v1','helper_sha256':self.m.PREFLIGHT_HELPER_SHA,'probe_sha256':PROBE_SHA,'matches':2,'guest_returncode':row.rc,'marker':row.marker};data.update(changes)
        path.write_text(json.dumps(data));path.chmod(0o600)

    def test_existing_private_companion_and_public_projection_preserve_closed_metadata(self):
        row=self.guest()
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'companion.json';self.companion(path,row)
            found=self.m.qualifier_companion(path,NONCE,224,KEY,self.config['source_vm'],self.config['run_token'])
            self.assertEqual(found,row.observation);self.assertIn('rootless_pull',found)
            public=self.m.preparation_projection({'stage':'source-php-preparation-and-seed','status':'failed','error_category':'runtime','qualifier_probe':found})
            self.assertEqual(public['qualifier_probe'],found);self.assertNotIn(PRIVATE,json.dumps(public))
            for changes in ({'matches':1},{'guest_returncode':0},{'guest_returncode':True}):
                self.companion(path,row,**changes);self.assertEqual(self.m.qualifier_companion(path,NONCE,224,KEY,self.config['source_vm'],self.config['run_token'])['chain'],'UNKNOWN')
            self.companion(path,row);path.chmod(0o640);self.assertEqual(self.m.qualifier_companion(path,NONCE,224,KEY,self.config['source_vm'],self.config['run_token'])['chain'],'UNKNOWN')

    def test_private_companion_alias_and_binding_refusals(self):
        row=self.guest()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);path=root/'companion.json';self.companion(path,row);alias=root/'alias.json';alias.symlink_to(path)
            for args in ((alias,NONCE,224,KEY,self.config['source_vm'],self.config['run_token']),(path,'d8'*16,224,KEY,self.config['source_vm'],self.config['run_token']),(path,NONCE,225,KEY,self.config['source_vm'],self.config['run_token']),(path,NONCE,224,KEY,'foreign-vm',self.config['run_token']),(path,NONCE,224,KEY,self.config['source_vm'],'foreign-token')):
                self.assertEqual(self.m.qualifier_companion(*args)['chain'],'UNKNOWN')

    def test_probe_program_hash_and_existing_map_are_unchanged(self):
        binding=self.m.qualifier_binding(NONCE,224,'seed',2,self.config)
        with self.assertRaises(self.m.Refusal):self.m.qualifier_guest_program(self.source+'\n',binding,KEY)
        self.assertEqual(self.m.QUALIFIER_PROBE_SHA,PROBE_SHA)
        self.assertEqual({name:self.m.QUALIFIER_SITES[name] for name in ('seed','create_fixture_container','rootless','command')},{'seed':(674,735),'create_fixture_container':(557,577),'rootless':(112,117),'command':(28,32)})


    def test_completed_process_identity_and_live_alias_changes_cannot_supply_metadata(self):
        class ForeignProcess(subprocess.CompletedProcess):pass
        transforms=(lambda result,ns:ForeignProcess(result.args,result.returncode,result.stdout,result.stderr),lambda result,ns:subprocess.CompletedProcess(list(result.args),result.returncode,result.stdout,result.stderr))
        for transform in transforms:
            row=self.guest(process_transform=transform)
            self.assertEqual(row.observation['chain'],CHAIN);self.assertNotIn('rootless_pull',row.observation)
            self.assertEqual(row.ls.call_count,0);self.assertEqual(row.cw.call_count,0)
        def change_alias(result,ns):
            ns['rootless']=lambda *a,**k:None
            return result
        row=self.guest(process_transform=change_alias)
        self.assertEqual(row.observation['chain'],CHAIN);self.assertNotIn('rootless_pull',row.observation)
        self.assertEqual(row.ls.call_count,0);self.assertEqual(row.cw.call_count,0)

    def test_metadata_runtime_errors_preserve_original_failure_and_primary_trace(self):
        row=self.guest(stats={path:RuntimeError(PRIVATE) for path in PATHS},cwd=RuntimeError(PRIVATE))
        self.assertEqual(row.rc,1);self.assertEqual(row.observation['chain'],CHAIN)
        self.assert_unknown_metadata(row.observation['rootless_pull']);self.assertEqual(row.ls.call_count,2)
        self.assertTrue(row.err.endswith('forward fixture probe failed: guest operation failed: runuser\n'))
        self.assertNotIn(PRIVATE,json.dumps(row.observation))

    def test_legacy_marker_without_optional_extension_remains_accepted(self):
        row=self.guest();wire=self.resigned(row,lambda value:value.pop('rootless_pull',None))
        found=self.m.qualifier_marker_record(wire,row.binding,KEY)
        self.assertIsNotNone(found);self.assertNotIn('rootless_pull',self.m.qualifier_projection(dict(found['payload'],action='seed')))

    def test_actual_original_host_prepare_run_transport_guest_boundary(self):
        helper=INPUTS/'ubuntu-forward-migration-fixture.py';helper_bytes=helper.read_bytes()
        self.assertEqual(hashlib.sha256(helper_bytes).hexdigest(),'7224534e0fed25a1d358f8e812fdea9820ab61c9cf6f4076e2d1da40abd0222c')
        def host(root,wrapped):
            ns={'__name__':'offline_actual_host_fixture','__file__':str(helper)};exec(compile(helper_bytes,str(helper),'exec'),ns)
            c=ns['example_spec']();c.update(self.config,architecture='amd64',version=1,ftp_password=PRIVATE,mailbox_password=PRIVATE)
            spec=root/'spec.json';spec.write_text(json.dumps(c));spec.chmod(0o600)
            calls=[];guest_rows=[];companion=root/'companion.json';observed=[]
            def transport(args,**kwargs):
                calls.append((copy.deepcopy(args),copy.deepcopy(kwargs)))
                if args[0]=='bash':return subprocess.CompletedProcess(args,0,'','')
                if args[0]=='ssh-keygen':
                    Path(args[-1]+'.pub').write_text('ssh-ed25519 OFFLINE')
                    return subprocess.CompletedProcess(args,0,'','')
                request=self.m.qualifier_invocation((args,),kwargs,self.original_source,c['source_vm'],c['run_token'])
                self.assertIsNotNone(request);action=request['action'];binding=self.m.qualifier_binding(NONCE,224,action,self.m.QUALIFIER_ACTIONS[action][1],request['config'])
                program=self.m.qualifier_guest_program(self.source,binding,KEY) if wrapped else self.source
                row=self.guest(wrapped=wrapped,config=request['config'],action=action,program_override=program)
                guest_rows.append(row)
                result=subprocess.CompletedProcess(args,row.rc,row.out,row.err)
                if row.rc and row.marker:observed.append(row)
                return result
            ns['subprocess']=types.SimpleNamespace(run=transport)
            error=None
            with patch.dict(os.environ,{},clear=True):
                try:ns['prepare'](spec,root/'prepared')
                except RuntimeError as caught:error=caught
            self.assertIs(type(error),RuntimeError);self.assertEqual(error.args,('fixture command failed: multipass',))
            if observed:self.companion(companion,observed[-1])
            return calls,guest_rows,companion,json.loads((root/'prepared/preparation-receipt.json').read_text())
        with tempfile.TemporaryDirectory() as td:
            old_root=Path(td)/'old';new_root=Path(td)/'new';old_root.mkdir(mode=0o700);new_root.mkdir(mode=0o700)
            old,old_guests,_,old_receipt=host(old_root,False);new,new_guests,companion,receipt=host(new_root,True)
            self.assertEqual([args[0] for args,kw in new],['bash','multipass','ssh-keygen','multipass'])
            self.assertEqual(len(new),len(old));self.assertEqual(receipt,old_receipt)
            self.assertEqual(receipt['stage'],'source-php-preparation-and-seed');self.assertEqual(receipt['status'],'failed')
            for (args,kwargs),(oldargs,oldkwargs) in zip(new,old):
                self.assertEqual(str(args).replace(str(new_root),str(old_root)),str(oldargs))
                self.assertEqual(str(kwargs).replace(str(new_root),str(old_root)),str(oldkwargs))
            self.assertEqual([r.ls.call_count for r in new_guests],[0,4]);self.assertEqual([r.cw.call_count for r in new_guests],[0,1])
            self.assertEqual(new_guests[-1].calls,old_guests[-1].calls)
            self.assertEqual(new_guests[-1].posts,old_guests[-1].posts)
            self.assertEqual(new_guests[-1].observation['rootless_pull'],diagnostic())
            found=self.m.qualifier_companion(companion,NONCE,224,KEY,self.config['source_vm'],self.config['run_token'])
            self.assertEqual(found,new_guests[-1].observation)



    def coordinator_failure(self,root,tree=None,tamper=None):
        m=self.m;c=m.Coordinator({'oci_image_ref':self.config['oci_image_ref']},INPUTS,INPUTS,root/'private',root/'public',env={})
        c.root.mkdir(mode=0o700);c.source=self.config['source_vm'];c.token=self.config['run_token'];c.boundary('prepare');owner=self
        class Boundary:
            def __init__(self):self.rows=[];self.counter=222;self.env={}
            def output(self,stage,args):
                self.counter+=1;self.rows.append({'stage':stage,'exit_code':0});return json.dumps(owner.config)
            def call(self,stage,args):
                self.counter+=1
                owner.assertEqual(args[10:13],[NONCE,'224',KEY])
                request=json.loads(Path(args[7]).read_text());row=owner.guest(config=request)
                prepared=Path(args[8]);prepared.mkdir(mode=0o700)
                m.publish(prepared/'preparation-receipt.json',{'version':1,'stage':'source-php-preparation-and-seed','status':'failed','error_type':'RuntimeError'})
                companion=Path(args[9]);owner.companion(companion,row)
                if tamper:tamper(companion)
                folder=c.root/'logs';folder.mkdir(mode=0o700);log=folder/(str(self.counter)+'-prepare.stderr');log.write_text('forward fixture failed: fixture command failed: multipass\n');log.chmod(0o600)
                result={'stage':stage,'exit_code':1,'owned_group_empty':True,'leader_reaped':True,'timed_out':False,'interrupted':False};result.update(tree or {});self.rows.append(result)
                raise m.Refusal(PRIVATE)
        c.run=Boundary()
        with patch.object(m.os,'urandom',side_effect=lambda n:bytes.fromhex(NONCE if n==16 else KEY)):
            with self.assertRaises(m.Refusal) as caught:c.prepare()
        c.remember_failure(caught.exception);c.capture_primary(caught.exception);c.state['stages']=c.run.rows
        return m.public_result(c.state),c

    def test_existing_custody_projects_only_fresh_drained_failed_command_and_keeps_primary(self):
        with tempfile.TemporaryDirectory() as td:
            result,c=self.coordinator_failure(Path(td))
            projection=result['primary_outcome']['preparation_diagnostic']['qualifier_probe']
            self.assertEqual(projection['chain'],CHAIN);self.assertEqual(projection['rootless_pull'],diagnostic())
            c.boundary('cleanup');c.cleanup_failure('source',self.m.Refusal(PRIVATE));later=self.m.public_result(c.state)
            self.assertEqual(later['primary_outcome'],result['primary_outcome']);self.assertNotIn('rootless_pull',json.dumps(later['cleanup_outcome']));self.assertNotIn(PRIVATE,json.dumps(later))

    def test_custody_rejects_missing_stale_undrained_unreaped_zero_timeout_interrupt(self):
        def stale(path):
            value=json.loads(path.read_text());value['marker']['payload']['binding']['nonce']='d8'*16;path.write_text(json.dumps(value))
        cases=[({'owned_group_empty':False},None),({'leader_reaped':False},None),({'exit_code':0},None),({'timed_out':True},None),({'interrupted':True},None),(None,lambda p:p.unlink()),(None,stale)]
        for tree,tamper in cases:
            with self.subTest(tree=tree,tamper=bool(tamper)),tempfile.TemporaryDirectory() as td:
                result,_=self.coordinator_failure(Path(td),tree,tamper)
                self.assertNotIn('rootless_pull',json.dumps(result));self.assertEqual(result['primary_outcome']['preparation_diagnostic'].get('qualifier_probe',{'chain':'UNKNOWN'})['chain'],'UNKNOWN')



    def test_largest_namespace_id_is_bounded_and_never_projected(self):
        row=self.guest(config=dict(self.config,subscription_id=2**63-1))
        self.assertEqual(row.ls.call_count,4);self.assertEqual(row.observation['rootless_pull'],diagnostic())
        self.assertEqual(row.ls.call_args_list[2].args[0],'/var/lib/nakpanel/containers/sub-9223372036854775807')
        self.assertNotIn('9223372036854775807',json.dumps(row.observation))

    def test_actual_source_preflight_failure_never_reads_pull_metadata(self):
        def failure(namespace):
            namespace['assert_fixture_php_inventory']=lambda *a,**k:(_ for _ in ()).throw(RuntimeError(PRIVATE))
        row=self.guest(action='source-preflight',inject=failure)
        self.assertEqual(row.rc,1);self.assertIsNotNone(row.marker);self.assertNotIn('rootless_pull',row.observation)
        self.assertEqual(row.ls.call_count,0);self.assertEqual(row.cw.call_count,0);self.assertEqual(row.calls,[])
        self.assertNotIn(PRIVATE,json.dumps(row.observation))

    def test_marker_bounds_and_unsafe_text_cannot_enter_projection(self):
        row=self.guest();self.assertLess(len(json.dumps(row.marker)),4096)
        for wire in ('x'*131073,self.m.QUALIFIER_PREFIX+'x'*98305,self.m.QUALIFIER_PREFIX+json.dumps({'payload':PRIVATE,'mac':'0'*64}),PRIVATE):
            self.assertIsNone(self.m.qualifier_marker_record(wire,row.binding,KEY))
        found=self.m.qualifier_marker_record(PRIVATE+'\n'+row.err+'\n'+PRIVATE,row.binding,KEY)
        self.assertIsNotNone(found)
        projection=self.m.qualifier_projection(dict(found['payload'],action='seed'))
        self.assertEqual(projection,row.observation);self.assertNotIn(PRIVATE,json.dumps(projection))
        bad=self.resigned(row,lambda p:p['rootless_pull']['parents']['STATE_PARENT'].update(raw=PRIVATE*10000))
        self.assertIsNone(self.m.qualifier_marker_record(bad,row.binding,KEY))


class PullContextTests(unittest.TestCase):
    """Real unchanged probe → trusted wrapper → companion/public projection."""
    setUp=ComponentTests.setUp
    guest=ComponentTests.guest
    companion=ComponentTests.companion
    resigned=ComponentTests.resigned

    def captured(self,stderr=PULL_STDERR,**kwargs):
        def replace(result,namespace):
            result.stderr=stderr
            return result
        return self.guest(process_transform=replace,**kwargs)

    def test_actual_completed_stderr_cwd_and_fixed_parent_ids_survive_projection(self):
        row=self.captured(stderr='Error: public registry unavailable\n',cwd='/home/ubuntu',stats={PATHS[0]:types.SimpleNamespace(st_mode=stat.S_IFDIR|0o711,st_uid=1000,st_gid=1001)})
        context=row.observation.get('rootless_pull',{})
        self.assertEqual(context.get('stderr'),{'text':'Error: public registry unavailable\n','truncated':False})
        self.assertEqual(context.get('cwd'),'/home/ubuntu')
        self.assertEqual(context['parents']['STATE_PARENT'],{'kind':'DIRECTORY','mode':0o711,'owner_is_root':False,'uid':1000,'gid':1001})
        self.assertEqual(row.rc,1);self.assertEqual(row.observation['chain'],CHAIN)
        self.assertNotIn(PRIVATE,json.dumps(context));self.assertEqual(len(row.calls),5)
        self.assertEqual(row.ls.call_count,4);self.assertEqual(row.cw.call_count,1)
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'companion.json';self.companion(path,row)
            found=self.m.qualifier_companion(path,NONCE,224,KEY,self.config['source_vm'],self.config['run_token'])
            self.assertEqual(found,row.observation)
            self.assertEqual(self.m.preparation_projection({'stage':'source-php-preparation-and-seed','status':'failed','error_category':'runtime','qualifier_probe':found})['qualifier_probe'],found)

    def test_stderr_is_an_actual_utf8_prefix_capped_at_8192_bytes(self):
        for text,want,cut in [('', '',False),('x'*8192,'x'*8192,False),('x'*8193,'x'*8192,True),('€'*3000,'€'*2730,True)]:
            with self.subTest(length=len(text)):
                value=self.captured(stderr=text).observation['rootless_pull'].get('stderr')
                self.assertEqual(value,{'text':want,'truncated':cut})
                self.assertLessEqual(len(value['text'].encode('utf-8')),8192)

    def test_maximum_json_escaped_context_fits_authenticated_companion(self):
        row=self.captured(stderr='\0'*8192,cwd='/'+'\n'*4095)
        self.assertEqual(row.observation['rootless_pull'].get('stderr'),{'text':'\0'*8192,'truncated':False})
        self.assertEqual(row.observation['rootless_pull'].get('cwd'),'/'+'\n'*4095)
        self.assertLessEqual(len(self.m.canonical(row.marker)),98304)
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'companion.json';self.companion(path,row)
            self.assertGreater(path.stat().st_size,8192)
            self.assertEqual(self.m.qualifier_companion(path,NONCE,224,KEY,self.config['source_vm'],self.config['run_token']),row.observation)

    def test_cwd_is_actual_absolute_utf8_bounded_or_unknown(self):
        for value,want in [('/', '/'),('/'+'x'*4095,'/'+'x'*4095),('/'+'x'*4096,'UNKNOWN'),('/\0bad','UNKNOWN'),('relative','UNKNOWN'),(True,'UNKNOWN'),(PermissionError(PRIVATE),'UNKNOWN')]:
            with self.subTest(value=str(value)[:30]):
                context=self.captured(cwd=value).observation['rootless_pull']
                self.assertEqual(context.get('cwd'),want)
                self.assertEqual(context['cwd_is_root'],want=='/' if want!='UNKNOWN' else 'UNKNOWN')

    def test_unavailable_stderr_never_stringifies_or_substitutes_exception_text(self):
        for value in (None,b'bytes',True,{'error':PRIVATE},'\ud800'):
            with self.subTest(value=repr(value)):
                row=self.captured(stderr=value)
                self.assertEqual(row.observation['rootless_pull'].get('stderr'),{'text':'UNKNOWN','truncated':'UNKNOWN'})
                self.assertEqual(row.observation['chain'],CHAIN)
                self.assertTrue(row.err.endswith('forward fixture probe failed: guest operation failed: runuser\n'))

    def test_parent_uid_gid_are_bounded_integer_facts(self):
        for uid,gid in [(0,0),(2**32-1,2**32-1),(1001,1002)]:
            row=self.captured(stats={PATHS[0]:types.SimpleNamespace(st_mode=stat.S_IFDIR|0o2770,st_uid=uid,st_gid=gid)})
            self.assertEqual(row.observation['rootless_pull']['parents']['STATE_PARENT'],fact(mode=0o2770,owner=uid==0,uid=uid,gid=gid))
        for uid,gid in [(True,0),(0,False),(-1,0),(0,-1),(2**32,0),(0,2**32),('secret',0)]:
            row=self.captured(stats={PATHS[0]:types.SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=uid,st_gid=gid)})
            self.assertEqual(row.observation['rootless_pull']['parents']['STATE_PARENT'],fact('UNKNOWN','UNKNOWN','UNKNOWN'))
            self.assertEqual(row.ls.call_count,2)

    def test_context_schema_refuses_oversize_types_extra_fields_and_inconsistent_ids(self):
        baseline=diagnostic()
        self.assertEqual(self.m.rootless_pull_projection(baseline),baseline)
        mutations=[lambda d:d.update(stdout=PRIVATE),lambda d:d.update(cwd='relative'),lambda d:d.update(cwd='/'+'x'*4096),lambda d:d.update(cwd=True),lambda d:d.update(cwd='/\0bad'),lambda d:d.update(cwd_is_root=True),lambda d:d['stderr'].update(text='x'*8193),lambda d:d['stderr'].update(truncated=1),lambda d:d['stderr'].update(raw=PRIVATE),lambda d:d['stderr'].update(text=None),lambda d:d['parents']['STATE_PARENT'].update(uid=True),lambda d:d['parents']['STATE_PARENT'].update(gid=2**32),lambda d:d['parents']['STATE_PARENT'].update(uid=1),lambda d:d['parents']['STATE_PARENT'].update(kind='MISSING')]
        for mutate in mutations:
            data=copy.deepcopy(baseline);mutate(data)
            with self.subTest(data=str(data)[:120]):self.assertIsNone(self.m.rootless_pull_projection(data))

    def test_success_unrelated_action_bad_identity_and_foreign_trace_retain_no_new_stream(self):
        success=self.captured(returncode=0)
        self.assertNotIn('rootless_pull',success.observation);self.assertEqual(success.ls.call_count,0);self.assertEqual(success.cw.call_count,0)
        preflight=self.captured(action='source-preflight',inject=lambda ns:ns.update(assert_fixture_php_inventory=lambda *a,**k:(_ for _ in ()).throw(RuntimeError(PRIVATE))))
        self.assertNotIn('rootless_pull',preflight.observation);self.assertNotIn(PULL_STDERR,json.dumps(preflight.observation));self.assertEqual(preflight.ls.call_count,0)
        invalid=self.captured(config=dict(self.config,subscription_id=True)).observation['rootless_pull']
        self.assertEqual(invalid.get('stderr'),{'text':'UNKNOWN','truncated':'UNKNOWN'});self.assertEqual(invalid.get('cwd'),'UNKNOWN')
        def foreign(ns):
            code=compile('def rootless(c,*args):\n    return command(["runuser","PRIVATE"])\n','<nakpanel-forward-reviewed-qualifier>','exec');n=dict(ns);exec(code,n);ns['rootless']=n['rootless']
        row=self.captured(inject=foreign);self.assertIsNone(row.marker);self.assertEqual(row.ls.call_count,0)

    def test_extended_context_still_needs_fresh_hmac_private_binding_and_exact_chain(self):
        row=self.captured()
        self.assertIn('stderr',row.observation['rootless_pull'])
        for mutate in (lambda p:p['rootless_pull']['stderr'].update(text='x'*8193),lambda p:p['rootless_pull'].update(stdout=PRIVATE),lambda p:p['chain'][-2].update(line=114),lambda p:p['binding'].update(action='source-preflight'),lambda p:p['binding'].update(nonce='d8'*16)):
            self.assertIsNone(self.m.qualifier_marker_record(self.resigned(row,mutate),row.binding,KEY))
        self.assertIsNone(self.m.qualifier_marker_record(row.err.replace('public nginx','spoofed nginx'),row.binding,KEY))
        self.assertIsNone(self.m.qualifier_marker_record(row.err,row.binding,'a1'*32))
        self.assertIsNone(self.m.qualifier_marker_record(row.err+row.err,row.binding,KEY))

    def test_projection_refuses_invalid_unicode_without_raising(self):
        for mutate in (lambda d:d.update(cwd='/\ud800'),lambda d:d['stderr'].update(text='\ud800')):
            value=diagnostic();mutate(value)
            try:found=self.m.rootless_pull_projection(value)
            except UnicodeError:found='RAISED_UNICODE_ERROR'
            self.assertIsNone(found)


if __name__=='__main__':unittest.main()
