"""Pure original-host -> run transport -> exact qualifier guest integrations."""
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
import unittest
from unittest.mock import patch

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
APP=Path('/Users/rickynkansah/.codex/worktrees/ubuntu-26-support/nakpanel')
SOURCE=APP/'deploy/multipass/ubuntu-forward-migration-probe.py'
HELPER=SOURCE.with_name('ubuntu-forward-migration-fixture.py')
sys.path.insert(0,str(HERE))
from test_forward_hosted import module,private
import test_forward_hosted as baseline_tests


class QualifierOverrideTests(unittest.TestCase):
    NONCE='c7'*16
    KEY='e9'*32
    VM='nakpanel-offline'
    TOKEN='offline-test-token'

    def api(self):
        m=module()
        self.assertTrue(callable(getattr(m,'qualifier_artifacts',None)),'explicit qualifier artifact verifier missing')
        return m

    def config(self):
        ns={'__name__':'offline_fixture','__file__':str(HELPER)}
        exec(compile(HELPER.read_bytes(),str(HELPER),'exec'),ns)
        c=ns['example_spec']();c.update(source_vm=self.VM,run_token=self.TOKEN,architecture='amd64',target_profile='ubuntu-26.04-native',normalize_php85=True,remediate_stale_php82=True,oci_image_ref='docker.io/library/nginx@sha256:'+'5'*64)
        c.update({key:'PRIVATE_SENTINEL' for key in ('database_password','application_secret','ftp_password','mailbox_password')})
        return c

    def guest(self,program,data,mode='command'):
        if getattr(self,'canonical_roundcube',False):
            import builtins
            from pathlib import PurePosixPath
            source=ast.parse((HERE/'qualifier-tests.py').read_text())
            cls=next(n for n in source.body if isinstance(n,ast.ClassDef) and n.name=='RoundcubePreflightTests')
            wrapper=ast.literal_eval(next(n.value for n in cls.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='DEBIAN_WRAPPER' for t in n.targets)))
            files={'debian-db-roundcube.php':wrapper,'debian-db.php':"<?php\n$dbtype='sqlite3';\n$basepath='/var/lib/roundcube';\n$dbname='roundcube.sqlite';\n"}
            class MockPath(PurePosixPath):
                def exists(self):return self.name in files
                def read_text(self):return files[self.name]
                def is_file(self):return str(self)=='/var/lib/roundcube/roundcube.sqlite'
                def is_symlink(self):return False
            real_exec=builtins.exec
            def execute(code,namespace=None,*args,**kwargs):
                result=real_exec(code,namespace,*args,**kwargs)
                if type(namespace) is dict and namespace.get('__name__') in ('nakpanel_observed_probe','nakpanel_qualifier_probe'):
                    namespace['Path']=MockPath
                    namespace['roundcube_preflight'].__defaults__=(MockPath('/etc/roundcube'),)
                return result
            with patch.object(builtins,'exec',execute):return baseline_tests.SourcePreflightMarkerTests().guest(program,mode,input_data=data)
        return baseline_tests.SourcePreflightMarkerTests().guest(program,mode,input_data=data)

    def host(self,root,fail_action='seed',original=False,legacy=False):
        m=self.api();c=self.config();spec=private(root/'spec.json',c);companion=root/'companion.json';output=root/'prepared';calls=[];objects=[]
        out,err=io.StringIO(),io.StringIO();rc=0
        def transport(args,**kwargs):
            calls.append((list(args),dict(kwargs)))
            if args[0]=='bash':result=subprocess.CompletedProcess(args,0,'','')
            elif args[0]=='ssh-keygen':
                Path(str(args[-1])+'.pub').write_text('ssh-ed25519 OFFLINE')
                result=subprocess.CompletedProcess(args,0,'','')
            else:
                self.assertEqual(args[:7],['multipass','exec',self.VM,'--','sudo','python3','-c'])
                request=json.loads(kwargs['input']);action=request.get('action')
                if fail_action=='live' and action=='seed':code,stdout,stderr=0,json.dumps(dict(request['config'],mailbox='offline@offline.test')),''
                elif fail_action=='live' and action is None:code,stdout,stderr=0,'SYNTHETIC_CERTIFICATE',''
                elif fail_action=='live' and action=='live':
                    self.assertEqual(args[7],SOURCE.read_text());code,stdout,stderr=7,'PRIVATE_SENTINEL','PRIVATE_SENTINEL'
                else:
                    self.assertIn(action,('source-preflight','seed'))
                    code,stdout,stderr,_=self.guest(args[7],kwargs['input'],'command' if action==fail_action else 'success')
                result=subprocess.CompletedProcess(args,code,stdout,stderr)
            objects.append((result,result.stdout,result.stderr,result.returncode));return result
        with patch.object(subprocess,'run',side_effect=transport),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            try:
                if original:
                    ns={'__name__':'offline_original_fixture','__file__':str(HELPER)};exec(compile(HELPER.read_bytes(),str(HELPER),'exec'),ns)
                    with patch.object(sys,'argv',[str(HELPER),'--prepare',str(spec),str(output)]):
                        ns['__name__']='__main__';tree=ast.parse(HELPER.read_text());exec(compile(ast.Module(body=[tree.body[-1]],type_ignores=[]),str(HELPER),'exec'),ns)
                elif legacy:m.observed_prepare(str(HELPER),str(spec),str(output),str(companion),self.NONCE,'220',self.KEY)
                else:m.observed_qualifier_prepare(str(HELPER),str(spec),str(output),str(companion),self.NONCE,'220',self.KEY,str(HERE),self.VM,self.TOKEN)
            except SystemExit as error:rc=error.code
        for result,stdout,stderr,code in objects:self.assertEqual((result.stdout,result.stderr,result.returncode),(stdout,stderr,code))
        return m,rc,out.getvalue(),err.getvalue(),calls,companion

    def test_exact_two_delivery_blobs_patch_and_original175_identity(self):
        m=self.api();verified=m.qualifier_artifacts(HERE,APP)
        self.assertEqual(hashlib.sha256(verified['source'].encode()).hexdigest(),'1fa03999f12fc7a3f0bc4bd07ee0afc04d5371c53824538e9496bf31fb6b68f8')
        self.assertEqual(verified['identity']['runtime_source_commit'],m.COMMIT)
        self.assertEqual(verified['identity']['qualifier_commit'],'a35a92ea987e6ff9d04e4d321a12e28642093642')
        self.assertEqual(verified['identity']['delivery_test_sha256'],'9c0e75dda3e8e03990ed36eaaf889da40a8a2f9d181c440c97f30dd86ab0ac16')
        manifest=json.loads((HERE.parent/'forward-hosted-candidate26-v3/SOURCE-INPUTS.json').read_text())
        self.assertEqual(len(manifest['app_helpers']),175)
        self.assertEqual(m.digest(m.canonical(manifest['app_helpers'])),m.ORIGINAL_HELPERS_SHA)
        for name,h in manifest['app_helpers'].items():self.assertEqual(m.sha(APP/name),h)

    def test_actual_host_prepare_substitutes_both_invocations_and_preserves_failure_and_other_calls(self):
        with tempfile.TemporaryDirectory() as td:
            a=Path(td)/'original';b=Path(td)/'new';a.mkdir(mode=0o700);b.mkdir(mode=0o700)
            _,oldrc,oldout,olderr,oldcalls,_=self.host(a,original=True)
            m,rc,out,err,calls,companion=self.host(b)
            self.assertEqual((rc,out,err),(oldrc,oldout,olderr));self.assertEqual(err,'forward fixture failed: fixture command failed: multipass\n')
            self.assertEqual([row[0][0] for row in calls],['bash','multipass','ssh-keygen','multipass'])
            self.assertEqual(len(calls),len(oldcalls))
            for (argv,kw),(oldargv,oldkw) in zip(calls,oldcalls):
                if argv[0]=='multipass':
                    self.assertNotEqual(argv[-1],SOURCE.read_text());self.assertEqual(argv[:-1],oldargv[:-1])
                    self.assertEqual(json.loads(kw['input'])['action'],json.loads(oldkw['input'])['action'])
                    for key in kw:
                        if key!='input':self.assertEqual(kw[key],oldkw[key])
                    self.assertEqual(kw['input'].replace(str(b),str(a)),oldkw['input'])
                    self.assertIn("'probe_sha256': '1fa03999",argv[-1])
                else:self.assertEqual(str(argv).replace(str(b),str(a)),str(oldargv))
            record=m.qualifier_companion(companion,self.NONCE,220,self.KEY,self.VM,self.TOKEN)
            self.assertEqual(record['action'],'seed');self.assertEqual(record['chain'][0]['function'],'seed');self.assertEqual(record['probe_sha256'],m.QUALIFIER_PROBE_SHA)
            self.assertNotIn('PRIVATE_SENTINEL',companion.read_text());self.assertNotIn(self.KEY,companion.read_text());self.assertNotIn(self.TOKEN,companion.read_text())

    def test_actual_preflight_failure_has_new_hash_shifted_full_trusted_chain(self):
        with tempfile.TemporaryDirectory() as td:
            m,rc,out,err,calls,p=self.host(Path(td),fail_action='source-preflight')
            record=m.qualifier_companion(p,self.NONCE,220,self.KEY,self.VM,self.TOKEN)
            self.assertEqual(rc,1);self.assertEqual(len(calls),2);self.assertEqual(record['action'],'source-preflight')
            self.assertEqual(record['chain'],[{'function':'source_preflight','line':549},{'function':'assert_fixture_php_inventory','line':397},{'function':'fixture_php_inventory','line':383},{'function':'pg','line':36},{'function':'command','line':31}])

    def test_wrong_program_action_vm_kwargs_payload_are_not_substituted(self):
        m=self.api();config=self.config();argv=['multipass','exec',self.VM,'--','sudo','python3','-c',SOURCE.read_text()]
        kwargs={'input':json.dumps({'action':'source-preflight','config':config}),'text':True,'capture_output':True,'env':None,'timeout':3600}
        self.assertEqual(m.qualifier_invocation((argv,),kwargs,SOURCE.read_text(),self.VM,self.TOKEN)['action'],'source-preflight')
        variants=[]
        a=copy.deepcopy(argv);a[-1]+='\n';variants.append(((a,),kwargs))
        a=copy.deepcopy(argv);a[2]='nakpanel-other';variants.append(((a,),kwargs))
        variants.append(((tuple(argv),),kwargs));variants.append(((argv,'extra'),kwargs))
        for key,value in (('timeout',600),('env',{}),('input','{}'),('text',False)):
            k=copy.deepcopy(kwargs);k[key]=value;variants.append(((argv,),k))
        for change in ({'action':'live'},{'action':'snapshot'},{'extra':'value'},{'config':dict(config,source_vm='nakpanel-other')},{'config':dict(config,run_token='foreign-token')}):
            request={'action':'source-preflight','config':config};request.update(change);k=dict(kwargs,input=json.dumps(request));variants.append(((argv,),k))
        for args,kw in variants:
            with self.subTest(case=len(str(args))+len(str(kw))):self.assertIsNone(m.qualifier_invocation(args,kw,SOURCE.read_text(),self.VM,self.TOKEN))

    def test_actual_host_other_probe_actions_and_guest_programs_pass_through(self):
        with tempfile.TemporaryDirectory() as td:
            m,rc,out,err,calls,p=self.host(Path(td),fail_action='live')
            self.assertEqual(rc,1);self.assertFalse(p.exists())
            probes=[(a,k) for a,k in calls if a[0]=='multipass']
            self.assertEqual([json.loads(k['input']).get('action') for a,k in probes],['source-preflight','seed',None,'live'])
            self.assertEqual(probes[-1][0][-1],SOURCE.read_text())
            self.assertNotIn(m.QUALIFIER_PREFIX,probes[-2][0][-1])

    def test_marker_trace_schema_hash_duplicate_and_old_map_negatives_even_with_test_key(self):
        import hmac
        m=self.api();config=self.config();binding=m.qualifier_binding(self.NONCE,220,'source-preflight',1,config)
        program=m.qualifier_guest_program((HERE/'qualifier-probe.py').read_text(),binding,self.KEY)
        _,_,stderr,_=self.guest(program,json.dumps({'action':'source-preflight','config':config}))
        original=m.qualifier_marker_record(stderr,binding,self.KEY);self.assertIsNotNone(original)
        for edit in (lambda d:d['payload'].update(chain=[{'function':'source_preflight','line':540}]),lambda d:d['payload'].update(chain=[{'function':'PRIVATE_SENTINEL','line':549}]),lambda d:d['payload'].update(chain=[{'function':'source_preflight','line':549}]*7),lambda d:d['payload'].update(chain=[{'function':'seed','line':675}]),lambda d:d['payload'].update(probe_sha256=m.PREFLIGHT_PROBE_SHA),lambda d:d['payload']['binding'].update(invocation=True)):
            row=copy.deepcopy(original);edit(row);row['mac']=hmac.new(bytes.fromhex(self.KEY),m.canonical(row['payload']),hashlib.sha256).hexdigest()
            self.assertIsNone(m.qualifier_marker_record(m.QUALIFIER_PREFIX+json.dumps(row),binding,self.KEY))
        for data in (stderr+stderr,'x'*65537,'PRIVATE_SENTINEL',stderr.replace(m.QUALIFIER_PREFIX,m.PREFLIGHT_PREFIX)):
            self.assertIsNone(m.qualifier_marker_record(data,binding,self.KEY))

    def test_foreign_same_filename_code_and_wrong_trusted_alias_cannot_emit_authenticated_trace(self):
        import builtins
        m=self.api();config=self.config();binding=m.qualifier_binding(self.NONCE,220,'source-preflight',1,config)
        program=m.qualifier_guest_program((HERE/'qualifier-probe.py').read_text(),binding,self.KEY);original_exec=builtins.exec
        for mode in ('foreign-code','trusted-wrong-root'):
            def intercepted(code,namespace=None,*args,**kwargs):
                result=original_exec(code,namespace,*args,**kwargs)
                if type(namespace) is dict and namespace.get('__name__')=='nakpanel_qualifier_probe':
                    if mode=='foreign-code':
                        extra={};original_exec(compile("def counterfeit(config):\n raise RuntimeError('PRIVATE_SENTINEL')\n",'<nakpanel-forward-reviewed-qualifier>','exec'),extra);namespace['source_preflight']=extra['counterfeit']
                    else:namespace['source_preflight']=namespace['command']
                return result
            with self.subTest(mode=mode),patch.object(builtins,'exec',intercepted):
                rc,out,stderr,_=self.guest(program,json.dumps({'action':'source-preflight','config':config}))
            self.assertEqual(rc,1);self.assertIsNone(m.qualifier_marker_record(stderr,binding,self.KEY))

    def test_actual_launcher_refuses_wrong_spec_vm_token_and_alias_before_transport(self):
        m=self.api()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);spec=private(root/'spec.json',self.config())
            for vm,token in (('nakpanel-other',self.TOKEN),(self.VM,'foreign-token')):
                with patch.object(subprocess,'run',side_effect=AssertionError('transport')),self.assertRaises(m.Refusal):m.observed_qualifier_prepare(str(HELPER),str(spec),str(root/'output'),str(root/'companion'),self.NONCE,'220',self.KEY,str(HERE),vm,token)
            alias=root/'alias';os.link(spec,alias)
            try:
                with patch.object(subprocess,'run',side_effect=AssertionError('transport')),self.assertRaises(m.Refusal):m.observed_qualifier_prepare(str(HELPER),str(spec),str(root/'output'),str(root/'companion'),self.NONCE,'220',self.KEY,str(HERE),self.VM,self.TOKEN)
            finally:alias.unlink()

    def test_artifact_source_hash_alias_and_patch_drift_refuse_before_any_transport(self):
        m=self.api()
        with tempfile.TemporaryDirectory() as td:
            ctrl=Path(td)/'controller';ctrl.mkdir()
            for name in m.QUALIFIER_FILES:shutil.copyfile(HERE/name,ctrl/name)
            for name in m.QUALIFIER_FILES:
                original=(ctrl/name).read_bytes();(ctrl/name).write_bytes(original+b'\n')
                with patch.object(subprocess,'run',side_effect=AssertionError('transport')),self.assertRaises((m.Refusal,OSError)):m.qualifier_artifacts(ctrl,APP)
                (ctrl/name).write_bytes(original)
            p=ctrl/'qualifier-probe.py';original=p.read_bytes();p.unlink();p.symlink_to(HERE/'qualifier-probe.py')
            with self.assertRaises((m.Refusal,OSError)):m.qualifier_artifacts(ctrl,APP)
            p.unlink();p.write_bytes(original);alias=ctrl/'hardlink-alias';os.link(p,alias)
            try:
                with self.assertRaises((m.Refusal,OSError)):m.qualifier_artifacts(ctrl,APP)
            finally:alias.unlink()
            with self.assertRaises((m.Refusal,OSError)):m.qualifier_artifacts(APP,APP)
            fake=Path(td)/'app';folder=fake/'deploy/multipass';folder.mkdir(parents=True)
            for name in ('ubuntu-forward-migration-probe.py','ubuntu_forward_migration_fixture_test.py'):shutil.copyfile(APP/'deploy/multipass'/name,folder/name)
            (folder/'ubuntu-forward-migration-probe.py').write_text('wrong source')
            with self.assertRaises((m.Refusal,OSError)):m.qualifier_artifacts(ctrl,fake)

    def test_private_companion_binding_nonce_ordinal_action_vm_token_key_and_alias_are_closed(self):
        with tempfile.TemporaryDirectory() as td:
            m,_,_,_,_,p=self.host(Path(td));raw=p.read_text();unknown=m.qualifier_projection(None)
            for nonce,ordinal,key,vm,token in [('d8'*16,220,self.KEY,self.VM,self.TOKEN),(self.NONCE,221,self.KEY,self.VM,self.TOKEN),(self.NONCE,220,'f8'*32,self.VM,self.TOKEN),(self.NONCE,220,self.KEY,'nakpanel-other',self.TOKEN),(self.NONCE,220,self.KEY,self.VM,'foreign-token')]:self.assertEqual(m.qualifier_companion(p,nonce,ordinal,key,vm,token),unknown)
            for edit in (lambda d:d.update(matches=1),lambda d:d.update(guest_returncode=0),lambda d:d['marker']['payload']['binding'].update(action='source-preflight'),lambda d:d['marker']['payload']['binding'].update(config_sha256='0'*64),lambda d:d['marker']['payload'].update(probe_sha256=m.PREFLIGHT_PROBE_SHA),lambda d:d['marker']['payload'].update(chain=[{'function':'PRIVATE_SENTINEL','line':549}]),lambda d:d['marker'].update(mac='0'*64)):
                value=json.loads(raw);edit(value);private(p,value);self.assertEqual(m.qualifier_companion(p,self.NONCE,220,self.KEY,self.VM,self.TOKEN),unknown)
            p.write_text(raw);p.chmod(0o644);self.assertEqual(m.qualifier_companion(p,self.NONCE,220,self.KEY,self.VM,self.TOKEN),unknown)
            p.chmod(0o600);link=p.with_name('alias');os.link(p,link)
            self.assertEqual(m.qualifier_companion(p,self.NONCE,220,self.KEY,self.VM,self.TOKEN),unknown);link.unlink()

    def test_guest_rejects_old_probe_and_wrong_private_config_before_product_call(self):
        m=self.api();config=self.config();binding=m.qualifier_binding(self.NONCE,220,'seed',2,config)
        with self.assertRaises(m.Refusal):m.qualifier_guest_program(SOURCE.read_text(),binding,self.KEY)
        source=(HERE/'qualifier-probe.py').read_text();program=m.qualifier_guest_program(source,binding,self.KEY)
        wrong=json.dumps({'action':'seed','config':dict(config,run_token='foreign-token')})
        rc,out,err,calls=self.guest(program,wrong)
        self.assertEqual(rc,1);self.assertEqual(calls,[]);self.assertIsNone(m.qualifier_marker_record(err,binding,self.KEY))

    def test_seed_successful_prelude_keeps_original_guest_failure_outputs_and_calls(self):
        m=self.api();config=self.config();source=(HERE/'qualifier-probe.py').read_text();data=json.dumps({'action':'seed','config':config});binding=m.qualifier_binding(self.NONCE,220,'seed',2,config)
        original=self.guest(source,data);wrapped=self.guest(m.qualifier_guest_program(source,binding,self.KEY),data)
        self.assertEqual(wrapped[0:2],original[0:2]);self.assertEqual(wrapped[3],original[3]);self.assertEqual(wrapped[2].splitlines()[-1],original[2].splitlines()[-1])
        self.assertIsNotNone(m.qualifier_marker_record(wrapped[2],binding,self.KEY))

    def test_explicit_identity_and_new_map_are_safe_and_never_relabel_runtime(self):
        m=self.api();identity=m.qualifier_artifacts(HERE,APP)['identity'];result=m.public_result({'status':'FAIL','qualifier_identity':identity})
        self.assertEqual(result['source_commit'],m.COMMIT);self.assertEqual(result['qualifier_identity'],identity);self.assertFalse(result['production_qualified'])
        polluted=dict(identity,raw='PRIVATE_SENTINEL');self.assertNotIn('PRIVATE_SENTINEL',json.dumps(m.public_result({'qualifier_identity':polluted})))
        mapping=json.loads((HERE/'qualifier-site-map.json').read_text())
        self.assertEqual(mapping['probe_sha256'],m.QUALIFIER_PROBE_SHA);self.assertEqual(mapping['sites'],{k:list(v) for k,v in m.QUALIFIER_SITES.items()})
        self.assertEqual(m.QUALIFIER_SITES['source_preflight'],(546,554));self.assertNotEqual(m.QUALIFIER_SITES,m.PREFLIGHT_SITES)

    def test_public_qualifier_projection_rejects_non_scalar_schema_and_private_fields(self):
        m=self.api();unknown=m.qualifier_projection(None)
        for action in (None,False,[],{},'PRIVATE_SENTINEL'):
            self.assertEqual(m.qualifier_projection({'action':action,'probe_sha256':m.QUALIFIER_PROBE_SHA,'chain':[],'raw':'PRIVATE_SENTINEL'}),unknown)

    def test_two_delivered_git_blob_digests_and_qualifier_parent_are_explicit(self):
        m=self.api();self.assertEqual(getattr(m,'QUALIFIER_GIT_BLOBS',None),{'qualifier-probe.py':'21db6b0c69b0878d0e2a1c9a50cdf6454e080421','qualifier-tests.py':'9fa43cef416d02e0b0d4b13b74506f351dd9856e'})
        identity=m.qualifier_artifacts(HERE,APP)['identity']
        self.assertEqual(identity['qualifier_parent_commit'],m.COMMIT)
        self.assertEqual(identity['qualifier_tree'],'96c8f8962096cbf809bf372bce73a9390e3be137')
        for name,digest in m.QUALIFIER_GIT_BLOBS.items():
            blob=(HERE/name).read_bytes();self.assertEqual(hashlib.sha1(b'blob '+str(len(blob)).encode()+b'\0'+blob).hexdigest(),digest)

    def controller_seed_failure(self,root,tree=None,tamper=None):
        m=self.api();root=root.resolve();c=m.Coordinator(baseline_tests.admission(),APP,HERE,root/'private',root/'public');c.root.mkdir(mode=0o700);c.source=self.VM;c.token=self.TOKEN;c.bundle=root/'bundle';c.key=root/'key';c.boundary('prepare');events=[]
        def transport(args,**kwargs):
            events.append(list(args))
            if args[0]=='bash':return subprocess.CompletedProcess(args,0,'','')
            if args[0]=='ssh-keygen':Path(str(args[-1])+'.pub').write_text('ssh-ed25519 OFFLINE');return subprocess.CompletedProcess(args,0,'','')
            action=json.loads(kwargs['input'])['action'];code,out,err,_=self.guest(args[-1],kwargs['input'],'success' if action=='source-preflight' else 'command')
            return subprocess.CompletedProcess(args,code,out,err)
        owner=self
        class Boundary:
            def __init__(self):self.rows=[];self.counter=0;self.env={}
            def output(self,stage,args):self.counter+=1;self.rows.append({'stage':stage,'exit_code':0});return json.dumps(owner.config())
            def call(self,stage,args):
                self.counter+=1;out,err=io.StringIO(),io.StringIO();code=0
                with patch.object(subprocess,'run',side_effect=transport),patch.object(sys,'argv',['-c',*map(str,args[5:])]),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                    try:exec(args[4],{'__name__':'__main__'})
                    except SystemExit as error:code=error.code
                folder=c.root/'logs';folder.mkdir(mode=0o700);p=folder/(str(self.counter)+'-prepare.stderr');p.write_text(err.getvalue());p.chmod(0o600)
                if tamper:tamper(Path(args[9]))
                row={'stage':stage,'exit_code':code,'owned_group_empty':True,'leader_reaped':True,'timed_out':False,'interrupted':False};row.update(tree or {});self.rows.append(row)
                raise m.Refusal('PRIVATE_SENTINEL')
        c.run=Boundary()
        with self.assertRaises(m.Refusal) as caught:c.prepare()
        c.remember_failure(caught.exception);c.capture_primary(caught.exception);c.state['stages']=c.run.rows
        return m.public_result(c.state),c,events

    def test_actual_coordinator_projects_seed_trace_only_after_fresh_drained_child_and_freezes_primary(self):
        with tempfile.TemporaryDirectory() as td:
            result,c,events=self.controller_seed_failure(Path(td));diagnostic=result['primary_outcome']['preparation_diagnostic']
            self.assertEqual(diagnostic['stage'],'source-php-preparation-and-seed');self.assertEqual(diagnostic['qualifier_probe']['action'],'seed');self.assertEqual(diagnostic['qualifier_probe']['chain'][0],{'function':'seed','line':677});self.assertEqual(len(events),4)
            c.boundary('cleanup');c.cleanup_failure('source',module().Refusal('PRIVATE_SENTINEL'));later=module().public_result(c.state)
            self.assertEqual(later['primary_outcome'],result['primary_outcome']);self.assertNotIn('qualifier_probe',json.dumps(later['cleanup_outcome']));self.assertNotIn('PRIVATE_SENTINEL',json.dumps(later))

    def test_seed_companion_is_not_projected_for_nonfresh_undrained_zero_interrupted_or_timeout_child(self):
        def nonce(path):row=json.loads(path.read_text());row['marker']['payload']['binding']['nonce']='d8'*16;private(path,row)
        for tree,tamper in [({'owned_group_empty':False},None),({'leader_reaped':False},None),({'exit_code':0},None),({'timed_out':True},None),({'interrupted':True},None),(None,lambda p:p.unlink()),(None,nonce)]:
            with self.subTest(tree=tree,tamper=bool(tamper)),tempfile.TemporaryDirectory() as td:
                result,_,_=self.controller_seed_failure(Path(td),tree=tree,tamper=tamper)
                self.assertEqual(result['primary_outcome']['preparation_diagnostic'].get('qualifier_probe',{'chain':'UNKNOWN'})['chain'],'UNKNOWN')

    def test_admission_requires_separate_qualifier_C_pins_and_exact_original175_inventory(self):
        m=self.api()
        for change in (lambda a:a.pop('qualifier'),lambda a:a['qualifier'].update(qualifier_commit=m.COMMIT),lambda a:a['controller_files'].pop('qualifier-probe.py'),lambda a:a['controller_files'].update({'qualifier-tests.py':'0'*64}),lambda a:a['app_helpers'].update({'deploy/multipass/ubuntu-forward-migration-probe.py':m.QUALIFIER_PROBE_SHA}),lambda a:a['app_helpers'].pop('deploy/multipass/ubuntu-forward-migration-probe.py')):
            value=baseline_tests.admission();change(value)
            with tempfile.TemporaryDirectory() as td:
                p=private(Path(td)/'admission.json',value)
                with self.assertRaises(m.Refusal):m.read_admission(p,m.sha(p),now=m.instant('2026-10-20T01:00:00Z'))

    def test_owned_execution_custody_budgets_and_other_application_commands_are_unchanged(self):
        m=self.api();old=ast.parse((HERE.parent/'forward-hosted-candidate26-v6/forward_hosted.py').read_text());new=ast.parse((HERE/'forward_hosted.py').read_text())
        def definitions(tree):return {n.name:ast.dump(n,include_attributes=False) for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        a,b=definitions(old),definitions(new)
        for name in ('Budget','Runner','owned_action','terminate_owned','check_positive','check_negative','check_paths','observed_prepare','preflight_guest_program','preflight_projection','preflight_marker_record','preflight_companion'):
            if name in a:self.assertEqual(a[name],b[name],name)
        self.assertIn("scope['observed_qualifier_prepare']",m.PREPARE_LAUNCHER)
        oldc=next(n for n in old.body if isinstance(n,ast.ClassDef) and n.name=='Coordinator');newc=next(n for n in new.body if isinstance(n,ast.ClassDef) and n.name=='Coordinator');before={n.name:ast.dump(n,include_attributes=False) for n in oldc.body if isinstance(n,ast.FunctionDef)};after={n.name:ast.dump(n,include_attributes=False) for n in newc.body if isinstance(n,ast.FunctionDef)}
        for name,value in before.items():
            if name not in ('setup','prepare'):self.assertEqual(value,after[name],name)

    def test_canonical_debian_wrapper_original_guard_fails_and_corrected_path_reaches_seed(self):
        self.canonical_roundcube=True
        with tempfile.TemporaryDirectory() as td:
            old=Path(td)/'old';new=Path(td)/'new';old.mkdir(mode=0o700);new.mkdir(mode=0o700)
            m,code,out,err,calls,p=self.host(old,legacy=True)
            self.assertEqual(code,1);self.assertEqual([a[0] for a,k in calls],['bash','multipass'])
            self.assertEqual(m.preflight_companion(p,self.NONCE,220,self.KEY)['chain'],[{'function':'source_preflight','line':538},{'function':'roundcube_preflight','line':242}])
            control=os.environ.get('FORWARD_V7_CANONICAL_CONTROL_ORIGINAL')=='1'
            m,code,out,err,calls,p=self.host(new,legacy=control)
            self.assertEqual([a[0] for a,k in calls],['bash','multipass','ssh-keygen','multipass'])
            self.assertEqual(code,1)  # Intentional fake PG failure after both SQLite preflights.
            record=m.qualifier_companion(p,self.NONCE,220,self.KEY,self.VM,self.TOKEN)
            self.assertEqual(record['action'],'seed');self.assertEqual(record['chain'][0],{'function':'seed','line':677})

    def test_corrected_trace_retains_only_actual_comprehension_frames_per_interpreter(self):
        m=self.api();config=self.config();source=(HERE/'qualifier-probe.py').read_text();binding=m.qualifier_binding(self.NONCE,220,'source-preflight',1,config)
        code,out,err,_=self.guest(m.qualifier_guest_program(source,binding,self.KEY),json.dumps({'action':'source-preflight','config':config}),'malformed-selected')
        function=next(item for item in compile(source,'<qualifier>','exec').co_consts if getattr(item,'co_name',None)=='assert_fixture_php_inventory')
        chain=[{'function':'source_preflight','line':549},{'function':'assert_fixture_php_inventory','line':402}]
        if any(getattr(item,'co_name',None)=='<setcomp>' and item.co_firstlineno==402 for item in function.co_consts):chain.append({'function':'assert_fixture_php_inventory.<setcomp>','line':402})
        self.assertEqual(code,1);record=m.qualifier_marker_record(err,binding,self.KEY);self.assertIsNotNone(record);self.assertEqual(record['payload']['chain'],chain)


if __name__=='__main__':unittest.main()
