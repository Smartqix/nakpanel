import copy, hashlib, importlib.util, json, os, signal, subprocess, sys, tempfile, threading, time, unittest, zipfile, tarfile, io
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
_MODULE=None

def module():
    global _MODULE
    if _MODULE is not None:return _MODULE
    path=HERE/'forward_hosted.py'
    if not path.exists(): raise AssertionError('the fixed hosted coordinator has not been implemented')
    s=importlib.util.spec_from_file_location('forward_hosted_under_test',path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);_MODULE=m;return m

def private(path,data):
    path.write_text(json.dumps(data));path.chmod(0o600);return path

def admission():
    result={'schema':'nakpanel-hosted-forward-admission-v1','state':'AUTHORIZED','source_commit':'1627bba3c681a884255eb91452dbba74a43ebbdc','source_tree':'fc003d27bc7e0fc13d095a4ebc464b17471dc26f','controller_commit':'b'*40,'valid_from':'2026-10-20T00:00:00Z','expires_at':'2026-10-20T02:00:00Z','nonce':'c'*32,'repository':'Smartqix/nakpanel','baseline_reviews':{'native24':'dcefa079e44d23d1f6fc9514b32f1be399d3bc7c89190e1f8028dd5cf17c8a18','native26':'f230cba666f3edbdc2fdca18a43e070d13d5b53fbe9fdd10c6aae2e4cabf4a3d','required_ci':'d020396446bb2368b90a7c146e3ff26749eb1aa27eb6b580b97757b58837918b','payload':'3dff375db5cb83a6afa2c54a07d76301a10087d8adaa319bebb108e93c91faf4'},'artifact':{'id':123,'run_id':456,'name':'synthetic-fixture','size':100,'sha256':'d'*64,'expires_at':'2026-10-21T00:00:00Z'},'payload':{'archive':'candidate/nakpanel-29.0.0-linux-amd64.tar.gz','archive_size':80,'archive_sha256':'e'*64,'manifest_sha256':'50a0cc9802629bcdecb50f26a64f0ec8e49a434856f3f3aabb8e36650e8a60cc','public_key_sha256':'043971dd64ac6b9868e3d9f6cf29c852548e8f32276822187c66c2d40656ba61','binaries':{'panel':'535185eb683942313793bcf833f6e71d481a0cf12149103711d1f0e68a0d9c5f','agent':'9dea11b8ddb98e0f21863747d50c5778ab6629b1406a2cb0971b876ccf12fd4c','panelctl':'44319f18d64575dc46afc48d24115634a81e63925a567d9420634cdaf212fc60'}},'oci_image_ref':'docker.io/library/nginx@sha256:'+'5'*64,'authority':{'scope':'fresh-synthetic-native-forward-only','maximum_guests':2,'cpus':2,'memory':'5G','disk':'32G','production':False},'controller_files':{'forward_hosted.py':'6'*64},'app_helpers':{'deploy/multipass/common.sh':'7'*64}}

    result['qualifier']=dict(module().QUALIFIER_IDENTITY)
    result['controller_files'].update({k:v[0] for k,v in module().QUALIFIER_FILES.items()})
    result['app_helpers']=json.loads((HERE.parent/'forward-hosted-candidate26-v3/SOURCE-INPUTS.json').read_text())['app_helpers']
    return result

class AdmissionTests(unittest.TestCase):
    def checked(self,item,change=None):
        m=module()
        with tempfile.TemporaryDirectory() as td:
            p=private(Path(td)/'admission.json',item)
            if change:change(p)
            return m.read_admission(p,hashlib.sha256(p.read_bytes()).hexdigest(),now=m.instant('2026-10-20T01:00:00Z'))
    def test_pending_refuses_before_external_or_credentials(self):
        m=module()
        with tempfile.TemporaryDirectory() as td:
            p=private(Path(td)/'a.json',{'schema':'nakpanel-hosted-forward-admission-v1','state':'PENDING'})
            with patch.object(m.subprocess,'Popen',side_effect=AssertionError('external call')),patch.dict(os.environ,{},clear=True):
                with self.assertRaises(m.Refusal):m.read_admission(p,hashlib.sha256(p.read_bytes()).hexdigest())
    def test_declared_utc_fraction_precisions_work_on_actual_python39(self):
        m=module()
        for fraction,want in [('1',100000),('12',120000),('123',123000),('1234',123400),('12345',123450),('123456',123456)]:
            with self.subTest(fraction=fraction):self.assertEqual(m.instant('2026-10-20T01:00:00.'+fraction+'Z').microsecond,want)
    def test_complete_explicit_admission_is_data_only(self):self.assertEqual(self.checked(admission())['authority']['maximum_guests'],2)
    def test_selected_payload_must_be_the_exact_accepted_native_bytes(self):
        for leaf in ('manifest_sha256','public_key_sha256','panel','agent','panelctl'):
            a=admission()
            if leaf in a['payload']['binaries']:a['payload']['binaries'][leaf]='0'*64
            else:a['payload'][leaf]='0'*64
            with self.subTest(leaf=leaf),self.assertRaises(module().Refusal):self.checked(a)
    def test_schema_types_scope_expiry_and_baseline_mismatch_refuse(self):
        cases=[('source_commit','a'*40),('source_tree','a'*40),('schema','other'),('state','PENDING'),('expires_at','2026-10-19T23:00:00Z'),('expires_at','tomorrow'),('controller_commit',None),('authority',None),('artifact',None),('extra','field'),('repository','somebody/other')]
        for key,value in cases:
            a=admission();a[key]=value
            with self.subTest(key=key),self.assertRaises(module().Refusal):self.checked(a)
        for edit in (lambda a:a['artifact'].update(id=True),lambda a:a['authority'].update(maximum_guests=3),lambda a:a['authority'].update(production=True),lambda a:a['baseline_reviews'].update(native24='0'*64),lambda a:a['payload']['binaries'].update(other='0'*64),lambda a:a.update(oci_image_ref='docker.io/library/nginx:latest')):
            a=admission();edit(a)
            with self.assertRaises(module().Refusal):self.checked(a)
    def test_out_of_band_hash_private_mode_and_duplicate_json_required(self):
        m=module()
        with tempfile.TemporaryDirectory() as td:
            p=private(Path(td)/'a.json',admission())
            with self.assertRaises(m.Refusal):m.read_admission(p,'0'*64)
            p.chmod(0o644)
            with self.assertRaises(m.Refusal):m.read_admission(p,hashlib.sha256(p.read_bytes()).hexdigest())
            p.chmod(0o600);p.write_text('{"state":"PENDING","state":"AUTHORIZED"}')
            with self.assertRaises(m.Refusal):m.read_admission(p,hashlib.sha256(p.read_bytes()).hexdigest())
    def test_artifact_metadata_must_match_digest_size_identity_and_current_expiry(self):
        m=module();a=admission();row={'id':123,'name':'synthetic-fixture','size_in_bytes':100,'digest':'sha256:'+'d'*64,'expired':False,'expires_at':'2026-10-21T00:00:00Z','workflow_run':{'id':456,'head_sha':a['source_commit']}}
        m.check_artifact(row,a,now=m.instant('2026-10-20T01:00:00Z'))
        for key,value in [('id',124),('size_in_bytes',99),('digest','sha256:'+'0'*64),('expired',True),('expired',0),('expires_at','2020-01-01T00:00:00Z'),('workflow_run',{'id':456,'head_sha':'a'*40})]:
            r=copy.deepcopy(row);r[key]=value
            with self.subTest(key=key),self.assertRaises(m.Refusal):m.check_artifact(r,a,now=m.instant('2026-10-20T01:00:00Z'))
    def test_budget_rejects_old_dr_proof_and_any_capacity_shortfall(self):
        m=module();r={'architecture':'x86_64','cpu_count':4,'total_memory':16*2**30,'available_memory':12*2**30,'free_disk':90*2**30,'kvm_api':12,'status':'PASS'}
        m.check_capacity(r)
        for key,value in [('available_memory',10*2**30),('free_disk',79*2**30),('cpu_count',3),('kvm_api',None),('status','FAIL')]:
            q=dict(r);q[key]=value
            with self.subTest(key=key),self.assertRaises(m.Refusal):m.check_capacity(q)
    def test_unknown_or_foreign_ownership_never_allows_cleanup(self):
        m=module()
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'owner';p.write_text('24.04\tamd64\towned-token\n');p.chmod(0o600)
            m.check_owner(p,'24.04','owned-token')
            for text in ('26.04\tamd64\towned-token\n','24.04\tamd64\tforeign-token\n','24.04\tarm64\towned-token\n',''):
                p.write_text(text)
                with self.assertRaises(m.Refusal):m.check_owner(p,'24.04','owned-token')
    def test_negative_is_exact_real_php_refusal_not_unrelated_traceback(self):
        m=module();m.check_negative(1,'panelctl: target lacks required hosted PHP 8.3; tenant intent cannot be rewritten\n',['8.3','8.4'])
        for code,text in [(0,'target lacks required hosted PHP 8.3; tenant intent cannot be rewritten'),(1,'Traceback: version8.3 failed'),(1,'target lacks required hosted PHP 8.2; tenant intent cannot be rewritten'),(1,'postgres unavailable'),(1,'error: target lacks required hosted PHP 8.3; tenant intent cannot be rewritten')]:
            with self.assertRaises(m.Refusal):m.check_negative(code,text,['8.3','8.4'])
    def test_projection_never_copies_child_data_or_secrets(self):
        m=module();s=m.public_result({'status':'FAIL','failure_code':'stage_failed','run_token':'owned-token','source_vm':'nakpanel-source','secret':'PRIVATE_SENTINEL','stderr':'PRIVATE_SENTINEL','archive_key':'PRIVATE_SENTINEL','stages':[{'stage':'prepare','exit_code':1,'stdout':'PRIVATE_SENTINEL'}]})
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(s));self.assertEqual(s['status'],'FAIL');self.assertFalse(s['production_qualified'])
    def test_public_failure_does_not_claim_an_unperformed_reboot_and_reports_measured_budget(self):
        m=module();state={'status':'FAIL','source_vm':'nakpanel-24-04-amd64-owned-token','negative_vm':'nakpanel-negative-owned-token','run_token':'owned-token','workflow_run_id':'123','actual_guest_allocations':[{'role':'source','vm':'nakpanel-24-04-amd64-owned-token','cpu_count':2,'memory_bytes':5368709120,'root_disk_bytes':32000000000}],'host_admission':{'cpu_count':4,'total_memory':16*2**30,'available_memory':12*2**30,'free_disk':90*2**30,'kvm_api':12,'private':'PRIVATE_SENTINEL'}}
        r=m.public_result(state);self.assertEqual(r['target_reboots'],0);self.assertEqual(r['planned_target_reboots'],1);self.assertEqual(r['source_vm'],state['source_vm']);self.assertEqual(r['actual_guest_allocations'][0]['memory_bytes'],5368709120);self.assertEqual(r['host_admission']['free_disk'],90*2**30);self.assertNotIn('PRIVATE_SENTINEL',json.dumps(r))
    def test_extraction_rejects_duplicate_traversal_symlink_and_unlisted_inventory(self):
        m=module()
        for name in ('../escape','/absolute','candidate/../escape'):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as td:
                p=Path(td)/'x.zip'
                with zipfile.ZipFile(p,'w') as z:z.writestr(name,b'bad')
                with self.assertRaises(m.Refusal):m.extract_zip(p,Path(td)/'out')
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'x.tar.gz'
            with tarfile.open(p,'w:gz') as t:
                i=tarfile.TarInfo('link');i.type=tarfile.SYMTYPE;i.linkname='/etc/passwd';t.addfile(i)
            with self.assertRaises(m.Refusal):m.extract_tar(p,Path(td)/'out')
    def test_cloud_archive_hashing_is_streamed_with_bounded_reads(self):
        m=module()
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'large';p.write_bytes(b'a'*1000000)
            with patch.object(m.Path,'read_bytes',side_effect=AssertionError('whole-file allocation forbidden')):
                self.assertEqual(m.sha(p),'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0')
    def test_existing_and_changed_frozen_inputs_reject(self):
        m=module()
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'input';p.write_bytes(b'original');p.chmod(0o600);pins={str(p):hashlib.sha256(b'original').hexdigest()};m.check_pins(pins);p.write_bytes(b'drift')
            with self.assertRaises(m.Refusal):m.check_pins(pins)
    def test_stage_budget_caps_fit_workflow_and_deadline_reserves_cleanup(self):
        m=module();self.assertLessEqual(sum(m.CAPS.values()),342*60);self.assertLess(m.TOTAL_SECONDS,360*60)
        b=m.Budget(start=100,clock=lambda:100);self.assertLessEqual(b.allowance('positive'),m.CAPS['positive'])
        b=m.Budget(start=100,clock=lambda:100+m.TOTAL_SECONDS-m.CAPS['cleanup']-1)
        with self.assertRaises(m.Refusal):b.allowance('positive')
        self.assertGreater(b.allowance('cleanup'),0)

class AdditionalBoundaryTests(unittest.TestCase):
    def test_checkout_and_output_roots_cannot_overlap_or_escape_runner(self):
        m=module()
        with tempfile.TemporaryDirectory() as td:
            r=Path(td).resolve();app=r/'app';ctrl=r/'controller';temp=r/'temp'
            for p in (app,ctrl,temp):p.mkdir()
            m.check_paths(app,ctrl,temp/'private',temp/'public',temp)
            for values in [(app,app,temp/'p',temp/'q',temp),(app,app/'nested',temp/'p',temp/'q',temp),(app,ctrl,app/'p',temp/'q',temp),(app,ctrl,temp/'same',temp/'same',temp)]:
                with self.assertRaises(m.Refusal):m.check_paths(*values)
    def test_public_flags_cannot_smuggle_arbitrary_child_strings(self):
        m=module();r=m.public_result({'status':'FAIL','stages':[{'stage':'prepare','exit_code':1,'owned_group_empty':'PRIVATE_SENTINEL','interrupted':'PRIVATE_SENTINEL'}]})
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(r))
    def test_positive_requires_authentic_compatible_summary_and_same_manifest(self):
        m=module();manifest={'platform':{'architecture':'amd64','profile':'ubuntu-24.04','version_id':'24.04','internal_php_version':'8.3','php_inventory_complete':True,'required_php_versions':['8.5']},'format_version':2,'include_mail_data':True,'roundcube_sqlite_path':'/var/lib/roundcube/roundcube.sqlite'}
        pre={'compatible':True,'mode':'forward-migration','migration_qualified':False,'manifest':manifest};result={'schema_mismatch':False,'services_started':['nakpanel.service'],'summary':{'extracted_entries':10,'mariadb_restored':['np_forward_fixture'],'schema_mismatch':False,'services_started':['nakpanel.service'],'manifest':manifest}}
        m.check_positive(pre,result)
        badpre,badresult=copy.deepcopy(pre),copy.deepcopy(result);badpre['manifest']['include_mail_data']=False;badresult['summary']['manifest']['include_mail_data']=False
        with self.assertRaises(m.Refusal):m.check_positive(badpre,badresult)
        for change in (lambda p,r:p.update(compatible=False),lambda p,r:p['manifest']['platform'].update(required_php_versions=['8.3','8.5']),lambda p,r:r['summary'].update(extracted_entries=True),lambda p,r:r.update(schema_mismatch=True),lambda p,r:r['summary'].update(mariadb_restored=[]),lambda p,r:p['manifest'].update(include_mail_data=False)):
            pp,rr=copy.deepcopy(pre),copy.deepcopy(result);change(pp,rr)
            with self.assertRaises(m.Refusal):m.check_positive(pp,rr)
    def test_work_stage_cannot_borrow_cleanup_reserve_after_command(self):
        m=module();t=[0];b=m.Budget(clock=lambda:t[0]);b.allowance('positive');t[0]=m.TOTAL_SECONDS-m.CAPS['cleanup']+.1
        with self.assertRaises(m.Refusal):b.check('positive')
        b.check('cleanup')

class OwnedProcessTests(unittest.TestCase):
    def run_action(self,program,timeout=2,publish_hook=None):
        m=module();td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name);root.chmod(0o700)
        state={'operation':'prepare','stage':'prepare'};B={'source_vm':'TEST-ONLY-NO-VM','run_token':'TEST-ONLY-NO-TOKEN','source_payload':{'commit':'a'*40}}
        out=open(root/'out','wb');self.addCleanup(out.close)
        caught=None
        try:
            with patch.object(m,'publish',side_effect=publish_hook or m.publish):m.owned_action(B,root,state,[sys.executable,'-I','-B','-c',program],dict(os.environ),stdout=out,stderr=out,timeout=timeout,term_grace=.3,kill_grace=1)
        except BaseException as e:caught=e
        receipts=list((root/'actions').glob('*.json'));self.assertEqual(len(receipts),1);return m,json.loads(receipts[0].read_text()),caught,state
    def test_group_probe_permission_denied_stays_present_not_empty(self):
        m=module()
        with patch.object(m.os,'killpg',side_effect=PermissionError):self.assertTrue(m.group_exists(99999999))
    def test_real_success_and_nonzero_retained(self):
        for code in (0,7):
            m,r,e,s=self.run_action('raise SystemExit('+str(code)+')');self.assertEqual(r['exit_code'],code);self.assertTrue(r['owned_group_empty']);self.assertTrue(r['leader_reaped']);self.assertEqual(e is None,code==0)
    def test_real_timeout_reaps_owned_group(self):
        m,r,e,s=self.run_action('import time;time.sleep(20)',timeout=.5);self.assertIsNotNone(e);self.assertTrue(r['timed_out'],r);self.assertTrue(r['owned_group_empty'],r);self.assertFalse(m.group_exists(r['action_pgid']),r)
    def test_actual_sigterm_during_success_publication_is_failed(self):
        m=module();fired=[];real=m.publish
        def publish(path,value):
            if value.get('status')=='passed' and not fired:fired.append(True);os.kill(os.getpid(),signal.SIGTERM)
            real(path,value)
        # Run exact module and handler in one object; no real transport.
        with tempfile.TemporaryDirectory() as td:
            B={'source_vm':'TEST-ONLY','run_token':'TEST-ONLY','source_payload':{'commit':'a'*40}};state={'operation':'prepare'}
            with patch.object(m,'publish',side_effect=publish),self.assertRaises(KeyboardInterrupt):m.owned_action(B,Path(td),state,[sys.executable,'-I','-B','-c','pass'],dict(os.environ),timeout=2)
            r=json.loads(next((Path(td)/'actions').glob('*.json')).read_text());self.assertEqual(r['status'],'failed');self.assertTrue(r['interrupted']);self.assertEqual(r['termination_signal'],15)
    def test_real_grandchild_is_empty_before_caller_can_cleanup(self):
        code="import subprocess,sys,signal,time,os\nc=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])\ndef stop(a,b):\n c.terminate();c.wait();raise SystemExit(9)\nsignal.signal(signal.SIGTERM,stop)\nprint(c.pid,flush=True)\ntime.sleep(30)"
        m,r,e,s=self.run_action(code,timeout=.12);self.assertIsNotNone(e);self.assertTrue(r['owned_group_empty']);self.assertTrue(r['leader_reaped']);self.assertFalse(m.group_exists(r['action_pgid']))
    def test_normal_zero_with_background_descendant_is_failed_and_drained(self):
        code="import subprocess,sys;subprocess.Popen([sys.executable,'-c','import time;time.sleep(5)'])"
        m,r,e,s=self.run_action(code);self.assertIsNotNone(e);self.assertTrue(r['unexpected_descendants']);self.assertTrue(r['owned_group_empty']);self.assertTrue(r['leader_reaped']);self.assertFalse(m.group_exists(r['action_pgid']))
    def test_actual_signal_during_startup_is_deferred_until_owned_child_is_known(self):
        m=module();real=m.subprocess.Popen;before={s:signal.getsignal(s) for s in (signal.SIGINT,signal.SIGTERM)}
        with tempfile.TemporaryDirectory() as td:
            state={'operation':'prepare'};B={'source_vm':'TEST','run_token':'TEST','source_payload':{'commit':'a'*40}}
            def start(*a,**kw):os.kill(os.getpid(),signal.SIGTERM);return real(*a,**kw)
            with patch.object(m.subprocess,'Popen',side_effect=start),self.assertRaises(KeyboardInterrupt):m.owned_action(B,Path(td),state,[sys.executable,'-I','-B','-c','import time;time.sleep(5)'],dict(os.environ),timeout=2)
            row=state['action_tree'];self.assertTrue(row['interrupted']);self.assertTrue(row['owned_group_empty']);self.assertTrue(row['leader_reaped']);self.assertEqual(row['status'],'failed')
        self.assertEqual({s:signal.getsignal(s) for s in before},before)
    def test_atomic_publication_cancellation_leaves_no_fixed_temp(self):
        m=module()
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'receipt.json';m.publish(p,{'status':'STARTED'});real=os.fsync
            with patch.object(m.os,'fsync',side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):m.publish(p,{'status':'PASS'})
            self.assertEqual(json.loads(p.read_text()),{'status':'STARTED'});self.assertEqual(sorted(x.name for x in Path(td).iterdir()),['receipt.json']);m.publish(p,{'status':'FAIL'})


class SourceAndWorkflowTests(unittest.TestCase):
    def test_workflow_pending_shell_refuses_without_external_calls(self):
        w=json.loads((HERE/'workflow.yml').read_text());step=w['jobs']['forward']['steps'][0];self.assertEqual(w['on'],{'workflow_dispatch':{}})
        with tempfile.TemporaryDirectory() as td:
            marker=Path(td)/'external';p=Path(td)/'multipass';p.write_text('#!/bin/sh\necho called > "'+str(marker)+'"\n');p.chmod(0o700)
            env=dict(os.environ,CONTROLLER_SHA='PENDING',ROOT_ADMISSION_SHA256='PENDING',PATH=td+':'+os.environ['PATH'])
            bash='/Users/rickynkansah/.local/state/nakpanel/qualification/2026-10-18/toolchains/bash-5.3.20/bin/bash'
            result=subprocess.run([bash,'-c',step['run']],env=env,capture_output=True,text=True);self.assertNotEqual(result.returncode,0);self.assertFalse(marker.exists())
    def test_workflow_uses_fixed_original_app_and_no_upload_of_private_tree(self):
        w=json.loads((HERE/'workflow.yml').read_text());j=w['jobs']['forward'];steps=j['steps'];checkout=[s for s in steps if s.get('uses','').startswith('actions/checkout')];self.assertEqual([s['with']['path'] for s in checkout],['controller','application']);self.assertEqual(checkout[1]['with']['ref'],'1627bba3c681a884255eb91452dbba74a43ebbdc');self.assertEqual(j['timeout-minutes'],360)
        uploads=[s for s in steps if s.get('uses','').startswith('actions/upload-artifact')];self.assertEqual(len(uploads),1);self.assertEqual(uploads[0]['with']['path'],'${{ runner.temp }}/forward-public/result.json')
    def test_real_coordinator_checkout_checker_compares_committed_helper_bytes(self):
        m=module()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve();app=root/'app';ctrl=root/'ctrl';app.mkdir();ctrl.mkdir();names=['deploy/multipass/common.sh','deploy/release/verify.py','deploy/install/platform.sh','deploy/install/platform_state.py'];blobs={n:('committed '+n+'\n').encode() for n in names};pins={}
            for n,b in blobs.items():p=app/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b);pins[n]=hashlib.sha256(b).hexdigest()
            class GitBoundary:
                count=0
                def output(self,stage,args):
                    cmd=list(map(str,args))[3:]
                    if cmd==['rev-parse','HEAD']:return m.COMMIT+'\n'
                    if cmd==['rev-parse','HEAD^{tree}']:return m.TREE+'\n'
                    if cmd[0]=='status':return ''
                    if cmd[0]=='ls-files':return 'deploy/multipass/common.sh\0'
                    raise AssertionError(cmd)
                def call(self,stage,args):
                    self.count+=1;n=str(args[-1]).split(':',1)[1];out=root/('git-'+str(self.count));out.write_bytes(blobs[n]);return 0,out,out
            c=m.Coordinator(admission(),app,ctrl,root/'p',root/'q');c.run=GitBoundary();c.checkout(app,m.COMMIT,m.TREE,pins)
            (app/names[0]).write_bytes(b'changed behavior')
            with self.assertRaises(m.Refusal):c.checkout(app,m.COMMIT,m.TREE,pins)
            with self.assertRaises(m.Refusal):c.checkout(app,m.COMMIT,m.TREE,{names[0]:pins[names[0]]})

class ExecutionTests(unittest.TestCase):
    def harness(self,root,fail=None,signal_at=None):
        m=module();events=[]
        class BoundaryHarness(m.Coordinator):
            def setup(self):
                self.root.mkdir(mode=0o700);self.public.mkdir(mode=0o700);self.private_created=True;self.public_created=True
                self.run=type('PrivateNoTransport',(),{'rows':[],'last_tree_empty':True,'budget':m.Budget()})()
            def invoke(self,name):
                events.append(name)
                if signal_at==name:os.kill(os.getpid(),signal.SIGTERM)
                if fail==name:raise m.Refusal('PRIVATE_SENTINEL raw child failure')
            def acquire(self):self.invoke('artifact')
            def host_prepare(self):self.invoke('host')
            def images(self):self.invoke('images')
            def source_phases(self):self.invoke('source')
            def negative_backup(self):self.invoke('negative-backup')
            def prepare(self):self.invoke('prepare')
            def negative_target(self):self.invoke('negative-target')
            def positive(self):self.invoke('positive');self.state.update(ordered_negative_check_only=True,positive_restore_verified=True,source_unchanged=True,target_reboot_verified=True)
            def cleanup(self):self.invoke('cleanup');self.state['cleanup_completed']=True
        return m,BoundaryHarness(admission(),root/'app',root/'controller',root/'private',root/'public'),events
    def test_fixed_flow_is_serial_and_cleanup_precedes_public_pass(self):
        with tempfile.TemporaryDirectory() as td:
            m,c,events=self.harness(Path(td));result=c.execute();self.assertEqual(result['status'],'PASS');self.assertEqual(events,['artifact','host','images','source','negative-backup','prepare','negative-target','positive','cleanup']);self.assertTrue(json.loads((c.public/'result.json').read_text())['cleanup_completed'])
    def test_failure_cleans_up_once_and_never_emits_private_error(self):
        with tempfile.TemporaryDirectory() as td:
            m,c,events=self.harness(Path(td),fail='prepare')
            with self.assertRaises(m.Refusal):c.execute()
            public=(c.public/'result.json').read_text();self.assertNotIn('PRIVATE_SENTINEL',public);self.assertEqual(events.count('cleanup'),1);self.assertNotIn('positive',events);self.assertEqual(json.loads(public)['status'],'FAIL')
    def test_first_real_signal_during_cleanup_cannot_be_ignored_as_pass(self):
        with tempfile.TemporaryDirectory() as td:
            m,c,events=self.harness(Path(td),signal_at='cleanup')
            with self.assertRaises(KeyboardInterrupt):c.execute()
            r=json.loads((c.public/'result.json').read_text());self.assertEqual(r['status'],'FAIL');self.assertEqual(r['failure_code'],'cancelled')
    def test_real_sigterm_at_final_pass_publication_becomes_durable_fail(self):
        with tempfile.TemporaryDirectory() as td:
            m,c,events=self.harness(Path(td));real=m.publish;fired=[]
            def publication(path,value):
                if value.get('status')=='PASS' and not fired:fired.append(True);os.kill(os.getpid(),signal.SIGTERM)
                real(path,value)
            with patch.object(m,'publish',side_effect=publication),self.assertRaises(KeyboardInterrupt):c.execute()
            self.assertEqual(json.loads((c.public/'result.json').read_text())['status'],'FAIL')
    def test_refusing_preexisting_outputs_never_overwrites_their_receipts(self):
        m=module()
        with tempfile.TemporaryDirectory() as td:
            r=Path(td).resolve();app=r/'app';ctrl=r/'ctrl';app.mkdir();ctrl.mkdir();private_root=r/'private';public_root=r/'public';private_root.mkdir();public_root.mkdir()
            old=private_root/'private-result.json';old.write_bytes(b'KEEP PRIVATE');other=public_root/'result.json';other.write_bytes(b'KEEP PUBLIC')
            c=m.Coordinator(admission(),app,ctrl,private_root,public_root,env={'RUNNER_TEMP':str(r)})
            with patch.object(c,'require_live_host'),patch.object(m.subprocess,'Popen',side_effect=AssertionError('no external command')),self.assertRaises(m.Refusal):c.execute()
            self.assertEqual(old.read_bytes(),b'KEEP PRIVATE');self.assertEqual(other.read_bytes(),b'KEEP PUBLIC')
    def test_cleanup_failure_is_not_pass_and_retains_private_raw_files(self):
        with tempfile.TemporaryDirectory() as td:
            m,c,events=self.harness(Path(td),fail='cleanup')
            with self.assertRaises(m.Refusal):c.execute()
            self.assertTrue(c.root.exists());self.assertEqual(json.loads((c.public/'result.json').read_text())['status'],'FAIL')
    def test_runner_fake_transport_preserves_actual_nonzero_and_private_stdin(self):
        m=module()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);root.chmod(0o700);r=m.Runner(root,dict(os.environ),{'source_vm':'FAKE-NO-VM','run_token':'FAKE-NO-TOKEN','source_payload':{'commit':'a'*40}})
            code,out,err=r.call('negative_check',[sys.executable,'-I','-B','-c','import sys;print(sys.stdin.read());print("private failure",file=sys.stderr);raise SystemExit(7)'],data='PRIVATE_SENTINEL',accepted=(7,))
            self.assertEqual(code,7);self.assertEqual(out.read_text().strip(),'PRIVATE_SENTINEL');self.assertEqual(err.read_text().strip(),'private failure');self.assertTrue(r.last_tree_empty);self.assertEqual(r.rows[-1]['exit_code'],7)
    def test_unconfirmed_action_group_prohibits_any_guest_cleanup(self):
        m=module()
        with tempfile.TemporaryDirectory() as td:
            r=Path(td);c=m.Coordinator(admission(),r/'app',r/'ctrl',r/'private',r/'public');c.run=type('NoGuestTransport',(),{'last_tree_empty':False})()
            with self.assertRaises(m.Refusal):c.cleanup()
    def test_cleanup_confirms_absence_without_adopting_or_deleting_unmarked_vm(self):
        m=module()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);c=m.Coordinator(admission(),root/'app',root/'ctrl',root/'private',root/'public');c.token='test-token';c.positive_vm='nakpanel-positive-test';c.source='nakpanel-source-test';c.known={'nakpanel-not-created':'26.04'}
            c.run=type('OnlyReadonlyListing',(),{'last_tree_empty':True,'env':{},'output':lambda *a,**k:'{"errors":[],"list":[]}'})()
            c.delete('nakpanel-not-created','cleanup');self.assertEqual(c.known,{})
    def test_stage_deadlines_are_cumulative_not_restarted_per_command(self):
        m=module();t=[0];b=m.Budget(clock=lambda:t[0]);self.assertEqual(b.allowance('negative_check'),296);t[0]=299
        with self.assertRaises(m.Refusal):b.allowance('negative_check')
    def test_real_pending_cli_cannot_be_enabled_by_environment_flag(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);p=private(root/'pending.json',{'schema':'nakpanel-hosted-forward-admission-v1','state':'PENDING'});calls=root/'external'
            fake=root/'multipass';fake.write_text('#!/bin/sh\necho called >> "'+str(calls)+'"\n');fake.chmod(0o700)
            env=dict(os.environ,PATH=str(root)+':'+os.environ['PATH'],NAKPANEL_FORWARD_AUTHORIZED='1',GH_TOKEN='PRIVATE_SENTINEL')
            r=subprocess.run([sys.executable,'-I','-B',str(HERE/'forward_hosted.py'),'run','--admission',str(p),'--sha256',hashlib.sha256(p.read_bytes()).hexdigest()],env=env,capture_output=True,text=True)
            self.assertNotEqual(r.returncode,0);self.assertFalse(calls.exists());self.assertNotIn('PRIVATE_SENTINEL',r.stdout+r.stderr)

class IndependentReviewRegressionTests(unittest.TestCase):
    def test_actual_setup_and_execute_reaches_callable_positive_dispatch(self):
        m=module();events=[]
        with tempfile.TemporaryDirectory() as td:
            r=Path(td).resolve();(r/'app').mkdir();(r/'controller').mkdir()
            class FakeTransport:
                def __init__(self,root,env,binding):self.env=env;self.rows=[];self.budget=m.Budget();self.last_tree_empty=True
                def output(self,*a,**k):return sys.executable+'\n'
            class ExternalBoundaries(m.Coordinator):
                def require_live_host(self):pass
                def checkout(self,*a):pass
                def acquire(self):pass
                def host_prepare(self):pass
                def images(self):pass
                def source_phases(self):pass
                def negative_backup(self):pass
                def prepare(self):pass
                def negative_target(self):self.state['ordered_negative_check_only']=True
                def positive(self):events.append('actual-dispatch');self.state.update(positive_restore_verified=True,source_unchanged=True,target_reboot_verified=True)
                def cleanup(self):self.state['cleanup_completed']=True
            c=ExternalBoundaries(admission(),r/'app',r/'controller',r/'private',r/'public',env={'RUNNER_TEMP':str(r),'GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1'});c.bash=sys.executable;old=os.umask(0o022)
            try:
                with patch.object(m,'Runner',FakeTransport),patch.object(m,'qualifier_artifacts',return_value={'identity':dict(m.QUALIFIER_IDENTITY)}):result=c.execute()
            finally:os.umask(old)
            self.assertEqual(result['status'],'PASS');self.assertEqual(events,['actual-dispatch']);self.assertTrue(callable(c.positive));self.assertTrue(c.positive_vm.startswith('nakpanel-positive-'))
    def test_actual_delete_final_explicit_error_retains_known_custody(self):
        m=module()
        for final in ({'errors':['PRIVATE_SENTINEL'],'list':[]},{'errors':None,'list':[]}):
            with self.subTest(final=final),tempfile.TemporaryDirectory() as td:
                r=Path(td);c=m.Coordinator(admission(),r/'app',r/'ctrl',r/'private',r/'public');c.token='synthetic-token';c.source='nakpanel-source';c.positive_vm='nakpanel-positive';name='nakpanel-negative';c.known={name:'26.04'}
                p=c.root/'owners'/c.token/name;p.parent.mkdir(parents=True);p.write_text('26.04\tamd64\t'+c.token+'\n');p.chmod(0o600)
                class Listing:
                    env={};last_tree_empty=True;calls=0
                    def output(self,*a,**k):
                        self.calls+=1;return json.dumps({'errors':[],'list':[{'name':name}]} if self.calls==1 else final)
                c.run=Listing();deletes=[];c.shell=lambda *a,**k:deletes.append(True)
                with self.assertRaises(m.Refusal):c.delete(name,'cleanup')
                self.assertIn(name,c.known);self.assertEqual(deletes,[True])
    def test_initial_cleanup_absence_rejects_explicit_error_values(self):
        m=module()
        for initial in ({'errors':['PRIVATE_SENTINEL'],'list':[]},{'errors':None,'list':[]}):
            with self.subTest(initial=initial),tempfile.TemporaryDirectory() as td:
                r=Path(td);c=m.Coordinator(admission(),r/'app',r/'ctrl',r/'private',r/'public');c.known={'nakpanel-owned':'26.04'}
                c.run=type('ReadOnlyListing',(),{'last_tree_empty':True,'output':lambda *a,**k:json.dumps(initial)})()
                with self.assertRaises(m.Refusal):c.delete('nakpanel-owned','cleanup')
                self.assertIn('nakpanel-owned',c.known)
    def positive_case(self,kind):
        m=module()
        with tempfile.TemporaryDirectory() as td:
            r=Path(td);initial='11111111-1111-1111-1111-111111111111';after='22222222-2222-2222-2222-222222222222'
            manifest={'platform':{'architecture':'amd64','profile':'ubuntu-24.04','version_id':'24.04','internal_php_version':'8.3','php_inventory_complete':True,'required_php_versions':['8.5']},'format_version':2,'include_mail_data':kind!='missing-mail','roundcube_sqlite_path':'/var/lib/roundcube/roundcube.sqlite'}
            pre={'compatible':True,'mode':'forward-migration','migration_qualified':False,'manifest':manifest};restored={'schema_mismatch':False,'services_started':['nakpanel.service'],'summary':{'extracted_entries':10,'mariadb_restored':['np_forward_fixture'],'schema_mismatch':False,'services_started':['nakpanel.service'],'manifest':manifest}}
            class Transport:
                env={};budget=m.Budget();last_tree_empty=True
                def __init__(self):self.rows=[]
                def call(self,stage,args,**kw):
                    self.rows.append(dict(stage=stage,exit_code=0,owned_group_empty=True,leader_reaped=True,timed_out=False,interrupted=False));e=r/'private/positive-evidence';e.mkdir(parents=True)
                    for n,name in enumerate(['assert-source-readonly','install-native-target','assert-baseline','assert-migration-data','assert-services','assert-trusted-tls','assert-reboot','assert-migration-data','assert-trusted-tls','assert-no-source-writes'],1):(e/(str(n)+'-'+name+'.log')).write_text('PRIVATE_SENTINEL stage output\n')
                    (e/'restore.json').write_text(json.dumps(restored));(e/'preflight.json').write_text(json.dumps(pre));(e/'initial-target-boot-id').write_text(initial+'\n');return 0,e/'restore.json',e/'restore.json'
            class FixedFlow(m.Coordinator):
                def setup(self):
                    self.root.mkdir();self.public.mkdir();self.private_created=True;self.public_created=True;self.source='nakpanel-source-synthetic';self.negative='nakpanel-negative-synthetic';self.positive_vm='nakpanel-positive-synthetic';self.run=Transport()
                def acquire(self):pass
                def host_prepare(self):pass
                def images(self):pass
                def source_phases(self):pass
                def negative_backup(self):pass
                def prepare(self):pass
                def negative_target(self):self.state['ordered_negative_check_only']=True
                def headroom(self,*a):pass
                def check_new_vm(self,*a):pass
                def observed_budget(self,*a):pass
                def proof(self,name,*a):return {'boot_id':initial if kind=='same-boot' else after}
                def cleanup(self):self.state['cleanup_completed']=True
            c=FixedFlow(admission(),r/'app',r/'ctrl',r/'private',r/'public',env={})
            if kind=='valid':result=c.execute();self.assertEqual(result['status'],'PASS')
            else:
                with self.assertRaises(m.Refusal):c.execute()
            raw=(c.public/'result.json').read_text();self.assertNotIn('PRIVATE_SENTINEL',raw);return json.loads(raw)
    def test_actual_positive_predicate_failures_have_distinct_closed_safe_codes(self):
        valid=self.positive_case('valid');mail=self.positive_case('missing-mail');boot=self.positive_case('same-boot')
        self.assertTrue(valid['positive_restore_verified']);self.assertEqual(mail['failure_predicate'],'positive_mail_data');self.assertEqual(boot['failure_predicate'],'positive_target_reboot');self.assertNotEqual(mail['failure_boundary'],boot['failure_boundary']);self.assertEqual(mail['failure_kind'],'semantic');self.assertEqual(boot['failure_kind'],'semantic');self.assertEqual(mail['stages'][-1]['exit_code'],0)
    def test_unrecognized_diagnostic_fields_remain_unknown_and_private(self):
        m=module();r=m.public_result({'status':'FAIL','current_boundary':'PRIVATE_SENTINEL','last_completed_boundary':'PRIVATE_SENTINEL','failure_boundary':'PRIVATE_SENTINEL','failure_predicate':'PRIVATE_SENTINEL','failure_kind':'PRIVATE_SENTINEL'})
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(r))
        for name in ('current_boundary','last_completed_boundary','failure_boundary','failure_predicate','failure_kind'):self.assertEqual(r[name],'UNKNOWN')
        for value in (None,[],{}):
            q=m.public_result({name:value for name in ('current_boundary','last_completed_boundary','failure_boundary','failure_predicate','failure_kind')})
            for name in ('current_boundary','last_completed_boundary','failure_boundary','failure_predicate','failure_kind'):self.assertEqual(q[name],'UNKNOWN')


class V3ContractTests(unittest.TestCase):
    # All external boundaries are fake; the actual proof/owner/pins/delete/execute run.
    UNITS=['nakpanel.service','nakpanel-agent.service','nginx.service','postgresql.service','mariadb.service','named.service','stalwart-mail.service','nakpanel-proftpd.service']
    def row(self,release='24.04'):
        return {'binaries':dict(module().ACCEPTED_PAYLOAD['binaries']),'architecture':'amd64','platform':{'profile':'ubuntu-24.04' if release=='24.04' else 'ubuntu-26.04-native','version_id':release},'database_fingerprint':'a'*64,'boot_id':'12345678-1234-1234-1234-123456789abc','units':dict.fromkeys(self.UNITS,'active')}
    def make(self,root,m=None):
        m=m or module();c=m.Coordinator(admission(),root/'app',root/'ctrl',root/'private',root/'public',env={});c.root.mkdir(mode=0o700);c.token='synthetic-v3-token';c.source='nakpanel-source';c.negative='nakpanel-negative';c.positive_vm='nakpanel-positive';c._work_operation='UNKNOWN'
        for name,release in ((c.source,'24.04'),(c.negative,'26.04'),(c.positive_vm,'26.04')):
            p=c.root/'owners'/c.token/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(release+'\tamd64\t'+c.token+'\n');p.chmod(0o600)
        pin=c.root/'pin';pin.write_text('fixed bytes');pin.chmod(0o600);c.pins={str(pin):m.sha(pin)}
        c.run=type('NoExternal',(),{'rows':[],'last_tree_empty':True,'budget':m.Budget(),'env':{}})();c._fake_calls=[]
        return c
    def transport(self,c,row):
        def shell(stage,*args,**kw):
            c._fake_calls.append((stage,args,kw));c.run.rows.append({'stage':stage,'exit_code':0,'owned_group_empty':True,'leader_reaped':True,'timed_out':False,'interrupted':False})
            n=len(c._fake_calls);p=c.root/('proof-'+str(n));e=c.root/('err-'+str(n));p.write_text(json.dumps(row));e.write_text('');return 0,p,e
        c.shell=shell
    def outcome(self,c,name,release,stage,frozen=False):
        try:return ('pass',c.proof(name,release,stage,frozen))
        except BaseException as e:return ('Refusal' if isinstance(e,module().Refusal) else type(e).__name__,e)
    def test_seven_policy_requires_actual_internal_role_operation_and_stage(self):
        m=module()
        cases=[('source','source_phases','current',True),('source','source_phases','phase28',True),('source','source_phases','phase30',True),('source','negative_backup','negative_backup',True),('negative','negative_target','negative_check',True),('positive_vm','negative_target','negative_check',False),('positive_vm','source_phases','current',False),('source','positive','current',False),('source','UNKNOWN','current',False),('source','source_phases','negative_check',False),('negative','source_phases','current',False)]
        for role,op,stage,want in cases:
            with self.subTest(role=role,op=op,stage=stage),tempfile.TemporaryDirectory() as td:
                c=self.make(Path(td));name=getattr(c,role);release='24.04' if role=='source' else '26.04';r=self.row(release);r['units'][self.UNITS[-1]]='inactive';self.transport(c,r);c._work_operation=op;c.state['proof_context']='current';c.state['current_boundary']='source'
                kind,_=self.outcome(c,name,release,stage);self.assertEqual(kind=='pass',want);self.assertEqual(len(c._fake_calls),1)
    def test_fixed_executing_action_loop_selects_seven_without_diagnostic_label_authority(self):
        m=module();t=self
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            class Fixed(m.Coordinator):
                def setup(self):
                    seed=t.make(root);self.__dict__.update(seed.__dict__);self.public.mkdir();self.private_created=True;self.public_created=True
                def acquire(self):pass
                def host_prepare(self):pass
                def images(self):pass
                def source_phases(self):
                    r=t.row();r['units'][t.UNITS[-1]]='inactive';t.transport(self,r);self.state['current_boundary']='UNKNOWN';self.proof(self.source,'24.04','current')
                def negative_backup(self):pass
                def prepare(self):pass
                def negative_target(self):
                    r=t.row('26.04');r['units'][t.UNITS[-1]]='inactive';t.transport(self,r);self.proof(self.negative,'26.04','negative_check');self.state['ordered_negative_check_only']=True
                def positive(self):self.state.update(positive_restore_verified=True,source_unchanged=True,target_reboot_verified=True)
                def cleanup(self):self.state['cleanup_completed']=True
            c=Fixed(admission(),root/'app',root/'ctrl',root/'private',root/'public',env={});result=None
            try:result=c.execute()
            except m.Refusal:pass
            self.assertIsNotNone(result);self.assertEqual(result['status'],'PASS')
    def test_optional_ftp_cannot_hide_unhashable_nonstring_missing_core_or_bad_shape(self):
        for value in ([],{},None,0,False):
            with self.subTest(value=value),tempfile.TemporaryDirectory() as td:
                c=self.make(Path(td));c._work_operation='source_phases';r=self.row();r['units'][self.UNITS[-1]]=value;self.transport(c,r);kind,_=self.outcome(c,c.source,'24.04','current');self.assertEqual(kind,'TypeError' if isinstance(value,(list,dict)) else 'Refusal')
        for edit in (lambda u:u.update({'postgresql.service':'inactive'}),lambda u:u.pop('postgresql.service'),lambda u:u.update(other='active')):
            with tempfile.TemporaryDirectory() as td:
                c=self.make(Path(td));c._work_operation='source_phases';r=self.row();r['units'][self.UNITS[-1]]='inactive';edit(r['units']);self.transport(c,r);self.assertEqual(self.outcome(c,c.source,'24.04','current')[0],'Refusal')
    def test_original_real_v2_decision_exception_and_command_parity_except_explicit_deltas(self):
        p=Path('/Users/rickynkansah/.local/state/nakpanel/qualification/2026-10-18/evidence/forward-hosted-candidate26-v2/forward_hosted.py');self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),'66aa4f0b5a03c806e95262bffba0d5619591204fcf9f355e8745b0a192ad5f50');s=importlib.util.spec_from_file_location('immutable_v2_parity',p);old=importlib.util.module_from_spec(s);s.loader.exec_module(old);self.assertEqual(module().PROOF,old.PROOF)
        rows=[self.row(),None,[],dict(self.row(),binaries={},platform=None),dict(self.row(),architecture='bad',platform=None),dict(self.row(),platform=None),dict(self.row(),database_fingerprint=None,boot_id=None),dict(self.row(),boot_id=None)]
        for x in ([],None,0):
            r=self.row();r['units'][self.UNITS[-1]]=x;rows.append(r)
        for i,row in enumerate(rows):
            with self.subTest(case=i):
                outcomes=[];traces=[]
                for m in (old,module()):
                    with tempfile.TemporaryDirectory() as td:
                        c=self.make(Path(td),m);self.transport(c,row)
                        try:c.proof(c.source,'24.04','current');kind='pass'
                        except BaseException as e:kind='Refusal' if isinstance(e,m.Refusal) else type(e).__name__
                        outcomes.append(kind);traces.append([(x[0],x[1][0],x[1][-1]) for x in c._fake_calls])
                self.assertEqual(outcomes[0],outcomes[1]);self.assertEqual(traces[0],traces[1])
    def test_unknown_unhashable_stage_diagnostic_does_not_preempt_original_service_refusal(self):
        for stage in (None,[],{}):
            with self.subTest(stage=stage),tempfile.TemporaryDirectory() as td:
                c=self.make(Path(td));c._work_operation='source_phases';r=self.row();r['units'][self.UNITS[-1]]='inactive';self.transport(c,r)
                kind,_=self.outcome(c,c.source,'24.04',stage);self.assertEqual(kind,'Refusal');self.assertEqual(len(c._fake_calls),1)
    def test_frozen_bypass_remains_even_for_malformed_unit_values(self):
        with tempfile.TemporaryDirectory() as td:
            c=self.make(Path(td));r=self.row();r['units']={'x':[]};self.transport(c,r);self.assertEqual(self.outcome(c,c.source,'24.04','prepare',True)[0],'pass')
    def test_missing_errors_supported_in_initial_and_final_owned_absence(self):
        m=module()
        for initial,final in [({'list':[]},None),({'list':[{'name':'nakpanel-source'}]},{'list':[]})]:
            with self.subTest(initial=initial),tempfile.TemporaryDirectory() as td:
                c=self.make(Path(td));c.known={c.source:'24.04'};rows=[initial]+([final] if final is not None else []);deleted=[];c.run.output=lambda *a,**k:json.dumps(rows.pop(0));c.shell=lambda *a,**k:deleted.append(True)
                error=None
                try:c.delete(c.source,'cleanup')
                except m.Refusal as e:error=e
                self.assertIsNone(error);self.assertNotIn(c.source,c.known);self.assertEqual(deleted,[True] if final is not None else [])
    def test_list_rows_errors_and_duplicates_fail_before_custody_is_dropped(self):
        m=module();bad=[{'list':[],'errors':None},{'list':[],'errors':['PRIVATE_SENTINEL']},{'list':[],'errors':''},{'list':[None]},{'list':[{'name':3}]},{'list':[{'name':''}]},{'list':[{'name':'../private'}]},{'list':[{'name':'same'},{'name':'same'}]},{'list':None}]
        for row in bad:
            with self.subTest(row=row),tempfile.TemporaryDirectory() as td:
                c=self.make(Path(td));c.known={c.source:'24.04'};c.run.output=lambda *a,**k:json.dumps(row);error=None
                try:c.delete(c.source,'cleanup')
                except BaseException as e:error=e
                self.assertIsInstance(error,m.Refusal);self.assertIn(c.source,c.known)
    def test_distinct_source_predicates_and_unexpected_type_remain_safe_unknown(self):
        m=module()
        for edit,want in [(lambda r:r.update(binaries={}), 'source_binary_inventory'),(lambda r:r.update(architecture='bad'),'source_architecture'),(lambda r:r['platform'].update(profile='bad'),'source_profile'),(lambda r:r['platform'].update(version_id='bad'),'source_version'),(lambda r:r.update(database_fingerprint='bad'),'source_database_fingerprint'),(lambda r:r.update(boot_id='bad'),'source_boot_id'),(lambda r:r['units'].update({'nginx.service':'failed'}),'source_units'),(lambda r:r.update(boot_id=None),'UNKNOWN')]:
            with self.subTest(want=want),tempfile.TemporaryDirectory() as td:
                c=self.make(Path(td));r=self.row();edit(r);self.transport(c,r);kind,e=self.outcome(c,c.source,'24.04','current');self.assertNotEqual(kind,'pass');c.remember_failure(e);public=m.public_result(c.state);self.assertEqual(public['failure_predicate'],want);self.assertNotIn('PRIVATE_SENTINEL',json.dumps(public))
    def execution_harness(self,root,source_bad=True,cleanup_bad=True,owner_second_failure=False):
        m=module();t=self
        class Fixed(m.Coordinator):
            def setup(self):
                seed=t.make(root);self.__dict__.update(seed.__dict__);self.public.mkdir();self.private_created=True;self.public_created=True;self.known={self.source:'24.04'}
                if owner_second_failure:t.transport(self,t.row());self.proof(self.source,'24.04','current')
            def acquire(self):pass
            def host_prepare(self):pass
            def images(self):pass
            def source_phases(self):
                if owner_second_failure:(self.root/'owners'/self.token/self.source).unlink()
                r=t.row()
                if source_bad:r['binaries']={}
                t.transport(self,r);self.proof(self.source,'24.04','current')
            def negative_backup(self):pass
            def prepare(self):pass
            def negative_target(self):self.state['ordered_negative_check_only']=True
            def positive(self):self.state.update(positive_restore_verified=True,source_unchanged=True,target_reboot_verified=True)
            def cleanup(self):
                if cleanup_bad:
                    def out(*a,**k):self.run.rows.append({'stage':'cleanup','exit_code':0});return '{"errors":["PRIVATE_SENTINEL"],"list":[]}'
                    self.run.output=out;return super().cleanup()
                self.state['cleanup_completed']=True
        return Fixed(admission(),root/'app',root/'ctrl',root/'private',root/'public',env={})
    def test_primary_source_failure_is_immutable_when_later_cleanup_fails(self):
        m=module()
        with tempfile.TemporaryDirectory() as td:
            c=self.execution_harness(Path(td))
            with self.assertRaises(m.Refusal):c.execute()
            public=json.loads((c.public/'result.json').read_text());primary=public.get('primary_outcome',{});cleanup=public.get('cleanup_outcome',{});self.assertEqual(primary.get('predicate'),'source_binary_inventory');self.assertEqual(primary.get('command_count'),1);self.assertEqual(cleanup.get('status'),'failed');self.assertEqual(cleanup.get('failures',[{}])[0].get('predicate'),'cleanup_initial_errors');self.assertEqual(cleanup['failures'][0]['role'],'source');self.assertEqual(public['failure_code'],'cleanup_failed');self.assertNotIn('PRIVATE_SENTINEL',json.dumps(public));self.assertEqual([r['exit_code'] for r in public['stages']],[0,0])
            saved=copy.deepcopy(primary);c.state.get('proof_observation',{}).setdefault('checks',{})['binary_inventory_matches']=True;c.state['current_boundary']='publication';self.assertEqual(public['primary_outcome'],saved);self.assertEqual(c.state['primary_outcome'],saved)
    def test_second_proof_resets_before_owner_and_has_no_stale_decoded_checks(self):
        with tempfile.TemporaryDirectory() as td:
            c=self.execution_harness(Path(td),source_bad=False,cleanup_bad=False,owner_second_failure=True)
            with self.assertRaises(FileNotFoundError):c.execute()
            public=json.loads((c.public/'result.json').read_text());o=public.get('primary_outcome',{}).get('proof_observation',{});self.assertEqual(o.get('invocation'),2);self.assertEqual(o.get('context'),'current');self.assertIs(o.get('json_decoded'),False);self.assertEqual(o.get('checks'),{});self.assertEqual(public['primary_outcome']['predicate'],'UNKNOWN')
    def test_cleanup_only_failure_keeps_work_passed_but_terminal_failed(self):
        m=module()
        with tempfile.TemporaryDirectory() as td:
            c=self.execution_harness(Path(td),source_bad=False)
            with self.assertRaises(m.Refusal):c.execute()
            p=json.loads((c.public/'result.json').read_text());self.assertEqual(p.get('primary_outcome',{}).get('status'),'passed');self.assertEqual(p.get('cleanup_outcome',{}).get('status'),'failed');self.assertEqual(p['status'],'FAIL')
    def test_unrecognized_nested_diagnostics_never_copy_raw_values(self):
        m=module();p=m.public_result({'status':'FAIL','primary_outcome':{'status':'failed','boundary':'PRIVATE_SENTINEL','predicate':['PRIVATE_SENTINEL'],'kind':{},'command_count':True,'proof_observation':{'invocation':True,'context':'PRIVATE_SENTINEL','json_decoded':'PRIVATE_SENTINEL','checks':{'panel':'PRIVATE_SENTINEL','PRIVATE_SENTINEL':True}}},'cleanup_outcome':{'status':'failed','failures':[{'role':'PRIVATE_SENTINEL','predicate':'PRIVATE_SENTINEL','raw':'PRIVATE_SENTINEL'}]}})
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(p));self.assertEqual(p.get('primary_outcome',{}).get('predicate'),'UNKNOWN')

    def test_owner_pin_and_metadata_false_guards_are_typed_without_new_command(self):
        m=module()
        for change,want,boundary in [('owner','host_owner_binding','proof_owner'),('metadata','trusted_file_metadata','proof_owner'),('pin','input_pin_mismatch','proof_pins')]:
            with self.subTest(change=change),tempfile.TemporaryDirectory() as td:
                c=self.make(Path(td));self.transport(c,self.row());owner=c.root/'owners'/c.token/c.source
                if change=='owner':owner.write_text('24.04\tamd64\tforeign-token\n')
                elif change=='metadata':owner.chmod(0o644)
                else:(c.root/'pin').write_text('changed bytes')
                kind,e=self.outcome(c,c.source,'24.04','current');self.assertEqual(kind,'Refusal');c.remember_failure(e);public=m.public_result(c.state);self.assertEqual(public['failure_predicate'],want);self.assertEqual(public['failure_boundary'],boundary);self.assertEqual(c._fake_calls,[])
                observation=c.state.get('proof_observation',{});self.assertIs(observation.get('json_decoded'),False);self.assertEqual(observation.get('checks'),{})
    def test_second_invalid_json_proof_has_no_successful_first_observation(self):
        m=module()
        with tempfile.TemporaryDirectory() as td:
            c=self.make(Path(td));self.transport(c,self.row());self.assertEqual(self.outcome(c,c.source,'24.04','current')[0],'pass')
            def invalid(*a,**k):
                c._fake_calls.append((a,k));p=c.root/'bad-json';p.write_text('PRIVATE_SENTINEL invalid');return 0,p,p
            c.shell=invalid;kind,e=self.outcome(c,c.source,'24.04','phase28');self.assertEqual(kind,'Refusal');c.remember_failure(e);o=c.state.get('proof_observation',{});self.assertEqual(o.get('invocation'),2);self.assertEqual(o.get('context'),'phase28');self.assertIs(o.get('json_decoded'),False);self.assertEqual(o.get('checks'),{});public=m.public_result(c.state);self.assertEqual(public['failure_predicate'],'UNKNOWN');self.assertEqual(public['failure_boundary'],'proof_json');self.assertNotIn('PRIVATE_SENTINEL',json.dumps(public));self.assertEqual(len(c._fake_calls),2)
    def test_final_malformed_list_or_owner_drift_never_loses_named_custody(self):
        m=module()
        for final in ({'list':[None]},{'list':[{'name':'same'},{'name':'same'}]},{'list':[],'errors':{}},{'list':[{'name':'nakpanel-source'}]}):
            with self.subTest(final=final),tempfile.TemporaryDirectory() as td:
                c=self.make(Path(td));c.known={c.source:'24.04'};rows=[{'list':[{'name':c.source}]},final];deleted=[];c.run.output=lambda *a,**k:json.dumps(rows.pop(0));c.shell=lambda *a,**k:deleted.append(True)
                with self.assertRaises(m.Refusal):c.delete(c.source,'cleanup')
                self.assertIn(c.source,c.known);self.assertEqual(deleted,[True])
        with tempfile.TemporaryDirectory() as td:
            c=self.make(Path(td));c.known={c.source:'24.04'};c.run.output=lambda *a,**k:json.dumps({'list':[{'name':c.source}]});(c.root/'owners'/c.token/c.source).write_text('foreign');deleted=[];c.shell=lambda *a,**k:deleted.append(True)
            with self.assertRaises(m.Refusal):c.delete(c.source,'cleanup')
            self.assertIn(c.source,c.known);self.assertEqual(deleted,[])
    def test_unrelated_failure_after_successful_proof_has_no_stale_proof_attachment(self):
        m=module();t=self
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            class Fixed(m.Coordinator):
                def setup(self):
                    seed=t.make(root);self.__dict__.update(seed.__dict__);self.public.mkdir();self.private_created=True;self.public_created=True
                def acquire(self):pass
                def host_prepare(self):pass
                def images(self):pass
                def source_phases(self):t.transport(self,t.row());self.proof(self.source,'24.04','current');raise OSError('PRIVATE_SENTINEL')
                def cleanup(self):self.state['cleanup_completed']=True
            c=Fixed(admission(),root/'app',root/'ctrl',root/'private',root/'public',env={})
            with self.assertRaises(OSError):c.execute()
            result=json.loads((c.public/'result.json').read_text());self.assertIn('primary_outcome',result);self.assertNotIn('proof_observation',result['primary_outcome']);self.assertEqual(result['primary_outcome']['predicate'],'UNKNOWN');self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result))
    def test_unknown_cleanup_json_failure_preserves_known_source_primary_snapshot(self):
        m=module();t=self
        with tempfile.TemporaryDirectory() as td:
            c=self.execution_harness(Path(td));original=c.cleanup
            def malformed_cleanup():
                def out(*a,**k):c.run.rows.append({'stage':'cleanup','exit_code':0});return 'PRIVATE_SENTINEL invalid-json'
                c.run.output=out;return m.Coordinator.cleanup(c)
            c.cleanup=malformed_cleanup
            with self.assertRaises(m.Refusal):c.execute()
            result=json.loads((c.public/'result.json').read_text());self.assertEqual(result.get('primary_outcome',{}).get('predicate'),'source_binary_inventory');self.assertEqual(result['cleanup_outcome']['failures'][0]['predicate'],'UNKNOWN');self.assertEqual(result['cleanup_outcome']['failures'][0]['boundary'],'cleanup_initial_json');self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result));self.assertEqual([r['exit_code'] for r in result['stages']],[0,0])

    def test_later_successful_cleanup_proof_cannot_overwrite_primary_snapshot(self):
        m=module()
        with tempfile.TemporaryDirectory() as td:
            c=self.execution_harness(Path(td))
            def cleanup():
                self.transport(c,self.row());c.proof(c.source,'24.04','positive',True)
                def out(*a,**k):c.run.rows.append({'stage':'cleanup','exit_code':0});return '{"errors":["PRIVATE_SENTINEL"],"list":[]}'
                c.run.output=out;return m.Coordinator.cleanup(c)
            c.cleanup=cleanup
            with self.assertRaises(m.Refusal):c.execute()
            result=json.loads((c.public/'result.json').read_text());o=result.get('primary_outcome',{}).get('proof_observation',{});self.assertEqual(o.get('invocation'),1);self.assertIs(o.get('checks',{}).get('binary_inventory_matches'),False);self.assertEqual(c.state['proof_observation']['invocation'],2);self.assertIs(c.state['proof_observation']['checks']['binary_inventory_matches'],True);self.assertNotIn('proof_observation',result['cleanup_outcome']['failures'][0]);self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result))
    def test_output_file_failure_and_nonzero_transport_do_not_invent_decoded_checks(self):
        m=module()
        for mode in ('file','transport'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as td:
                c=self.make(Path(td));calls=[]
                def shell(*a,**k):
                    calls.append(True)
                    if mode=='transport':c.run.rows.append({'stage':'current','exit_code':7});raise m.Refusal('PRIVATE_SENTINEL')
                    c.run.rows.append({'stage':'current','exit_code':0});return 0,c.root/'missing-output',c.root/'missing-error'
                c.shell=shell;kind,e=self.outcome(c,c.source,'24.04','current');self.assertEqual(kind,'FileNotFoundError' if mode=='file' else 'Refusal');c.remember_failure(e);result=m.public_result(c.state);self.assertEqual(result['failure_kind'],'UNKNOWN' if mode=='file' else 'command');self.assertEqual(result['failure_predicate'],'UNKNOWN');self.assertEqual(c.state['proof_observation']['checks'],{});self.assertIs(c.state['proof_observation']['json_decoded'],False);self.assertEqual(calls,[True]);self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result))


class PreparationDiagnosticTests(unittest.TestCase):
    UNKNOWN={'stage':'UNKNOWN','status':'UNKNOWN','error_category':'UNKNOWN'}
    def failed_prepare(self,root,receipt=None,raw=None,stderr=b'forward fixture failed: fixture command failed: bash\n',kind='regular',prepared=True,exit_code=1):
        m=module();c=m.Coordinator(admission(),root/'app',root/'controller',root/'private',root/'public');c.root.mkdir(mode=0o700)
        c.source='nakpanel-test-source';c.token='PRIVATE_SENTINEL';c.bundle=root/'bundle';c.key=root/'key';c.boundary('prepare');c.state['status']='FAIL';calls=[]
        class LocalBoundary:
            rows=[];counter=0;env={}
            def output(self,stage,args):
                self.counter+=1;calls.append(list(map(str,args)));self.rows.append({'stage':'prepare','exit_code':0,'owned_group_empty':True,'leader_reaped':True,'timed_out':False,'interrupted':False})
                return json.dumps({'version':1,'private':'PRIVATE_SENTINEL'})
            def call(self,stage,args):
                self.counter+=1;calls.append(list(map(str,args)));self.rows.append({'stage':'prepare','exit_code':exit_code,'owned_group_empty':True,'leader_reaped':True,'timed_out':False,'interrupted':False})
                target=c.root/'prepared'
                if prepared:
                    target.mkdir(mode=0o700)
                    p=target/'preparation-receipt.json'
                    if kind=='directory':p.mkdir(mode=0o700)
                    elif kind=='fifo':os.mkfifo(p,0o600)
                    elif receipt is not None or raw is not None:
                        p.write_bytes(raw if raw is not None else json.dumps(receipt).encode());p.chmod(0o600)
                        if kind=='symlink':p.rename(target/'held');p.symlink_to(target/'held')
                        elif kind=='hardlink':os.link(p,target/'held')
                        elif kind=='permissive':p.chmod(0o640)
                logs=c.root/'logs';logs.mkdir(mode=0o700)
                p=logs/(str(self.counter)+'-prepare.stderr');p.write_bytes(stderr);p.chmod(0o600)
                if kind=='stderr-symlink':p.rename(logs/'held');p.symlink_to(logs/'held')
                elif kind=='stderr-permissive':p.chmod(0o640)
                raise m.Refusal('PRIVATE_SENTINEL private failure /private/path')
        c.run=LocalBoundary()
        with patch.object(m.subprocess,'Popen',side_effect=AssertionError('offline only')):
            try:c.prepare()
            except m.Refusal as error:c.remember_failure(error);c.capture_primary(error)
            else:raise AssertionError('local failing child did not fail')
        c.state['stages']=c.run.rows
        result=m.public_result(c.state)
        expected=[[c.python,'-I','-B',str(c.app/'deploy/multipass/ubuntu-forward-migration-fixture.py'),'--template'],[c.python,'-I','-B',str(c.app/'deploy/multipass/ubuntu-forward-migration-fixture.py'),'--prepare',str(c.root/'spec.json'),str(c.root/'prepared')]]
        self.assertEqual(calls[0],expected[0]);self.assertEqual(len(calls),2);self.assertEqual(calls[1][:4],[c.python,'-I','-B','-c']);self.assertEqual(calls[1][5:9],[str(c.controller/'forward_hosted.py'),str(c.app/'deploy/multipass/ubuntu-forward-migration-fixture.py'),str(c.root/'spec.json'),str(c.root/'prepared')]);self.assertRegex(calls[1][10],r'^[a-f0-9]{32}$');self.assertEqual(calls[1][9],str(c.root/('prepare-preflight-'+calls[1][10]+'.json')));self.assertEqual(calls[1][11],'2');self.assertRegex(calls[1][12],r'^[a-f0-9]{64}$');self.assertEqual(result['primary_outcome']['boundary'],'prepare');self.assertEqual(result['primary_outcome']['kind'],'command' if exit_code else 'UNKNOWN');self.assertEqual(result['primary_outcome']['predicate'],'UNKNOWN');self.assertEqual(result['primary_outcome']['command_count'],2);self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result));self.assertNotIn('/private/path',json.dumps(result))
        return result,c
    def test_failed_child_projects_fixed_receipt_without_private_fields(self):
        # Missing receipt capture must hide the known safe stage and fail this test.
        with tempfile.TemporaryDirectory() as td:
            result,c=self.failed_prepare(Path(td),{'version':1,'stage':'source-php-preparation-and-seed','status':'failed','error_type':'RuntimeError','source_vm':'PRIVATE_SENTINEL','run_token':'PRIVATE_SENTINEL','before_php_inventory':['PRIVATE_SENTINEL'],'env':{'PRIVATE_SENTINEL':'PRIVATE_SENTINEL'},'path':'/private/path','exception':'PRIVATE_SENTINEL'})
            self.assertEqual(result['primary_outcome'].get('preparation_diagnostic'),{'stage':'source-php-preparation-and-seed','status':'failed','error_category':'runtime'})
    def test_receipt_error_names_map_to_fixed_categories(self):
        for error,want in [('ValueError','value'),('RuntimeError','runtime'),('OSError','io'),('FileNotFoundError','io'),('PermissionError','io'),('TimeoutExpired','timeout'),('JSONDecodeError','json'),('KeyError','key'),('TypeError','type'),('UnicodeDecodeError','encoding'),('PRIVATE_SENTINEL','UNKNOWN')]:
            with self.subTest(error=error),tempfile.TemporaryDirectory() as td:
                result,c=self.failed_prepare(Path(td),{'version':1,'stage':'offline-export','status':'failed','error_type':error})
                self.assertEqual(result['primary_outcome'].get('preparation_diagnostic'),{'stage':'offline-export','status':'failed','error_category':want})
    def test_running_and_passed_receipts_describe_last_checkpoint_without_error(self):
        for stage,status in [('read-only-preflight','passed'),('encrypted-backup','running'),('complete','passed')]:
            with self.subTest(stage=stage),tempfile.TemporaryDirectory() as td:
                result,c=self.failed_prepare(Path(td),{'version':1,'stage':stage,'status':status,'error_type':'ValueError'})
                self.assertEqual(result['primary_outcome'].get('preparation_diagnostic'),{'stage':stage,'status':status,'error_category':'UNKNOWN'})
    def test_missing_malformed_or_unbounded_receipt_is_unknown(self):
        for raw in (None,b'{',b'[]',b'{"version":true,"stage":"offline-export","status":"failed"}',b'{"version":1,"stage":"offline-export","stage":"encrypted-backup","status":"failed"}',b'{"version":1,"stage":"PRIVATE_SENTINEL","status":"failed"}',b'{"version":1,"stage":"offline-export","status":[]}',b' '*65537):
            with self.subTest(raw=repr(raw)[:60]),tempfile.TemporaryDirectory() as td:
                result,c=self.failed_prepare(Path(td),raw=raw)
                self.assertEqual(result['primary_outcome'].get('preparation_diagnostic'),self.UNKNOWN)
    def test_malformed_failed_receipt_error_type_is_unknown(self):
        for error in (None,[],{},True,7):
            with self.subTest(error=error),tempfile.TemporaryDirectory() as td:
                result,c=self.failed_prepare(Path(td),{'version':1,'stage':'offline-export','status':'failed','error_type':error})
                self.assertEqual(result['primary_outcome'].get('preparation_diagnostic'),self.UNKNOWN)
    def test_receipt_must_be_private_single_link_regular_file(self):
        for kind in ('directory','fifo','symlink','hardlink','permissive'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as td:
                result,c=self.failed_prepare(Path(td),{'version':1,'stage':'offline-export','status':'failed','error_type':'RuntimeError'},kind=kind)
                self.assertEqual(result['primary_outcome'].get('preparation_diagnostic'),self.UNKNOWN)
    def test_absent_prepared_and_exact_early_envelopes_are_command_categories(self):
        for stderr,stage in [(b'forward fixture failed: fixture command failed: bash\n','EARLY_IDENTITY_COMMAND'),(b'forward fixture failed: fixture command failed: multipass\n','EARLY_SOURCE_PREFLIGHT_COMMAND')]:
            with self.subTest(stage=stage),tempfile.TemporaryDirectory() as td:
                result,c=self.failed_prepare(Path(td),prepared=False,stderr=stderr)
                want={'stage':stage,'status':'failed','error_category':'runtime'}
                if stage=='EARLY_SOURCE_PREFLIGHT_COMMAND':want['source_preflight']={'error_category':'UNKNOWN','chain':'UNKNOWN'}
                self.assertEqual(result['primary_outcome'].get('preparation_diagnostic'),want)
    def test_any_other_early_output_and_unsafe_stderr_are_unknown(self):
        for stderr,kind in [(b'forward fixture failed: fixture command failed: bash\nPRIVATE_SENTINEL','regular'),(b'forward fixture failed: fixture command failed: bash','regular'),(b'forward fixture failed: PRIVATE_SENTINEL\n','regular'),(b'forward fixture failed: fixture command failed: bash\n','stderr-symlink'),(b'forward fixture failed: fixture command failed: bash\n','stderr-permissive'),(b' '*65537,'regular')]:
            with self.subTest(kind=kind,stderr=repr(stderr)[:70]),tempfile.TemporaryDirectory() as td:
                result,c=self.failed_prepare(Path(td),prepared=False,stderr=stderr,kind=kind)
                self.assertEqual(result['primary_outcome'].get('preparation_diagnostic'),self.UNKNOWN)
    def test_early_envelope_requires_known_nonzero_child_exit(self):
        with tempfile.TemporaryDirectory() as td:
            result,c=self.failed_prepare(Path(td),prepared=False,exit_code=0)
            self.assertEqual(result['primary_outcome'].get('preparation_diagnostic'),self.UNKNOWN)
    def test_primary_diagnostic_is_snapshotted_before_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            result,c=self.failed_prepare(Path(td),{'version':1,'stage':'roundcube-canary-seed','status':'failed','error_type':'ValueError'})
            c.boundary('cleanup');c.cleanup_failure('source',module().Refusal('PRIVATE_SENTINEL'))
            (c.root/'prepared/preparation-receipt.json').write_text('PRIVATE_SENTINEL')
            later=module().public_result(c.state)
            self.assertEqual(later['primary_outcome'].get('preparation_diagnostic'),{'stage':'roundcube-canary-seed','status':'failed','error_category':'value'})
            self.assertNotIn('preparation_diagnostic',later['cleanup_outcome']['failures'][0]);self.assertNotIn('PRIVATE_SENTINEL',json.dumps(later))
    def test_public_projection_rechecks_fixed_diagnostic_fields(self):
        result=module().public_result({'status':'FAIL','primary_outcome':{'status':'failed','preparation_diagnostic':{'stage':'PRIVATE_SENTINEL','status':['PRIVATE_SENTINEL'],'error_category':{'PRIVATE_SENTINEL':'PRIVATE_SENTINEL'},'raw':'PRIVATE_SENTINEL'}}})
        self.assertEqual(result['primary_outcome'].get('preparation_diagnostic'),self.UNKNOWN);self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result))


class SourcePreflightMarkerTests(unittest.TestCase):
    APP=Path('/Users/rickynkansah/.codex/worktrees/ubuntu-26-support/nakpanel')
    HELPER=APP/'deploy/multipass/ubuntu-forward-migration-fixture.py'
    PROBE=APP/'deploy/multipass/ubuntu-forward-migration-probe.py'
    NONCE='c7'*16
    KEY='e9'*32
    def api(self):
        m=module();self.assertTrue(callable(getattr(m,'preflight_guest_program',None)),'bounded pinned guest marker wrapper is missing');return m
    def guest(self,program,mode='command',input_data=None):
        import contextlib,sqlite3
        out,err=io.StringIO(),io.StringIO();calls=[];real_exists=Path.exists;real_read=Path.read_text;real_file=Path.is_file;real_link=Path.is_symlink
        config={'source_vm':'nakpanel-offline','run_token':'PRIVATE_SENTINEL','target_profile':'ubuntu-26.04-native','normalize_php85':True,'remediate_stale_php82':True,'oci_image_ref':'docker.io/library/nginx@sha256:'+'5'*64,'site_id':0,'worker_id':0}
        data=json.dumps({'action':'source-preflight','config':config}) if input_data is None else input_data
        def exists(path):return mode!='roundcube' if str(path).startswith('/etc/roundcube/') else real_exists(path)
        def read(path,*a,**k):return "$config['db_dsnw']='sqlite:/var/lib/roundcube/roundcube.sqlite';" if str(path).startswith('/etc/roundcube/') else real_read(path,*a,**k)
        class Connection:
            def __enter__(self):return self
            def __exit__(self,*a):return False
            def execute(self,q):return self
            def fetchall(self):return [('ok',)]
        def boundary(args,**kw):
            calls.append((args,kw));self.assertEqual(args[:7],['runuser','-u','postgres','--','psql','-Atq','-d']);q=args[-1]
            if mode=='command':return subprocess.CompletedProcess(args,7,'PRIVATE_SENTINEL','PRIVATE_SENTINEL')
            if "'selected'" in q:stdout=json.dumps({'selected':[{}] if mode=='malformed-selected' else [],'plans':[],'subscriptions':[],'addons':[],'overrides':[]})
            elif 'subscription_entitlements e' in q:stdout='[]'
            elif "domain='phase30-managed.test'" in q:stdout='1'
            elif "json_build_object('domain'" in q:stdout=json.dumps({'domain':'offline.test','username':'offline','subscription_id':3})
            elif 'SELECT w.id FROM php_workers' in q:stdout='2'
            elif 'SELECT a.php_version FROM php_workers' in q:stdout='8.5'
            else:raise AssertionError('unexpected offline product query')
            return subprocess.CompletedProcess(args,0,stdout,'')
        rc=0
        with patch.object(sys,'stdin',io.StringIO(data)),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err),patch.object(Path,'exists',exists),patch.object(Path,'read_text',read),patch.object(Path,'is_file',lambda p:True if str(p)=='/var/lib/roundcube/roundcube.sqlite' else real_file(p)),patch.object(Path,'is_symlink',lambda p:False if str(p)=='/var/lib/roundcube/roundcube.sqlite' else real_link(p)),patch.object(sqlite3,'connect',return_value=Connection()),patch.object(subprocess,'run',side_effect=boundary):
            try:exec(compile(program,'<offline-guest-wrapper>','exec'),{'__name__':'__main__'})
            except SystemExit as e:rc=e.code
        return rc,out.getvalue(),err.getvalue(),calls
    def observed(self,root,mode='command'):
        import contextlib
        m=self.api()
        # Load declarations only; never invoke the helper's default/main path.
        ns={'__name__':'offline_fixture_declarations','__file__':str(self.HELPER)};exec(compile(self.HELPER.read_bytes(),str(self.HELPER),'exec'),ns);spec=ns['example_spec']();spec.update(source_vm='nakpanel-offline',run_token='offline-test-token',architecture='amd64',target_profile='ubuntu-26.04-native',normalize_php85=True,remediate_stale_php82=True,oci_image_ref='docker.io/library/nginx@sha256:'+'5'*64)
        p=private(root/'spec.json',spec);companion=root/'companion.json';output=root/'prepared';calls=[];objects=[];out,err=io.StringIO(),io.StringIO()
        def transport(args,**kw):
            calls.append((list(args),dict(kw)))
            if args[0] in ('bash','ssh-keygen'):result=subprocess.CompletedProcess(args,0,'','')
            else:
                self.assertEqual(args[:7],['multipass','exec','nakpanel-offline','--','sudo','python3','-c'])
                if json.loads(kw['input'])['action']=='source-preflight':
                    rc,stdout,stderr,_=self.guest(args[-1],'success' if mode=='success-then-seed' else mode,input_data=kw['input']);result=subprocess.CompletedProcess(args,rc,stdout,stderr)
                else:
                    self.assertEqual(json.loads(kw['input'])['action'],'seed');self.assertEqual(args[-1],self.PROBE.read_text());result=subprocess.CompletedProcess(args,7,'PRIVATE_SENTINEL','PRIVATE_SENTINEL')
            objects.append((result,result.stdout,result.stderr,result.returncode));return result
        rc=0
        original_read=Path.read_text
        def key_read(path,*args,**kwargs):return 'ssh-ed25519 OFFLINE' if path.name=='sftp-key.pub' else original_read(path,*args,**kwargs)
        with patch.object(subprocess,'run',side_effect=transport),patch.object(Path,'read_text',key_read),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            try:m.observed_prepare(str(self.HELPER),str(p),str(output),str(companion),self.NONCE,'220',self.KEY)
            except SystemExit as error:rc=error.code
        for result,stdout,stderr,returncode in objects:self.assertEqual((result.stdout,result.stderr,result.returncode),(stdout,stderr,returncode))
        return m,rc,out.getvalue(),err.getvalue(),calls,companion
    def test_actual_probe_generic_command_guard_retains_full_trusted_caller_chain(self):
        m=self.api();program=m.preflight_guest_program(self.PROBE.read_text(),self.NONCE,self.KEY)
        rc,stdout,stderr,calls=self.guest(program)
        observation=m.preflight_marker(stderr,self.NONCE,self.KEY)
        self.assertEqual(rc,1);self.assertEqual(stdout,'');self.assertEqual(observation,{'error_category':'runtime','chain':[{'function':'source_preflight','line':540},{'function':'assert_fixture_php_inventory','line':388},{'function':'fixture_php_inventory','line':374},{'function':'pg','line':36},{'function':'command','line':31}]});self.assertEqual(len(calls),1);self.assertNotIn('PRIVATE_SENTINEL',json.dumps(observation))
    def test_actual_probe_direct_guard_reports_fixed_site_without_command(self):
        m=self.api();rc,stdout,stderr,calls=self.guest(m.preflight_guest_program(self.PROBE.read_text(),self.NONCE,self.KEY),'roundcube')
        self.assertEqual(rc,1);self.assertEqual(stdout,'');self.assertEqual(calls,[]);self.assertEqual(m.preflight_marker(stderr,self.NONCE,self.KEY),{'error_category':'runtime','chain':[{'function':'source_preflight','line':538},{'function':'roundcube_preflight','line':242}]})
    def test_guest_success_keeps_original_outputs_return_and_commands(self):
        m=self.api();source=self.PROBE.read_text();original=self.guest(source,'success');wrapped=self.guest(m.preflight_guest_program(source,self.NONCE,self.KEY),'success')
        self.assertEqual(wrapped,original);self.assertEqual(original[0],0);self.assertEqual(original[2],'')
    def test_host_executes_pinned_helper_and_preserves_original_failure(self):
        with tempfile.TemporaryDirectory() as td:
            m,rc,stdout,stderr,calls,p=self.observed(Path(td))
            self.assertEqual(rc,1);self.assertEqual(stdout,'');self.assertEqual(stderr,'forward fixture failed: fixture command failed: multipass\n');self.assertEqual(len(calls),2)
            self.assertEqual(calls[0][0][:3],['bash','-c','source "$1"; assert_vm_identity "$2" "$3" "$4" "$5"']);self.assertEqual(calls[1][1]['timeout'],3600);self.assertIs(calls[1][1]['text'],True);self.assertIs(calls[1][1]['capture_output'],True)
            observation=m.preflight_companion(p,self.NONCE,220,self.KEY)
            self.assertEqual(observation['chain'][-3:],[{'function':'fixture_php_inventory','line':374},{'function':'pg','line':36},{'function':'command','line':31}]);self.assertNotIn('PRIVATE_SENTINEL',p.read_text())
    def test_marker_and_companion_are_bound_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            m,rc,stdout,stderr,calls,p=self.observed(Path(td));raw=p.read_text();unknown={'error_category':'UNKNOWN','chain':'UNKNOWN'}
            self.assertEqual(m.preflight_companion(p,'d8'*16,220,self.KEY),unknown);self.assertEqual(m.preflight_companion(p,self.NONCE,221,self.KEY),unknown)
            for mutate in (lambda d:d.update(matches=2),lambda d:d.update(guest_returncode=0),lambda d:d['marker']['payload'].update(chain=[{'function':'PRIVATE_SENTINEL','line':540}]),lambda d:d['marker']['payload'].update(chain=[{'function':'source_preflight','line':540}]*7),lambda d:d['marker'].update(mac='0'*64)):
                data=json.loads(raw);mutate(data);private(p,data);self.assertEqual(m.preflight_companion(p,self.NONCE,220,self.KEY),unknown)
            p.write_text(raw);p.chmod(0o640);self.assertEqual(m.preflight_companion(p,self.NONCE,220,self.KEY),unknown)
    def test_invalid_duplicate_unbounded_or_wrong_nonce_markers_are_unknown(self):
        m=self.api();rc,stdout,stderr,calls=self.guest(m.preflight_guest_program(self.PROBE.read_text(),self.NONCE,self.KEY));unknown={'error_category':'UNKNOWN','chain':'UNKNOWN'}
        for data,nonce in [(stderr,'d8'*16),(stderr+stderr,self.NONCE),('PRIVATE_SENTINEL',self.NONCE),('x'*65537,self.NONCE),(stderr.replace('"line":540','"line":999999'),self.NONCE)]:self.assertEqual(m.preflight_marker(data,nonce,self.KEY),unknown)
    def test_public_projection_allows_only_closed_site_chain(self):
        m=module();result=m.public_result({'status':'FAIL','primary_outcome':{'status':'failed','preparation_diagnostic':{'stage':'EARLY_SOURCE_PREFLIGHT_COMMAND','status':'failed','error_category':'runtime','source_preflight':{'error_category':'PRIVATE_SENTINEL','chain':[{'function':'PRIVATE_SENTINEL','line':540}],'raw':'PRIVATE_SENTINEL'}}}})
        self.assertEqual(result['primary_outcome']['preparation_diagnostic'].get('source_preflight'),{'error_category':'UNKNOWN','chain':'UNKNOWN'});self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result))



    def test_host_passes_through_nonpreflight_program_and_product_commands(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve();m,rc,stdout,stderr,calls,p=self.observed(root,'success-then-seed')
            self.assertEqual(rc,1);self.assertEqual(stdout,'');self.assertEqual(stderr,'forward fixture failed: fixture command failed: multipass\n');self.assertFalse(p.exists());self.assertEqual([row[0][0] for row in calls],['bash','multipass','ssh-keygen','multipass'])
            self.assertEqual(calls[2][0],['ssh-keygen','-q','-t','ed25519','-N','','-f',str(root/'prepared/sftp-key')]);self.assertEqual(calls[3][0][-1],self.PROBE.read_text())
            self.assertEqual(json.loads(calls[3][1]['input'])['action'],'seed');self.assertEqual(calls[3][1]['timeout'],3600)
    def test_pinned_probe_drift_refuses_before_guest_execution(self):
        m=self.api()
        with self.assertRaises(m.Refusal):m.preflight_guest_program(self.PROBE.read_text()+'\n',self.NONCE,self.KEY)


    def test_marker_authentication_requires_independent_secret_key(self):
        m=self.api()
        try:program=m.preflight_guest_program(self.PROBE.read_text(),self.NONCE,self.KEY)
        except TypeError:self.fail('independent marker authentication key is missing')
        rc,stdout,stderr,calls=self.guest(program)
        self.assertNotEqual(m.preflight_marker(stderr,self.NONCE,self.KEY)['chain'],'UNKNOWN');self.assertEqual(m.preflight_marker(stderr,self.NONCE,'f8'*32),{'error_category':'UNKNOWN','chain':'UNKNOWN'});self.assertNotIn(self.KEY,stderr)


    def test_malformed_inventory_retains_trusted_comprehension_frame(self):
        m=self.api();rc,stdout,stderr,calls=self.guest(m.preflight_guest_program(self.PROBE.read_text(),self.NONCE,self.KEY),'malformed-selected')
        # Python 3.12 inlines comprehensions; require only actual code frames.
        compiled=compile(self.PROBE.read_text(),str(self.PROBE),'exec')
        function=next(code for code in compiled.co_consts if hasattr(code,'co_name') and code.co_name=='assert_fixture_php_inventory')
        chain=[{'function':'source_preflight','line':540},{'function':'assert_fixture_php_inventory','line':393}]
        if any(getattr(code,'co_name',None)=='<setcomp>' and code.co_firstlineno==393 for code in function.co_consts):chain.append({'function':'assert_fixture_php_inventory.<setcomp>','line':393})
        self.assertEqual(rc,1);self.assertEqual(m.preflight_marker(stderr,self.NONCE,self.KEY),{'error_category':'key','chain':chain})

    def controller_failure(self,root,tamper=None,tree=None):
        import contextlib
        m=self.api();c=m.Coordinator(admission(),self.APP,HERE,root/'private',root/'public');c.root.mkdir(mode=0o700);c.source='nakpanel-offline';c.token='offline-test-token';c.bundle=root/'bundle';c.key=root/'key';c.boundary('prepare');c.state['status']='FAIL';events=[]
        ns={'__name__':'offline_fixture_declarations','__file__':str(self.HELPER)};exec(compile(self.HELPER.read_bytes(),str(self.HELPER),'exec'),ns)
        testcase=self
        def transport(args,**kw):
            events.append(list(args))
            if args[0]=='bash':return subprocess.CompletedProcess(args,0,'','')
            testcase.assertEqual(args[:7],['multipass','exec','nakpanel-offline','--','sudo','python3','-c']);rc,out,err,_=testcase.guest(args[-1],input_data=kw['input']);return subprocess.CompletedProcess(args,rc,out,err)
        class Boundary:
            rows=[];counter=0;env={}
            def output(self,stage,args):
                self.counter+=1;self.rows.append({'stage':'prepare','exit_code':0});return json.dumps(ns['example_spec']())
            def call(self,stage,args):
                self.counter+=1;out,err=io.StringIO(),io.StringIO();rc=0
                with patch.object(subprocess,'run',side_effect=transport),patch.object(sys,'argv',['-c',*map(str,args[5:])]),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                    try:exec(args[4],{'__name__':'__main__'})
                    except SystemExit as error:rc=error.code
                logs=c.root/'logs';logs.mkdir(mode=0o700);p=logs/(str(self.counter)+'-prepare.stderr');p.write_text(err.getvalue());p.chmod(0o600)
                if tamper:tamper(Path(args[9]))
                row={'stage':'prepare','exit_code':rc,'owned_group_empty':True,'leader_reaped':True,'timed_out':False,'interrupted':False};row.update(tree or {});self.rows.append(row)
                raise m.Refusal('PRIVATE_SENTINEL')
        c.run=Boundary()
        with self.assertRaises(m.Refusal) as caught:c.prepare()
        c.remember_failure(caught.exception);c.capture_primary(caught.exception);c.state['stages']=c.run.rows
        return m.public_result(c.state),c,events
    def test_controller_projects_fresh_drained_nonzero_companion_and_snapshots_before_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            result,c,events=self.controller_failure(Path(td));value=result['primary_outcome']['preparation_diagnostic'];chain=value.get('qualifier_probe',{}).get('chain')
            self.assertEqual(chain,[{'function':'source_preflight','line':549},{'function':'assert_fixture_php_inventory','line':397},{'function':'fixture_php_inventory','line':383},{'function':'pg','line':36},{'function':'command','line':31}]);self.assertEqual(result['primary_outcome']['predicate'],'UNKNOWN');self.assertEqual(result['primary_outcome']['command_count'],2);self.assertEqual(len(events),2)
            c.boundary('cleanup');c.cleanup_failure('source',module().Refusal('PRIVATE_SENTINEL'));later=module().public_result(c.state)
            self.assertEqual(later['primary_outcome'],result['primary_outcome']);self.assertNotIn('preparation_diagnostic',later['cleanup_outcome']['failures'][0]);self.assertNotIn('PRIVATE_SENTINEL',json.dumps(later))
    def test_controller_rejects_missing_or_mismatched_companion_and_undrained_child(self):
        def nonce(path):data=json.loads(path.read_text());data['nonce']='d8'*16;private(path,data)
        for tamper,tree in [(lambda p:p.unlink(),None),(nonce,None),(None,{'owned_group_empty':False}),(None,{'leader_reaped':False}),(None,{'timed_out':True}),(None,{'interrupted':True})]:
            with self.subTest(tree=tree,tamper=bool(tamper)),tempfile.TemporaryDirectory() as td:
                result,c,events=self.controller_failure(Path(td),tamper= tamper,tree=tree)
                self.assertEqual(result['primary_outcome']['preparation_diagnostic'].get('qualifier_probe',{'chain':'UNKNOWN'})['chain'],'UNKNOWN');self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result))


class SourcePhaseLogTests(unittest.TestCase):
    APP=Path('/Users/rickynkansah/.codex/worktrees/ubuntu-26-support/nakpanel')
    BASH='/Users/rickynkansah/.local/state/nakpanel/qualification/2026-10-18/toolchains/bash-5.3.20/bin/bash'
    CURRENT_SHA='bdd1c43ee410417e6beef31bd58f7d7ab9bfa27f452fb41e09848aefc494f931'
    def source_current_output(self):
        env=dict(os.environ,NAKPANEL_INSTALL_ONLY='1',NAKPANEL_RELEASE_BUNDLE='',NAKPANEL_MULTIPASS_ARCH='amd64',NAKPANEL_RUN_TOKEN='offline-token')
        return subprocess.run([self.BASH,str(self.APP/'deploy/multipass/current-install-verify.sh')],env=env,capture_output=True,timeout=5)
    def failed(self,root,stage='current',stdout=b'',stderr=None,tree=None,unsafe=None,drift=False):
        m=module();c=m.Coordinator(admission(),self.APP,HERE,root/'private',root/'public');c.root.mkdir(mode=0o700);c.source='nakpanel-offline';c.token='offline-token';c.bundle=self.APP;c._work_operation='source_phases';c.check_new_vm=lambda *a:None;c.observed_budget=lambda *a:None;c.proof=lambda *a:None;commands=[]
        if stderr is None:stderr=self.source_current_output().stderr
        class Boundary:
            rows=[];counter=0;env={}
            def call(self,called,args,**kwargs):
                self.counter+=1;commands.append((called,list(map(str,args))));row={'stage':called,'exit_code':1 if called==stage else 0,'owned_group_empty':True,'leader_reaped':True,'timed_out':False,'interrupted':False}
                if called==stage:
                    row.update(tree or {});logs=c.root/'logs';logs.mkdir(mode=0o700)
                    for suffix,data in [('stdout',stdout),('stderr',stderr)]:
                        p=logs/(str(self.counter)+'-'+called+'.'+suffix)
                        if unsafe=='fifo':os.mkfifo(p,0o600)
                        elif unsafe=='directory':p.mkdir(mode=0o700)
                        else:
                            p.write_bytes(data);p.chmod(0o600)
                            if unsafe=='symlink':p.rename(logs/(suffix+'-held'));p.symlink_to(logs/(suffix+'-held'))
                            elif unsafe=='hardlink':os.link(p,logs/(suffix+'-held'))
                            elif unsafe=='permissive':p.chmod(0o640)
                    self.rows.append(row)
                    if (tree or {}).get('_counter_delta'):self.counter+=tree['_counter_delta']
                    if (tree or {}).get('_extra_row'):self.rows.append(dict(row))
                    raise m.Refusal('PRIVATE_SENTINEL')
                self.rows.append(row);return 0,root/'unused',root/'unused'
        c.run=Boundary()
        if drift:c.app=root/'missing-app';c.bundle=root/'missing-bundle'
        with self.assertRaises(m.Refusal)as caught:c.source_phases()
        c.remember_failure(caught.exception);c.capture_primary(caught.exception);c.state['status']='FAIL';c.state['stages']=c.run.rows;result=m.public_result(c.state)
        self.assertEqual([r[0]for r in commands],['current','phase28','phase30'][:['current','phase28','phase30'].index(stage)+1]);self.assertEqual(result['primary_outcome']['predicate'],'UNKNOWN');self.assertEqual(result['primary_outcome']['kind'],'command' if (tree or {}).get('exit_code',1) else 'UNKNOWN');self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result))
        self.assertEqual(commands[0][1][-1],'--');self.assertIn('init_qualification_run; exec "$BASH" "$APP_SOURCE/deploy/multipass/current-install-verify.sh"',commands[0][1][-2])
        return result,c
    def test_actual_source_early_error_is_projected_from_same_failed_command(self):
        actual=self.source_current_output();self.assertEqual(actual.returncode,1);self.assertEqual(actual.stderr,b'install-only qualification requires the selected signed release\n')
        with tempfile.TemporaryDirectory()as td:
            result,c=self.failed(Path(td),stderr=actual.stderr);diag=result['primary_outcome'].get('source_phase_diagnostic');self.assertIsNotNone(diag,'source phase log diagnostic is missing')
            self.assertEqual(diag['context'],'current');self.assertEqual(diag['command_ordinal'],1);self.assertEqual(diag['binding'],'MATCHED_REAPED_FAILED_COMMAND');self.assertEqual(diag['error'],{'label':'CURRENT_INSTALL_L008','source_sha256':self.CURRENT_SHA,'predicate':'FIXED_ERROR_ENVELOPE'});self.assertEqual(diag['last_stage']['label'],'UNKNOWN')
    def test_all_three_source_phase_calls_capture_closed_source_owned_errors(self):
        for stage,line,label in [('current',b'current-install: physical MariaDB canary did not round trip\n','CURRENT_INSTALL_L086'),('phase28',b'phase28: subordinate UID range is missing\n','PHASE28_L191'),('phase30',b'phase30: current panel is not healthy\n','PHASE30_L198')]:
            with self.subTest(stage=stage),tempfile.TemporaryDirectory()as td:
                result,c=self.failed(Path(td),stage=stage,stderr=line);diag=result['primary_outcome'].get('source_phase_diagnostic');self.assertIsNotNone(diag);self.assertEqual(diag['error']['label'],label);self.assertEqual(diag['context'],stage)
    def test_phase30_progress_and_trap_line_are_closed_envelopes(self):
        with tempfile.TemporaryDirectory()as td:
            result,c=self.failed(Path(td),stage='phase30',stdout=b'phase30: create panel-owned Classic and Managed PHP fixtures\nphase30: prove quota and cross-subscription filesystem isolation\n',stderr=b'phase30 verifier failed at line 529: PRIVATE_ARGV_SQL_IP_SECRET\n');diag=result['primary_outcome'].get('source_phase_diagnostic');self.assertIsNotNone(diag);self.assertEqual(diag['last_stage']['label'],'PHASE30_L506');self.assertEqual(diag['trap']['label'],'PHASE30_ERR_L529');self.assertNotIn('PRIVATE_ARGV_SQL_IP_SECRET',json.dumps(result));self.assertEqual(diag['error']['label'],'UNKNOWN')
    def test_common_real_source_guard_is_projected_without_emitting_token(self):
        env=dict(os.environ,NAKPANEL_MULTIPASS_ARCH='amd64',NAKPANEL_RUN_TOKEN='PRIVATE_SENTINEL!')
        r=subprocess.run([self.BASH,'-c','source "$1"; validate_run_identity "$NAKPANEL_RUN_TOKEN"','--',str(self.APP/'deploy/multipass/common.sh')],env=env,capture_output=True,timeout=5);self.assertEqual(r.returncode,1)
        with tempfile.TemporaryDirectory()as td:
            result,c=self.failed(Path(td),stderr=r.stderr);diag=result['primary_outcome'].get('source_phase_diagnostic');self.assertIsNotNone(diag);self.assertEqual(diag['error']['label'],'COMMON_L151')
    def test_unsafe_logs_missing_sources_and_unbound_child_are_unknown(self):
        for unsafe,tree,drift in [('fifo',None,False),('directory',None,False),('symlink',None,False),('hardlink',None,False),('permissive',None,False),(None,None,True),(None,{'owned_group_empty':False},False),(None,{'leader_reaped':False},False),(None,{'timed_out':True},False),(None,{'interrupted':True},False),(None,{'exit_code':0},False)]:
            with self.subTest(unsafe=unsafe,tree=tree,drift=drift),tempfile.TemporaryDirectory()as td:
                result,c=self.failed(Path(td),unsafe=unsafe,tree=tree,drift=drift);diag=result['primary_outcome'].get('source_phase_diagnostic');self.assertIsNotNone(diag);self.assertEqual(diag['error']['label'],'UNKNOWN');self.assertEqual(diag['trap']['label'],'UNKNOWN')
    def test_lookalikes_wrong_stream_phase_and_control_text_do_not_become_labels(self):
        for stderr in [b'prefix current-install: physical MariaDB canary did not round trip\n',b'current-install: physical MariaDB canary did not round trip PRIVATE_SENTINEL\n',b'\x1b[31mcurrent-install: physical MariaDB canary did not round trip\n',b'current-install: physical MariaDB canary did not round trip\x00\n',b'phase28: subordinate UID range is missing\n',b'phase30 verifier failed at line 99999: PRIVATE_SENTINEL\n']:
            with self.subTest(stderr=stderr),tempfile.TemporaryDirectory()as td:
                result,c=self.failed(Path(td),stderr=stderr,stdout=b'current-install: physical MariaDB canary did not round trip\n');diag=result['primary_outcome'].get('source_phase_diagnostic');self.assertIsNotNone(diag);self.assertEqual(diag['error']['label'],'UNKNOWN');self.assertEqual(diag['trap']['label'],'UNKNOWN')
    def test_tail_reads_are_bounded_and_discard_partial_lines(self):
        with tempfile.TemporaryDirectory()as td:
            result,c=self.failed(Path(td),stderr=b'x'*70000+b'\ncurrent-install: physical MariaDB canary did not round trip\n');diag=result['primary_outcome'].get('source_phase_diagnostic');self.assertIsNotNone(diag);self.assertEqual(diag['stderr_scope'],'TAIL');self.assertEqual(diag['error']['label'],'CURRENT_INSTALL_L086')
    def test_public_projection_and_cleanup_cannot_inject_or_replace_snapshot(self):
        with tempfile.TemporaryDirectory()as td:
            result,c=self.failed(Path(td));before=result['primary_outcome'];c.boundary('cleanup');c.cleanup_failure('source',module().Refusal('PRIVATE_SENTINEL'));self.assertEqual(module().public_result(c.state)['primary_outcome'],before);self.assertNotIn('source_phase_diagnostic',module().public_result(c.state)['cleanup_outcome']['failures'][0])
        r=module().public_result({'status':'FAIL','primary_outcome':{'status':'failed','source_phase_diagnostic':{'context':'PRIVATE_SENTINEL','error':{'label':'PRIVATE_SENTINEL','source_sha256':'PRIVATE_SENTINEL','predicate':'PRIVATE_SENTINEL'}}}})
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(r));self.assertEqual(r['primary_outcome'].get('source_phase_diagnostic',{}).get('error',{}).get('label'),'UNKNOWN')


    def test_source_fragments_are_not_complete_progress_envelopes(self):
        with tempfile.TemporaryDirectory()as td:
            result,c=self.failed(Path(td),stage='phase30',stdout=b'session=\nopcache=\nuploads=\npublic=\nsecret=\n',stderr=b'PRIVATE_SENTINEL\n');diag=result['primary_outcome']['source_phase_diagnostic'];self.assertEqual(diag['last_stage']['label'],'UNKNOWN')
    def test_actual_installer_root_guard_is_a_bound_installer_envelope(self):
        self.assertNotEqual(os.geteuid(),0,'offline installer guard fixture requires an unprivileged test user')
        r=subprocess.run([self.BASH,str(self.APP/'deploy/install/install.sh'),'--yes'],capture_output=True,timeout=5);self.assertEqual(r.returncode,1);self.assertEqual(r.stderr,b'install.sh must be run as root\n')
        with tempfile.TemporaryDirectory()as td:
            result,c=self.failed(Path(td),stderr=r.stderr);diag=result['primary_outcome']['source_phase_diagnostic'];self.assertEqual(diag['error']['label'],'INSTALL_INSTALL_L018')
    def test_error_envelopes_are_capped_without_raw_values(self):
        lines=b'install-only qualification requires the selected signed release\ninstall-only recovery qualification requires modern secure administrator setup\ncurrent-install: physical MariaDB canary did not round trip\npublic seed clients remain enabled\ncurrent-install: invalid fixture owner token\ncurrent-install: unsupported mail fixture profile\ncurrent-install: owned fixture effective PHP/mail/webmail entitlement is unavailable\ncurrent-install: owned fixture row or bootstrap domain already exists; refusing reuse\ncurrent-install: owned plan is not ready with the required PHP/mail/webmail contract\n'
        with tempfile.TemporaryDirectory()as td:
            result,c=self.failed(Path(td),stderr=lines);diag=result['primary_outcome']['source_phase_diagnostic'];self.assertTrue(diag['errors_truncated']);self.assertEqual(len(diag['error_labels']),8);self.assertEqual(diag['error']['label'],'CURRENT_INSTALL_L210');self.assertEqual(diag['error_labels'][0],'CURRENT_INSTALL_L012')


    def test_unbound_ordinal_stage_and_extra_row_never_claim_a_failed_command_binding(self):
        for tree in ({'_counter_delta':1},{'_extra_row':True},{'stage':'phase30'},{'exit_code':0},{'interrupted':True}):
            with self.subTest(tree=tree),tempfile.TemporaryDirectory()as td:
                result,c=self.failed(Path(td),tree=tree);diag=result['primary_outcome']['source_phase_diagnostic'];self.assertEqual(diag['binding'],'UNKNOWN');self.assertEqual(diag['command_ordinal'],0);self.assertEqual(diag['error']['label'],'UNKNOWN')
    def test_partial_or_unterminated_lines_do_not_become_complete_envelopes(self):
        for data in (b'current-install: physical MariaDB canary did not round trip',b'x'*70000+b'current-install: physical MariaDB canary did not round trip\n'):
            with self.subTest(size=len(data)),tempfile.TemporaryDirectory()as td:
                result,c=self.failed(Path(td),stderr=data);self.assertEqual(result['primary_outcome']['source_phase_diagnostic']['error']['label'],'UNKNOWN')


    def test_log_directory_replacement_after_open_is_unknown(self):
        m=module()
        with tempfile.TemporaryDirectory()as td:
            root=Path(td);logs=root/'logs';logs.mkdir(mode=0o700);p=logs/'1-current.stderr';p.write_bytes(b'current-install: physical MariaDB canary did not round trip\n');p.chmod(0o600);real=m.os.open;swapped=[]
            def opening(path,flags,*args,**kwargs):
                descriptor=real(path,flags,*args,**kwargs)
                if Path(path)==logs and not swapped:logs.rename(root/'retired');logs.mkdir(mode=0o700);swapped.append(True)
                return descriptor
            with patch.object(m.os,'open',side_effect=opening):lines,scope=m.source_log_tail(root,1,'current','stderr')
            self.assertEqual(scope,'UNKNOWN');self.assertEqual(lines,[])


    def test_actual_phase28_and_phase30_signed_source_guard_and_err_trap(self):
        for stage,site in [('phase28','PHASE28_ERR_L026'),('phase30','PHASE30_ERR_L052')]:
            with self.subTest(stage=stage),tempfile.TemporaryDirectory()as td:
                root=Path(td);stub=root/'multipass';marker=root/'backend-called';stub.write_text('#!/bin/sh\nprintf called > "$OFFLINE_MARKER"\nexit 93\n');stub.chmod(0o700)
                env=dict(os.environ,PATH=td+':'+os.environ['PATH'],OFFLINE_MARKER=str(marker),NAKPANEL_SKIP_PRIOR_PHASES='1',NAKPANEL_MULTIPASS_ARCH='amd64',NAKPANEL_MULTIPASS_VM='nakpanel-offline',NAKPANEL_RUN_TOKEN='offline-token',NAKPANEL_REMOTE_SRC='',NAKPANEL_RELEASE_BUNDLE=str(root/'missing-bundle'),NAKPANEL_RELEASE_PUBLIC_KEY=str(root/'missing-key'),NAKPANEL_RELEASE_VERSION='29.0.0')
                captured=subprocess.run([self.BASH,str(self.APP/('deploy/multipass/'+stage+'-verify.sh'))],env=env,capture_output=True,timeout=5);self.assertEqual(captured.returncode,1);self.assertFalse(marker.exists())
                result,c=self.failed(root,stage=stage,stdout=captured.stdout,stderr=captured.stderr);diag=result['primary_outcome']['source_phase_diagnostic'];self.assertEqual(diag['trap']['label'],site);self.assertEqual(diag['error']['label'],'COMMON_L134');self.assertIn('QUALIFICATION_ARTIFACTS_SH_L032',diag['error_labels'])


    def test_log_reader_rejects_path_shaped_ordinal(self):
        m=module()
        with tempfile.TemporaryDirectory()as td:
            root=Path(td);(root/'logs').mkdir(mode=0o700);p=root/'secret-current.stderr';p.write_bytes(b'PRIVATE_SENTINEL\n');p.chmod(0o600)
            lines,scope=m.source_log_tail(root,'../secret','current','stderr');self.assertEqual((lines,scope),([],'UNKNOWN'))

if __name__=='__main__':unittest.main()
