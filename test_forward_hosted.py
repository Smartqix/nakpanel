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
    return {'schema':'nakpanel-hosted-forward-admission-v1','state':'AUTHORIZED','source_commit':'1627bba3c681a884255eb91452dbba74a43ebbdc','source_tree':'fc003d27bc7e0fc13d095a4ebc464b17471dc26f','controller_commit':'b'*40,'valid_from':'2026-10-20T00:00:00Z','expires_at':'2026-10-20T02:00:00Z','nonce':'c'*32,'repository':'Smartqix/nakpanel','baseline_reviews':{'native24':'dcefa079e44d23d1f6fc9514b32f1be399d3bc7c89190e1f8028dd5cf17c8a18','native26':'f230cba666f3edbdc2fdca18a43e070d13d5b53fbe9fdd10c6aae2e4cabf4a3d','required_ci':'d020396446bb2368b90a7c146e3ff26749eb1aa27eb6b580b97757b58837918b','payload':'3dff375db5cb83a6afa2c54a07d76301a10087d8adaa319bebb108e93c91faf4'},'artifact':{'id':123,'run_id':456,'name':'synthetic-fixture','size':100,'sha256':'d'*64,'expires_at':'2026-10-21T00:00:00Z'},'payload':{'archive':'candidate/nakpanel-29.0.0-linux-amd64.tar.gz','archive_size':80,'archive_sha256':'e'*64,'manifest_sha256':'50a0cc9802629bcdecb50f26a64f0ec8e49a434856f3f3aabb8e36650e8a60cc','public_key_sha256':'043971dd64ac6b9868e3d9f6cf29c852548e8f32276822187c66c2d40656ba61','binaries':{'panel':'535185eb683942313793bcf833f6e71d481a0cf12149103711d1f0e68a0d9c5f','agent':'9dea11b8ddb98e0f21863747d50c5778ab6629b1406a2cb0971b876ccf12fd4c','panelctl':'44319f18d64575dc46afc48d24115634a81e63925a567d9420634cdaf212fc60'}},'oci_image_ref':'docker.io/library/nginx@sha256:'+'5'*64,'authority':{'scope':'fresh-synthetic-native-forward-only','maximum_guests':2,'cpus':2,'memory':'5G','disk':'32G','production':False},'controller_files':{'forward_hosted.py':'6'*64},'app_helpers':{'deploy/multipass/common.sh':'7'*64}}

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
                with patch.object(m,'Runner',FakeTransport):result=c.execute()
            finally:os.umask(old)
            self.assertEqual(result['status'],'PASS');self.assertEqual(events,['actual-dispatch']);self.assertTrue(callable(c.positive));self.assertTrue(c.positive_vm.startswith('nakpanel-positive-'))
    def test_actual_delete_final_error_or_missing_errors_retains_known_custody(self):
        m=module()
        for final in ({'errors':['PRIVATE_SENTINEL'],'list':[]},{'list':[]},{'errors':None,'list':[]}):
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
    def test_initial_cleanup_absence_also_requires_explicit_empty_errors(self):
        m=module()
        for initial in ({'errors':['PRIVATE_SENTINEL'],'list':[]},{'list':[]},{'errors':None,'list':[]}):
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

if __name__=='__main__':unittest.main()
