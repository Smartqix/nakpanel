import copy
import contextlib
import io
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
HELPER = HERE / 'sury-maintenance-drill.py'
MODE = 'SAME_VERSION_REINSTALL_AND_FAILED_CONFIGURATION_RECOVERY'
GATES = ['bundle','fresh-install','inventory','real-upgrade','phase28','valkey-platform','security','phase29','phase30','phase31','phase32','internal-tools','mail-workspace','phase33','phase34','domain-removal','release-artifacts']

class MaintenanceTests(unittest.TestCase):
    def snapshot_record(self):
        return {'children':[],'comment':'Owned cold retention before maintenance','cpu_count':'2','created':'Mon Oct 19 02:05:00 2026 EDT','disk_space':'48.0GiB','memory_size':'5.0GiB','mounts':{},'parent':'','size':''}

    def module(self):
        self.assertTrue(HELPER.exists(), 'the inert maintenance helper is missing')
        spec = importlib.util.spec_from_file_location('maintenance_under_test', HELPER)
        module = importlib.util.module_from_spec(spec)
        with patch('subprocess.run', side_effect=AssertionError('import executed a command')):
            spec.loader.exec_module(module)
        return module

    @contextlib.contextmanager
    def package_file_fixture(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);file=root/'fixture-file';link=root/'fixture-link'
            file.write_bytes(b'owned package file fixture\n');file.chmod(0o640)
            link.symlink_to(file.name)
            yield self.module(),root,file,link

    def collect_package_files(self, module, stdout):
        packages=[{'Package':'fixture-a'},{'Package':'fixture-b'}]
        def command(args):
            self.assertEqual(args,['dpkg-query','-L','fixture-a','fixture-b'])
            return subprocess.CompletedProcess(args,0,stdout,'')
        # Only command is faked; filesystem reads, guards and hashes are real.
        with patch.object(module,'command',side_effect=command):
            return module.package_files(packages)

    def expected_package_files(self, file, link):
        regular=file.lstat();symlink=link.lstat()
        return {str(file):{'mode':stat.S_IMODE(regular.st_mode),'uid':regular.st_uid,'gid':regular.st_gid,'value':hashlib.sha256(file.read_bytes()).hexdigest()},
                str(link):{'mode':stat.S_IMODE(symlink.st_mode),'uid':symlink.st_uid,'gid':symlink.st_gid,'link':file.name}}

    def test_package_files_preserves_real_metadata_and_deduplicates(self):
        with self.package_file_fixture() as (m,root,file,link):
            result=self.collect_package_files(m,str(file)+'\n'+str(link)+'\n'+str(file)+'\n')
            self.assertEqual(result,self.expected_package_files(file,link))

    def test_package_files_accepts_documented_empty_inter_package_separator(self):
        with self.package_file_fixture() as (m,root,file,link):
            result=self.collect_package_files(m,str(file)+'\n\n'+str(link)+'\n')
            self.assertEqual(result,self.expected_package_files(file,link))

    def test_package_files_empty_separator_preserves_adjacent_file_bytes(self):
        with self.package_file_fixture() as (m,root,file,link):
            result=self.collect_package_files(m,str(link)+'\n\n'+str(root)+'\n'+str(file)+'\n\n')
            self.assertEqual(result,self.expected_package_files(file,link))

    def test_package_files_refuses_nonempty_relative_parent_and_human_records(self):
        with self.package_file_fixture() as (m,root,file,link):
            invalid=['relative-file',str(root/'..'/'fixture-file'),' ','\t','diversion by fixture-provider from: /fixture-file','fixture-a:']
            for record in invalid:
                with self.subTest(category=invalid.index(record)),self.assertRaisesRegex(ValueError,'^unexpected package file path$'):
                    self.collect_package_files(m,record+'\n')

    def test_package_files_empty_separator_cannot_hide_invalid_nonempty_record(self):
        with self.package_file_fixture() as (m,root,file,link):
            with self.assertRaisesRegex(ValueError,'^unexpected package file path$'):
                self.collect_package_files(m,str(file)+'\n\nnonempty-invalid-record\n')

    def test_package_files_records_symlink_without_following_missing_target(self):
        with self.package_file_fixture() as (m,root,file,link):
            link.unlink();link.symlink_to('missing-owned-fixture-target')
            result=self.collect_package_files(m,str(link)+'\n')
            self.assertEqual(result[str(link)]['link'],'missing-owned-fixture-target')
            self.assertNotIn('value',result[str(link)])

    def test_package_files_still_refuses_group_writable_regular_file(self):
        with self.package_file_fixture() as (m,root,file,link):
            file.chmod(0o660)
            with self.assertRaisesRegex(ValueError,'^unsafe input type/owner/mode:'):
                self.collect_package_files(m,str(file)+'\n')

    def inputs(self):
        binary = {name: str(n) * 64 for name,n in [('panel',1),('agent',2),('panelctl',3)]}
        b = {'source_vm':'nakpanel-26-04-arm64-test1234','run_token':'test1234','release':'26.04','architecture':'arm64','profile':'ubuntu-26.04-sury','php_provider':'sury','app_version':'29.0.0','runtime_commit':'a'*40,'manifest_sha256':'b'*64,'installed_binary_sha256':binary}
        raw = {'schema':'nakpanel-roundcube-send-read-v1','success':True,'status':'PASS','send_attempts':1,'http_send_completed':True,'self_recipient_verified':True,'imap_arrival_verified':True,'imap_message_id_verified':True,'roundcube_body_verified':True,'message_id':'<real-generated-id@example.test>','uid':'42','subject_sha256':'c'*64,'body_sha256':'d'*64,'recipient_sha256':'e'*64,'qualifier_helper_sha256':'f'*64,'certificate_sha256':'7'*64}
        supplement = dict(b, schema='nakpanel-roundcube-supplement-v1', success=True, qualifier_wrapper_sha256='8'*64,qualifier_helper_sha256='f'*64,raw_receipt=raw,raw_receipt_sha256=hashlib.sha256((json.dumps(raw,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode('ascii')).hexdigest())
        report = {k:b[k] for k in ('source_vm','run_token','release','architecture','profile','php_provider')}
        report.update(schema_version=1,qualification_passed=True,full_php_parity=True,php_contract=['8.3','8.4','8.5'],pending_gates=[],gates=[{'name':name,'status':'PASS','exit_code':0} for name in GATES])
        retention = dict(b,schema='nakpanel-sury-maintenance-retention-v1',status='PASS',snapshot_name='maintenance-sury-test1234',snapshot_id=b['source_vm']+'.maintenance-sury-test1234',snapshot_info_sha256=hashlib.sha256((json.dumps(self.snapshot_record(),sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode('ascii')).hexdigest(),cold_snapshot=True,running_revalidated=True,ownership_verified=True)
        handoff = dict(b,schema='nakpanel-sury-maintenance-handoff-v1',exclusive_source_handoff=True,allowed_operations=[MODE],qualification_report_sha256='9'*64,roundcube_receipt_sha256='0'*64,retention_receipt_sha256='6'*64)
        config = dict(b,operation=MODE,qualification_report_sha256='9'*64,roundcube_receipt_sha256='0'*64,retention_receipt_sha256='6'*64,retention_snapshot='maintenance-sury-test1234',qualifier_wrapper_sha256='8'*64,qualifier_helper_sha256='f'*64)
        return config,report,supplement,retention,handoff

    def test_import_is_inert_and_complete_bound_receipts_are_accepted(self):
        m=self.module();m.validate_authorization(*self.inputs())

    def test_every_canonical_gate_and_real_supplement_is_mandatory(self):
        m=self.module()
        for name in GATES:
            a=list(self.inputs());a[1]['gates']=[g for g in a[1]['gates'] if g['name']!=name]
            with self.subTest(gate=name),self.assertRaises(ValueError):m.validate_authorization(*a)
        for key in ('http_send_completed','self_recipient_verified','imap_arrival_verified','imap_message_id_verified','roundcube_body_verified'):
            a=list(self.inputs());a[2]['raw_receipt'][key]=False
            with self.subTest(raw=key),self.assertRaises(ValueError):m.validate_authorization(*a)
        for key,value in [('send_attempts',True),('success',1),('uid','0'),('message_id','')]:
            a=list(self.inputs());a[2]['raw_receipt'][key]=value
            with self.subTest(raw=key),self.assertRaises(ValueError):m.validate_authorization(*a)

    def test_wrong_payload_hash_raw_bytes_or_pending_handoff_cannot_authorize(self):
        m=self.module()
        for field,value in [('source_vm','other'),('runtime_commit','c'*40),('manifest_sha256','c'*64),('installed_binary_sha256',{}),('qualifier_helper_sha256','c'*64),('raw_receipt_sha256','c'*64)]:
            a=list(self.inputs());a[2][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):m.validate_authorization(*a)
        for index,key,value in [(1,'qualification_passed',False),(3,'cold_snapshot',False),(3,'snapshot_id',''),(3,'snapshot_id','other.snapshot'),(3,'snapshot_info_sha256',None),(3,'snapshot_info_sha256','bad'),(4,'exclusive_source_handoff',False),(4,'allowed_operations',['remove']),(0,'operation','provider-switch')]:
            a=list(self.inputs());a[index][key]=value
            with self.subTest(index=index,key=key),self.assertRaises(ValueError):m.validate_authorization(*a)

    def test_apt_plan_allows_only_identical_explicit_php_packages(self):
        m=self.module();versions={'php8.3-fpm':'8.3.35-1+ubuntu26.04','php-common':'2:99'}
        plan='Reading package lists...\nInst php8.3-fpm [8.3.35-1+ubuntu26.04] (8.3.35-1+ubuntu26.04 deb.sury.org [arm64])\nConf php8.3-fpm (8.3.35-1+ubuntu26.04 deb.sury.org [arm64])\n'
        m.check_apt_plan(plan,versions,{'php8.3-fpm'})
        for changed in [plan.replace('Inst php8.3-fpm','Inst libc6'),plan.replace('(8.3.35-1+ubuntu26.04','(8.3.36-1+ubuntu26.04'),'Remv php8.5-fpm [8.5.11]\n'+plan,'Reading package lists...\n']:
            with self.subTest(plan=changed),self.assertRaises(ValueError):m.check_apt_plan(changed,versions,{'php8.3-fpm'})

    def test_selected_candidate_requires_exact_sury_https_resolute_and_version(self):
        m=self.module();policy='php8.3-fpm:\n Installed: V\n Candidate: V\n Version table:\n *** V 500\n -1 https://packages.sury.org/php resolute/main arm64 Packages\n 100 /var/lib/dpkg/status\n'
        m.check_candidate(policy,'V')
        for changed in [policy.replace('Candidate: V','Candidate: OTHER'),policy.replace('https://packages.sury.org/php','http://packages.sury.org/php'),policy.replace('resolute/main','noble/main'),policy.replace('packages.sury.org','evil.test')]:
            with self.subTest(policy=changed),self.assertRaises(ValueError):m.check_candidate(changed,'V')

    def test_fault_creation_never_overwrites_and_removal_requires_same_inode_and_hash(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);root.chmod(0o700);original=root/'existing.conf';original.write_bytes(b'original setting\n');original.chmod(0o640)
            fault=m.FaultFile(root,'test1234');fault.create();self.assertEqual(original.read_bytes(),b'original setting\n');self.assertEqual(stat.S_IMODE(original.stat().st_mode),0o640)
            with self.assertRaises(FileExistsError):m.FaultFile(root,'test1234').create()
            fault.path.write_bytes(b'changed by another owner')
            with self.assertRaises(ValueError):fault.remove()
            self.assertTrue(fault.path.exists())
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);f=m.FaultFile(root,'test1234');f.create();owned=f.path;old=root/'old';owned.rename(old);owned.write_bytes(old.read_bytes())
            with self.assertRaises(ValueError):f.remove()
            self.assertTrue(owned.exists())

    def test_fault_symlink_is_refused_and_own_exact_file_can_be_removed(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);outside=root/'outside';outside.write_bytes(b'keep');f=m.FaultFile(root,'test1234');f.path.symlink_to(outside)
            with self.assertRaises(FileExistsError):f.create()
            self.assertEqual(outside.read_bytes(),b'keep');f.path.unlink();f.create();f.remove();self.assertFalse(f.path.exists())

    def test_actual_failed_configuration_is_distinguished_from_unrelated_errors(self):
        m=self.module();path='/etc/php/8.3/fpm/pool.d/zz-nakpanel-maintenance-test1234.conf';test=subprocess.CompletedProcess([],78,'','ERROR: ['+path+":2] unknown entry 'nakpanel_owned_drill_invalid'")
        apt=subprocess.CompletedProcess([],100,'','dpkg: error processing package php8.3-fpm (--configure):\n installed php8.3-fpm package post-installation script subprocess returned error exit status 1')
        m.check_expected_failure('8.3',path,test,apt,'install ok half-configured')
        for changed_test,changed_apt,status in [(subprocess.CompletedProcess([],0,'',''),apt,'install ok half-configured'),(test,subprocess.CompletedProcess([],100,'','network unavailable'),'install ok half-configured'),(test,apt,'install ok installed'),(test,subprocess.CompletedProcess([],0,'',''), 'install ok half-configured')]:
            with self.subTest(status=status),self.assertRaises(ValueError):m.check_expected_failure('8.3',path,changed_test,changed_apt,status)

    def test_service_restoration_never_starts_previously_stopped_units(self):
        m=self.module();before={'nakpanel.service':'active','nakpanel-agent.service':'inactive'}
        self.assertEqual(m.restore_service_actions(before),[('start','nakpanel.service'),('stop','nakpanel-agent.service')])
        with self.assertRaises(ValueError):m.restore_service_actions({'other.service':'active'})

    def test_actual_installed_panel_daemon_is_quiesced_before_any_package_transaction(self):
        m=self.module();self.assertTrue((HERE.parent/'systemd/nakpanel.service').is_file())
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'packages.json').write_text('[]');(root/'packages.json').chmod(0o600)
            states={'nakpanel.service':'active','nakpanel-agent.service':'active'};transactions=[]
            class Backend:
                def __init__(self,*args):pass
                def prepare(self):pass
                def reinstall(self,*args):
                    if any(states.values()):raise ValueError('actual panel daemon remained live during package transaction')
                    transactions.append('same-version');return subprocess.CompletedProcess([],0,'','')
                def record(self,*args):pass
            def command(args,**kwargs):
                if args[0]=='systemctl' and args[1] in ('start','stop'):states[args[2]]='active' if args[1]=='start' else ''
                return subprocess.CompletedProcess(args,0,'','')
            with patch.object(m,'GuestBackend',Backend),patch.object(m,'verify_gpgv'),patch.object(m,'command',side_effect=command),patch.object(m,'service_state',side_effect=lambda name:states.get(name,'') or 'inactive'),patch.object(m,'package_inventory',return_value={}),patch.object(m,'guarded_settings',return_value={}),patch.object(m,'package_files',return_value={}),patch.object(m,'intent_state',return_value={}),patch.object(m,'managed_state',return_value={}),patch.object(m,'service_wait'),patch.object(m,'php_smoke'),patch.object(m,'drill_minor'),patch.object(m,'guest_health',return_value={}):
                m.run_guest(root,dict(self.inputs()[0],maintenance_id='drill1234'))
            self.assertEqual(transactions,['same-version']);self.assertEqual(states,{'nakpanel.service':'active','nakpanel-agent.service':'active'})

    def test_failed_managed_baseline_refuses_before_stop_or_package_reinstall(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'packages.json').write_text('[]');(root/'packages.json').chmod(0o600);mutations=[]
            class Backend:
                def __init__(self,*args):pass
                def prepare(self):pass
                def reinstall(self,*args):mutations.append('apt');return subprocess.CompletedProcess([],0,'','')
                def record(self,*args):pass
            def command(args,**kwargs):mutations.append(args);return subprocess.CompletedProcess(args,0,'','')
            with patch.object(m,'GuestBackend',Backend),patch.object(m,'verify_gpgv'),patch.object(m,'command',side_effect=command),patch.object(m,'service_state',return_value='inactive'),patch.object(m,'package_inventory',return_value={}),patch.object(m,'guarded_settings',return_value={}),patch.object(m,'package_files',return_value={}),patch.object(m,'intent_state',return_value={'sites':[],'applications':[],'workers':[]}),patch.object(m,'managed_state',return_value={'nakpanel-php-worker@1.service':'failed'}),patch.object(m,'service_wait'),patch.object(m,'php_smoke'),patch.object(m,'drill_minor'),patch.object(m,'guest_health',return_value={}):
                with self.assertRaisesRegex(ValueError,'managed'):m.run_guest(root,dict(self.inputs()[0],maintenance_id='drill1234'))
            self.assertEqual(mutations,[])

    def test_managed_services_must_match_effective_desired_state_without_starting_stopped_workers(self):
        m=self.module();self.assertTrue(callable(getattr(m,'assert_managed_services',None)), 'managed desired-state guard is missing')
        intent={'sites':[[7,'active','active','8.3','8.3']],'applications':[[4,7,'8.3','active',2,9,'managed']],'workers':[[3,4,'worker','worker.php',[],2,'stopped',5]]}
        states={'nakpanel-php-fpm@7.service':'active','nakpanel-php-worker@3.service':'inactive','nakpanel-php-worker@3-2.service':'inactive'}
        m.assert_managed_services(states,intent)
        for unit,state in [('nakpanel-php-worker@3.service','active'),('nakpanel-php-worker@3.service','failed'),('nakpanel-php-worker@3.service','activating'),('nakpanel-php-fpm@7.service','inactive')]:
            with self.subTest(unit=unit,state=state),self.assertRaises(ValueError):m.assert_managed_services(dict(states,**{unit:state}),intent)
        running=copy.deepcopy(intent);running['workers'][0][6]='running'
        with self.assertRaises(ValueError):m.assert_managed_services(states,running)
        with self.assertRaises(ValueError):m.assert_managed_services({},intent)
        suspended=copy.deepcopy(intent);suspended['sites'][0][2]='suspended';m.assert_managed_services({key:'inactive' for key in states},suspended)
        classic=copy.deepcopy(intent);classic['applications'][0][6]='classic';m.assert_managed_services({},classic)
        maximum=copy.deepcopy(intent);maximum['workers'][0][5]=64
        many={'nakpanel-php-fpm@7.service':'active',**{'nakpanel-php-worker@3'+('' if n==1 else '-'+str(n))+'.service':'inactive' for n in range(1,65)}}
        m.assert_managed_services(many,maximum)

    def test_postboot_inactive_service_fails_without_repair_and_retains_readonly_observation(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);before={'nakpanel.service':'active','nakpanel-agent.service':'inactive'}
            baseline={'mutation_services':before,'database_manager':False,'package_inventory':{},'settings':{},'package_files':{},'intent':{},'managed_services':{}}
            smoke={minor:{'tools':{}} for minor in ('8.3','8.4','8.5')}
            for name,value in [('baseline.json',baseline),('packages.json',[]),('php-smoke-before.json',smoke)]:
                (root/name).write_text(json.dumps(value));(root/name).chmod(0o600)
            states=dict(before,**{'nakpanel.service':'inactive'});mutations=[]
            def command(args,**kwargs):
                if args[:1]==['systemctl'] and args[1] in ('start','stop','restart'):
                    mutations.append(args);states[args[2]]='active' if args[1]!='stop' else 'inactive'
                return subprocess.CompletedProcess(args,0,'','')
            def state(unit):return states.get(unit,'active')
            read=m.root_regular
            with patch.object(m,'root_regular',side_effect=lambda path: b'boot-after\n' if str(path)=='/proc/sys/kernel/random/boot_id' else read(path)),patch.object(m,'command',side_effect=command),patch.object(m,'service_state',side_effect=state),patch.object(m,'package_inventory',return_value={}),patch.object(m,'guarded_settings',return_value={}),patch.object(m,'package_files',return_value={}),patch.object(m,'intent_state',return_value={}),patch.object(m,'managed_state',return_value={}),patch.object(m,'php_smoke',return_value=smoke),patch.object(m.time,'monotonic',side_effect=[0,121]):
                with self.assertRaisesRegex(ValueError,'readiness timed out'):m.guest_health(root,self.inputs()[0],'reboot-1',reboot=True)
            self.assertEqual(mutations,[])
            observed=json.loads((root/'observed-reboot-1.json').read_text())
            self.assertEqual(observed['mutation_services']['nakpanel.service'],'inactive')
            self.assertEqual(observed['package_inventory'],{})

    def test_configuration_tree_receipt_detects_byte_mode_and_symlink_drift(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);f=p/'php.ini';f.write_bytes(b'baseline');f.chmod(0o640);link=p/'20-module.ini';link.symlink_to('php.ini');baseline=m.tree_state(p)
            f.write_bytes(b'changed');self.assertNotEqual(baseline,m.tree_state(p));f.write_bytes(b'baseline');self.assertEqual(baseline,m.tree_state(p));f.chmod(0o600);self.assertNotEqual(baseline,m.tree_state(p));f.chmod(0o640);link.unlink();link.symlink_to('different');self.assertNotEqual(baseline,m.tree_state(p))

    def test_real_minor_transaction_restores_config_and_pending_package_state(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);pool=root/'pool';pool.mkdir();original=pool/'working.conf';original.write_bytes(b'working');baseline=m.tree_state(pool)
            class Backend:
                status='install ok installed'
                def config_test(self,minor):
                    f=next(pool.glob('zz-nakpanel-maintenance-*'),None)
                    return subprocess.CompletedProcess([],78 if f else 0,'',('ERROR: ['+str(f)+":2] unknown entry 'nakpanel_owned_drill_invalid'") if f else '')
                def reinstall(self,minor):
                    if list(pool.glob('zz-nakpanel-maintenance-*')):
                        self.status='install ok half-configured';return subprocess.CompletedProcess([],100,'',f'dpkg: error processing package php{minor}-fpm (--configure): installed php{minor}-fpm package post-installation script subprocess returned error exit status 1')
                    self.status='install ok installed';return subprocess.CompletedProcess([],0,'','')
                def package_status(self,minor):return self.status
            backend=Backend();events=[];m.drill_minor('8.3','test1234',pool,backend,lambda step,data:events.append(step))
            self.assertEqual(backend.status,'install ok installed');self.assertEqual(m.tree_state(pool),baseline);self.assertIn('expected_configuration_failure',events);self.assertIn('recovered',events)

    def test_unsupported_cli_operations_refuse_without_any_multipass_call(self):
        self.module();wrapper=HERE/'sury-maintenance-verify.sh';self.assertTrue(wrapper.exists())
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);fake=p/'multipass';fake.write_text('#!/bin/sh\necho called >> "$LOG"\nexit 99\n');fake.chmod(0o700)
            for op in ('remove','switch-provider','upgrade','advance','rollback'):
                r=subprocess.run(['bash',str(wrapper),op],env=dict(os.environ,PATH=str(p)+':'+os.environ['PATH'],LOG=str(p/'log')),capture_output=True,text=True)
                self.assertNotEqual(r.returncode,0);self.assertFalse((p/'log').exists())

    def test_fault_that_does_not_fail_validation_never_starts_apt(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as td:
            pool=Path(td);state={'apt_called':False}
            class Backend:
                def config_test(self,minor):return subprocess.CompletedProcess([],0,'','')
                def reinstall(self,minor):state['apt_called']=True;return subprocess.CompletedProcess([],100,'','unrelated')
                def package_status(self,minor):return 'install ok installed'
            with self.assertRaises(ValueError):m.drill_minor('8.3','test1234',pool,Backend(),lambda *x:None)
            self.assertFalse(state['apt_called']);self.assertTrue(list(pool.glob('zz-nakpanel-maintenance-*')))

    def test_native_gpgv_receipt_is_exactly_bound_before_retained_packages_are_used(self):
        m=self.module();self.assertTrue(callable(getattr(m,'check_native_gpgv',None)), 'native signature receipt guard is missing')
        c=self.inputs()[0];proof={'native_gpgv':True,'exit_code':0,'vm':c['source_vm'],'run_token':c['run_token'],'release':'26.04','architecture':'arm64','key_sha256':m.KEY_SHA,'inrelease_sha256':'a'*64,'validsig_fingerprint':m.FINGERPRINT,'guest_mutation':False,'package_transaction':False}
        m.check_native_gpgv(proof,c,'a'*64)
        for key,value in [('native_gpgv',False),('exit_code',True),('vm','other'),('key_sha256','b'*64),('inrelease_sha256','b'*64),('validsig_fingerprint','bad')]:
            bad=dict(proof,**{key:value})
            with self.subTest(field=key),self.assertRaises(ValueError):m.check_native_gpgv(bad,c,'a'*64)

    def test_malformed_supported_host_spec_is_refused_before_any_command(self):
        m=self.module();self.assertTrue(callable(getattr(m,'host_main',None)), 'host authorization entrypoint is missing')
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'spec.json';p.write_text('{}');p.chmod(0o600)
            with patch('subprocess.run',side_effect=AssertionError('unauthorized command')):
                with self.assertRaises((ValueError,KeyError)):m.host_main(p)

    def test_remote_loader_does_not_run_the_host_main_entrypoint(self):
        m=self.module();self.assertTrue(callable(getattr(m,'remote_program',None)), 'inert remote loader is missing')
        code="import json,sys\nif __name__=='__main__':raise RuntimeError('host CLI ran remotely')\ndef guest_action(request):return {'passed':request['action']=='health'}\n"
        r=subprocess.run([__import__('sys').executable,'-c',m.remote_program(code)],input=json.dumps({'action':'health'}),capture_output=True,text=True)
        self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout),{'passed':True})

    def test_ubuntu_os_release_symlink_is_accepted_only_for_its_fixed_root_owned_target(self):
        m=self.module();self.assertTrue(callable(getattr(m,'os_identity_bytes',None)), 'narrow OS metadata reader is missing')
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'etc').mkdir();(root/'usr/lib').mkdir(parents=True);target=root/'usr/lib/os-release';target.write_bytes(b'ID=ubuntu\n');target.chmod(0o644);link=root/'etc/os-release';link.symlink_to('../usr/lib/os-release');self.assertEqual(m.os_identity_bytes(root),b'ID=ubuntu\n')
            link.unlink();link.symlink_to('/tmp/unrelated')
            with self.assertRaises(ValueError):m.os_identity_bytes(root)

    def test_cached_archive_targets_require_the_exact_authenticated_https_artifact(self):
        m=self.module();self.assertTrue(callable(getattr(m,'archive_targets',None)), 'constrained APT cache mapping is missing')
        entries=[{'Package':'php8.3-fpm','Filename':'pool/main/p/php8.3/php8.3-fpm_V_arm64.deb','Size':'123','SHA256':'a'*64}]
        good="'https://packages.sury.org/php/pool/main/p/php8.3/php8.3-fpm_V_arm64.deb' php8.3-fpm_V_arm64.deb 123 SHA256:"+'a'*64+'\n'
        self.assertEqual(m.archive_targets(good,entries),{'php8.3-fpm':'php8.3-fpm_V_arm64.deb'})
        for bad in [good.replace('https:','http:'),good.replace('packages.sury.org','evil.test'),good.replace(' 123 ',' 124 '),good.replace(' php8.3-fpm_V_arm64.deb ',' ../escape '),'']:
            with self.subTest(line=bad),self.assertRaises(ValueError):m.archive_targets(bad,entries)

    def host_case(self, failure=None):
        m=self.module();temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=Path(temp.name);evidence=root/'evidence';evidence.mkdir(mode=0o700)
        c,report,supplement,retention,handoff=self.inputs();qualifier=root/'qualifier';(qualifier/'deploy/multipass').mkdir(parents=True);wrapper=qualifier/'deploy/multipass/internal-tools-verify.sh';wrapper.write_bytes(b'reviewed wrapper');wrapper.chmod(0o600);whash=hashlib.sha256(wrapper.read_bytes()).hexdigest();c['qualifier_wrapper_sha256']=whash;supplement['qualifier_wrapper_sha256']=whash
        c.update(public_key_sha256='a'*64,signature_sha256='b'*64,roundcube_execution_sha256='4'*64,qualifier_files_sha256={'deploy/multipass/internal-tools-verify.sh':whash,'deploy/multipass/roundcube-send-read.py':'f'*64,'deploy/multipass/roundcube_send_read_test.go':'5'*64,'deploy/multipass/roundcube_send_read_test.py':'6'*64},maintenance_id='drill1234',maintenance_helper_sha256=hashlib.sha256(HELPER.read_bytes()).hexdigest(),ownership_directory=str(root/'ownership'),bundle=str(root/'bundle'),public_key=str(root/'public.pem'),allow_development=True,cell_report_directory=str(root/'cell'),qualifier_source_sha256={'deploy/multipass/internal-tools-verify.sh':whash},qualifier_commit='d'*40)
        record=Path(c['ownership_directory'])/c['run_token']/c['source_vm'];record.parent.mkdir(parents=True,mode=0o700);record.write_text('26.04\tarm64\t'+c['run_token']+'\n');record.chmod(0o600)
        payload=root/'php8.3-fpm_V_arm64.deb';payload.write_bytes(b'retained authenticated package');payload.chmod(0o600);packages=[{'Package':'php8.3-fpm','Version':'V','Architecture':'arm64','Size':str(len(payload.read_bytes())),'Filename':'pool/main/p/php8.3/'+payload.name,'SHA256':hashlib.sha256(payload.read_bytes()).hexdigest(),'retained_file':str(payload)}]
        state={'boots':0,'flows':0,'stopped':False,'mutated':False}
        def command(args,**kwargs):
            if args[:2]==['multipass','info']:
                self.assertEqual(args,['multipass','info',retention['snapshot_id'],'--format','json'])
                metadata=self.snapshot_record();snapshots={c['retention_snapshot']:metadata};value={'errors':[],'info':{c['source_vm']:{'snapshots':snapshots}}}
                if failure=='snapshot-missing':snapshots.clear()
                if failure=='snapshot-recreated':metadata['created']='Mon Oct 19 02:06:00 2026 EDT'
                if failure=='snapshot-extra':snapshots['unrelated']=copy.deepcopy(metadata)
                if failure=='snapshot-errors':value['errors']=['snapshot not found']
                if failure=='snapshot-wrong-vm':value['info']={'other':{'snapshots':snapshots}}
                if failure=='snapshot-command-failed':return subprocess.CompletedProcess(args,1,json.dumps(value),'daemon unavailable')
                return subprocess.CompletedProcess(args,0,json.dumps(value),'')
            if args[:2]==['multipass','transfer']:state['mutated']=True
            if args[:2]==['multipass','stop']:self.assertEqual(args[2],c['source_vm']);state['stopped']=True
            if args[:2]==['multipass','restart']:state['boots']+=1
            if args[:2]==['multipass','exec']:
                request=json.loads(kwargs['data']);action=request['action']
                if action=='stage':value={'status':'STAGED'}
                elif action=='run':
                    if failure in ('transaction','ownership-drift'):
                        if failure=='ownership-drift':record.write_text('changed')
                        raise RuntimeError('transaction failure')
                    value={'status':'RECOVERED','operation':MODE,'boot_id':'boot-0'}
                else:
                    value={'status':'HEALTHY','boot_id':'boot-'+str(state['boots']) if failure!='same-boot' else 'boot-0','service_repair_performed':failure=='postboot-repaired','observation_sha256':'a'*64}
                    if failure=='postboot-no-observation':value.pop('observation_sha256')
                return subprocess.CompletedProcess(args,0,json.dumps(value),'')
            if args[-1:] == ['--roundcube-only']:
                state['flows']+=1;proof=copy.deepcopy(supplement)
                if failure!='reused-flow':proof['raw_receipt'].update(message_id='<flow-'+str(state['flows'])+'@example.test>',uid=str(42+state['flows']))
                proof['raw_receipt_sha256']=hashlib.sha256(m.canonical(proof['raw_receipt'])).hexdigest();output=Path(kwargs['env']['NAKPANEL_INTERNAL_TOOLS_RECEIPT']);output.write_bytes(m.canonical(proof));output.chmod(0o600)
            return subprocess.CompletedProcess(args,0,'verified selected installed release','')
        receipts={'qualification_report':report,'roundcube_receipt':supplement,'roundcube_execution_receipt':{},'retention_receipt':retention,'exclusive_handoff':handoff}
        return m,c,packages,receipts,evidence,qualifier,state,command

    def test_host_acceptance_requires_two_distinct_boots_and_three_fresh_realflow_receipts(self):
        m,c,packages,receipts,evidence,qualifier,state,run=self.host_case()
        with contextlib.redirect_stdout(io.StringIO()),patch.object(m,'command',side_effect=run):m.host_execute(c,packages,b'release',b'index',receipts,evidence,HELPER,qualifier,qualifier)
        result=json.loads((evidence/'result.json').read_text());self.assertEqual(result['status'],'PASS');self.assertEqual(state['boots'],2);self.assertEqual(state['flows'],3);self.assertFalse(state['stopped']);self.assertIs(result['genuine_version_advance'],False);self.assertIs(result['apt_version_rollback'],False);self.assertEqual(result.get('qualifier_commit'),c['qualifier_commit'])

    def test_missing_or_recreated_retention_snapshot_refuses_before_first_guest_write(self):
        for failure in ('snapshot-missing','snapshot-recreated','snapshot-extra','snapshot-errors','snapshot-wrong-vm','snapshot-command-failed'):
            with self.subTest(failure=failure):
                m,c,packages,receipts,evidence,qualifier,state,run=self.host_case(failure)
                with contextlib.redirect_stdout(io.StringIO()),patch.object(m,'command',side_effect=run):
                    with self.assertRaisesRegex(ValueError,'snapshot'):m.host_execute(c,packages,b'release',b'index',receipts,evidence,HELPER,qualifier,qualifier)
                self.assertFalse(state['mutated']);self.assertFalse(state['stopped']);self.assertEqual(state['boots'],0);self.assertEqual(state['flows'],0)

    def test_postboot_repair_or_missing_observation_cannot_be_accepted_as_persistence(self):
        for failure in ('postboot-repaired','postboot-no-observation'):
            with self.subTest(failure=failure):
                m,c,packages,receipts,evidence,qualifier,state,run=self.host_case(failure)
                with contextlib.redirect_stdout(io.StringIO()),patch.object(m,'command',side_effect=run):
                    with self.assertRaisesRegex(ValueError,'unassisted'):m.host_execute(c,packages,b'release',b'index',receipts,evidence,HELPER,qualifier,qualifier)
                self.assertEqual(state['boots'],1);self.assertEqual(state['flows'],1);self.assertTrue(state['stopped']);self.assertEqual(json.loads((evidence/'result.json').read_text())['status'],'FAIL')

    def test_reused_flow_or_same_boot_never_becomes_a_passing_recovery(self):
        for failure in ('reused-flow','same-boot'):
            with self.subTest(failure=failure):
                m,c,packages,receipts,evidence,qualifier,state,run=self.host_case(failure)
                with patch.object(m,'command',side_effect=run):
                    with self.assertRaises(ValueError):m.host_execute(c,packages,b'release',b'index',receipts,evidence,HELPER,qualifier,qualifier)
                self.assertEqual(json.loads((evidence/'result.json').read_text())['status'],'FAIL');self.assertTrue(state['stopped'])

    def test_host_failure_stops_exact_known_owner_and_does_not_stop_after_owner_drift(self):
        for failure in ('transaction','ownership-drift'):
            with self.subTest(failure=failure):
                m,c,packages,receipts,evidence,qualifier,state,run=self.host_case(failure)
                with patch.object(m,'command',side_effect=run):
                    with self.assertRaises(RuntimeError):m.host_execute(c,packages,b'release',b'index',receipts,evidence,HELPER,qualifier,qualifier)
                result=json.loads((evidence/'result.json').read_text());self.assertEqual(result['guest_state'],'stopped_after_failure' if failure=='transaction' else 'failure_stop_unconfirmed');self.assertEqual(state['stopped'],failure=='transaction');self.assertEqual(state['boots'],0)

    def test_controlled_cancellation_after_transfer_records_failure_and_preserves_ownership_stop_guard(self):
        for drift in (False,True):
            with self.subTest(ownership_drift=drift):
                m,c,packages,receipts,evidence,qualifier,state,run=self.host_case()
                def interrupted(args,**kwargs):
                    if args[:2]==['multipass','exec'] and json.loads(kwargs['data'])['action']=='run':
                        if drift:(Path(c['ownership_directory'])/c['run_token']/c['source_vm']).write_text('changed')
                        raise KeyboardInterrupt()
                    return run(args,**kwargs)
                with patch.object(m,'command',side_effect=interrupted):
                    with self.assertRaises(KeyboardInterrupt):m.host_execute(c,packages,b'release',b'index',receipts,evidence,HELPER,qualifier,qualifier)
                result=json.loads((evidence/'result.json').read_text());self.assertEqual(result['status'],'FAIL');self.assertEqual(result['guest_state'],'failure_stop_unconfirmed' if drift else 'stopped_after_failure');self.assertEqual(state['stopped'],not drift)

    def test_interrupted_atomic_success_publication_cannot_block_failure_receipt_and_owned_stop(self):
        m,c,packages,receipts,evidence,qualifier,state,run=self.host_case();fsync=m.os.fsync;fired=False
        def interrupted(fd):
            nonlocal fired
            pending=[path for path in evidence.glob('.result.json.*') if path.is_file() and json.loads(path.read_text()).get('status')=='PASS']
            if not fired and pending:fired=True;raise KeyboardInterrupt()
            return fsync(fd)
        error=None
        with patch.object(m,'command',side_effect=run),patch.object(m.os,'fsync',side_effect=interrupted):
            try:m.host_execute(c,packages,b'release',b'index',receipts,evidence,HELPER,qualifier,qualifier)
            except BaseException as caught:error=type(caught).__name__
        self.assertTrue(fired);self.assertEqual(error,'KeyboardInterrupt');self.assertEqual(json.loads((evidence/'result.json').read_text())['status'],'FAIL');self.assertTrue(state['stopped']);self.assertEqual(list(evidence.glob('.result.json.*')),[])

    def test_sigterm_after_guest_write_is_a_controlled_failure_with_cold_retention(self):
        with tempfile.TemporaryDirectory() as td:
            output=Path(td)/'cancelled.json'
            code='''import importlib.util,json,os,signal,sys
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('fixture',sys.argv[1]);f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
owner=f.MaintenanceTests();m,c,packages,receipts,evidence,qualifier,state,run=owner.host_case()
def terminated(args,**kwargs):
 if args[:2]==['multipass','exec'] and json.loads(kwargs['data'])['action']=='run':os.kill(os.getpid(),signal.SIGTERM)
 return run(args,**kwargs)
try:
 with patch.object(m,'command',side_effect=terminated):m.host_execute(c,packages,b'release',b'index',receipts,evidence,f.HELPER,qualifier,qualifier)
except KeyboardInterrupt:pass
finally:
 Path(sys.argv[2]).write_text(json.dumps({'result':json.loads((evidence/'result.json').read_text()),'stopped':state['stopped']}));owner.doCleanups()
'''
            run=subprocess.run([__import__('sys').executable,'-c',code,str(Path(__file__).resolve()),str(output)],capture_output=True,text=True,timeout=10)
            self.assertEqual(run.returncode,0,run.stderr);proof=json.loads(output.read_text());self.assertEqual(proof['result']['status'],'FAIL');self.assertEqual(proof['result']['guest_state'],'stopped_after_failure');self.assertTrue(proof['stopped'])

    def test_outer_roundcube_execution_requires_reviewed_commit_all_four_files_and_real_exit(self):
        m=self.module();self.assertTrue(callable(getattr(m,'check_roundcube_execution',None)), 'outer real-execution receipt guard is missing')
        c,_,envelope,_,_=self.inputs();c.update(qualifier_commit='d'*40,qualifier_files_sha256={'deploy/multipass/internal-tools-verify.sh':'8'*64,'deploy/multipass/roundcube-send-read.py':'f'*64,'deploy/multipass/roundcube_send_read_test.go':'5'*64,'deploy/multipass/roundcube_send_read_test.py':'6'*64})
        receipt={k:c[k] for k in ('source_vm','run_token','release','architecture','profile','php_provider','runtime_commit')};receipt.update(schema='nakpanel-roundcube-supplement-execution-v1',success=True,exit_code=0,qualifier_commit=c['qualifier_commit'],qualifier_files_sha256=c['qualifier_files_sha256'],envelope_sha256=hashlib.sha256(m.canonical(envelope)).hexdigest(),started_at='2026-10-19T06:00:00+00:00',finished_at='2026-10-19T06:00:01+00:00')
        m.check_roundcube_execution(receipt,c,envelope)
        for key,value in [('exit_code',True),('qualifier_commit','e'*40),('qualifier_files_sha256',{}),('envelope_sha256','0'*64),('finished_at','pending')]:
            bad=dict(receipt,**{key:value})
            with self.subTest(field=key),self.assertRaises(ValueError):m.check_roundcube_execution(bad,c,envelope)

    def test_malformed_receipt_types_and_incomplete_php_contract_reject_cleanly(self):
        m=self.module()
        for index,key,value in [(1,'gates',[False]*17),(1,'php_contract',['8.5']),(1,'full_php_parity',False),(2,'raw_receipt',[]),(0,'installed_binary_sha256',False)]:
            inputs=list(self.inputs());inputs[index][key]=value
            with self.subTest(index=index,key=key),self.assertRaises(ValueError):m.validate_authorization(*inputs)

    def test_host_credentials_and_private_paths_never_enter_transferred_guest_control(self):
        m=self.module();self.assertTrue(callable(getattr(m,'guest_configuration',None)), 'minimal guest configuration projection is missing')
        c=self.inputs()[0];c.update(maintenance_id='drill1234',allow_development=True,public_key_sha256='a'*64,signature_sha256='b'*64,qualifier_commit='c'*40,qualifier_files_sha256={},maintenance_helper_sha256='d'*64,roundcube_execution_sha256='e'*64,mailbox_password='private credential',evidence_directory='/private/host/path',references={'private':'data'})
        guest=m.guest_configuration(c);self.assertNotIn('mailbox_password',guest);self.assertNotIn('references',guest);self.assertNotIn('evidence_directory',guest);self.assertEqual(guest['source_vm'],c['source_vm']);self.assertNotIn('private credential',json.dumps(guest))

    def test_tool_health_requires_successful_matching_nonroot_composer_php_worker(self):
        m=self.module();self.assertTrue(callable(getattr(m,'parse_tool_results',None)), 'actual tool/@php worker proof is missing')
        composer=subprocess.CompletedProcess([],0,'Composer version 2.10.3 2026-09-01\n','');wp=subprocess.CompletedProcess([],0,'WP-CLI version:\t2.12.0\n','');worker=subprocess.CompletedProcess([],0,'NAKPANEL_MAINTENANCE_WORKER='+json.dumps({'version':'8.3.35','uid':65534})+'\n','')
        proof=m.parse_tool_results('8.3',65534,composer,wp,worker);self.assertEqual(proof['composer_version'],'2.10.3');self.assertEqual(proof['worker']['uid'],65534)
        for bad in [subprocess.CompletedProcess([],1,worker.stdout,''),subprocess.CompletedProcess([],0,worker.stdout.replace('65534','0'),''),subprocess.CompletedProcess([],0,worker.stdout.replace('8.3.35','8.4.26'),''),subprocess.CompletedProcess([],0,'> quoted marker without actual worker output','')]:
            with self.subTest(output=bad.stdout),self.assertRaises(ValueError):m.parse_tool_results('8.3',65534,composer,wp,bad)

if __name__=='__main__':unittest.main()
