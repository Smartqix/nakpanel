import copy
import contextlib
import io
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import socket
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
HELPER = HERE / 'sury-maintenance-drill.py'
MODE = 'SAME_VERSION_REINSTALL_AND_FAILED_CONFIGURATION_RECOVERY'
GATES = ['bundle','fresh-install','inventory','phase28','valkey-platform','security','phase29','phase30','phase31','phase32','internal-tools','mail-workspace','phase33','phase34','domain-removal','release-artifacts']

class MaintenanceTests(unittest.TestCase):
    def test_failed_remote_retains_reviewed_locations_without_private_values(self):
        m=self.module()
        source=HELPER.read_text()+"\ndef guest_action(request):\n raise ValueError('private-password-and-command-output')\n"
        result=subprocess.run([sys.executable,'-c',m.remote_program(source)],input='{}',capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        proof=json.loads(result.stdout)
        self.assertEqual(proof['schema'],'nakpanel-maintenance-guest-failure-v1')
        self.assertEqual(proof['error_type'],'ValueError')
        self.assertTrue(proof['failure_frames'])
        self.assertEqual(proof['failure_frames'][-1]['function'],'guest_action')
        self.assertNotIn('private-password',result.stdout)
        self.assertNotIn(str(HERE),result.stdout)
        self.assertEqual(m.validated_failure_frames(proof['failure_frames'],source),proof['failure_frames'])
        for invalid in ([{'function':'private-secret','line':1}],[{'function':{},'line':1}],[{'function':'guest_action','line':10**6}],[{'function':'guest_action','line':1,'filename':'private-path'}]):
            self.assertEqual(m.validated_failure_frames(invalid,source),[])

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
        report.update(schema_version=1,qualification_scope="CURRENT_VERSION_ONLY",excluded_gates=["real-upgrade"],qualification_passed=True,full_php_parity=True,php_contract=['8.3','8.4','8.5'],pending_gates=[],gates=[{'name':name,'status':'PASS','exit_code':0} for name in GATES])
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

    def postinst_failure_fixture(self, minor, wording, *, returncode=100):
        path=Path('/etc/php/'+minor+'/fpm/pool.d/zz-nakpanel-maintenance-owned123.conf')
        config=subprocess.CompletedProcess([],78,'',str(path)+": unknown entry 'nakpanel_owned_drill_invalid'")
        package='php'+minor+'-fpm'
        detail={'legacy':'installed '+package+' package post-installation script subprocess returned error exit status 1',
                'current':'old '+package+' package postinst maintainer script subprocess failed with exit status 1'}[wording]
        text='dpkg: error processing package '+package+' (--configure):\n '+detail+'\n'
        return path,config,subprocess.CompletedProcess([],returncode,'',text)

    def test_postinst_failure_accepts_exact_dpkg_122_and_123_diagnostics(self):
        m=self.module()
        # dpkg src/main/script.c + lib/dpkg/subproc.c, 1.22.22 / 1.23.7.
        # https://sources.debian.org/src/dpkg/1.23.7/src/main/script.c/
        for minor in m.MINORS:
            for wording in ('legacy','current'):
                with self.subTest(minor=minor,wording=wording):
                    path,config,transaction=self.postinst_failure_fixture(minor,wording)
                    accepted=True
                    try:m.check_expected_failure(minor,path,config,transaction,'install ok half-configured')
                    except ValueError:accepted=False
                    self.assertTrue(accepted,'documented real postinst exit1 diagnostic was rejected')

    def test_postinst_failure_wording_cannot_accept_wrong_package_script_or_exit(self):
        m=self.module();minor='8.3'
        for wording in ('legacy','current'):
            path,config,transaction=self.postinst_failure_fixture(minor,wording)
            text=transaction.stderr
            wrong=[text.replace('php8.3-fpm','php8.4-fpm'),
                   text.replace('(--configure)','(--remove)'),
                   text.replace('post-installation script','pre-installation script') if wording=='legacy' else text.replace('postinst maintainer script','prerm maintainer script'),
                   text.replace('exit status 1','exit status 10'),
                   text.replace('exit status 1','exit status 2')+'unrelated fixture exit status 1\n']
            for index,value in enumerate(wrong):
                with self.subTest(wording=wording,case=index),self.assertRaisesRegex(ValueError,'APT failure was not the expected real FPM postinst failure'):
                    m.check_expected_failure(minor,path,config,subprocess.CompletedProcess([],100,'',value),'install ok half-configured')

    def test_postinst_failure_equivalent_wording_retains_code_status_and_owned_fault_guards(self):
        m=self.module();minor='8.3'
        for wording in ('legacy','current'):
            path,config,transaction=self.postinst_failure_fixture(minor,wording)
            with self.subTest(wording=wording,guard='APT100'),self.assertRaisesRegex(ValueError,'APT failure was not the expected real FPM postinst failure'):
                m.check_expected_failure(minor,path,config,subprocess.CompletedProcess([],0,'',transaction.stderr),'install ok half-configured')
            with self.subTest(wording=wording,guard='dpkg-half-configured'),self.assertRaisesRegex(ValueError,'real dpkg half-configured state required'):
                m.check_expected_failure(minor,path,config,transaction,'install ok installed')
            with self.subTest(wording=wording,guard='owned-config'),self.assertRaisesRegex(ValueError,'owned injected FPM configuration did not cause the exact expected failure'):
                m.check_expected_failure(minor,path,subprocess.CompletedProcess([],78,'','unknown unrelated directive'),transaction,'install ok half-configured')

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

    def test_classic_dedicated_fpm_follows_active_site_and_ignores_managed_application_intent(self):
        m=self.module()
        # Product SitePlan uses dedicated FPM for positive persisted site IDs;
        # classic reconciliation leaves site hosting active even if the separate
        # managed application desired_state/version is stale or suspended.
        intent={'sites':[[7,'active','active','8.5','8.5']],'applications':[[4,7,'8.3','suspended',2,None,'classic']],'workers':[]}
        try:m.assert_managed_services({'nakpanel-php-fpm@7.service':'active'},intent)
        except ValueError as error:self.fail('legitimate active Classic FPM refused: '+str(error))

    def test_classic_dedicated_fpm_follows_site_suspension(self):
        m=self.module()
        intent={'sites':[[7,'suspended','suspended','8.5','8.5']],'applications':[[4,7,'8.3','active',2,None,'classic']],'workers':[]}
        m.assert_managed_services({'nakpanel-php-fpm@7.service':'inactive'},intent)
        with self.assertRaises(ValueError):m.assert_managed_services({'nakpanel-php-fpm@7.service':'active'},intent)

    def test_classic_shared_pool_absence_is_allowed_but_present_unit_state_is_checked(self):
        m=self.module();intent={'sites':[[7,'active','active','8.5','8.5']],'applications':[[4,7,'8.5','active',2,None,'classic']],'workers':[]}
        m.assert_managed_services({},intent)
        for states in ({'nakpanel-php-fpm@7.service':'inactive'},{'nakpanel-php-fpm@7.service':'failed'},{'nakpanel-php-fpm@7.service':'activating'}):
            with self.subTest(states=states),self.assertRaises(ValueError):m.assert_managed_services(states,intent)

    def test_known_site_fpm_without_application_row_follows_site_state(self):
        m=self.module();intent={'sites':[[7,'active','active','8.5','8.5']],'applications':[],'workers':[]}
        m.assert_managed_services({'nakpanel-php-fpm@7.service':'active'},intent)
        m.assert_managed_services({},intent)
        with self.assertRaises(ValueError):m.assert_managed_services({'nakpanel-php-fpm@7.service':'inactive'},intent)
        intent['sites'][0][2]='suspended'
        m.assert_managed_services({'nakpanel-php-fpm@7.service':'inactive'},intent)
        with self.assertRaises(ValueError):m.assert_managed_services({'nakpanel-php-fpm@7.service':'active'},intent)
        with self.assertRaises(ValueError):m.assert_managed_services({'nakpanel-php-fpm@99.service':'inactive'},intent)

    def test_previously_present_classic_fpm_disappearing_is_still_rejected_by_health(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);before={unit:'active' for unit in m.SERVICES}
            intent={'sites':[[7,'active','active','8.5','8.5']],'applications':[[4,7,'8.5','active',2,None,'classic']],'workers':[]}
            baseline={'mutation_services':before,'database_manager':False,'package_inventory':{},'settings':{},'package_files':{},'intent':intent,'managed_services':{'nakpanel-php-fpm@7.service':'active'}}
            for name,value in [('baseline.json',baseline),('packages.json',[])]:
                (root/name).write_text(json.dumps(value));(root/name).chmod(0o600)
            def command(args,**kwargs):
                self.assertTrue(args[:2]==['systemctl','show'] or args==['dpkg','--audit'],'unexpected command or attempted service repair')
                return subprocess.CompletedProcess(args,0,'','')
            read=m.root_regular
            with patch.object(m,'root_regular',side_effect=lambda path:b'boot-after\n' if str(path)=='/proc/sys/kernel/random/boot_id' else read(path)),patch.object(m,'command',side_effect=command),patch.object(m,'service_state',return_value='active'),patch.object(m,'package_inventory',return_value={}),patch.object(m,'guarded_settings',return_value={}),patch.object(m,'package_files',return_value={}),patch.object(m,'intent_state',return_value=intent),patch.object(m,'managed_state',return_value={}),patch.object(m,'service_wait'):
                with self.assertRaisesRegex(ValueError,'managed PHP service active/stopped state changed'):m.guest_health(root,self.inputs()[0],'reboot-1',reboot=True)
            observed=json.loads((root/'observed-reboot-1.json').read_text());self.assertEqual(observed['managed_services'],{})

    def test_classic_global_fpm_legacy_plan_has_no_dedicated_unit(self):
        m=self.module();intent={'sites':[[0,'active','active','8.3','8.3']],'applications':[[4,0,'8.3','active',2,None,'classic']],'workers':[]}
        m.assert_managed_services({},intent)
        with self.assertRaises(ValueError):m.assert_managed_services({'nakpanel-php-fpm@7.service':'active'},intent)

    def test_classic_workers_remain_stopped_even_with_running_desired_state(self):
        m=self.module();intent={'sites':[[7,'active','active','8.5','8.5']],'applications':[[4,7,'8.5','active',2,None,'classic']],'workers':[[3,4,'worker','worker.php',[],2,'running',5]]}
        states={'nakpanel-php-fpm@7.service':'active','nakpanel-php-worker@3.service':'inactive','nakpanel-php-worker@3-2.service':'inactive'}
        m.assert_managed_services(states,intent)
        for unit in ('nakpanel-php-worker@3.service','nakpanel-php-worker@3-2.service'):
            with self.subTest(unit=unit),self.assertRaises(ValueError):m.assert_managed_services(dict(states,**{unit:'active'}),intent)

    def test_classic_and_managed_units_refuse_unknown_stale_and_wrong_states(self):
        m=self.module();intent={'sites':[[7,'active','active','8.5','8.5'],[8,'active','active','8.3','8.3']],'applications':[[4,7,'8.5','active',2,None,'classic'],[5,8,'8.3','active',3,11,'managed']],'workers':[[3,5,'worker','worker.php',[],1,'stopped',5]]}
        states={'nakpanel-php-fpm@7.service':'active','nakpanel-php-fpm@8.service':'active','nakpanel-php-worker@3.service':'inactive'}
        m.assert_managed_services(states,intent)
        running=copy.deepcopy(intent);running['workers'][0][6]='running'
        with self.assertRaises(ValueError):m.assert_managed_services({k:v for k,v in states.items() if not k.startswith('nakpanel-php-worker')},running)
        suspended=copy.deepcopy(intent);suspended['applications'][1][3]='suspended'
        m.assert_managed_services(dict(states,**{'nakpanel-php-fpm@8.service':'inactive'}),suspended)
        with self.assertRaises(ValueError):m.assert_managed_services(states,suspended)
        for unit,state in [('nakpanel-php-fpm@99.service','active'),('nakpanel-php-fpm@99.service','inactive'),('nakpanel-php-worker@99.service','inactive'),('nakpanel-php-fpm@8.service','inactive'),('nakpanel-php-worker@3.service','active')]:
            with self.subTest(unit=unit,state=state),self.assertRaises(ValueError):m.assert_managed_services(dict(states,**{unit:state}),intent)

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
                    raise AssertionError('APT --reinstall cannot recover this half-configured package')
                def configure(self,minor):
                    if list(pool.glob('zz-nakpanel-maintenance-*')):raise AssertionError('fault must be removed before configuration')
                    self.status='install ok installed';return subprocess.CompletedProcess([],0,'','')
                def package_status(self,minor):return self.status
            backend=Backend();events=[];m.drill_minor('8.3','test1234',pool,backend,lambda step,data:events.append(step))
            self.assertEqual(backend.status,'install ok installed');self.assertEqual(m.tree_state(pool),baseline);self.assertIn('expected_configuration_failure',events);self.assertIn('recovered',events)

    def test_configuration_only_plan_refuses_unpack_other_packages_and_missing_configuration(self):
        m=self.module();versions={'php8.3-fpm':'V','php8.4-fpm':'OTHER'}
        m.check_apt_plan('Conf php8.3-fpm (V provider [amd64])\n',versions,{'php8.3-fpm'},configuration_only=True)
        for value in ('Inst php8.3-fpm [V] (V provider [amd64])\nConf php8.3-fpm (V provider [amd64])\n',
                      'Conf php8.4-fpm (OTHER provider [amd64])\n', 'Conf php8.3-fpm (WRONG provider [amd64])\n',
                      'Remv php8.3-fpm [V]\n', '', 'Conf php8.3-fpm (V provider [amd64])\nConf php8.3-fpm (V provider [amd64])\n'):
            with self.subTest(plan=value),self.assertRaises(ValueError):
                m.check_apt_plan(value,versions,{'php8.3-fpm'},configuration_only=True)

    def test_configuration_recovery_requires_exact_pending_package_and_signed_script(self):
        for failure in ('none','not-prepared','not-pending','foreign-pending','changed-version','changed-script','invalid-config','unpack-plan','foreign-plan','apt-failure'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as td:
                m=self.module();root=Path(td);script=root/'postinst';script.write_bytes(b'#!/bin/sh\nexit 0\n');script.chmod(0o600)
                backend=m.GuestBackend(root,{'architecture':'amd64'},[{'Package':'php8.3-fpm','Version':'V'}])
                backend.prepared=failure!='not-prepared'
                backend.original_inventory={'php8.3-fpm':['V','install ok installed'],'unrelated':['U','install ok installed']}
                backend.postinst_sha256={'8.3':hashlib.sha256(script.read_bytes()).hexdigest()}
                if failure=='changed-script':script.write_bytes(b'changed postinst')
                observed={'php8.3-fpm':['V','install ok half-configured'],'unrelated':['U','install ok installed']}
                if failure=='not-pending':observed['php8.3-fpm'][1]='install ok installed'
                if failure=='foreign-pending':observed['unrelated'][1]='install ok half-configured'
                if failure=='changed-version':observed['php8.3-fpm'][0]='WRONG'
                mutations=[];real_regular=m.root_regular
                def regular(path,expected=None):
                    self.assertEqual(str(path),'/var/lib/dpkg/info/php8.3-fpm.postinst')
                    return real_regular(script,expected)
                def command(args,**kwargs):
                    if args[0]=='dpkg-query':
                        self.assertEqual(args,['dpkg-query','-W','-f=${binary:Package}\t${Version}\t${Status}\n'])
                        return subprocess.CompletedProcess(args,0,''.join(name+'\t'+'\t'.join(value)+'\n' for name,value in observed.items()),'')
                    if args[0]=='/usr/sbin/php-fpm8.3':
                        return subprocess.CompletedProcess(args,78 if failure=='invalid-config' else 0,'','')
                    self.assertEqual(args[0],'apt-get');self.assertNotIn('--reinstall',args)
                    self.assertIn('--no-remove',args);self.assertEqual(args[-2:],['install','php8.3-fpm=V'])
                    if '--simulate' in args:
                        plan='Conf php8.3-fpm (V provider [amd64])\n'
                        if failure=='unpack-plan':plan='Inst php8.3-fpm [V] (V provider [amd64])\n'+plan
                        if failure=='foreign-plan':plan+='Conf unrelated (U provider [amd64])\n'
                        return subprocess.CompletedProcess(args,0,plan,'')
                    self.assertIn('--no-download',args);mutations.append(args)
                    return subprocess.CompletedProcess(args,100 if failure=='apt-failure' else 0,'','')
                with patch.object(m,'command',side_effect=command),patch.object(m,'root_regular',side_effect=regular):
                    if failure in ('none','apt-failure'):
                        result=backend.configure('8.3');self.assertEqual(result.returncode,100 if failure=='apt-failure' else 0)
                    else:
                        with self.assertRaises(ValueError):backend.configure('8.3')
                self.assertEqual(len(mutations),1 if failure in ('none','apt-failure') else 0)

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

    def test_early_host_refusals_retain_failure_without_any_guest_write_or_stop(self):
        for failure,stage in (('ownership','host-ownership-check'),('identity','host-identity-check'),('helper','host-helper-check')):
            with self.subTest(failure=failure):
                m,c,packages,receipts,evidence,qualifier,state,run=self.host_case()
                if failure=='ownership':
                    (Path(c['ownership_directory'])/c['run_token']/c['source_vm']).write_text('foreign owner')
                if failure=='helper':c['maintenance_helper_sha256']='0'*64
                def refused(args,**kwargs):
                    if failure=='identity':raise ValueError('private identity failure')
                    return run(args,**kwargs)
                with patch.object(m,'command',side_effect=refused),self.assertRaises(ValueError):
                    m.host_execute(c,packages,b'release',b'index',receipts,evidence,HELPER,qualifier,qualifier)
                self.assertTrue((evidence/'result.json').exists(),'early refusal lost its result receipt')
                result=json.loads((evidence/'result.json').read_text())
                self.assertEqual(result['status'],'FAIL')
                self.assertEqual(result['maintenance_stage'],stage)
                self.assertEqual(result['guest_state'],'unchanged_before_guest_write')
                self.assertTrue(result['failure_frames'])
                self.assertFalse(state['mutated']);self.assertFalse(state['stopped'])

    def test_reboot_failures_keep_exact_stage_and_stop_only_owned_guest(self):
        for number in (1,2):
            for step in ('identity-before','restart','cloud-init','identity-after'):
                with self.subTest(reboot=number,step=step):
                    m,c,packages,receipts,evidence,qualifier,state,run=self.host_case()
                    expected='reboot-'+str(number)+'-'+step
                    def interrupted(args,**kwargs):
                        receipt=evidence/'result.json'
                        current=json.loads(receipt.read_text()).get('maintenance_stage') if receipt.exists() else None
                        if current==expected and args[:2]!=['multipass','stop']:raise RuntimeError('private reboot failure')
                        return run(args,**kwargs)
                    with patch.object(m,'command',side_effect=interrupted),self.assertRaisesRegex(RuntimeError,'private reboot failure'):
                        m.host_execute(c,packages,b'release',b'index',receipts,evidence,HELPER,qualifier,qualifier)
                    result=json.loads((evidence/'result.json').read_text())
                    self.assertEqual(result['status'],'FAIL')
                    self.assertEqual(result['maintenance_stage'],expected)
                    self.assertEqual(result['guest_state'],'stopped_after_failure')
                    self.assertTrue(state['stopped'])

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

    @contextlib.contextmanager
    def real_php_smoke_fixture(self, mode='pass'):
        m=self.module();run=subprocess.run;calls=[];sockets=[]
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            root=Path(temporary).resolve();runroot=root/'run';runroot.mkdir();public_root=root/'private';public_root.mkdir(mode=0o700)
            for name in ('usr/sbin','usr/local/bin','usr/bin','bin'):(root/name).mkdir(parents=True,exist_ok=True)
            runner=root/'usr/sbin/runuser'
            runner.write_text('#!'+sys.executable+'\n'+"""import json,os,sys
a=sys.argv[1:]
if len(a)<5 or a[:3]!=['-u','nobody','--'] or not a[3].startswith('/usr/bin/php'):sys.exit(91)
minor=a[3][-3:];mode=os.environ['OWNED_SMOKE_FIXTURE']
if mode=='tool-fail':sys.exit(7)
if a[4]=='/usr/local/lib/nakpanel/wp-cli.phar':print('WP-CLI version:\\t2.12.0')
elif '--version' in a:print('Composer version 2.10.3 2026-09-01')
elif 'run-script' in a:print('NAKPANEL_MAINTENANCE_WORKER='+json.dumps({'version':minor+'.1','uid':0 if mode=='worker-root' else 65534}))
else:sys.exit(92)
""")
            runner.chmod(0o700)
            def local_path(value):return runroot if str(value)=='/run' else Path(value)
            def boundary(args,**kwargs):
                calls.append((args,kwargs))
                if args[0].startswith('/usr/bin/php'):
                    minor=args[0][-3:];out=json.dumps(dict(version=minor+'.1',ini='/etc/php/'+minor+'/cli/php.ini',extensions=list(m.REQUIRED_EXTENSIONS)))
                elif args[0]=='systemd-run':
                    runtime=next(arg.split('=',2)[2] for arg in args if arg.startswith('--property=RuntimeDirectory='))
                    target=runroot/runtime;target.mkdir(mode=0o700);sock=socket.socket(socket.AF_UNIX);sock.bind(str(target/'fpm.sock'));sockets.append(sock);out=''
                elif args[0]=='/usr/bin/cgi-fcgi':
                    minor=Path(kwargs['env']['SCRIPT_FILENAME']).parent.name[-2:];minor=minor[0]+'.'+minor[1]
                    proof=dict(version=minor+'.1',uid=0 if mode=='fpm-root' else 65534,ini='/etc/php/'+minor+'/fpm/php.ini',extensions=list(m.REQUIRED_EXTENSIONS),own_read=True,other_denied=True,shell_disabled=True)
                    out='Content-Type: application/json\r\n\r\n'+json.dumps(proof)
                elif args[0] in ('runuser','/usr/sbin/runuser'):
                    self.assertEqual(kwargs['env']['PATH'],'/usr/local/bin:/usr/bin:/bin')
                    self.assertEqual(args[1:4],['-u','nobody','--']);self.assertRegex(args[4],r'^/usr/bin/php8\.[345]$')
                    argv=[str(runner) if args[0].startswith('/') else args[0],*args[1:]]
                    env=dict(kwargs['env'],PATH=':'.join(str(root/name) for name in ('usr/local/bin','usr/bin','bin')),OWNED_SMOKE_FIXTURE=mode)
                    return run(argv,**dict(kwargs,env=env))
                elif args[:2]==['systemctl','stop']:out=''
                else:self.fail('unexpected smoke command boundary')
                return subprocess.CompletedProcess(args,0,out,'')
            try:
                with patch.object(m,'Path',side_effect=local_path),patch.object(m.subprocess,'run',side_effect=boundary):yield m,public_root,calls
            finally:
                for sock in sockets:sock.close()

    def test_php_smoke_uses_absolute_runuser_for_all_three_real_tool_launches(self):
        with self.real_php_smoke_fixture() as (m,root,calls):
            result=m.php_smoke(root,{'maintenance_id':'drill1234'},'before')
            self.assertEqual(set(result),set(m.MINORS));self.assertTrue((root/'php-smoke-before.json').is_file())
            tools=[args for args,kwargs in calls if args[0] in ('runuser','/usr/sbin/runuser')]
            self.assertEqual(len(tools),9);self.assertTrue(all(args[0]=='/usr/sbin/runuser' for args in tools))
            for minor in m.MINORS:self.assertEqual(result[minor]['tools']['worker'],{'version':minor+'.1','uid':65534})

    def test_php_smoke_still_refuses_root_fpm_before_tools_and_stops_unit(self):
        with self.real_php_smoke_fixture('fpm-root') as (m,root,calls):
            with self.assertRaisesRegex(ValueError,'confinement proof failed'):m.php_smoke(root,{'maintenance_id':'drill1234'},'before')
            self.assertFalse(any(args[0] in ('runuser','/usr/sbin/runuser') for args,kwargs in calls));self.assertEqual(calls[-1][0][:2],['systemctl','stop'])

    def test_php_smoke_tool_nonzero_remains_failure_and_stops_unit(self):
        with self.real_php_smoke_fixture('tool-fail') as (m,root,calls):
            with self.assertRaises(RuntimeError):m.php_smoke(root,{'maintenance_id':'drill1234'},'before')
            self.assertEqual(calls[-1][0][:2],['systemctl','stop']);self.assertFalse((root/'php-smoke-before.json').exists())

    def test_php_smoke_real_worker_wrong_uid_still_refuses_and_stops_unit(self):
        with self.real_php_smoke_fixture('worker-root') as (m,root,calls):
            with self.assertRaisesRegex(ValueError,'wrong interpreter/UID'):m.php_smoke(root,{'maintenance_id':'drill1234'},'before')
            self.assertEqual(calls[-1][0][:2],['systemctl','stop']);self.assertFalse((root/'php-smoke-before.json').exists())

    def test_tool_health_requires_successful_matching_nonroot_composer_php_worker(self):
        m=self.module();self.assertTrue(callable(getattr(m,'parse_tool_results',None)), 'actual tool/@php worker proof is missing')
        composer=subprocess.CompletedProcess([],0,'Composer version 2.10.3 2026-09-01\n','');wp=subprocess.CompletedProcess([],0,'WP-CLI version:\t2.12.0\n','');worker=subprocess.CompletedProcess([],0,'NAKPANEL_MAINTENANCE_WORKER='+json.dumps({'version':'8.3.35','uid':65534})+'\n','')
        proof=m.parse_tool_results('8.3',65534,composer,wp,worker);self.assertEqual(proof['composer_version'],'2.10.3');self.assertEqual(proof['worker']['uid'],65534)
        for bad in [subprocess.CompletedProcess([],1,worker.stdout,''),subprocess.CompletedProcess([],0,worker.stdout.replace('65534','0'),''),subprocess.CompletedProcess([],0,worker.stdout.replace('8.3.35','8.4.26'),''),subprocess.CompletedProcess([],0,'> quoted marker without actual worker output','')]:
            with self.subTest(output=bad.stdout),self.assertRaises(ValueError):m.parse_tool_results('8.3',65534,composer,wp,bad)

if __name__=='__main__':unittest.main()
