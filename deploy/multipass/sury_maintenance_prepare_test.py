import importlib.util
import json
import os
from pathlib import Path
import subprocess
import signal
import sys
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
HELPER = HERE / 'sury-maintenance-prepare.py'


class PreparationTests(unittest.TestCase):
    def module(self):
        self.assertTrue(HELPER.exists(), 'portable maintenance preparation producer is missing')
        spec = importlib.util.spec_from_file_location('preparation_under_test', HELPER)
        module = importlib.util.module_from_spec(spec)
        with patch('subprocess.run', side_effect=AssertionError('import launched a process')):
            spec.loader.exec_module(module)
        return module

    def report(self):
        return dict(schema_version=1, qualification_passed=True, full_php_parity=True,
                    pending_gates=[], source_vm='nakpanel-26-04-amd64-hosted-123456-1-26-04',
                    run_token='hosted-123456-1-26-04', release='26.04', architecture='amd64',
                    profile='ubuntu-26.04-sury', php_provider='sury', php_contract=['8.5','8.4','8.3'],
                    features={'database_manager_requested': True},
                    gates=[dict(name=n,status='PASS',exit_code=0) for n in (
                        'bundle','fresh-install','inventory','real-upgrade','phase28','valkey-platform',
                        'security','phase29','phase30','phase31','phase32','internal-tools','mail-workspace',
                        'phase33','phase34','domain-removal','release-artifacts')])

    def test_import_is_inert_and_missing_or_incomplete_real_baseline_refuses(self):
        m = self.module(); report = self.report()
        m.check_report(report, report)
        for field,value in [('qualification_passed',False),('pending_gates',['phase34']),
                            ('php_provider','native'),('architecture','arm64'),('gates',[]),
                            ('features',{'database_manager_requested':False})]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                m.check_report(dict(report,**{field:value}),report)

    def test_canonical_process_really_exits_and_no_background_child_can_authorize_handoff(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); report=root/'report.json'; report.write_text(json.dumps(self.report()))
            receipt=root/'execution.json'
            m.run_canonical([sys.executable,'-c','pass'],receipt,report,self.report(),os.environ.copy())
            proof=json.loads(receipt.read_text())
            self.assertEqual(proof['exit_code'],0)
            self.assertIs(proof['process_exited'],True)
            self.assertIs(proof['process_group_empty'],True)
            self.assertEqual(receipt.stat().st_mode & 0o777,0o600)
            with self.assertRaisesRegex(ValueError,'child'):
                m.run_canonical([sys.executable,'-c',
                    'import subprocess; subprocess.Popen(["sleep","30"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)'],
                    root/'child.json',report,self.report(),os.environ.copy())
            failed=json.loads((root/'child.json').read_text())
            self.assertIs(failed['success'],False)
            self.assertIs(failed['process_group_empty'],False)

    def test_failed_process_cannot_turn_existing_pass_report_into_authorization(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); report=root/'report.json'; report.write_text(json.dumps(self.report()))
            with self.assertRaises(ValueError):
                m.run_canonical([sys.executable,'-c','raise SystemExit(29)'],root/'execution.json',report,self.report(),os.environ.copy())
            self.assertEqual(json.loads((root/'execution.json').read_text())['exit_code'],29)

    def test_interrupted_wait_terminates_and_reaps_only_its_real_owned_group(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);receipt=root/'execution.json';children=[];popen=subprocess.Popen
            def interrupted(*args,**kwargs):
                child=popen(*args,**kwargs);children.append(child);wait=child.wait;first=[True]
                def waiting(*args,**kwargs):
                    if first[0]:first[0]=False;raise KeyboardInterrupt()
                    return wait(*args,**kwargs)
                child.wait=waiting
                return child
            try:
                with patch.object(m.subprocess,'Popen',side_effect=interrupted):
                    with self.assertRaises(KeyboardInterrupt):
                        m.run_canonical([sys.executable,'-c','import time;time.sleep(60)'],receipt,root/'report',self.report(),os.environ.copy())
                self.assertIsNotNone(children[0].poll(),'interrupted child was neither terminated nor reaped')
                self.assertFalse(m.process_group_exists(children[0].pid),'owned isolated process group remains alive')
                proof=json.loads(receipt.read_text())
                self.assertIs(proof['success'],False)
                self.assertIs(proof['process_exited'],True)
                self.assertIs(proof['cleanup_group_empty'],True)
            finally:
                for child in children:
                    if child.poll() is None:
                        os.killpg(child.pid,signal.SIGKILL);child.wait()

    def test_startup_sigterm_is_deferred_until_real_pid_custody_and_then_reaped(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);receipt=root/'execution.json';children=[];popen=subprocess.Popen
            previous={number:signal.getsignal(number) for number in (signal.SIGINT,signal.SIGTERM)}
            def interrupted_start(*args,**kwargs):
                child=popen(*args,**kwargs);children.append(child)
                # Deliver the real signal after the OS has created the new
                # session, before the Python caller has received its child.
                os.kill(os.getpid(),signal.SIGTERM)
                return child
            try:
                with patch.object(m.subprocess,'Popen',side_effect=interrupted_start):
                    with self.assertRaises(SystemExit) as raised:
                        m.run_canonical([sys.executable,'-c','import time;time.sleep(60)'],receipt,root/'report',self.report(),os.environ.copy())
                self.assertEqual(raised.exception.code,143)
                self.assertIsNotNone(children[0].poll(),'startup signal orphaned the newly created child')
                self.assertFalse(m.process_group_exists(children[0].pid))
                proof=json.loads(receipt.read_text())
                self.assertEqual(proof['pid'],children[0].pid)
                self.assertEqual(proof['process_group'],children[0].pid)
                self.assertIs(proof['success'],False)
                self.assertIs(proof['cleanup_group_empty'],True)
                for number,handler in previous.items():self.assertEqual(signal.getsignal(number),handler)
            finally:
                for child in children:
                    if child.poll() is None:
                        os.killpg(child.pid,signal.SIGKILL);child.wait()

    def assert_actual_signal_cleanup(self,number):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);pid_file=root/'child.pid';receipt=root/'execution.json'
            code='''import importlib.util,json,os,pathlib,sys
s=importlib.util.spec_from_file_location('producer',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
child='import os,pathlib,sys,time;pathlib.Path(sys.argv[1]).write_text(str(os.getpid()));time.sleep(60)'
m.run_canonical([sys.executable,'-c',child,sys.argv[2]],pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4]),json.loads(sys.argv[5]),os.environ.copy())
'''
            worker=subprocess.Popen([sys.executable,'-c',code,str(HELPER),str(pid_file),str(receipt),str(root/'report'),json.dumps(self.report())],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            child_pid=None
            try:
                import time
                for _ in range(100):
                    if pid_file.exists():child_pid=int(pid_file.read_text());break
                    if worker.poll() is not None:break
                    time.sleep(.02)
                self.assertIsNotNone(child_pid,'canonical child did not start')
                worker.send_signal(number);worker.wait(timeout=8)
                proof=json.loads(receipt.read_text())
                self.assertIs(proof['success'],False)
                self.assertIs(proof['process_exited'],True)
                self.assertIs(proof['cleanup_group_empty'],True)
                with self.assertRaises(ProcessLookupError):os.kill(child_pid,0)
            finally:
                if worker.poll() is None:worker.kill();worker.wait()
                if child_pid:
                    try:os.killpg(child_pid,signal.SIGKILL)
                    except ProcessLookupError:pass

    def test_actual_sigterm_records_failure_and_removes_the_isolated_canonical_child(self):
        self.assert_actual_signal_cleanup(signal.SIGTERM)

    def test_actual_ctrl_c_records_failure_and_removes_the_isolated_canonical_child(self):
        self.assert_actual_signal_cleanup(signal.SIGINT)

    def test_signed_installed_php_dependency_closure_rejects_extra_missing_and_changed_packages(self):
        m=self.module()
        rows=[dict(Package='php8.3-cli',Version='1',Architecture='amd64',Depends='php8.3-common (= 1), libc6'),
              dict(Package='php8.3-common',Version='1',Architecture='amd64',Depends='php-common'),
              dict(Package='php-common',Version='2',Architecture='all',Depends='psmisc')]
        installed={r['Package']:[r['Version'],'install ok installed'] for r in rows}
        selected=m.installed_closure(rows,installed,['php8.3-cli'],'amd64')
        self.assertEqual({r['Package'] for r in selected},set(installed))
        for changed in (dict(installed,**{'php8.3-unreviewed':['1','install ok installed']}),
                        dict(installed,**{'php8.2-cli':['1','install ok installed']}),
                        dict(installed,**{'php8.3-common':['99','install ok installed']}),
                        {k:v for k,v in installed.items() if k!='php-common'},
                        dict(installed,**{'php8.3-common':['1','install ok half-configured']})):
            with self.subTest(installed=changed),self.assertRaises(ValueError):
                m.installed_closure(rows,changed,['php8.3-cli'],'amd64')
        with self.assertRaises(ValueError):m.installed_closure(rows+rows[:1],installed,['php8.3-cli'],'amd64')

    def test_both_signed_indexes_must_match_compressed_and_plain_release_checksums(self):
        m=self.module()
        import lzma,hashlib
        plain=b'Package: php-common\nVersion: 1\nArchitecture: all\n\n'; compressed=lzma.compress(plain)
        entries=[]
        for arch in ('amd64','arm64'):
            for suffix,data in (('',plain),('.xz',compressed)):
                entries.append(' '+hashlib.sha256(data).hexdigest()+' '+str(len(data))+' main/binary-'+arch+'/Packages'+suffix)
        release=('-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nOrigin: deb.sury.org\nSuite: resolute\nCodename: resolute\nArchitectures: amd64 arm64\nSHA256:\n'+'\n'.join(entries)+'\n-----BEGIN PGP SIGNATURE-----\ntest\n').encode()
        m.check_indexes(release,{'amd64':compressed,'arm64':compressed})
        with self.assertRaises(ValueError):m.check_indexes(release,{'amd64':compressed,'arm64':compressed+b'tamper'})
        with self.assertRaises(ValueError):m.check_indexes(release,{'amd64':compressed})

    def test_source_binding_accepts_only_exact_readme_build_marker(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            subprocess.run(['git','init','-q',str(root)],check=True)
            (root/'README.md').write_text('original\n');(root/'owned.py').write_text('pass\n')
            subprocess.run(['git','-C',str(root),'add','.'],check=True)
            subprocess.run(['git','-C',str(root),'-c','user.name=test','-c','user.email=test@example.test','commit','-qm','fixture'],check=True)
            m.source_map(root,['owned.py'],'123')
            with (root/'README.md').open('a') as f:f.write('\n<!-- hosted development qualification 123 -->\n')
            m.source_map(root,['owned.py'],'123')
            with (root/'README.md').open('a') as f:f.write('unreviewed\n')
            with self.assertRaises(ValueError):m.source_map(root,['owned.py'],'123')

    def test_normal_python_cli_keeps_clean_committed_source_and_rejects_foreign_cache(self):
        m=self.module()
        import shutil
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);checkout=root/'checkout';checkout.mkdir()
            for relative in m.FROZEN | {'README.md','.gitignore'}:
                target=checkout/relative;target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(m.SOURCE/relative,target)
            subprocess.run(['git','init','-q',str(checkout)],check=True)
            subprocess.run(['git','-C',str(checkout),'add','.'],check=True)
            subprocess.run(['git','-C',str(checkout),'-c','user.name=test','-c','user.email=test@example.test',
                            'commit','-qm','committed CLI fixture'],check=True)
            fakebin=root/'bin';fakebin.mkdir();marker=root/'canonical-started';evidence=root/'evidence'
            driver=root/'canonical.py'
            driver.write_text('import json,os,pathlib\n'
                'root=pathlib.Path(os.environ["NAKPANEL_CELL_REPORT_DIR"]);root.mkdir()\n'
                '(root/"report.json").write_text(os.environ["TEST_CANONICAL_REPORT"])\n'
                'pathlib.Path(os.environ["TEST_CANONICAL_MARKER"]).write_text("owned fixture only")\n')
            bash=fakebin/'bash'
            bash.write_text('#!/bin/sh\nexec "$TEST_CANONICAL_PYTHON" "$TEST_CANONICAL_DRIVER" "$@"\n')
            bash.chmod(0o755)
            report=self.report();env=os.environ.copy()
            for name in ('PYTHONDONTWRITEBYTECODE','PYTHONPYCACHEPREFIX'):env.pop(name,None)
            env.update(PATH=str(fakebin)+os.pathsep+env['PATH'],GITHUB_RUN_ID='123456',
                NAKPANEL_MULTIPASS_VM=report['source_vm'],NAKPANEL_RUN_TOKEN=report['run_token'],
                NAKPANEL_CELL_REPORT_DIR=str(evidence),TEST_CANONICAL_REPORT=json.dumps(report),
                TEST_CANONICAL_MARKER=str(marker),TEST_CANONICAL_PYTHON=sys.executable,
                TEST_CANONICAL_DRIVER=str(driver))
            status=lambda:subprocess.run(['git','-C',str(checkout),'status','--porcelain',
                '--untracked-files=all'],capture_output=True,text=True,check=True).stdout
            self.assertEqual(status(),'')
            receipt=root/'execution.json'
            # No -B or bytecode-disable environment: use Linux's ordinary local
            # cache location even on Apple's Python with its global cache default.
            argv=[sys.executable,'-X','pycache_prefix=',str(checkout/'deploy/multipass/sury-maintenance-prepare.py'),
                  'qualify','--execution-receipt',str(receipt)]
            result=subprocess.run(argv,env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr+'\n'+status())
            self.assertTrue(marker.exists(),'actual canonical subprocess boundary was not reached')
            proof=json.loads(receipt.read_text())
            self.assertEqual(proof['status'],'PASS')
            self.assertIs(proof['process_exited'],True)
            self.assertIs(proof['process_group_empty'],True)
            self.assertEqual(status(),'','normal CLI must not dirty its frozen source')
            marker.unlink()
            foreign=checkout/'deploy/multipass/__pycache__/foreign.pyc'
            foreign.parent.mkdir();foreign.write_bytes(b'unreviewed cache file')
            refused=root/'refused.json';argv[-1]=str(refused)
            result=subprocess.run(argv,env=env,capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(marker.exists(),'unreviewed source launched the canonical subprocess')
            self.assertFalse(refused.exists())
            self.assertIn('foreign.pyc',status(),'strict source cleanliness must not ignore caches')

    def test_capacity_uses_actual_source_disk_and_rejects_before_quiesce(self):
        m=self.module()
        proof=m.check_capacity(32*2**30,35*2**30)
        self.assertEqual(proof['source_disk_bytes'],32*2**30)
        with self.assertRaises(ValueError):m.check_capacity(32*2**30,33*2**30)

    def test_cold_snapshot_is_quiesced_stopped_and_revalidated_without_touching_another_vm(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve();producer=m.Producer(root,root/'private',root/'execution',{})
            config=dict(self.report(),retention_snapshot='maintenance-sury-test1234')
            config.update(app_version='29.0.0',runtime_commit='a'*40,manifest_sha256='b'*64,
                          installed_binary_sha256={name:'c'*64 for name in ('panel','agent','panelctl')})
            producer.config=config;events=[];state=['Running']
            metadata=dict(children=[],comment='owned',cpu_count='2',created='now',disk_space='32.0GiB',
                          memory_size='5.0GiB',mounts={},parent='',size='')
            def command(args,**kwargs):
                out=''
                if args[:2]==['multipass','exec']:
                    self.assertEqual(args[2],config['source_vm'])
                    if 'blockdev' in args[-1]:out=str(32*2**30)
                    elif 'systemctl stop' in args[-1]:
                        self.assertIn('nakpanel.service',args[-1])
                        self.assertNotIn('nakpanel-panel.service',args[-1])
                        self.assertTrue((HERE.parent/'systemd'/'nakpanel.service').is_file())
                        events.append('quiesce')
                    else:events.append('postboot-active')
                elif args[:2]==['multipass','stop']:events.append('stop');state[0]='Stopped'
                elif args[:2]==['multipass','snapshot']:
                    self.assertEqual(state[0],'Stopped');events.append('snapshot')
                elif args[:2]==['multipass','start']:events.append('start');state[0]='Running'
                elif args[:2]==['multipass','info']:
                    if args[2]==config['source_vm']:out=json.dumps({'errors':[],'info':{config['source_vm']:{'state':state[0]}}})
                    else:out=json.dumps({'errors':[],'info':{config['source_vm']:{'snapshots':{config['retention_snapshot']:metadata}}}})
                elif args[:2]==['bash','-c']:events.append('wait-cloud-init')
                else:self.fail('unexpected external operation '+repr(args))
                return subprocess.CompletedProcess(args,0,out,'')
            def identity(*args):self.assertEqual(state[0],'Running');events.append('identity')
            with patch.object(m.M,'command',side_effect=command),patch.object(m.M,'host_record',return_value='owned'),\
                 patch.object(m.M,'host_identity',side_effect=identity),patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=35*2**30)):
                retention=producer.cold_retention()
            self.assertIs(retention['cold_snapshot'],True)
            self.assertIs(retention['running_revalidated'],True)
            self.assertLess(events.index('quiesce'),events.index('stop'))
            self.assertLess(events.index('stop'),events.index('snapshot'))
            self.assertLess(events.index('snapshot'),events.index('start'))
            self.assertEqual(events[-1],'postboot-active')

    def test_native_signature_failure_prevents_any_index_or_deb_download(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve();producer=m.Producer(root,root/'private',root/'execution',{})
            producer.config=dict(self.report(),baseline_directory=str(root/'private'/'baseline'))
            downloads=[]
            def download(url,path,**kwargs):
                downloads.append(url);path.write_bytes(b'untrusted InRelease');path.chmod(0o600)
                return path.read_bytes()
            def guest(args,**kwargs):
                return subprocess.CompletedProcess(args,0 if args[0]=='sha256sum' else 1,
                    m.M.KEY_SHA+'  key' if args[0]=='sha256sum' else '[GNUPG:] BADSIG forged', '')
            with patch.object(m,'download',side_effect=download),patch.object(producer,'guest',side_effect=guest):
                with self.assertRaisesRegex(ValueError,'native gpgv'):producer.collect_baseline(lambda *args:self.fail('unauthenticated receipt'))
            self.assertEqual(downloads,[m.BASE+'dists/resolute/InRelease'])

    def test_private_inputs_and_error_diagnostics_never_enter_upload_allowlist(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);private=root/'private';private.mkdir();(private/'drill').mkdir()
            for name in ('spec.json','controller.log','retained-baseline.tar','roundcube-baseline.log'):
                (private/name).write_text('secret credential')
            m.M.write_private(private/'preparation.json',{'status':'FAIL','stage':'maintenance-handoff'})
            m.M.write_private(private/'drill'/'result.json',{'status':'FAIL','diagnostic':'secret credential','error_type':'ValueError'})
            m.publish(private,root/'upload')
            self.assertEqual({p.name for p in (root/'upload').iterdir()},{'preparation.json','result.json'})
            self.assertNotIn('secret',str([p.read_text() for p in (root/'upload').iterdir()]))

    def test_prepare_uses_actual_roundcube_then_cold_snapshot_then_signed_baseline_and_bound_handoff(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve();cell=root/'cell';cell.mkdir();report=self.report();(cell/'report.json').write_text(json.dumps(report))
            bundle=root/'bundle';bundle.mkdir();manifest={'commit':'a'*40,'architecture':'amd64','version':'29.0.0','development':True,
                'files':{'bin/'+name:str(n)*64 for name,n in (('panel',1),('agent',2),('panelctl',3))}}
            (bundle/'manifest.json').write_text(json.dumps(manifest));(bundle/'manifest.sig').write_bytes(b'signature')
            (cell/'release-manifest.json').write_bytes((bundle/'manifest.json').read_bytes())
            key=root/'key';key.write_bytes(b'public key')
            mapping={name:'b'*64 for name in m.FROZEN}
            execution=dict(schema='nakpanel-canonical-execution-v1',success=True,process_exited=True,process_group_empty=True,
                exit_code=0,source_binding={k:report[k] for k in ('source_vm','run_token','release','architecture','profile','php_provider')},
                qualification_report_sha256=m.M.digest((cell/'report.json').read_bytes()),process_group=99999999,runtime_commit='a'*40,qualifier_source_sha256=mapping)
            m.M.write_private(root/'execution.json',execution)
            env=dict(NAKPANEL_CELL_REPORT_DIR=str(cell),NAKPANEL_MULTIPASS_VM=report['source_vm'],NAKPANEL_RUN_TOKEN=report['run_token'],
                NAKPANEL_RELEASE_BUNDLE=str(bundle),NAKPANEL_RELEASE_PUBLIC_KEY=str(key),NAKPANEL_OWNERSHIP_DIR=str(root/'ownership'),NAKPANEL_VERIFY_SURY_MAINTENANCE='1')
            coverage_path,coverage=m.record_request(env)
            producer=m.Producer(root,root/'private',root/'execution.json',env);events=[]
            def command(args,**kwargs):
                if '--roundcube-only' in args:
                    events.append('real-roundcube')
                    raw=dict(schema='nakpanel-roundcube-send-read-v1',success=True,status='PASS',send_attempts=1,
                        http_send_completed=True,self_recipient_verified=True,imap_arrival_verified=True,imap_message_id_verified=True,
                        roundcube_body_verified=True,message_id='<fresh-server-id@example.test>',uid='42',
                        **{k:'b'*64 for k in ('subject_sha256','body_sha256','recipient_sha256','qualifier_helper_sha256','certificate_sha256')})
                    envelope={k:producer.config[k] for k in m.M.BINDING}
                    envelope.update(schema='nakpanel-roundcube-supplement-v1',success=True,qualifier_wrapper_sha256='b'*64,
                        qualifier_helper_sha256='b'*64,raw_receipt=raw,raw_receipt_sha256=m.M.digest(m.M.canonical(raw)))
                    m.M.write_private(Path(kwargs['env']['NAKPANEL_INTERNAL_TOOLS_RECEIPT']),envelope)
                return subprocess.CompletedProcess(args,0,'','')
            def cold():
                events.append('cold-snapshot');value={k:producer.config[k] for k in m.M.BINDING}
                value.update(schema='nakpanel-sury-maintenance-retention-v1',status='PASS',snapshot_name=producer.config['retention_snapshot'],
                    snapshot_id=report['source_vm']+'.'+producer.config['retention_snapshot'],snapshot_info_sha256='d'*64,
                    cold_snapshot=True,running_revalidated=True,ownership_verified=True)
                return value
            def collect(receipt):
                events.append('signed-baseline');receipt('native_gpgv_receipt',{'native_gpgv':True});receipt('baseline_inventory',{})
            with patch.object(m,'source_map',return_value=('a'*40,mapping)),patch.object(m,'process_group_exists',return_value=False),\
                 patch.object(m.M,'command',side_effect=command),patch.object(m.M,'host_identity'),patch.object(m.M,'host_record'),\
                 patch.object(producer,'cold_retention',side_effect=cold),patch.object(producer,'collect_baseline',side_effect=collect):
                spec=producer.prepare()
            selected=json.loads(spec.read_text())
            self.assertEqual(events,['real-roundcube','cold-snapshot','signed-baseline'])
            self.assertEqual(selected['runtime_commit'],selected['qualifier_commit'])
            self.assertEqual(set(selected['references']),{'qualification_report','roundcube_receipt','roundcube_execution_receipt',
                'retention_receipt','exclusive_handoff','native_gpgv_receipt','baseline_inventory'})
            handoff=json.loads(Path(selected['references']['exclusive_handoff']['path']).read_text())
            self.assertIs(handoff['exclusive_source_handoff'],True)
            self.assertEqual(handoff['roundcube_execution_sha256'],selected['roundcube_execution_sha256'])
            # Close the actual request -> producer -> controller-success path.
            # Prior code omitted app_version from the coverage request, causing
            # M.bound to fail only after all real maintenance had succeeded.
            def controller(args,**kwargs):
                self.assertIn('same-version',args)
                evidence=producer.root/'drill';evidence.mkdir()
                result={k:selected[k] for k in ('source_vm','run_token','runtime_commit','qualifier_commit')}
                result.update(schema='nakpanel-sury-maintenance-result-v1',operation=m.M.MODE,status='PASS',same_version_delivery=True,
                    failed_configuration_recovery=True,two_reboots_verified=True,genuine_version_advance=False,apt_version_rollback=False,
                    application_rollback=False,roundcube_send_read_steps=3,reboots=['boot-first','boot-second'])
                m.M.write_private(evidence/'result.json',result)
                return subprocess.CompletedProcess(args,0,'','')
            with patch.object(m,'Producer',return_value=producer),patch.object(producer,'prepare',return_value=spec),\
                 patch.object(m.M,'command',side_effect=controller),patch.object(m.os,'environ',env),\
                 patch.object(m.sys,'argv',['producer','prepare','--execution-receipt',str(root/'execution.json'),'--private-root',str(producer.root)]):
                m.main()
            final=json.loads(coverage_path.read_text())
            self.assertEqual(final['status'],'PASS')
            self.assertEqual(final['app_version'],manifest['version'])
            self.assertEqual(final['result_sha256'],m.M.digest((cell/'sury-maintenance'/'result.json').read_bytes()))

    def test_actual_workflow_summary_requires_requested_real_recovery_and_explicit_opt_out(self):
        m=self.module()
        workflow=(HERE.parents[1]/'.github/workflows/ubuntu-hosted-qualification.yml').read_text()
        section=workflow.split('  hosted-evidence-summary:',1)[1]
        script=textwrap.dedent(section.split("python3 - <<'PYSUMMARY'\n",1)[1].split('\n          PYSUMMARY',1)[0])
        for mode in ('complete','opt-out','missing-result','pending','wrong-source','wrong-app-version','no-two-boots','false-version-advance','lying-opt-out'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as td:
                root=Path(td); requested=mode!='opt-out'
                manifest=dict(version='29.0.0',commit='a'*40,files={'bin/'+name:str(n)*64 for name,n in (('panel',1),('agent',2),('panelctl',3))})
                manifest_bytes=m.M.canonical(manifest)
                for release in ('24.04','26.04'):
                    cell=root/'hosted-results'/release;cell.mkdir(parents=True)
                    report=self.report();report.update(release=release,promotion_eligible=False,signature_class='development')
                    report_bytes=m.M.canonical(report);(cell/'report.json').write_bytes(report_bytes)
                    (cell/'release-manifest.json').write_bytes(manifest_bytes)
                    expected=requested and release=='26.04'
                    proof={k:report[k] for k in ('source_vm','run_token','release','architecture','profile','php_provider')}
                    proof.update(schema='nakpanel-sury-maintenance-coverage-v1',requested=expected,
                        status='PASS' if expected else 'NOT_REQUESTED',app_version='29.0.0',runtime_commit='a'*40,qualifier_commit='a'*40,
                        installed_binary_sha256={name:manifest['files']['bin/'+name] for name in ('panel','agent','panelctl')},
                        manifest_sha256=m.M.digest(manifest_bytes),qualification_report_sha256=m.M.digest(report_bytes),genuine_version_advance=False)
                    if expected and mode!='missing-result':
                        actual={k:proof[k] for k in ('source_vm','run_token','runtime_commit','qualifier_commit')}
                        actual.update(schema='nakpanel-sury-maintenance-result-v1',operation=m.M.MODE,status='PASS',
                            same_version_delivery=True,failed_configuration_recovery=True,two_reboots_verified=True,
                            genuine_version_advance=False,apt_version_rollback=False,application_rollback=False,
                            roundcube_send_read_steps=3,reboots=['first','second'])
                        if mode=='wrong-source':actual['source_vm']='foreign-vm'
                        if mode=='no-two-boots':actual['reboots']=['first']
                        if mode=='false-version-advance':actual['genuine_version_advance']=True
                        evidence=cell/'sury-maintenance';evidence.mkdir();raw=m.M.canonical(actual)
                        (evidence/'result.json').write_bytes(raw);proof['result_sha256']=m.M.digest(raw)
                    if expected and mode=='pending':proof['status']='PENDING'
                    if expected and mode=='wrong-app-version':proof['app_version']='unselected-version'
                    if expected and mode=='lying-opt-out':proof.update(requested=False,status='NOT_REQUESTED')
                    (cell/'sury-maintenance-request.json').write_bytes(m.M.canonical(proof))
                result=subprocess.run([sys.executable,'-'],input=script,text=True,capture_output=True,cwd=root,
                    env=dict(os.environ,JOB_RESULTS=json.dumps({'qualify-amd64':{'result':'success'}}),SURY_MAINTENANCE_REQUESTED='1' if requested else '0'))
                self.assertEqual(result.returncode==0,mode in ('complete','opt-out'),result.stdout+result.stderr)
                final=json.loads((root/'hosted-summary.json').read_text())
                self.assertIs(final['promotion_eligible'],False)


if __name__=='__main__':unittest.main()
