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
        return dict(schema_version=1, qualification_scope='CURRENT_VERSION_ONLY', excluded_gates=['real-upgrade'], qualification_passed=True, full_php_parity=True,
                    pending_gates=[], source_vm='nakpanel-26-04-amd64-hosted-123456-1-26-04',
                    run_token='hosted-123456-1-26-04', release='26.04', architecture='amd64',
                    profile='ubuntu-26.04-sury', php_provider='sury', php_contract=['8.5','8.4','8.3'],
                    features={'database_manager_requested': True},
                    gates=[dict(name=n,status='PASS',exit_code=0) for n in (
                        'bundle','fresh-install','inventory','phase28','valkey-platform',
                        'security','phase29','phase30','phase31','phase32','internal-tools','mail-workspace',
                        'phase33','phase34','domain-removal','release-artifacts')])

    def test_current_only_report_requires_exact16_and_never_credits_historical_upgrade(self):
        m=self.module();report=self.report()
        report['gates']=[g for g in report['gates'] if g['name']!='real-upgrade']
        report.update(qualification_scope='CURRENT_VERSION_ONLY',excluded_gates=['real-upgrade'])
        m.check_report(report,report)
        for field,value in [('qualification_scope','FULL_HISTORICAL'),('excluded_gates',[]),('gates',report['gates']+[dict(name='real-upgrade',status='PASS',exit_code=0)]),('gates',report['gates'][:-1])]:
            with self.subTest(field=field),self.assertRaises(ValueError):m.check_report(dict(report,**{field:value}),report)

    def test_actual_current_driver_runs16_gates_on24_and26_without_upgrade_execution(self):
        driver=(HERE/'ubuntu-platform-verify.sh').read_bytes()
        for release,provider in [('24.04','native'),('26.04','sury')]:
            with self.subTest(release=release),tempfile.TemporaryDirectory() as td:
                root=Path(td);scripts=root/'deploy/multipass';scripts.mkdir(parents=True);(scripts/'ubuntu-platform-verify.sh').write_bytes(driver)
                (scripts/'common.sh').write_text('init_qualification_run(){ :; }; multipass_host_arch(){ echo amd64; }; multipass(){ [[ "$1" != info ]]; }; assert_current_vm_identity(){ :; }; multipass_exec_short(){ :; }; assert_qualification_installed_release(){ :; }\n')
                for name in ('current-install','phase28','valkey-platform','security','phase29','phase30','phase31','phase32','mail-workspace','phase33','phase34','domain-removal'):
                    p=scripts/(name+'-verify.sh');p.write_text('#!/usr/bin/env bash\nexit 0\n');p.chmod(0o700)
                (scripts/'ubuntu-upgrade-verify.sh').write_text('#!/usr/bin/env bash\nprintf forbidden >"'+str(root/'FORBIDDEN_UPGRADE')+'"\nexit 99\n');(scripts/'ubuntu-upgrade-verify.sh').chmod(0o700)
                (scripts/'roundcube-send-read.py').write_text('pass\n');release_dir=root/'deploy/release';release_dir.mkdir();(release_dir/'verify.py').write_text('pass\n')
                tools=root/'tools';tools.mkdir();(tools/'git').write_text('#!/bin/sh\nexit 0\n');(tools/'git').chmod(0o700)
                bundle=root/'bundle';bundle.mkdir();(bundle/'manifest.json').write_text('{}');reports=root/'reports';owner=root/'ownership';owner.mkdir()
                env=dict(os.environ,PATH=str(tools)+':'+os.environ['PATH'],NAKPANEL_RELEASE_BUNDLE=str(bundle),NAKPANEL_RELEASE_PUBLIC_KEY=str(root/'key'),NAKPANEL_RELEASE_VERSION='29.0.0',NAKPANEL_MULTIPASS_ARCH='amd64',NAKPANEL_MULTIPASS_IMAGE=release,NAKPANEL_RUN_TOKEN='owned-current123',NAKPANEL_MULTIPASS_VM='owned-current123-source',NAKPANEL_MULTIPASS_DR_VM='owned-current123-dr',NAKPANEL_CELL_REPORT_DIR=str(reports),NAKPANEL_OWNERSHIP_DIR=str(owner),NAKPANEL_PHP_VERSIONS='8.5,8.4,8.3',NAKPANEL_QUALIFICATION_PROFILE='ubuntu-'+release+'-'+provider,NAKPANEL_QUALIFICATION_PHP_PROVIDER=provider,NAKPANEL_VERIFY_DATABASE_MANAGER='1')
                bash='/opt/homebrew/bin/bash' if Path('/opt/homebrew/bin/bash').is_file() else 'bash'
                child=subprocess.run([bash,str(scripts/'ubuntu-platform-verify.sh')],env=env,capture_output=True,text=True,timeout=15)
                self.assertEqual(child.returncode,0,child.stderr);self.assertFalse((root/'FORBIDDEN_UPGRADE').exists())
                value=json.loads((reports/'report.json').read_text());self.assertEqual(value['qualification_scope'],'CURRENT_VERSION_ONLY');self.assertEqual(value['excluded_gates'],['real-upgrade']);self.assertTrue(value['qualification_passed']);self.assertEqual(len(value['gates']),16);self.assertNotIn('real-upgrade',[g['name'] for g in value['gates']]);self.assertIsNone(value['features']['genuine_historical_upgrade_release']);self.assertFalse(value['features']['same_profile_26_update_required']);self.assertEqual(value['release'],release)

    def test_current_qualify_authenticates_runtime_driver_and_actual_qualifier_maps(self):
        for separate in (False,True):
            with self.subTest(separate=separate):
                m=self.module();qualifier=Path('/qualifier');driver=Path('/driver') if separate else qualifier;env=dict(NAKPANEL_MULTIPASS_VM=self.report()['source_vm'],NAKPANEL_RUN_TOKEN=self.report()['run_token'],NAKPANEL_CELL_REPORT_DIR='/cell');calls=[];observed=[]
                def mapping(path,files,run):calls.append(path);return ('a'*40 if path==driver else 'c'*40),{'fixture':('b'*64 if path==driver else 'd'*64)}
                argv=['prepare','qualify','--execution-receipt','/execution']+(['--driver-source',str(driver)] if separate else [])
                with patch.object(m,'SOURCE',qualifier),patch.object(m.os,'environ',env),patch.object(m.sys,'argv',argv),patch.object(m,'source_map',side_effect=mapping),patch.object(m,'run_canonical',side_effect=lambda *a:observed.append(a)):
                    m.main()
                self.assertEqual(observed[0][0],['bash','/qualifier/deploy/multipass/ubuntu-platform-verify.sh'])
                proof=observed[0][-1];self.assertEqual(proof['runtime_commit'],'a'*40);self.assertEqual(proof['qualifier_commit'],'c'*40 if separate else 'a'*40);self.assertEqual(proof['driver_source_sha256'],{'fixture':'b'*64});self.assertEqual(proof['qualifier_source_sha256'],{'fixture':('d'*64 if separate else 'b'*64)})
                self.assertEqual(calls,[driver,qualifier] if separate else [qualifier])

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

    def database_meta_layout(self):
        version='8.5.11-fixture1'
        rows=[dict(Package='php8.5-'+extension,Version=version,Architecture='amd64',
                   Depends='php8.5-common (= '+version+'), libc6')
              for extension in ('cli','mysql','pgsql','sqlite3')]
        rows += [dict(Package='php8.5-common',Version=version,Architecture='amd64',Depends='php-common'),
                 dict(Package='php-common',Version='2',Architecture='all',Depends='psmisc')]
        installed={row['Package']:[row['Version'],'install ok installed'] for row in rows}
        for extension in ('mysql','pgsql','sqlite3'):
            # Actual Ubuntu php-defaults99ubuntu1 .deb controls have these
            # two dependencies, confirmed independently of this verifier.
            installed['php-'+extension]=['2:8.5+99ubuntu1','install ok installed','all','php-common, php8.5-'+extension]
        return rows,installed,['php8.5-cli','php8.5-mysql','php8.5-sqlite3']

    def test_native_meta_retained_layout_accepts_only_signed_runtime_transaction(self):
        # Names come from the original qualified installer; rows are synthetic
        # contract inputs, not a claim of package signature/guest execution.
        m=self.module();rows,installed,direct=self.database_meta_layout()
        selected=m.installed_closure(rows,installed,direct,'amd64')
        self.assertEqual({row['Package'] for row in selected},{row['Package'] for row in rows})
        self.assertIn('php8.5-pgsql',{row['Package'] for row in selected})
        self.assertTrue(all(not row['Package'].startswith('php-') or row['Package']=='php-common' for row in selected))
        without_meta={name:value for name,value in installed.items() if name not in ('php-mysql','php-pgsql','php-sqlite3')}
        self.assertEqual(m.installed_closure(rows,without_meta,direct,'amd64'),selected)

    def test_native_meta_unknown_state_architecture_or_dependency_refuses(self):
        m=self.module();rows,installed,direct=self.database_meta_layout()
        bad_values=[['2:8.5+99ubuntu1','install ok installed'],
                    ['2:8.5+99ubuntu1','install ok half-configured','all','php-common, php8.5-mysql'],
                    ['2:8.5+99ubuntu1','install ok installed','arm64','php-common, php8.5-mysql']]
        bad_values += [['2:8.5+99ubuntu1','install ok installed','all',dependency]
                       for dependency in ('php-common, php8.4-mysql','php-common, php8.5-mysql | php8.4-mysql',
                                          'php-common, php8.5-mysql, bash','php-common, php8.5-mysql (>= 99)',
                                          'php8.5-mysql','php-common','php-common, php-common, php8.5-mysql','')]
        for value in bad_values:
            with self.subTest(value=value),self.assertRaises(ValueError):
                m.installed_closure(rows,dict(installed,**{'php-mysql':value}),direct,'amd64')
        for name in ('php-cli','php8.2-cli','php8.4-pgsql','php8.5-unreviewed'):
            extra=dict(Package=name,Version='1',Architecture='amd64',Depends='php-common')
            with self.subTest(name=name),self.assertRaises(ValueError):
                m.installed_closure(rows+[extra],dict(installed,**{name:['1','install ok installed']}),direct,'amd64')
        for missing in ('php8.5-pgsql','php8.5-mysql','php-common'):
            with self.subTest(missing=missing),self.assertRaises(ValueError):
                m.installed_closure(rows,{k:v for k,v in installed.items() if k!=missing},direct,'amd64')

    def test_native_meta_control_binding_requires_exact_actual_inventory(self):
        m=self.module();_,enriched,_=self.database_meta_layout()
        installed={name:value[:2] for name,value in enriched.items()}
        lines=['\t'.join([name,*enriched[name]]) for name in ('php-mysql','php-pgsql','php-sqlite3')]
        raw='\n'.join(lines)+'\n'
        self.assertEqual(m.bind_distribution_php_controls(installed,raw,'amd64'),enriched)
        self.assertTrue(all(len(value)==2 for value in installed.values()),'binding mutated original inventory')
        bad=[raw+lines[0]+'\n','\n'.join(lines[:-1])+'\n',raw+'php-cgi\t1\tinstall ok installed\tall\tphp8.5-cli\n',
             raw.replace('2:8.5+99ubuntu1','2:8.4+99ubuntu1',1),
             raw.replace('install ok installed','install ok half-configured',1),
             raw.replace('\tall\t','\tarm64\t',1),raw.replace('php8.5-mysql','php8.4-mysql',1)]
        for value in bad:
            with self.subTest(kind='malformed-control'),self.assertRaises(ValueError):
                m.bind_distribution_php_controls(installed,value,'amd64')

    def test_native_meta_layout_diagnostic_omits_raw_values_and_is_bounded(self):
        m=self.module();_,installed,direct=self.database_meta_layout()
        layout=m.package_layout(installed,direct,'amd64')
        self.assertEqual(layout['schema'],'nakpanel-sury-package-layout-v1')
        self.assertEqual(layout['distribution_metapackages'],['php-mysql','php-pgsql','php-sqlite3'])
        self.assertEqual(layout['application_roots'],['php8.5-pgsql'])
        self.assertNotIn('8.5.11-fixture1',json.dumps(layout));self.assertNotIn('2:8.5+99ubuntu1',json.dumps(layout))
        with self.assertRaises(ValueError):m.package_layout(dict(installed,**{'php-'+('x'*512):['1','install ok installed']}),direct,'amd64')

    def test_native_meta_failure_diagnostics_accept_only_fixed_substages_and_codes(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as td:
            producer=m.Producer.__new__(m.Producer);producer.root=Path(td);producer.config={}
            producer.stage='signed-provider-baseline';producer.substage='exact-php-closure'
            producer.record('FAIL',failure_code='unsupported-installed-php')
            value=json.loads((Path(td)/'preparation.json').read_text())
            self.assertEqual(value['substage'],'exact-php-closure');self.assertEqual(value['failure_code'],'unsupported-installed-php')
            before=(Path(td)/'preparation.json').read_bytes()
            with self.assertRaises(ValueError):producer.record('FAIL',failure_code='SYNTHETIC_PRIVATE_DIAGNOSTIC')
            self.assertEqual((Path(td)/'preparation.json').read_bytes(),before)
            producer.substage='SYNTHETIC_PRIVATE_DIAGNOSTIC'
            with self.assertRaises(ValueError):producer.record('FAIL')
            self.assertEqual((Path(td)/'preparation.json').read_bytes(),before)

    def test_native_meta_preparation_queries_actual_controls_and_excludes_aliases_from_apt_and_retention(self):
        m=self.module();rows,installed,direct=self.database_meta_layout()
        import hashlib
        for row in rows:
            row.update(Filename='pool/'+row['Package']+'.deb',Size='3',SHA256=hashlib.sha256(b'deb').hexdigest())
        aliases=sorted(set(installed)&set(m.DISTRIBUTION_PHP));calls=[];receipts={}
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve();producer=m.Producer(HERE.parents[1],root/'private',root/'execution',{})
            producer.stage='signed-provider-baseline'
            producer.config=dict(self.report(),baseline_directory=str(producer.root/'baseline'),
                                 runtime_commit='a'*40,qualifier_commit='a'*40)
            self.assertEqual(m.M.command.__kwdefaults__['timeout'],180)
            def guest(args,**kwargs):
                calls.append(args)
                if args[0]!='apt-get':self.assertNotIn('timeout',kwargs)
                if args[0]=='sha256sum':out=m.M.KEY_SHA+'  key'
                elif args[0]=='gpgv':out='[GNUPG:] VALIDSIG '+m.M.FINGERPRINT
                elif args[:2]==['dpkg-query','-W']:
                    if len(args)==3:out='\n'.join('\t'.join([name,*value[:2]]) for name,value in installed.items())+'\n'
                    else:
                        self.assertEqual(args,['dpkg-query','-W','-f=${binary:Package}\t${Version}\t${Status}\t${Architecture}\t${Depends}\n',*aliases])
                        out='\n'.join('\t'.join([name,*installed[name]]) for name in aliases)+'\n'
                elif args[:2]==['apt-cache','policy']:
                    self.assertNotIn(args[2],aliases)
                    version=installed[args[2]][0]
                    out='Candidate: '+version+'\n *** '+version+' 500\n 500 https://packages.sury.org/php resolute/main amd64 Packages\n'
                elif args[0]=='apt-get':
                    selectors=[name+'='+installed[name][0] for name in sorted({row['Package'] for row in rows})]
                    self.assertEqual(args,['apt-get','--simulate','--no-remove','--reinstall','--fix-broken','install',*selectors])
                    self.assertEqual(kwargs,{'timeout':600})
                    out='\n'.join('Inst '+row['Package']+' ('+row['Version']+' fixture)' for row in rows)
                else:self.fail('unexpected guest operation '+repr(args))
                return subprocess.CompletedProcess(args,0,out,'')
            def download(url,path,**kwargs):
                value=b'deb' if url.endswith('.deb') else b'synthetic signed fixture'
                m.M.write_private(path,value);return value
            def command(args,**kwargs):
                self.assertEqual(args[0],'bash');return subprocess.CompletedProcess(args,0,'\n'.join(direct)+'\n','')
            def receipt(name,value):
                receipts[name]=value;m.M.write_private(producer.root/(name+'.json'),value);return 'b'*64
            with patch.object(producer,'guest',side_effect=guest),patch.object(m,'download',side_effect=download),\
                 patch.object(m,'check_indexes',return_value={'amd64':rows,'arm64':[]}),\
                 patch.object(m.M,'check_index_packages'),patch.object(m.M,'release_body',return_value=({},{})),\
                 patch.object(m.M,'command',side_effect=command):
                producer.collect_baseline(receipt)
            self.assertEqual(sum(args[0]=='dpkg-query' for args in calls),2)
            self.assertEqual(producer.substage,'baseline-complete')
            derivation=receipts['baseline_inventory']['derivation']
            self.assertEqual(derivation['application_roots'],['php8.5-pgsql'])
            self.assertEqual(derivation['unchanged_distribution_metapackages'],aliases)
            retained={path.stem for path in (producer.root/'baseline/retained-baseline/amd64').iterdir()}
            self.assertEqual(retained,{row['Package'] for row in rows})
            m.publish(producer.root,root/'upload')
            layout=json.loads((root/'upload/package-layout.json').read_text())
            self.assertEqual(layout['runtime_commit'],'a'*40)
            self.assertEqual(layout['distribution_metapackages'],aliases)

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

    def test_distinct_qualifier_preserves_actual_driver_canonical_and_manifest_bindings(self):
        for mode in ('default','separate','canonical-map','manifest','qualifier-source'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as td:
                m=self.module();root=Path(td).resolve();driver=root/'driver';driver.mkdir();qualifier=root/'qualifier';qualifier.mkdir()
                cell=root/'cell';cell.mkdir();report=self.report();report_bytes=m.M.canonical(report);(cell/'report.json').write_bytes(report_bytes)
                bundle=root/'bundle';bundle.mkdir();manifest=dict(commit=('c'*40 if mode=='manifest' else 'a'*40),architecture='amd64',version='29.0.0',development=True,files={'bin/'+name:'1'*64 for name in ('panel','agent','panelctl')})
                (bundle/'manifest.json').write_bytes(m.M.canonical(manifest));(bundle/'manifest.sig').write_bytes(b'sig');key=root/'key';key.write_bytes(b'key')
                mapping={name:'b'*64 for name in m.FROZEN};qmapping=dict(mapping,**{'deploy/multipass/sury-maintenance-drill.py':'d'*64})
                execution=dict(schema='nakpanel-canonical-execution-v1',success=True,process_exited=True,process_group_empty=True,exit_code=0,source_binding={k:report[k] for k in ('source_vm','run_token','release','architecture','profile','php_provider')},qualification_report_sha256=m.M.digest(report_bytes),process_group=99999999,runtime_commit='a'*40,driver_source_sha256=mapping,qualifier_commit=('a'*40 if mode=='default' else 'c'*40),qualifier_source_sha256=(mapping if mode in ('default','canonical-map') else qmapping))
                m.M.write_private(root/'execution.json',execution)
                env=dict(NAKPANEL_CELL_REPORT_DIR=str(cell),NAKPANEL_MULTIPASS_VM=report['source_vm'],NAKPANEL_RUN_TOKEN=report['run_token'],NAKPANEL_RELEASE_BUNDLE=str(bundle),NAKPANEL_RELEASE_PUBLIC_KEY=str(key),NAKPANEL_OWNERSHIP_DIR=str(root/'ownership'))
                producer=m.Producer(driver,root/'private',root/'execution.json',env,**({} if mode=='default' else {'qualifier_source':qualifier}));calls=[];maps=[]
                def source_map(path,files,run):
                    maps.append(path);self.assertEqual(files,m.FROZEN)
                    if path==driver:return 'a'*40,mapping
                    self.assertEqual(path,qualifier)
                    if mode=='qualifier-source':raise ValueError('foreign qualifier source refused')
                    return 'c'*40,qmapping
                def command(args,**kwargs):
                    calls.append(args)
                    if '--roundcube-only' in args:
                        self.assertEqual(args[1],str((driver if mode=='default' else qualifier)/'deploy/multipass/internal-tools-verify.sh'))
                        raw=dict(schema='nakpanel-roundcube-send-read-v1',success=True,status='PASS',send_attempts=1,http_send_completed=True,self_recipient_verified=True,imap_arrival_verified=True,imap_message_id_verified=True,roundcube_body_verified=True,message_id='<fixture@example.test>',uid='42',**{k:'b'*64 for k in ('subject_sha256','body_sha256','recipient_sha256','qualifier_helper_sha256','certificate_sha256')})
                        envelope={k:producer.config[k] for k in m.M.BINDING};envelope.update(schema='nakpanel-roundcube-supplement-v1',success=True,qualifier_wrapper_sha256='b'*64,qualifier_helper_sha256='b'*64,raw_receipt=raw,raw_receipt_sha256=m.M.digest(m.M.canonical(raw)))
                        m.M.write_private(Path(kwargs['env']['NAKPANEL_INTERNAL_TOOLS_RECEIPT']),envelope)
                    return subprocess.CompletedProcess(args,0,'','')
                def cold():
                    value={k:producer.config[k] for k in m.M.BINDING};value.update(schema='nakpanel-sury-maintenance-retention-v1',status='PASS',snapshot_name=producer.config['retention_snapshot'],snapshot_id=report['source_vm']+'.'+producer.config['retention_snapshot'],snapshot_info_sha256='d'*64,cold_snapshot=True,running_revalidated=True,ownership_verified=True);return value
                def collect(receipt):receipt('native_gpgv_receipt',{'native_gpgv':True});receipt('baseline_inventory',{})
                with patch.object(m,'source_map',side_effect=source_map),patch.object(m,'process_group_exists',return_value=False),patch.object(m.M,'command',side_effect=command),patch.object(m.M,'host_identity'),patch.object(m.M,'host_record'),patch.object(producer,'cold_retention',side_effect=cold),patch.object(producer,'collect_baseline',side_effect=collect):
                    if mode in ('canonical-map','manifest','qualifier-source'):
                        with self.assertRaises(ValueError):producer.prepare()
                        self.assertEqual(calls,[],'rejected source binding reached external work')
                        continue
                    spec=producer.prepare()
                selected=json.loads(spec.read_bytes());separate=mode=='separate'
                self.assertEqual(maps,[driver,qualifier] if separate else [driver]);self.assertEqual(selected['driver_source'],str(driver));self.assertEqual(selected['runtime_commit'],'a'*40)
                self.assertEqual(selected['qualifier_source'],str(qualifier if separate else driver));self.assertEqual(selected['qualifier_commit'],'c'*40 if separate else 'a'*40)
                self.assertEqual(selected['driver_source_sha256'],{n:mapping[n] for n in m.DRIVER});self.assertEqual(selected['qualifier_source_sha256'],qmapping if separate else mapping)
                self.assertEqual(selected['maintenance_helper_sha256'],'d'*64 if separate else 'b'*64)
                outer=json.loads(Path(selected['references']['roundcube_execution_receipt']['path']).read_bytes());self.assertEqual(outer['qualifier_commit'],selected['qualifier_commit']);self.assertEqual(outer['runtime_commit'],'a'*40)

    def test_qualifier_option_is_scoped_to_prepare_and_controller_uses_qualifier(self):
        m=self.module();env=dict(NAKPANEL_MULTIPASS_VM=self.report()['source_vm'],NAKPANEL_RUN_TOKEN=self.report()['run_token'])
        for operation in ('request',):
            with self.subTest(operation=operation),patch.object(m.os,'environ',env),patch.object(m.sys,'argv',['producer',operation,'--driver-source','/driver','--execution-receipt','/execution']),patch.object(m,'record_request',side_effect=AssertionError('foreign operation reached work')),patch.object(m,'source_map',side_effect=AssertionError('foreign operation reached work')):
                with self.assertRaisesRegex(ValueError,'qualifier'):m.main()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);env['NAKPANEL_CELL_REPORT_DIR']=str(root);producer=SimpleNamespace(root=root,qualifier_source=Path('/qualifier'),config=dict(qualifier_commit='c'*40),prepare=lambda:root/'spec',record=lambda *a,**k:None)
            def command(args,**kwargs):
                self.assertEqual(args,['bash','/qualifier/deploy/multipass/sury-maintenance-verify.sh','same-version',str(root/'spec')]);raise RuntimeError('owned boundary reached')
            with patch.object(m,'SOURCE',Path('/qualifier')),patch.object(m.os,'environ',env),patch.object(m.sys,'argv',['producer','prepare','--driver-source','/driver','--execution-receipt','/execution','--private-root',str(root)]),patch.object(m,'Producer',return_value=producer) as constructor,patch.object(m.M,'command',side_effect=command),patch.object(m,'publish'):
                with self.assertRaisesRegex(RuntimeError,'owned boundary'):m.main()
                self.assertEqual(constructor.call_args.args[0],Path('/driver'));self.assertEqual(constructor.call_args.kwargs['qualifier_source'],Path('/qualifier'))

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
