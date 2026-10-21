#!/usr/bin/env python3
"""Guard real scheduling/restore acceptance, replacing external VM boundaries only."""
import copy
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent


class ScheduledBackupTests(unittest.TestCase):
    def module(self):
        path=HERE/'scheduled-backup-verify.py'
        self.assertTrue(path.is_file(),'focused scheduled-backup verifier is missing')
        spec=importlib.util.spec_from_file_location('scheduled_backup',path)
        module=importlib.util.module_from_spec(spec)
        with patch('subprocess.run',side_effect=AssertionError('import executed a command')):
            spec.loader.exec_module(module)
        return module

    def backup(self):
        return dict(id=7,destination_id=3,destination_name='phase4-local',scheduled=True,status='active',
            sha256='a'*64,size_bytes=12345,created_at='2026-10-21T21:00:01+00:00',
            completed_at='2026-10-21T21:00:15+00:00',verified_at='2026-10-21T21:00:14+00:00',
            river_state='completed',scheduler_audit=True,verify_detail={'entries':80,'pg_restore_list_ok':True})

    def test_manual_unverified_stale_or_unrelated_backup_cannot_prove_scheduling(self):
        m=self.module();since=datetime(2026,10,21,21,tzinfo=timezone.utc)
        m.check_scheduled_backup(self.backup(),3,since)
        for key,value in [('scheduled',False),('scheduled',1),('destination_id',4),('destination_name','other'),
                          ('status','running'),('verified_at',None),('river_state','running'),('scheduler_audit',False),
                          ('size_bytes',0),('sha256','bad'),('created_at','2026-10-21T20:59:00+00:00'),
                          ('completed_at','2026-10-21T20:00:00+00:00'),('verify_detail',{'entries':0,'pg_restore_list_ok':False})]:
            with self.subTest(field=key,value=value),self.assertRaises(ValueError):
                m.check_scheduled_backup(dict(self.backup(),**{key:value}),3,since)

    def test_changed_runtime_source_cannot_reuse_phase3_acceptance(self):
        m=self.module()
        m.check_changed_paths(['README.md','docs/superpowers/plans/2026-10-21-phase4-scheduled-backups.md',
            'deploy/multipass/scheduled-backup-verify.py','.github/workflows/ubuntu-hosted-qualification.yml'])
        for name in ('internal/backup/restore.go','deploy/install/platform.sh','cmd/panel/main.go',
                     'deploy/multipass/common.sh','deploy/multipass/current-install-verify.sh'):
            with self.subTest(path=name),self.assertRaises(ValueError):m.check_changed_paths([name])

    def test_phase3_archive_manifest_key_and_source_must_all_match(self):
        m=self.module()
        identity=dict(commit='63c00f6006df3bba1ca9ef474e0f350ff7835165',
            archive_sha256='daed8aae60f859882a896e1cd321d975ccd6ef9b9276e53ad1f90b97419aa194',
            manifest_sha256='31b264e7ed4810687196b7fbb4c78713460cb9590e12f7f9dd3edaf4a682adc6',
            public_key_sha256='23e246427ffacccafee7aaac5af736b23a2ddf069c098b062796e8b050ed324d')
        m.check_baseline(identity)
        for key in identity:
            with self.subTest(field=key),self.assertRaises(ValueError):m.check_baseline(dict(identity,**{key:'0'*len(identity[key])}))

    def test_restore_proof_requires_all_three_php_intents_bytes_and_nonroot_execution(self):
        m=self.module();expected={minor:{'sha256':'a'*64} for minor in ('8.3','8.4','8.5')}
        observed={minor:dict(sha256='a'*64,cli_version=minor+'.1',http_version=minor+'.1',
            uid=1001,user_uid=1001,php_version=minor,desired_php_version=minor,status='active') for minor in expected}
        m.check_php_sites(observed,expected)
        for key,value in [('sha256','b'*64),('cli_version','8.2.1'),('http_version','8.2.1'),
                          ('uid',0),('uid',1002),('desired_php_version','8.5'),('status','pending')]:
            changed=copy.deepcopy(observed);changed['8.3'][key]=value
            with self.subTest(field=key),self.assertRaises(ValueError):m.check_php_sites(changed,expected)
        del observed['8.4']
        with self.assertRaises(ValueError):m.check_php_sites(observed,expected)

    def test_failure_receipt_retains_location_without_exception_secrets(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'result.json'
            try:raise ValueError('nkbk1-PRIVATE-ARCHIVE-KEY arbitrary private stderr')
            except ValueError as error:m.write_failure(p,{'stage':'restore'},error)
            text=p.read_text();value=json.loads(text)
            self.assertEqual(value['status'],'FAIL');self.assertEqual(value['stage'],'restore')
            self.assertEqual(value['error_type'],'ValueError');self.assertNotIn('PRIVATE',text);self.assertNotIn('stderr',text)
            self.assertEqual(p.stat().st_mode & 0o777,0o600)

    def test_cli_refuses_nonhosted_environment_before_external_commands(self):
        self.module()
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);calls=p/'calls';fake=p/'python3'
            fake.write_text('#!/bin/sh\necho external >> "$CALLS"\nexit 90\n');fake.chmod(0o700)
            for actions,runner in (('false','github-hosted'),('true','self-hosted'),('false','local')):
                result=subprocess.run(['bash',str(HERE/'scheduled-backup-verify.sh'),'run'],
                    env=dict(os.environ,GITHUB_ACTIONS=actions,RUNNER_ENVIRONMENT=runner,CALLS=str(calls),PATH=str(p)+':/usr/bin:/bin'),capture_output=True,text=True)
                self.assertNotEqual(result.returncode,0);self.assertFalse(calls.exists())

    def test_control_canary_is_created_by_the_principal_that_dumps_and_restores_it(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as td:
            drill=object.__new__(m.Drill);drill.source='nakpanel-26-04-amd64-scheduled-123-1'
            drill.token='scheduled-123-1';drill.private=Path(td)
            rows=[dict(id=i,domain=domain,username='npscheduled',document_root='/home/npscheduled/domains/'+domain+'/public_html',
                php_version=minor,desired_php_version=minor,status='active') for i,(minor,domain) in enumerate(
                [('8.3','current-bootstrap.test'),('8.4','scheduled84.test'),('8.5','scheduled85.test')],1)]
            owners=[]
            def command(args,**kwargs):
                if args[0]=='curl':return 'data-np-role="admin"' if args[-1].endswith('/login') else '303'
                self.assertEqual(args[:4],['multipass','exec',drill.source,'--'])
                if 'psql' in args:
                    query=args[-1]
                    if query.startswith('SELECT subscription_id'):return '9'
                    self.assertIn('CREATE TABLE nakpanel_qualification_backup_canary',query)
                    principal=args[args.index('-u')+1]
                    self.assertEqual(principal,'nakpanel','postgres-owned fixture cannot be dumped by the real nakpanel backup role')
                    owners.append(principal)
                return ''
            with patch.object(drill,'cmd',side_effect=command),patch.object(drill,'ip',return_value='10.0.0.2'),\
                 patch.object(drill,'shell',return_value='csrf'),patch.object(drill,'sites',return_value=rows):
                drill.seed()
            self.assertEqual(owners,['nakpanel'])

    def test_http_failure_retains_safe_status_and_readonly_runtime_diagnostics(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as td:
            drill=object.__new__(m.Drill);drill.private=Path(td);drill.sequence=0
            drill.env=dict(os.environ);drill.state={'stage':'restored-data-validation'};drill.last_exit_code=0
            def command(args,**kwargs):
                self.assertEqual(args[0],'curl')
                self.assertNotIn('-skfL',args)
                Path(args[args.index('-o')+1]).write_text('private HTTP response nkbk1-SECRET')
                return '502'
            with patch.object(drill,'cmd',side_effect=command):
                with self.assertRaises(ValueError):drill.php_http('dr','8.3','current-bootstrap.test','10.0.0.2','canary.php')
            receipt=json.dumps(drill.state)
            self.assertIn('502',receipt);self.assertNotIn('SECRET',receipt);self.assertNotIn('private HTTP response',receipt)
            self.assertEqual(drill.state['last_php_http']['minor'],'8.3')

    def test_restore_wait_collects_diagnostics_without_repairing_or_accepting_failure(self):
        m=self.module();drill=object.__new__(m.Drill)
        with patch.object(drill,'health',side_effect=ValueError('HTTP failed')),\
             patch.object(drill,'runtime_diagnostics') as diagnostics,\
             patch.object(m.time,'monotonic',side_effect=[0,181]):
            with self.assertRaises(ValueError):drill.wait_health('dr')
        self.assertEqual(diagnostics.call_args_list,[(('dr','first-failure'),),(('dr','final-failure'),)])


if __name__=='__main__':unittest.main()
