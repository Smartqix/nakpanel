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


if __name__=='__main__':unittest.main()
