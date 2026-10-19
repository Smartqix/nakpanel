import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent

class ThrottleDiagnostics(unittest.TestCase):
    def helper(self):
        spec=importlib.util.spec_from_file_location('throttle_under_test',HERE/'phase29-login-throttle.py');module=importlib.util.module_from_spec(spec)
        with patch('subprocess.run',side_effect=AssertionError('import executed a boundary')):spec.loader.exec_module(module)
        return module

    def run_drill(self,mode='success'):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=Path(temp.name);tools=root/'bin';tools.mkdir();report=root/'report';report.mkdir()
        fake=tools/'multipass';fake.write_text('''#!/usr/bin/env python3
import json,os,subprocess,sys
from pathlib import Path
root=Path(os.environ['FIXTURE']);args=sys.argv[1:];assert args[:3]==['exec','nakpanel-fixture','--']
args=args[3:];path=root/'counts.json';state=json.loads(path.read_text()) if path.exists() else {'wrong':0,'posts':0,'restarts':0}
if args[0]=='curl':
 assert args[-1]=='https://127.0.0.1:7443/login' and args[args.index('-o')+1]=='/dev/null'
 assert not set(args)&{'-b','-c','-L','-v','--retry','--location'}
 wrong='password=wrong-password' in args;state['posts']+=1;state['wrong']+=int(wrong);path.write_text(json.dumps(state))
 if os.environ['MODE']=='transport' and state['wrong']==3:
  print('private-email password private-cookie',file=sys.stderr);sys.exit(28)
 code='303' if wrong or os.environ['MODE']=='mismatch' or (os.environ['MODE']=='restart-mismatch' and state['restarts']) else '429'
 if '-w' in args:print(code,end='')
elif 'psql' in args:
 assert 'ON_ERROR_STOP=1' in args and any('default_transaction_read_only=on' in x for x in args)
 if os.environ['MODE']=='database-error':print('private-email password private-cookie',file=sys.stderr);sys.exit(2)
 print(json.dumps({'database_connected':True,'database_utc':'2026-10-19T07:00:00Z','window_start_utc':'2026-10-19T06:45:00Z','window_seconds':900,'total_attempts':state['posts'],'fixture_failures_window':state['wrong'],'loopback_failures_window':state['wrong'],'all_failures_window':state['wrong'],'all_successes_window':0}))
elif 'python3' in args:
 code=args[args.index('-c')+1];sys.exit(subprocess.run([sys.executable,'-c',code],env=os.environ).returncode)
elif args[:3]==['sudo','systemctl','restart']:
 state['restarts']+=1;path.write_text(json.dumps(state))
else:raise AssertionError('unexpected boundary')
''');fake.chmod(0o700)
        journal=tools/'journalctl';journal.write_text("#!/bin/sh\nprintf '%s\\n' 'nakpanel-auth: login failed for private-email from private-address' 'record login attempt: private-password (SQLSTATE 08006)' 'login throttle query: private-cookie (SQLSTATE 42P01)'\n");journal.chmod(0o700)
        source=(HERE/'phase29-verify.sh').read_text();start=source.index('# Durable login throttle:');end=source.index('cli user unlock',start)
        script='''set -euo pipefail
VM_NAME=nakpanel-fixture;BASE_URL=https://not-used.invalid;NAKPANEL_RUN_TOKEN=fixture
SCRIPT_DIR="$QUALIFIER";NAKPANEL_CELL_REPORT_DIR="$REPORT"
multipass_exec_short(){ multipass exec "$@"; }
curl(){ return 0; }
sleep(){ :; }
fail(){ echo "$*" >&2;exit 1; }
'''+source[start:end]
        result=subprocess.run(['bash','-c',script],env=dict(os.environ,PATH=str(tools)+':'+os.environ['PATH'],FIXTURE=str(root),REPORT=str(report),QUALIFIER=str(HERE),MODE=mode),capture_output=True,text=True,timeout=20)
        return result,root,report

    def test_success_retains_twelve_single_post_receipts_and_aggregate_window_checks(self):
        result,root,report=self.run_drill();self.assertEqual(result.returncode,0,result.stderr)
        counts=json.loads((root/'counts.json').read_text());self.assertEqual(counts,{'wrong':10,'posts':12,'restarts':1})
        records=sorted(report.glob('phase29-login-throttle/attempt.*/request-*.json'));self.assertEqual(len(records),12,'existing drill discarded each request status/transport/time')
        for ordinal,path in enumerate(records,1):
            value=json.loads(path.read_text());self.assertEqual(value['ordinal'],ordinal);self.assertEqual(value['transport_exit'],0);self.assertIn(value['http_code'],('303','429'));self.assertTrue(value['started_at'].endswith('+00:00'));self.assertEqual(path.stat().st_mode&0o777,0o600)
        snapshots=list(report.glob('phase29-login-throttle/attempt.*/snapshot-*.json'));self.assertEqual(len(snapshots),4)
        self.assertEqual([json.loads(p.read_text())['window_seconds'] for p in snapshots],[900]*4)
        self.assertFalse(list(report.glob('**/diagnostic-*.json')))

    def test_mismatch_keeps_exact_attempt_count_and_only_filtered_diagnostics(self):
        for mode,posts,restarts in [('mismatch',11,0),('restart-mismatch',12,1)]:
            with self.subTest(mode=mode):
                result,root,report=self.run_drill(mode);self.assertNotEqual(result.returncode,0);self.assertIn('got 303',result.stderr)
                counts=json.loads((root/'counts.json').read_text());self.assertEqual(counts,{'wrong':10,'posts':posts,'restarts':restarts})
                diagnostics=list(report.glob('**/diagnostic-*.json'));self.assertEqual(len(diagnostics),1)
                value=json.loads(diagnostics[0].read_text());self.assertEqual(value['journal']['login_failure_lines'],1);self.assertEqual(value['journal']['throttle_query_errors'],1);self.assertEqual(value['journal']['sqlstate_codes'],['08006','42P01'])
                retained=''.join(p.read_text() for p in report.rglob('*') if p.is_file())+result.stdout+result.stderr
                for secret in ('private-email','private-address','private-password','private-cookie','NakpanelAdmin!2026','wrong-password'):self.assertNotIn(secret,retained)

    def test_transport_failure_is_retained_once_and_never_replayed_or_counted_as_success(self):
        result,root,report=self.run_drill('transport');self.assertNotEqual(result.returncode,0)
        self.assertEqual(json.loads((root/'counts.json').read_text()),{'wrong':3,'posts':3,'restarts':0})
        records=sorted(report.glob('**/request-*.json'));self.assertEqual(len(records),3);self.assertEqual(json.loads(records[-1].read_text())['transport_exit'],28)
        self.assertNotIn('private-email',result.stderr);self.assertEqual(len(list(report.glob('**/diagnostic-*.json'))),1)

    def test_database_diagnostic_failure_records_no_raw_error_or_query_text(self):
        result,root,report=self.run_drill('database-error');self.assertEqual(result.returncode,0,result.stderr)
        snapshots=list(report.glob('**/snapshot-*.json'));self.assertEqual(len(snapshots),4)
        for path in snapshots:
            value=json.loads(path.read_text());self.assertFalse(value['database_connected']);self.assertEqual(value['transport_exit'],2)
            for secret in ('private-email','private-cookie','password','SELECT','admin@'):self.assertNotIn(secret,path.read_text())

    def test_duplicate_ordinal_refuses_before_a_second_post(self):
        result,root,report=self.run_drill();self.assertEqual(result.returncode,0,result.stderr);directory=next(report.glob('phase29-login-throttle/attempt.*'));before=(root/'counts.json').read_bytes()
        run=subprocess.run([sys.executable,str(HERE/'phase29-login-throttle.py'),'request','nakpanel-fixture',str(directory),'wrong','--ordinal','1','--credential','wrong'],env=dict(os.environ,PATH=str(root/'bin')+':'+os.environ['PATH'],FIXTURE=str(root),MODE='success'),capture_output=True,text=True,timeout=5)
        self.assertNotEqual(run.returncode,0);self.assertEqual((root/'counts.json').read_bytes(),before)

    def test_timeout_is_one_uncertain_attempt_and_retains_no_exception_payload(self):
        m=self.helper()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);root.chmod(0o700);args=type('Args',(),dict(action='request',vm='nakpanel-fixture',directory=root,phase='wrong',ordinal=1,credential='wrong'))()
            calls=[]
            def timed_out(argv,**kwargs):calls.append(argv);raise subprocess.TimeoutExpired(argv,30,output='private-body',stderr='private-password')
            with patch.object(m.subprocess,'run',side_effect=timed_out):self.assertEqual(m.run(args),1)
            self.assertEqual(len(calls),1);proof=json.loads((root/'request-01.json').read_text());self.assertEqual(proof['transport_exit'],124);self.assertEqual(proof['status'],'FAILED');self.assertEqual(proof['http_code'],'INVALID');self.assertNotIn('private-',(root/'request-01.json').read_text())

    def test_filtered_guest_journal_is_bounded_and_does_not_emit_identifiers(self):
        m=self.helper();raw='private-email private-password\n'*300+'record login attempt: private-cookie (SQLSTATE 08006)\n'
        proof=m.journal_summary(raw,0);self.assertEqual(proof['inspected_lines'],200);self.assertTrue(proof['bounded_at_200']);self.assertEqual(proof['record_attempt_errors'],1);self.assertEqual(proof['sqlstate_codes'],['08006']);self.assertNotIn('private-',json.dumps(proof))

if __name__=='__main__':unittest.main()
