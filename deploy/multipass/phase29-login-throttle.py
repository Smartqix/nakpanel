#!/usr/bin/env python3
"""Private, bounded observations for the existing Phase29 login drill.

Requests are single-shot. Response bodies, cookies, credentials, raw query
errors, and journal messages are never emitted or retained by this helper.
"""
import argparse
from datetime import datetime, timezone
import inspect
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

COUNTS=('total_attempts','fixture_failures_window','loopback_failures_window','all_failures_window','all_successes_window')
SQL="""SELECT json_build_object(
'database_connected',true,
'database_utc',to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
'window_start_utc',to_char((now()-interval '15 minutes') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
'window_seconds',extract(epoch FROM '15m0s'::interval)::integer,
'total_attempts',count(*),
'fixture_failures_window',count(*) FILTER(WHERE email='admin@nakpanel.test' AND NOT succeeded AND attempted_at>now()-interval '15 minutes'),
'loopback_failures_window',count(*) FILTER(WHERE ip_address IN ('127.0.0.1','::1') AND NOT succeeded AND attempted_at>now()-interval '15 minutes'),
'all_failures_window',count(*) FILTER(WHERE NOT succeeded AND attempted_at>now()-interval '15 minutes'),
'all_successes_window',count(*) FILTER(WHERE succeeded AND attempted_at>now()-interval '15 minutes')) FROM login_attempts"""


def utc():return datetime.now(timezone.utc).isoformat()


def safe_run(args,timeout):
    try:return subprocess.run(args,capture_output=True,text=True,timeout=timeout,check=False)
    except subprocess.TimeoutExpired:return subprocess.CompletedProcess(args,124,'','')
    except OSError:return subprocess.CompletedProcess(args,127,'','')


def journal_summary(raw,exit_code):
    lines=raw.splitlines()[-200:]
    selected=[line for line in lines if 'record login attempt:' in line or 'login throttle query:' in line or 'write auth audit event:' in line]
    return {'journal_exit':exit_code,'inspected_lines':len(lines),'bounded_at_200':len(lines)==200,
            'login_failure_lines':sum('nakpanel-auth: login failed for ' in line for line in lines),
            'record_attempt_errors':sum('record login attempt:' in line for line in lines),
            'throttle_query_errors':sum('login throttle query:' in line for line in lines),
            'audit_write_errors':sum('write auth audit event:' in line for line in lines),
            'sqlstate_codes':sorted(set(re.findall(r'\bSQLSTATE ([A-Z0-9]{5})\b','\n'.join(selected))))}


def journal_program():
    # Filter inside the root guest process: raw journal text never crosses the
    # transport boundary or enters the host evidence directory.
    return 'import json,re,subprocess\n'+inspect.getsource(journal_summary)+'''\ntry:
 result=subprocess.run(['journalctl','-u','nakpanel.service','--since','-15 min','--no-pager','-n','200','--output=cat'],capture_output=True,text=True,timeout=10,check=False)
 value=journal_summary(result.stdout,result.returncode)
except (subprocess.TimeoutExpired,OSError):value=journal_summary('',124)
print(json.dumps(value,sort_keys=True,separators=(',',':')))
'''


def encode(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode('ascii')


def update(fd,value):
    os.lseek(fd,0,os.SEEK_SET);os.ftruncate(fd,0);os.write(fd,encode(value));os.fsync(fd)


def reserve(directory,name,initial):
    info=directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('unsafe report directory')
    parent=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
    finally:os.close(parent)
    update(fd,initial);return fd


def run(args):
    if not re.fullmatch(r'nakpanel-[A-Za-z0-9-]+',args.vm):raise ValueError('unsafe VM')
    initial={'schema':'nakpanel-phase29-login-throttle-'+args.action+'-v1','phase':args.phase,'started_at':utc(),'status':'STARTED'}
    if args.action=='request':
        if not ((args.phase=='wrong' and 1<=args.ordinal<=10 and args.credential=='wrong') or (args.phase=='threshold' and args.ordinal==11 and args.credential=='correct') or (args.phase=='post-restart' and args.ordinal==12 and args.credential=='correct')):raise ValueError('unsupported request ordinal/purpose')
        name='request-'+str(args.ordinal).zfill(2)+'.json';initial['ordinal']=args.ordinal
    else:name=args.action+'-'+args.phase+'.json'
    fd=reserve(args.directory,name,initial)
    try:
        base=['multipass','exec',args.vm,'--']
        if args.action=='request':
            password='wrong-password' if args.credential=='wrong' else 'NakpanelAdmin!2026'
            result=safe_run(base+['curl','-sk','--connect-timeout','10','--max-time','20','-o','/dev/null','-w','%{http_code}','-d','email=admin@nakpanel.test','-d','password='+password,'https://127.0.0.1:7443/login'],30)
            code=result.stdout.strip() if re.fullmatch(r'[1-5][0-9]{2}',result.stdout.strip()) else 'INVALID'
            good=result.returncode==0 and code!='INVALID'
            update(fd,dict(initial,finished_at=utc(),status='PASS' if good else 'FAILED',http_code=code,transport_exit=result.returncode))
            if good:print(code);return 0
            return 1
        if args.action=='snapshot':
            result=safe_run(base+['sudo','-u','postgres','env','PGCONNECT_TIMEOUT=5','PGOPTIONS=-c statement_timeout=5000 -c default_transaction_read_only=on','psql','-XAtq','-d','nakpanel','-v','ON_ERROR_STOP=1','-v','VERBOSITY=sqlstate','-c',SQL],20)
            value={};good=False
            if result.returncode==0:
                try:
                    candidate=json.loads(result.stdout)
                    expected={'database_connected','database_utc','window_start_utc','window_seconds',*COUNTS}
                    good=type(candidate) is dict and set(candidate)==expected and candidate['database_connected'] is True and type(candidate['window_seconds']) is int and candidate['window_seconds']==900 and all(type(candidate[k]) is int and candidate[k]>=0 for k in COUNTS) and all(type(candidate[k]) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ',candidate[k]) for k in ('database_utc','window_start_utc'))
                    if good:value=candidate
                except (ValueError,TypeError):pass
            update(fd,dict(initial,finished_at=utc(),status='PASS' if good else 'FAILED',transport_exit=result.returncode,database_connected=good,**{k:v for k,v in value.items() if k!='database_connected'}))
            # Diagnostic unavailability never manufactures a successful request
            # or changes the original required HTTP429 assertion.
            return 0
        result=safe_run(base+['sudo','python3','-c',journal_program()],20)
        summary=None
        if result.returncode==0:
            try:
                candidate=json.loads(result.stdout);expected=set(journal_summary('',0))
                if type(candidate) is dict and set(candidate)==expected and type(candidate['bounded_at_200']) is bool and all(type(candidate[k]) is int for k in expected-{'bounded_at_200','sqlstate_codes'}) and type(candidate['sqlstate_codes']) is list and all(type(code) is str and re.fullmatch(r'[A-Z0-9]{5}',code) for code in candidate['sqlstate_codes']):summary=candidate
            except (ValueError,TypeError):pass
        update(fd,dict(initial,finished_at=utc(),status='PASS' if summary is not None else 'FAILED',transport_exit=result.returncode,journal=summary))
        return 0
    finally:os.close(fd)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('request','snapshot','diagnostic'));parser.add_argument('vm');parser.add_argument('directory',type=Path);parser.add_argument('phase',choices=('before','after-ten','after-threshold','after-restart','transport-failure','wrong','threshold','post-restart'));parser.add_argument('--ordinal',type=int);parser.add_argument('--credential',choices=('wrong','correct'));args=parser.parse_args()
    return run(args)


if __name__=='__main__':
    try:sys.exit(main())
    except (ValueError,OSError,TypeError):
        print('Phase29 login diagnostic helper refused unsafe/duplicate input',file=sys.stderr);sys.exit(1)
