"""Private mechanical child custody, with no CLI or runtime-admission authority.

Trusted integration must independently bind the exact accepted initializer or
sweep command. This library never authenticates caller-supplied provenance.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import threading
import time

MAX_PRIVATE_LOG = 64*1024*1024


class Rejected(ValueError):
    def __init__(self):super().__init__('day0 command custody rejected')


class Interrupted(BaseException):
    def __init__(self, number):self.number=number


class Failed(Exception):
    def __init__(self, code):self.code=code


def need(condition):
    if not condition:raise Rejected()


def utc():return datetime.now(timezone.utc).isoformat()


def binding_copy(value):
    fields={'source_commit','manifest_sha256','source_vm','run_token','profile','php_provider',
            'architecture','installed_binary_sha256'}
    need(type(value) is dict and set(value)==fields)
    need(type(value['source_commit']) is str and re.fullmatch('[a-f0-9]{40}',value['source_commit']))
    need(type(value['manifest_sha256']) is str and re.fullmatch('[a-f0-9]{64}',value['manifest_sha256']))
    need(type(value['source_vm']) is str and re.fullmatch('nakpanel-[a-z0-9-]{6,100}',value['source_vm']))
    need(type(value['run_token']) is str and re.fullmatch('[a-z][a-z0-9-]{9,100}',value['run_token']))
    profiles={'ubuntu-24.04':'native','ubuntu-26.04-native':'native','ubuntu-26.04-sury':'sury'}
    need(type(value['profile']) is str and value['profile'] in profiles and
         value['php_provider']==profiles[value['profile']] and value['architecture']=='amd64')
    binaries=value['installed_binary_sha256']
    need(type(binaries) is dict and set(binaries)=={'panel','agent','panelctl'} and
         all(type(v) is str and re.fullmatch('[a-f0-9]{64}',v) for v in binaries.values()))
    return dict(value,installed_binary_sha256=dict(binaries))


def group_state(pid):
    try:os.killpg(pid,0);return 'present'
    except ProcessLookupError:return 'empty'
    except OSError:return 'unconfirmed'


def stop_owned(proc):
    for number in (signal.SIGTERM,signal.SIGKILL):
        try:os.killpg(proc.pid,number)
        except OSError:pass
        try:proc.wait(timeout=1)
        except subprocess.TimeoutExpired:pass
    for _ in range(40):
        state=group_state(proc.pid)
        if state=='empty':return proc.poll() is not None
        if state=='unconfirmed':return False
        time.sleep(.05)
    return False


@contextmanager
def cancellation_custody():
    need(threading.current_thread() is threading.main_thread())
    numbers={signal.SIGTERM,signal.SIGINT};pending=[]
    previous={n:signal.getsignal(n) for n in numbers}
    def defer(number,frame):
        if not pending:pending.append(number)
    held=signal.pthread_sigmask(signal.SIG_BLOCK,numbers)
    try:
        for n in numbers:signal.signal(n,defer)
    finally:signal.pthread_sigmask(signal.SIG_SETMASK,held)
    try:yield pending
    finally:
        held=signal.pthread_sigmask(signal.SIG_BLOCK,numbers)
        try:
            for n,handler in previous.items():signal.signal(n,handler)
        finally:signal.pthread_sigmask(signal.SIG_SETMASK,held)
        if pending:raise Interrupted(pending[0])


def identity(info):return info.st_dev,info.st_ino


def log_metadata(info):
    return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,info.st_nlink,
            info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def namespace_stable(root,rootfd,phase,phasefd):
    try:
        r=root.lstat();p=os.stat(phase,dir_fd=rootfd,follow_symlinks=False)
        return (identity(r)==identity(os.fstat(rootfd)) and identity(p)==identity(os.fstat(phasefd)) and
                all(stat.S_ISDIR(x.st_mode) and stat.S_IMODE(x.st_mode)==0o700 and x.st_uid==os.getuid() for x in (r,p)))
    except OSError:return False


def write_receipt(fd,value):
    data=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
    out=os.open('.receipt.tmp',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
    with os.fdopen(out,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
    os.replace('.receipt.tmp','receipt.json',src_dir_fd=fd,dst_dir_fd=fd)
    os.fsync(fd)


def log_summary(fd,parent,name):
    info=os.fstat(fd)
    need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and
         stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1)
    named=os.stat(name,dir_fd=parent,follow_symlinks=False)
    need(log_metadata(named)==log_metadata(info) and stat.S_ISREG(named.st_mode))
    os.fsync(fd)
    digest=None
    if info.st_size<=MAX_PRIVATE_LOG:
        os.lseek(fd,0,os.SEEK_SET);h=hashlib.sha256()
        while True:
            block=os.read(fd,1024*1024)
            if not block:break
            h.update(block)
        after=os.fstat(fd)
        need(log_metadata(after)==log_metadata(info))
        digest=h.hexdigest()
    need(log_metadata(os.stat(name,dir_fd=parent,follow_symlinks=False))==log_metadata(info))
    return dict(bytes=info.st_size,sha256=digest),log_metadata(info)


def logs_stable(logs,parent,metadata):
    try:
        return all(log_metadata(os.fstat(fd))==expected and
                   log_metadata(os.stat(name,dir_fd=parent,follow_symlinks=False))==expected
                   for fd,name,expected in zip(logs,('stdout.log','stderr.log'),metadata))
    except OSError:return False


def run_once(private_root,phase,argv,*,binding,env,timeout_seconds):
    rootfd=phasefd=None;logs=[];proc=None
    try:
        need(threading.current_thread() is threading.main_thread())
        need(phase in ('initializer','sweep'))
        bound=binding_copy(binding)
        need(type(argv) in (list,tuple) and 0<len(argv)<=32 and
             all(type(x) is str and 0<len(x)<=16384 and '\0' not in x for x in argv))
        need(type(env) is dict and all(type(k) is str and type(v) is str and '\0' not in k+v for k,v in env.items()))
        need(type(timeout_seconds) in (int,float) and math.isfinite(timeout_seconds) and 0<timeout_seconds<=7200)
        root=Path(private_root);need(root.is_absolute() and root.resolve()==root)
        info=root.lstat();need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode)==0o700 and info.st_uid==os.getuid())
        rootfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        need(identity(info)==identity(os.fstat(rootfd)))
        os.mkdir(phase,mode=0o700,dir_fd=rootfd)
        phasefd=os.open(phase,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=rootfd)
        for name in ('stdout.log','stderr.log'):
            logs.append(os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=phasefd))
        command_hash=hashlib.sha256(json.dumps(list(argv),separators=(',',':')).encode()).hexdigest()
        start=time.monotonic();deadline=start+timeout_seconds
        receipt=dict(schema='nakpanel-day0-command-custody-v1',phase=phase,status='STARTED',failure_code=None,
                     source_binding=bound,command_sha256=command_hash,started_at=utc(),finished_at=None,
                     pid=None,process_group=None,exit_code=None,process_exited=False,process_group_empty=False,group_observation='not-started',
                     duration_monotonic_seconds=None,claims_runtime_or_day0_acceptance=False)
        write_receipt(phasefd,receipt)
        failure=None;code=None
        try:
            with cancellation_custody() as pending:
                try:
                    if pending:raise Interrupted(pending[0])
                    proc=subprocess.Popen(list(argv),env=dict(env),stdin=subprocess.DEVNULL,
                                          stdout=logs[0],stderr=logs[1],start_new_session=True)
                    receipt.update(pid=proc.pid,process_group=proc.pid)
                    write_receipt(phasefd,receipt)
                    while True:
                        if pending:raise Interrupted(pending[0])
                        if sum(os.fstat(fd).st_size for fd in logs)>MAX_PRIVATE_LOG:raise Failed('output-budget')
                        remaining=deadline-time.monotonic()
                        if remaining<=0:raise Failed('timeout')
                        try:proc.wait(timeout=min(.1,remaining));break
                        except subprocess.TimeoutExpired:pass
                    if proc.returncode!=0:raise Failed('exit')
                    state=group_state(proc.pid)
                    if state=='unconfirmed':raise Failed('group-unconfirmed')
                    if state=='present':raise Failed('background-child')
                    if time.monotonic()>deadline:raise Failed('timeout')
                finally:
                    if proc is not None and (proc.poll() is None or group_state(proc.pid)!='empty'):
                        if not stop_owned(proc):raise Failed('cleanup')
        except BaseException as error:
            failure=error
            code='cancelled' if isinstance(error,(Interrupted,KeyboardInterrupt,SystemExit)) else error.code if isinstance(error,Failed) else 'launch' if proc is None else 'internal'
        if not namespace_stable(root,rootfd,phase,phasefd):failure=Rejected();code='namespace'
        metadata=[]
        try:
            hashed=[log_summary(fd,phasefd,name) for fd,name in zip(logs,('stdout.log','stderr.log'))]
            summaries=[value[0] for value in hashed];metadata=[value[1] for value in hashed]
        except Exception:failure=Rejected();code='private-log';summaries=[]
        if sum(x['bytes'] for x in summaries)>MAX_PRIVATE_LOG:failure=Rejected();code='output-budget'
        if metadata and not logs_stable(logs,phasefd,metadata):failure=Rejected();code='private-log'
        if not namespace_stable(root,rootfd,phase,phasefd):failure=Rejected();code='namespace'
        state=group_state(proc.pid) if proc is not None else 'not-started'
        empty=state=='empty'
        exited=proc is not None and proc.poll() is not None
        if state=='unconfirmed':failure=Rejected();code='group-unconfirmed'
        if not (empty and exited) and failure is None:failure=Rejected();code='cleanup'
        receipt.update(status='PASS' if failure is None else 'FAIL',failure_code=code,finished_at=utc(),
                       duration_monotonic_seconds=time.monotonic()-start,exit_code=proc.returncode if proc is not None else None,
                       process_exited=exited,process_group_empty=empty,group_observation=state,stdout=summaries[0] if summaries else None,
                       stderr=summaries[1] if summaries else None)
        # This receipt distinguishes confirmed drain from unconfirmed cleanup.
        # Callers must await return/outer exit and verify the canonical receipt.
        write_receipt(phasefd,receipt)
        if not namespace_stable(root,rootfd,phase,phasefd):
            failure=Rejected();code='namespace'
            receipt.update(status='FAIL',failure_code=code)
            write_receipt(phasefd,receipt)
        elif metadata and not logs_stable(logs,phasefd,metadata):
            failure=Rejected();code='private-log'
            receipt.update(status='FAIL',failure_code=code)
            write_receipt(phasefd,receipt)
        if failure is not None:
            if isinstance(failure,(Interrupted,KeyboardInterrupt,SystemExit)):raise failure
            raise Rejected()
        return receipt
    except (Interrupted,KeyboardInterrupt,SystemExit):raise
    except Exception:raise Rejected() from None
    finally:
        for fd in logs:os.close(fd)
        if phasefd is not None:os.close(phasefd)
        if rootfd is not None:os.close(rootfd)
