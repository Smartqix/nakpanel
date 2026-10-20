"""L3 adapter over unchanged, hash-pinned custody mechanics; no CLI authority."""
import hashlib,json,math,os,re,stat,subprocess,time
from pathlib import Path
import custody_base as base
from l3 import SOURCE,PHASES,need,canonical

def _run(root,phase,argv,*,binding,env,timeout_seconds):
 """One exclusive claim and one owned session. Never replays a command.

Deadline and combined stream budget are checked after wait, drain, hashing and
publication. A real child exit0 is retained even if publication makes FAIL.
"""
 root=Path(root);need(re.fullmatch(r'a[0-9]{3,5}-(?:source|target|host)',phase) is not None,'IDENTITY')
 need(type(binding) is dict and set(binding)=={'run_id','role','vm','token','source_commit','operation'} and binding['source_commit']==SOURCE and binding['role'] in ('source','target','host'),'IDENTITY')
 need(type(argv) is list and argv and len(argv)<=128 and all(type(x) is str and '\0' not in x for x in argv),'IDENTITY');need(type(timeout_seconds) in (int,float) and math.isfinite(timeout_seconds) and 0<timeout_seconds<=4500,'DEADLINE')
 rootfd=phasefd=None;logs=[];proc=None;failure=None;code=None;start=time.monotonic();deadline=start+timeout_seconds;receipt=None
 try:
  need(root.is_absolute() and root.resolve()==root,'IDENTITY');info=root.lstat();need(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700,'IDENTITY')
  rootfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);need(base.identity(info)==base.identity(os.fstat(rootfd)),'IDENTITY')
  os.mkdir(phase,0o700,dir_fd=rootfd);phasefd=os.open(phase,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=rootfd)
  for n in ('stdout.log','stderr.log'):logs.append(os.open(n,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=phasefd))
  receipt={'schema':'nakpanel-l3-custody-v1','phase':phase,'binding':dict(binding),'command_sha256':hashlib.sha256(canonical(argv)).hexdigest(),'status':'STARTED','failure_code':None,'exit_code':None,'pid':None,'process_group':None,'process_exited':False,'process_group_empty':False,'started_at':base.utc(),'finished_at':None,'duration_monotonic_seconds':None}
  base.write_receipt(phasefd,receipt)
  try:
   with base.cancellation_custody() as pending:
    try:
     if pending:raise base.Interrupted(pending[0])
     proc=subprocess.Popen(argv,env=dict(env),stdin=subprocess.DEVNULL,stdout=logs[0],stderr=logs[1],start_new_session=True)
     receipt.update(pid=proc.pid,process_group=proc.pid);base.write_receipt(phasefd,receipt)
     while True:
      if pending:raise base.Interrupted(pending[0])
      if sum(os.fstat(fd).st_size for fd in logs)>base.MAX_PRIVATE_LOG:raise base.Failed('output-budget')
      remaining=deadline-time.monotonic()
      if remaining<=0:raise base.Failed('timeout')
      try:proc.wait(timeout=min(.1,remaining));break
      except subprocess.TimeoutExpired:pass
     if proc.returncode!=0:raise base.Failed('exit')
     state=base.group_state(proc.pid)
     if state!='empty':raise base.Failed('background-child' if state=='present' else 'group-unconfirmed')
     if time.monotonic()>=deadline:raise base.Failed('timeout')
    finally:
     if proc is not None and (proc.poll() is None or base.group_state(proc.pid)!='empty'):
      if not base.stop_owned(proc):raise base.Failed('cleanup')
  except BaseException as error:
   failure=error;code='cancelled' if isinstance(error,(base.Interrupted,KeyboardInterrupt,SystemExit)) else error.code if isinstance(error,base.Failed) else 'launch' if proc is None else 'internal'
  summaries=[];metadata=[]
  try:
   hashed=[base.log_summary(fd,phasefd,n) for fd,n in zip(logs,('stdout.log','stderr.log'))];summaries=[x[0] for x in hashed];metadata=[x[1] for x in hashed]
  except BaseException:failure=base.Rejected();code='private-log'
  def terminal_check():
   nonlocal failure,code
   if not base.namespace_stable(root,rootfd,phase,phasefd):failure=base.Rejected();code='namespace'
   if metadata and not base.logs_stable(logs,phasefd,metadata):failure=base.Rejected();code='private-log'
   if sum(x['bytes'] for x in summaries)>base.MAX_PRIVATE_LOG:failure=base.Rejected();code='output-budget'
   if time.monotonic()>=deadline:failure=base.Rejected();code='timeout'
  terminal_check();state=base.group_state(proc.pid) if proc else 'not-started';exited=proc is not None and proc.poll() is not None
  if state=='unconfirmed':failure=base.Rejected();code='group-unconfirmed'
  if not(state=='empty' and exited) and failure is None:failure=base.Rejected();code='cleanup'
  receipt.update(status='PASS' if failure is None else 'FAIL',failure_code=code,exit_code=proc.returncode if proc else None,process_exited=exited,process_group_empty=state=='empty',group_observation=state,finished_at=base.utc(),duration_monotonic_seconds=time.monotonic()-start,stdout=summaries[0] if summaries else None,stderr=summaries[1] if summaries else None)
  base.write_receipt(phasefd,receipt);terminal_check()
  if failure is not None:
   receipt.update(status='FAIL',failure_code=code);base.write_receipt(phasefd,receipt)
   if isinstance(failure,(base.Interrupted,KeyboardInterrupt,SystemExit)):raise failure
   raise base.Rejected()
  return receipt
 finally:
  for fd in logs:os.close(fd)
  if phasefd is not None:os.close(phasefd)
  if rootfd is not None:os.close(rootfd)


def run(root,phase,argv,*,binding,env,timeout_seconds):
 # The outer deferred handler covers hashes and final publication as well as
 # child custody. Late cancellation preserves the real child exit in FAIL.
 result=None;error=None
 with base.cancellation_custody() as pending:
  try:result=_run(root,phase,argv,binding=binding,env=env,timeout_seconds=timeout_seconds)
  except BaseException as caught:error=caught
  if pending:
   p=Path(root)/phase/'receipt.json'
   if p.exists():
    with p.open('rb') as source:receipt=json.load(source)
    receipt.update(status='FAIL',failure_code='cancelled',finished_at=base.utc())
    fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:base.write_receipt(fd,receipt)
    finally:os.close(fd)
   error=base.Interrupted(pending[0])
  if error is not None:raise error
 return result
