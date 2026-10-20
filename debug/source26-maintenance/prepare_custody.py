"""One fixed prepare command; no CLI, retry, live admission or VM cleanup."""
import hashlib,os,re,signal,stat,subprocess,sys,threading,time,uuid
from datetime import datetime,timezone
from pathlib import Path
from contract import SOURCE,FILES,Rejected,need,context,parse,digest,read_private,root_identity,canonical
# Import exactly the separately reviewed low-level implementation. No day0 run_once call.
_BASE=Path(__file__).with_name('custody_base.py')
need(digest(_BASE.read_bytes())=='bbe68b69d270aae3a253c2848dee8e4145eb546454d767e00ab2d8392e11b8b3')
import custody_base as base
PREPARE_SCRIPT_SHA='180c2da2874de86b2e03741e334a7faba80c7afb080089d12d38117624e32614'
PREPARE_SECONDS=6000
GATES={'bundle','fresh-install','inventory','real-upgrade','phase28','valkey-platform','security','phase29','phase30','phase31','phase32','internal-tools','mail-workspace','phase33','phase34','domain-removal','release-artifacts'}

def validate_canonical(execution,report,bound):
    need(type(execution) is dict and execution.get('schema')=='nakpanel-canonical-execution-v1')
    wanted={k:bound[k] for k in ('source_vm','run_token')};wanted.update(release='26.04',architecture='amd64',profile='ubuntu-26.04-sury',php_provider='sury')
    need(execution.get('source_binding')==wanted and execution.get('runtime_commit')==SOURCE)
    need(execution.get('status')=='PASS' and execution.get('success') is True and execution.get('process_exited') is True and execution.get('process_group_empty') is True)
    need(type(execution.get('exit_code')) is int and execution['exit_code']==0 and type(execution.get('pid')) is int and execution['pid']>1 and type(execution.get('process_group')) is int and execution['process_group']==execution['pid'])
    mapping=execution.get('qualifier_source_sha256');need(type(mapping) is dict and bool(mapping) and all(type(k) is str and type(v) is str and re.fullmatch('[a-f0-9]{64}',v) for k,v in mapping.items()))
    raw=report;value=parse(raw)
    need(execution.get('qualification_report_sha256')==digest(raw) and type(value) is dict and value.get('schema_version')==1 and type(value.get('schema_version')) is int)
    need(value.get('qualification_passed') is True and value.get('pending_gates')==[] and value.get('full_php_parity') is True and value.get('php_contract')==['8.5','8.4','8.3'])
    need(all(value.get(k)==v for k,v in wanted.items()))
    gates=value.get('gates');need(type(gates) is list and len(gates)==17 and all(type(g) is dict and type(g.get('name')) is str for g in gates) and {g['name'] for g in gates}==GATES)
    need(all(g.get('status')=='PASS' and type(g.get('exit_code')) is int and g['exit_code']==0 for g in gates))
    return execution['pid']

def fixed_argv(application,private_root,execution):
    app=Path(application);need(app.is_absolute() and app.resolve()==app)
    info=app.lstat();need(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o022)
    leaf=app/'deploy/multipass/sury-maintenance-prepare.py';need(leaf.resolve()==leaf)
    info=leaf.lstat();need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o022 and info.st_nlink==1 and digest(leaf.read_bytes())==PREPARE_SCRIPT_SHA)
    return [str(Path(sys.executable).resolve()),'-I','-B',str(leaf),'prepare','--execution-receipt',str(execution),'--private-root',str(private_root)]

def capture(root,record):
    if not Path(root).exists():return
    try:
        record['private_root_identity']=root_identity(root)
        for relative in FILES:
            try:raw,_=read_private(root,relative,65536)
            except Rejected:continue
            record['files'][relative]=dict(bytes=len(raw),sha256=digest(raw))
        record['spec_sha256']=record['files'].get('spec.json',{}).get('sha256')
    except Exception:record['capture_state']='INVALID'

def run_prepare(application,private_root,execution_receipt,custody_root,expected,env):
    need(threading.current_thread() is threading.main_thread())
    bound=context(expected);private_root=Path(private_root);execution_receipt=Path(execution_receipt);custody_root=Path(custody_root)
    need(private_root.is_absolute() and private_root.parent.resolve()==private_root.parent and not private_root.exists() and not private_root.is_symlink())
    root_identity(private_root.parent);root_identity(custody_root)
    need(type(env) is dict and all(type(k) is str and type(v) is str and '\0' not in k+v for k,v in env.items()))
    raw,_=read_private(execution_receipt.parent,execution_receipt.name)
    report,_=read_private(Path(env['NAKPANEL_CELL_REPORT_DIR']),'report.json')
    canonical_pid=validate_canonical(parse(raw),report,bound)
    need(base.group_state(canonical_pid)=='empty')
    argv=fixed_argv(application,private_root,execution_receipt)
    clean={k:v for k,v in env.items() if not k.startswith('PYTHON') and k!='__PYVENV_LAUNCHER__'}
    need(0<PREPARE_SECONDS<=6000)
    rootfd=phasefd=None;logs=[];proc=None;record=None
    try:
        rootfd=os.open(custody_root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        os.mkdir('prepare',mode=0o700,dir_fd=rootfd)
        phasefd=os.open('prepare',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=rootfd)
        for name in ('stdout.log','stderr.log'):logs.append(os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=phasefd))
        record=dict(schema='source26-prepare-custody-v1',status='STARTED',finished=False,failure_code=None,invocation_id=uuid.uuid4().hex,
          source_binding=bound,private_root=str(private_root),private_root_identity=None,command_sha256=digest(canonical(argv)),
          canonical_execution_sha256=digest(raw),cwd=str(application),pid=None,process_group=None,exit_code=None,process_exited=False,
          group_observation='not-started',started_at=datetime.now(timezone.utc).isoformat(),finished_at=None,
          claims_M_success=False,spec_sha256=None,files={})
        base.write_receipt(phasefd,record);start=time.monotonic();failure=None;code=None
        try:
            with base.cancellation_custody() as pending:
                try:
                    if pending:raise base.Interrupted(pending[0])
                    proc=subprocess.Popen(argv,cwd=str(application),env=clean,stdin=subprocess.DEVNULL,stdout=logs[0],stderr=logs[1],start_new_session=True)
                    record.update(pid=proc.pid,process_group=proc.pid);base.write_receipt(phasefd,record)
                    while True:
                        if pending:raise base.Interrupted(pending[0])
                        if sum(os.fstat(fd).st_size for fd in logs)>base.MAX_PRIVATE_LOG:raise base.Failed('output-budget')
                        remain=PREPARE_SECONDS-(time.monotonic()-start)
                        if remain<=0:raise base.Failed('timeout')
                        try:proc.wait(timeout=min(.1,remain));break
                        except subprocess.TimeoutExpired:pass
                    if proc.returncode!=0:raise base.Failed('exit')
                    state=base.group_state(proc.pid)
                    if state!='empty':raise base.Failed('group-unconfirmed' if state=='unconfirmed' else 'background-child')
                    if time.monotonic()-start>=PREPARE_SECONDS:raise base.Failed('timeout')
                except BaseException as error:
                    failure=error;code='cancelled' if isinstance(error,(base.Interrupted,KeyboardInterrupt,SystemExit)) else error.code if isinstance(error,base.Failed) else 'launch' if proc is None else 'internal'
                finally:
                    if proc is not None and (proc.poll() is None or base.group_state(proc.pid)!='empty'):
                        if not base.stop_owned(proc):failure=Rejected();code='cleanup'
                state=base.group_state(proc.pid) if proc is not None else 'not-started'
                exited=proc is not None and proc.poll() is not None
                if state!='empty' or not exited:failure=Rejected();code='group-unconfirmed' if state=='unconfirmed' else 'cleanup'
                summaries=[];metadata=[]
                try:
                    need(base.namespace_stable(custody_root,rootfd,'prepare',phasefd))
                    hashed=[base.log_summary(fd,phasefd,name) for fd,name in zip(logs,('stdout.log','stderr.log'))]
                    summaries=[x[0] for x in hashed];metadata=[x[1] for x in hashed]
                    need(base.logs_stable(logs,phasefd,metadata))
                except Exception:failure=Rejected();code='private-log'
                if failure is None and sum(value['bytes'] for value in summaries)>base.MAX_PRIVATE_LOG:
                    failure=Rejected();code='output-budget'
                if state=='empty' and exited:capture(private_root,record)
                if pending:failure=base.Interrupted(pending[0]);code='cancelled'
                if failure is None and time.monotonic()-start>=PREPARE_SECONDS:
                    failure=Rejected();code='timeout'
                record.update(status='PASS' if failure is None else 'FAIL',finished=True,failure_code=code,
                  finished_at=datetime.now(timezone.utc).isoformat(),duration_monotonic_seconds=time.monotonic()-start,
                  exit_code=proc.returncode if proc is not None else None,process_exited=exited,group_observation=state,
                  stdout=summaries[0] if summaries else None,stderr=summaries[1] if summaries else None)
                base.write_receipt(phasefd,record)
                if not base.namespace_stable(custody_root,rootfd,'prepare',phasefd) or (metadata and not base.logs_stable(logs,phasefd,metadata)):
                    failure=Rejected();record.update(status='FAIL',failure_code='private-log');base.write_receipt(phasefd,record)
                if failure is None and time.monotonic()-start>=PREPARE_SECONDS:
                    failure=Rejected();record.update(status='FAIL',failure_code='timeout',finished_at=datetime.now(timezone.utc).isoformat(),duration_monotonic_seconds=time.monotonic()-start);base.write_receipt(phasefd,record)
                if pending:
                    failure=base.Interrupted(pending[0]);record.update(status='FAIL',failure_code='cancelled');base.write_receipt(phasefd,record)
                if failure is not None:raise failure
                return record
        except BaseException as error:
            if record is not None and isinstance(error,(base.Interrupted,KeyboardInterrupt,SystemExit)):
                record.update(status='FAIL',finished=True,failure_code='cancelled');base.write_receipt(phasefd,record)
            if isinstance(error,(base.Interrupted,KeyboardInterrupt,SystemExit)):raise
            raise Rejected() from None
    except (base.Interrupted,KeyboardInterrupt,SystemExit):raise
    except Exception:raise Rejected() from None
    finally:
        for fd in logs:os.close(fd)
        if phasefd is not None:os.close(phasefd)
        if rootfd is not None:os.close(rootfd)
if __name__=='__main__':raise SystemExit(2)
