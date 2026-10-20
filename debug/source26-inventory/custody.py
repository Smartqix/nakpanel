"""Fixed inventory-only phases using the reviewed owned-command custody loop."""
import errno,os,signal,stat,subprocess,sys,threading,time,uuid
from datetime import datetime,timezone
from pathlib import Path
from contract import SCOPE,PINS,Rejected,need,context,parse,digest,read_private,root_identity,canonical,validate_runtime_files,pinned_source
_BASE=Path(__file__).with_name('custody_base.py')
need(digest(_BASE.read_bytes())=='bbe68b69d270aae3a253c2848dee8e4145eb546454d767e00ab2d8392e11b8b3')
import custody_base as base
LIMITS={'install':6000,'inventory':1200,'cleanup':300}
FILES=('observation.json','result.json','identity.json')
CLEANUP_SHELL='set -euo pipefail; source "$1"; expected="$2"; [[ "${NAKPANEL_CI_OWNERSHIP_READY:-}" == 1 && "$NAKPANEL_RUN_TOKEN" == "$expected" ]]; status=0; for record in "$NAKPANEL_OWNERSHIP_DIR/$expected"/nakpanel-*; do [[ -f "$record" && "$record" != *.image.json ]] || continue; destroy_owned_vm "$(basename "$record")" "$expected" || status=1; done; exit "$status"'
def fixed_argv(phase,application,private_root,bound):
    bound=context(bound);app=Path(application);private=Path(private_root);need(app.is_absolute() and app.resolve()==app and phase in LIMITS)
    pins=validate_runtime_files()
    if phase=='install':
        leaf=app/'deploy/multipass/current-install-verify.sh';pinned_source(leaf,PINS['source26_inputs']['deploy/multipass/current-install-verify.sh']['sha256'])
        return ['bash',str(leaf)]
    if phase=='inventory':
        leaf=Path(__file__).resolve().with_name('driver.py');pinned_source(leaf,pins['driver.py'])
        return [str(Path(sys.executable).resolve()),'-I','-B',str(leaf),str(private)]
    leaf=app/'deploy/multipass/common.sh';pinned_source(leaf,PINS['source26_inputs']['deploy/multipass/common.sh']['sha256'])
    return ['bash','-c',CLEANUP_SHELL,'_',str(leaf),bound['run_token']]

def capture(root,record):
    if not Path(root).exists():return
    try:
        record['private_root_identity']=root_identity(root)
        for relative in FILES:
            try:raw,_=read_private(root,relative,65536)
            except Rejected:continue
            except OSError as error:
                if error.errno not in (errno.ENOENT,errno.ENOTDIR):raise
                continue
            record['files'][relative]=dict(bytes=len(raw),sha256=digest(raw))
    except Exception:record['capture_state']='INVALID'

def run_owned(phase,application,private_root,custody_root,expected,env):
    need(threading.current_thread() is threading.main_thread())
    bound=context(expected);private_root=Path(private_root);custody_root=Path(custody_root)
    need(phase in LIMITS and private_root.is_absolute() and private_root.parent.resolve()==private_root.parent and not private_root.exists() and not private_root.is_symlink())
    root_identity(private_root.parent);root_identity(custody_root)
    need(type(env) is dict and all(type(k) is str and type(v) is str and '\0' not in k+v for k,v in env.items()))
    need(env.get('NAKPANEL_RUN_TOKEN')==bound['run_token'] and env.get('NAKPANEL_MULTIPASS_VM')==bound['source_vm'] and env.get('NAKPANEL_MULTIPASS_IMAGE')=='26.04' and env.get('NAKPANEL_MULTIPASS_ARCH')=='amd64' and env.get('NAKPANEL_QUALIFICATION_PHP_PROVIDER')=='sury')
    if phase=='install':need(env.get('NAKPANEL_INSTALL_ONLY')=='1' and env.get('NAKPANEL_RELEASE_ALLOW_DEVELOPMENT')=='1')
    argv=fixed_argv(phase,application,private_root,bound)
    clean={k:v for k,v in env.items() if not k.startswith('PYTHON') and k!='__PYVENV_LAUNCHER__'}
    budget=LIMITS[phase]
    rootfd=phasefd=None;logs=[];proc=None;record=None
    try:
        rootfd=os.open(custody_root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        os.mkdir(phase,mode=0o700,dir_fd=rootfd)
        phasefd=os.open(phase,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=rootfd)
        for name in ('stdout.log','stderr.log'):logs.append(os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=phasefd))
        record=dict(schema='source26-inventory-command-custody-v1',scope=SCOPE,phase=phase,status='STARTED',finished=False,failure_code=None,invocation_id=uuid.uuid4().hex,
          source_binding=bound,private_root=str(private_root),private_root_identity=None,command_sha256=digest(canonical(argv)),
          cwd=str(application),pid=None,process_group=None,exit_code=None,process_exited=False,
          group_observation='not-started',started_at=datetime.now(timezone.utc).isoformat(),finished_at=None,
          claims_M_success=False,claims_full17=False,files={})
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
                        remain=budget-(time.monotonic()-start)
                        if remain<=0:raise base.Failed('timeout')
                        try:proc.wait(timeout=min(.1,remain));break
                        except subprocess.TimeoutExpired:pass
                    if proc.returncode!=0:raise base.Failed('exit')
                    state=base.group_state(proc.pid)
                    if state!='empty':raise base.Failed('group-unconfirmed' if state=='unconfirmed' else 'background-child')
                    if time.monotonic()-start>=budget:raise base.Failed('timeout')
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
                    need(base.namespace_stable(custody_root,rootfd,phase,phasefd))
                    hashed=[base.log_summary(fd,phasefd,name) for fd,name in zip(logs,('stdout.log','stderr.log'))]
                    summaries=[x[0] for x in hashed];metadata=[x[1] for x in hashed]
                    need(base.logs_stable(logs,phasefd,metadata))
                except Exception:failure=Rejected();code='private-log'
                if failure is None and sum(value['bytes'] for value in summaries)>base.MAX_PRIVATE_LOG:
                    failure=Rejected();code='output-budget'
                if state=='empty' and exited:capture(private_root,record)
                if pending:failure=base.Interrupted(pending[0]);code='cancelled'
                if failure is None and time.monotonic()-start>=budget:
                    failure=Rejected();code='timeout'
                record.update(status='PASS' if failure is None else 'FAIL',finished=True,failure_code=code,
                  finished_at=datetime.now(timezone.utc).isoformat(),duration_monotonic_seconds=time.monotonic()-start,
                  exit_code=proc.returncode if proc is not None else None,process_exited=exited,group_observation=state,
                  stdout=summaries[0] if summaries else None,stderr=summaries[1] if summaries else None)
                base.write_receipt(phasefd,record)
                if not base.namespace_stable(custody_root,rootfd,phase,phasefd) or (metadata and not base.logs_stable(logs,phasefd,metadata)):
                    failure=Rejected();record.update(status='FAIL',failure_code='private-log');base.write_receipt(phasefd,record)
                if failure is None and time.monotonic()-start>=budget:
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
