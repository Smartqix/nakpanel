"""Fixed, read-only private-result projection; no command or live-admission API."""
import os,stat
from pathlib import Path
from contract import SOURCE,HELPER,MODE,FILES,Rejected,need,context,parse,digest,read_private,root_identity,stable,exclusive_output,canonical
HOST_PHASE={
 'guest stage failed; inspect retained stdout/stderr and cold snapshot':'STAGE',
 'private guest staging was not confirmed':'STAGE',
 'guest run failed; inspect retained stdout/stderr and cold snapshot':'RUN',
 'actual same-version failed-configuration recovery did not complete':'RUN'}
PREDICATES=parse((Path(__file__).parent/'known-predicates.json').read_bytes())
RESULT_REQUIRED={'schema','operation','source_vm','run_token','runtime_commit','qualifier_commit','maintenance_helper_sha256','genuine_version_advance','apt_version_rollback','application_rollback','status','guest_state','reboots'}
RESULT_OPTIONAL={'error_type','diagnostic','stop_error_type','same_version_delivery','failed_configuration_recovery','two_reboots_verified','roundcube_send_read_steps'}

def verify_result(value,bound):
    need(type(value) is dict and RESULT_REQUIRED<=set(value)<=RESULT_REQUIRED|RESULT_OPTIONAL)
    need(value['schema']=='nakpanel-sury-maintenance-result-v1' and value['operation']==MODE)
    need(all(type(value[k]) is str and value[k]==bound[k] for k in ('source_vm','run_token','runtime_commit','qualifier_commit','maintenance_helper_sha256')))
    need(value['status'] in ('PASS','FAIL') and type(value['guest_state']) is str and value['guest_state'] in ('identity_verified','unchanged_before_guest_write','failure_stop_unconfirmed','stopped_after_failure','running_revalidated'))
    need(all(value[k] is False for k in ('genuine_version_advance','apt_version_rollback','application_rollback')))
    need(type(value['reboots']) is list and len(value['reboots'])<=2 and all(type(x) is str and len(x)<=64 for x in value['reboots']))
    for k in ('diagnostic','error_type','stop_error_type'):
        if k in value:need(type(value[k]) is str and len(value[k])<=16384)
    for k in ('same_version_delivery','failed_configuration_recovery','two_reboots_verified'):
        if k in value:need(type(value[k]) is bool)
    if 'roundcube_send_read_steps' in value:need(type(value['roundcube_send_read_steps']) is int and 0<=value['roundcube_send_read_steps']<=3)
    if value['status']=='PASS':
        need(value['guest_state']=='running_revalidated' and all(value.get(k) is True for k in ('same_version_delivery','failed_configuration_recovery','two_reboots_verified')) and type(value.get('roundcube_send_read_steps')) is int and value['roundcube_send_read_steps']==3 and len(value['reboots'])==2 and len(set(value['reboots']))==2)

def verify_drain(record,bound,root):
    need(type(record) is dict and record.get('schema')=='source26-prepare-custody-v1' and record.get('source_binding')==bound)
    need(record.get('status') in ('PASS','FAIL') and record.get('finished') is True and record.get('process_exited') is True and record.get('group_observation')=='empty')
    need(type(record.get('pid')) is int and record['pid']>1 and type(record.get('process_group')) is int and record['process_group']==record['pid'])
    need(type(record.get('exit_code')) is int and type(record.get('invocation_id')) is str and len(record['invocation_id'])==32)
    need(record.get('private_root')==str(root) and record.get('private_root_identity')==root_identity(root))

def checked_read(root,relative,record,seals,limit=65536):
    raw,extra=read_private(root,relative,limit);expected=record.get('files',{}).get(relative)
    need(expected==dict(bytes=len(raw),sha256=digest(raw)))
    seals.extend(extra);return raw

def companion_observation(root,record,phase,seals):
    name='drill/'+('stage' if phase=='STAGE' else 'run')+'-stage.stderr'
    if name not in record.get('files',{}):return 'UNKNOWN'
    raw=checked_read(root,name,record,seals)
    for message,code in PREDICATES.items():
        if raw==('maintenance guest failed: '+message+'\n').encode():return code
    return 'UNKNOWN'

def project(expected,record,private_root,output):
    bound=context(expected);root=Path(private_root);seals=[]
    safe=dict(schema='source26-maintenance-diagnostic-v1',diagnostic_only=True,claims_M_success=False,
       input_binding='INVALID',observation='UNKNOWN',expected_context=bound,observed_identity=None,
       invocation_drain='UNKNOWN',phase='UNKNOWN',predicate='UNKNOWN',guest_exit_code=None,prepare_exit_code=None,M_status=None)
    try:
        verify_drain(record,bound,root);safe['invocation_drain']='EMPTY'
        spec_raw=checked_read(root,'spec.json',record,seals);need(record.get('spec_sha256')==digest(spec_raw))
        spec=parse(spec_raw);need(type(spec) is dict and spec.get('operation')==MODE and all(spec.get(k)==bound[k] for k in ('source_vm','run_token','runtime_commit','qualifier_commit','maintenance_helper_sha256')))
        need(spec.get('evidence_directory')==str(root/'drill') and spec.get('baseline_directory')==str(root/'baseline'))
        result=parse(checked_read(root,'drill/result.json',record,seals));verify_result(result,bound)
        safe.update(input_binding='MATCHED',observation='CURRENT_BOUND_RESULT',observed_identity=bound,prepare_exit_code=record['exit_code'],M_status=result['status'])
        phase=HOST_PHASE.get(result.get('diagnostic'),'UNKNOWN');safe['phase']=phase
        if phase!='UNKNOWN':safe['predicate']=companion_observation(root,record,phase,seals)
        need(stable(seals))
    except Exception:
        safe.update(input_binding='INVALID',observation='UNKNOWN',observed_identity=None,phase='UNKNOWN',predicate='UNKNOWN',prepare_exit_code=None,M_status=None)
    fd=exclusive_output(output,safe)
    try:
        if not stable(seals):
            safe.update(input_binding='INVALID',observation='UNKNOWN',observed_identity=None,phase='UNKNOWN',predicate='UNKNOWN',prepare_exit_code=None,M_status=None)
            os.lseek(fd,0,os.SEEK_SET);os.ftruncate(fd,0);os.write(fd,canonical(safe));os.fsync(fd)
        info=os.fstat(fd);named=Path(output).lstat()
        from contract import meta,directory
        directory(Path(output).parent)
        need(meta(info)==meta(named) and stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==0o600 and info.st_uid==os.getuid() and info.st_nlink==1)
        os.lseek(fd,0,os.SEEK_SET);need(os.read(fd,len(canonical(safe))+1)==canonical(safe))
        need(meta(os.fstat(fd))==meta(info) and meta(Path(output).lstat())==meta(info))
        return safe
    finally:os.close(fd)
if __name__=='__main__':raise SystemExit(2)
