"""Fixed, read-only private-result projection; no command or live-admission API."""
import os,stat
from pathlib import Path
from instrumentation import STAGES,ERRORS,IDENTITY,PREDICATES as SAFE_PREDICATES,PREP_STAGES,PREP_SUBSTAGES,PREP_CATEGORIES,SOURCE_LIMITS,GUARD_SITES,PREPARE_SHA,validate_package_file_context,validate_managed_service_context
from prepare_custody import INSTRUMENTATION_SHA
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

def early_observation(root,record,bound,seals):
    value=parse(checked_read(root,'early-preparation.json',record,seals))
    need(type(value) is dict and set(value)=={'schema','phase','pid','process_group','context','invocation_id','nonce','source_sha256','stage','substage','status','terminal','last_command'})
    need(value['schema']=='source26-early-preparation-v1' and value['phase']=='PREP' and value['context']==bound)
    need(value['invocation_id']==value['nonce']==record['invocation_id'] and all(c in '0123456789abcdef' for c in value['nonce']))
    need(type(value['pid']) is int and value['pid']==record['pid'] and type(value['process_group']) is int and value['process_group']==record['process_group'])
    need(value['source_sha256']==dict(prepare=PREPARE_SHA,helper=HELPER,wrapper=INSTRUMENTATION_SHA))
    need(value['stage'] in PREP_STAGES and value['substage'] in PREP_SUBSTAGES and value['status'] in ('STARTED','PASS','FAIL'))
    terminal=value['terminal'];need(type(terminal) is dict and set(terminal)=={'source_unit','source_site','error_type','predicate'})
    unit=terminal['source_unit'];site=terminal['source_site']
    need(unit in SOURCE_LIMITS and type(site) is int and 0<=site<=SOURCE_LIMITS[unit] and terminal['error_type'] in ERRORS)
    predicates={'UNKNOWN'}|{unit+'_GUARD_'+str(line) for unit,lines in GUARD_SITES.items() for line in lines}
    need(terminal['predicate'] in predicates)
    if terminal['predicate']!='UNKNOWN':need(terminal['predicate']==unit+'_GUARD_'+str(site) and terminal['error_type']=='VALUE_ERROR')
    command=value['last_command']
    if command is not None:
        need(type(command) is dict and set(command)=={'category','source_unit','source_site','caller_site','exit_code','completed','leader_reaped'})
        need(command['category'] in PREP_CATEGORIES and command['source_unit'] in SOURCE_LIMITS)
        need(type(command['source_site']) is int and 0<=command['source_site']<=SOURCE_LIMITS[command['source_unit']] and type(command['caller_site']) is int and 0<=command['caller_site']<=SOURCE_LIMITS['PREPARE'])
        need(type(command['completed']) is bool and (command['leader_reaped'] is True if command['completed'] else command['leader_reaped'] is None))
        need(type(command['exit_code']) is int and -2**31<=command['exit_code']<2**31 if command['completed'] else command['exit_code'] is None)
    return value

def project(expected,record,private_root,output):
    bound=context(expected);root=Path(private_root);seals=[]
    safe=dict(schema='source26-maintenance-diagnostic-v1',diagnostic_only=True,claims_M_success=False,
       input_binding='INVALID',observation='UNKNOWN',expected_context=bound,observed_identity=None,
       invocation_drain='UNKNOWN',phase='UNKNOWN',predicate='UNKNOWN',guest_exit_code=None,prepare_exit_code=None,M_status=None,remote_exit_code=None,remote_action=None,guest_stage='UNKNOWN',guest_error_type='OTHER',guest_site=0,preparation_binding='MISSING',preparation=None,package_file_context=None,managed_service_context=None)
    try:
        verify_drain(record,bound,root);safe['invocation_drain']='EMPTY'
        if 'early-preparation.json' in record.get('files',{}):
            try:
                early=early_observation(root,record,bound,seals)
                safe.update(preparation_binding='MATCHED',preparation=early,prepare_exit_code=record['exit_code'])
            except Exception:safe.update(preparation_binding='INVALID',preparation=None)
        spec_raw=checked_read(root,'spec.json',record,seals);need(record.get('spec_sha256')==digest(spec_raw))
        spec=parse(spec_raw);need(type(spec) is dict and spec.get('operation')==MODE and all(spec.get(k)==bound[k] for k in ('source_vm','run_token','runtime_commit','qualifier_commit','maintenance_helper_sha256')))
        need(spec.get('evidence_directory')==str(root/'drill') and spec.get('baseline_directory')==str(root/'baseline'))
        result=parse(checked_read(root,'drill/result.json',record,seals));verify_result(result,bound)
        safe.update(input_binding='MATCHED',observation='CURRENT_BOUND_RESULT',observed_identity=bound,prepare_exit_code=record['exit_code'],M_status=result['status'])
        phase=HOST_PHASE.get(result.get('diagnostic'),'UNKNOWN');safe['phase']=phase
        if phase!='UNKNOWN':safe['predicate']=companion_observation(root,record,phase,seals)
        available=record.get('files',{})
        name='drill/diagnostic-run.json' if 'drill/diagnostic-run.json' in available else 'drill/diagnostic-stage.json' if phase=='STAGE' and 'drill/diagnostic-stage.json' in available else None
        if name is not None:
            need(not (phase=='STAGE' and name.endswith('diagnostic-run.json')))
            action='run' if name.endswith('diagnostic-run.json') else 'stage'
            execution=parse(checked_read(root,name,record,seals))
            need(type(execution) is dict and set(execution)=={'schema','action',*IDENTITY,'remote_exit_code','guest'})
            need(execution['schema']=='source26-remote-execution-v1' and execution['action']==action and all(execution[k]==bound[k] for k in IDENTITY))
            need(type(execution['remote_exit_code']) is int and -2**31<=execution['remote_exit_code']<2**31)
            safe.update(remote_action=action,remote_exit_code=execution['remote_exit_code'])
            guest=execution['guest']
            if guest is not None:
                keys={'stage','site','predicate','error_type','exit_code'}
                need(type(guest) is dict and keys<=set(guest)<=keys|{'package_file_context','managed_service_context'})
                need(guest['stage'] in STAGES and guest['error_type'] in ERRORS and guest['predicate'] in {'UNKNOWN',*SAFE_PREDICATES.values()} and type(guest['site']) is int and 0<=guest['site']<=1044)
                need(guest['exit_code'] is None or type(guest['exit_code']) is int and -2**31<=guest['exit_code']<2**31)
                need(guest['exit_code'] is None or guest['exit_code']==execution['remote_exit_code'])
                selected=validate_package_file_context(guest.get('package_file_context'),guest['error_type'])
                services=validate_managed_service_context(guest.get('managed_service_context'),guest['error_type'],guest['predicate'])
                need(selected is None or services is None)
                safe.update(guest_exit_code=guest['exit_code'],guest_stage=guest['stage'],guest_error_type=guest['error_type'],guest_site=guest['site'],predicate=guest['predicate'],package_file_context=selected,managed_service_context=services)
        need(stable(seals))
    except Exception:
        safe.update(input_binding='INVALID',observation='UNKNOWN',observed_identity=None,phase='UNKNOWN',predicate='UNKNOWN',prepare_exit_code=None,M_status=None,remote_exit_code=None,remote_action=None,guest_exit_code=None,guest_stage='UNKNOWN',guest_error_type='OTHER',guest_site=0,package_file_context=None,managed_service_context=None)
    if safe['preparation_binding']=='MATCHED' and safe['prepare_exit_code'] is None:safe['prepare_exit_code']=record['exit_code']
    fd=exclusive_output(output,safe)
    try:
        if not stable(seals):
            safe.update(preparation_binding='INVALID',preparation=None)
            safe.update(input_binding='INVALID',observation='UNKNOWN',observed_identity=None,phase='UNKNOWN',predicate='UNKNOWN',prepare_exit_code=None,M_status=None,remote_exit_code=None,remote_action=None,guest_exit_code=None,guest_stage='UNKNOWN',guest_error_type='OTHER',guest_site=0,package_file_context=None,managed_service_context=None)
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
