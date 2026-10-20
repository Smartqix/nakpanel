"""Only inventory diagnostic authority. No canonical17 or maintenance credit."""
import os,re
from pathlib import Path
from contract import *
import custody
from observer import ERRORS,CATEGORIES
from driver import identity_program,validate_identity,guard_sites

def command_binding(record,phase,bound,application,private_root,live=True):
    need(type(record) is dict and record.get('schema')=='source26-inventory-command-custody-v1' and record.get('scope')==SCOPE and record.get('phase')==phase)
    need(record.get('source_binding')==context(bound) and record.get('finished') is True and record.get('process_exited') is True and record.get('group_observation')=='empty')
    need(record.get('claims_M_success') is False and record.get('claims_full17') is False and record.get('status') in ('PASS','FAIL'))
    need(type(record.get('pid')) is int and record['pid']>1 and record.get('process_group')==record['pid'])
    need(type(record.get('exit_code')) is int and -255<=record['exit_code']<=255)
    need(type(record.get('invocation_id')) is str and re.fullmatch('[0-9a-f]{32}',record['invocation_id']))
    need(record.get('private_root')==str(private_root) and record.get('cwd')==str(application))
    need(record.get('command_sha256')==digest(canonical(custody.fixed_argv(phase,application,private_root,bound))))
    if live:need(custody.base.group_state(record['pid'])=='empty')
    return record

def site(value,guards,driver_lines):
    need(type(value) is dict and set(value)=={'source_unit','source_site','error_type','predicate'})
    unit=value['source_unit'];line=value['source_site'];kind=value['error_type'];predicate=value['predicate']
    need(unit in ('UNKNOWN','PREPARE','HELPER','DRIVER') and type(line) is int and kind in ERRORS)
    need((unit=='UNKNOWN' and line==0) or (unit=='PREPARE' and 1<=line<=700) or (unit=='HELPER' and 1<=line<=1039) or (unit=='DRIVER' and 1<=line<=driver_lines))
    need(predicate=='UNKNOWN' or (unit in guards and line in guards[unit] and predicate==unit+'_GUARD_'+str(line) and kind=='VALUE_ERROR'))

def observation(value,record,bound,application):
    keys={'schema','scope','context','phase','nonce','pid','process_group','status','step','source_sha256','guest_source_sha256','installed_identity','block_completed','terminal','last_command','claims_full17','claims_M_success'}
    need(type(value) is dict and set(value)==keys and value['schema']=='source26-inventory-observation-v1' and value['scope']==SCOPE and value['context']==bound and value['phase']=='inventory')
    need(value['nonce']==record['invocation_id'] and value['pid']==record['pid'] and value['process_group']==record['process_group'])
    need(value['claims_full17'] is False and value['claims_M_success'] is False and value['status'] in ('STARTED','PASS','FAIL') and value['step'] in ('IDENTITY','INVENTORY_BLOCK'))
    pins=validate_runtime_files();expected=dict(prepare=PREPARE,helper=HELPER,driver=pins['driver.py'],observer=pins['observer.py'],inventory_ast=pins['inventory_ast'])
    need(value['source_sha256']==expected)
    helper=pinned_source(Path(application)/'deploy/multipass/sury-maintenance-drill.py',HELPER)
    prepare=pinned_source(Path(application)/'deploy/multipass/sury-maintenance-prepare.py',PREPARE)
    guards=guard_sites(prepare,helper);site(value['terminal'],guards,len((HERE/'driver.py').read_text().splitlines()))
    guest_sha=value['guest_source_sha256']
    if guest_sha is not None:need(guest_sha==digest(identity_program(helper.decode(),bound,record['invocation_id']).encode()))
    identity=value['installed_identity']
    if identity is not None:
        need(guest_sha is not None);validate_identity(identity,bound,record['invocation_id'],identity.get('exit_code'))
        if identity['predicate']!='UNKNOWN':need(identity['source_site'] in guards['HELPER'] and identity['error_type']=='VALUE_ERROR')
    last=value['last_command']
    if last is not None:
        need(type(last) is dict and set(last)=={'category','source_unit','source_site','caller_site','exit_code','completed','leader_reaped'})
        need(last['category'] in CATEGORIES and last['source_unit'] in ('PREPARE','HELPER','DRIVER','UNKNOWN'))
        site(dict(source_unit=last['source_unit'],source_site=last['source_site'],error_type='NONE',predicate='UNKNOWN'),guards,len((HERE/'driver.py').read_text().splitlines()))
        need(type(last['caller_site']) is int and 0<=last['caller_site']<=700)
        if last['completed'] is True:need(type(last['exit_code']) is int and -255<=last['exit_code']<=255 and last['leader_reaped'] is True)
        else:need(last['completed'] is False and last['exit_code'] is None and last['leader_reaped'] is None)
    need(type(value['block_completed']) is bool and value['block_completed']==(value['status']=='PASS'))
    if value['status']=='PASS':need(record['exit_code']==0 and record['status']=='PASS' and value['step']=='INVENTORY_BLOCK' and identity is not None and identity['status']=='PASS' and value['terminal']['error_type']=='NONE' and last is not None and last['completed'] is True and last['exit_code']==0)
    return value

def project(bound,record,private_root,application,destination=None):
    bound=context(bound);root=Path(private_root)
    public=dict(schema='source26-inventory-public-v1',scope=SCOPE,context=bound,diagnostic_only=True,claims_full17=False,claims_M_success=False,input_binding='INVALID',status='UNKNOWN',phase='inventory',invocation_exit_code=None,leader_reaped=None,owned_group='UNKNOWN',step='UNKNOWN',terminal=None,last_command=None,installed_identity=None,block_completed=False)
    try:
        command_binding(record,'inventory',bound,application,root);need(record.get('capture_state')!='INVALID')
        public.update(invocation_exit_code=record['exit_code'],leader_reaped=True,owned_group='EMPTY')
        need(root_identity(root)==record['private_root_identity'])
        name=next(name for name in ('result.json','observation.json') if name in record['files'])
        raw,seals=read_private(root,name);need(record['files'][name]==dict(bytes=len(raw),sha256=digest(raw)))
        value=observation(parse(raw),record,bound,application);need(stable(seals))
        public.update(input_binding='MATCHED',status=value['status'],step=value['step'],terminal=value['terminal'],last_command=value['last_command'],installed_identity=value['installed_identity'],block_completed=value['block_completed'])
    except Exception:pass
    if destination is not None:safe_save(destination,public)
    return public
