"""Diagnostic entrypoints around pinned source26; never a product implementation."""
import ast
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid
import stat
import types
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from contract import HELPER,SOURCE,need,digest,parse,canonical,MODE
_predicates=(HERE/'known-predicates.json').read_bytes()
need(digest(_predicates)=='11991c3c1e040bcb348746601b81d81b8a97687d42d7c13011b47d8273ca9161')
PREDICATES=parse(_predicates)
PREPARE_SHA='180c2da2874de86b2e03741e334a7faba80c7afb080089d12d38117624e32614'
IDENTITY=('source_vm','run_token','runtime_commit','qualifier_commit','maintenance_helper_sha256')
STAGES={'ENTRY','IDENTITY','STAGING','RUN_PREPARE','RUN_BASELINE','RUN_READINESS','RUN_SMOKE','RUN_QUIESCE','RUN_DELIVERY','RUN_FAULT','RUN_RECOVERY','HEALTH','UNKNOWN'}
ERRORS={'NONE','VALUE_ERROR','RUNTIME_ERROR','OS_ERROR','KEY_ERROR','TYPE_ERROR','SUBPROCESS_ERROR','SYSTEM_EXIT','KEYBOARD_INTERRUPT','OTHER'}
PREFIX='NAKPANEL_SAFE_GUEST_V1 '

def load_pinned(path,expected,name):
    path=Path(path);need(path.resolve()==path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd);need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o022 and info.st_nlink==1 and info.st_size<=256*1024)
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(256*1024+1)
        need(len(raw)==info.st_size and digest(raw)==expected)
    finally:os.close(fd)
    module=types.ModuleType(name);module.__file__=str(path)
    exec(compile(raw,str(path),'exec'),module.__dict__)
    return module

def guest_program(source,nonce):
    need(digest(source.encode())==HELPER and type(nonce) is str and len(nonce)==32 and all(c in '0123456789abcdef' for c in nonce))
    # The helper is executed verbatim. Only its stdin/stdout exception wrapper
    # adds safe diagnostic records; no product function or call is replaced.
    header="import json,sys,subprocess\nscope={'__name__':'maintenance_guest','__file__':'reviewed-maintenance-helper'}\nexec(compile("+repr(source)+",'reviewed-maintenance-helper','exec'),scope)\nrequest=json.load(sys.stdin)\n"
    body=r'''
def safe_error(error):
 if error is None:return 'NONE'
 if isinstance(error,ValueError):return 'VALUE_ERROR'
 if isinstance(error,RuntimeError):return 'RUNTIME_ERROR'
 if isinstance(error,OSError):return 'OS_ERROR'
 if isinstance(error,KeyError):return 'KEY_ERROR'
 if isinstance(error,TypeError):return 'TYPE_ERROR'
 if isinstance(error,subprocess.SubprocessError):return 'SUBPROCESS_ERROR'
 if isinstance(error,SystemExit):return 'SYSTEM_EXIT'
 if isinstance(error,KeyboardInterrupt):return 'KEYBOARD_INTERRUPT'
 return 'OTHER'
def emit(error,code):
 stage='ENTRY';site=0
 trace=error.__traceback__ if error is not None else None
 frames=[]
 while trace is not None:
  if trace.tb_frame.f_code.co_filename=='reviewed-maintenance-helper':frames.append((trace.tb_frame.f_code.co_name,trace.tb_lineno))
  trace=trace.tb_next
 for name,line in frames:
  if name=='guest_identity':stage='IDENTITY';site=line
  elif name=='stage_guest':stage='STAGING';site=line
  elif name=='run_guest':
   stage='RUN_PREPARE' if line<=981 else 'RUN_BASELINE' if line<=986 else 'RUN_READINESS' if line==987 else 'RUN_QUIESCE' if line<=991 else 'RUN_DELIVERY' if line<=994 else 'RUN_FAULT' if line<=998 else 'RUN_RECOVERY';site=line
  elif name=='prepare' and 771<=line<=798:stage='RUN_PREPARE';site=line
  elif name=='php_smoke':stage='RUN_SMOKE';site=line
  elif name=='service_wait':stage='RUN_READINESS';site=line
  elif name=='drill_minor':stage='RUN_FAULT';site=line
  elif name=='guest_health':stage='HEALTH';site=line
 predicate=predicates.get(str(error),'UNKNOWN') if type(error) is ValueError else 'UNKNOWN'
 identity={k:request['config'][k] for k in identity_keys}
 record=dict(schema='source26-guest-diagnostic-v1',nonce=nonce,action=request.get('action'),**identity,stage=stage,site=site,predicate=predicate,error_type=safe_error(error),exit_code=code)
 print(prefix+json.dumps(record,sort_keys=True,separators=(',',':')),file=sys.stderr)
def quiet_emit(error,code):
 try:emit(error,code)
 except Exception:pass
try:
 value=scope['guest_action'](request)
except BaseException as error:
 code=1 if isinstance(error,Exception) else error.code if isinstance(error,SystemExit) and type(error.code) is int else 0 if isinstance(error,SystemExit) and error.code is None else None
 quiet_emit(error,code)
 if isinstance(error,Exception):sys.exit(1)
 raise
else:
 print(json.dumps(value,sort_keys=True))
 quiet_emit(None,0)
'''
    return header+'predicates='+repr(PREDICATES)+'\nidentity_keys='+repr(IDENTITY)+'\nnonce='+repr(nonce)+'\nprefix='+repr(PREFIX)+'\n'+body

def validate_guest(value,identity,action,nonce):
    need(type(value) is dict and set(value)=={'schema','nonce','action',*IDENTITY,'stage','site','predicate','error_type','exit_code'})
    need(value['schema']=='source26-guest-diagnostic-v1' and value['nonce']==nonce and value['action']==action)
    need(all(value[k]==identity[k] for k in IDENTITY))
    need(value['stage'] in STAGES and value['error_type'] in ERRORS and value['predicate'] in {'UNKNOWN',*PREDICATES.values()})
    need(type(value['site']) is int and 0<=value['site']<=1039)
    need(value['exit_code'] is None or type(value['exit_code']) is int and -2**31<=value['exit_code']<2**31)
    return {k:value[k] for k in ('stage','site','predicate','error_type','exit_code')}

def observe_remote(module,original,config,evidence,nonce,args,kwargs):
    result=original(args,**kwargs)
    # This observer is read-only around the original command. A diagnostic I/O
    # error cannot change the product result or suppress a product exception.
    try:
        if len(args)!=8 or args[:7]!=['multipass','exec',config['source_vm'],'--','sudo','python3','-c']:return result
        request=parse(kwargs.get('data',''));action=request.get('action')
        if action not in ('stage','run','health') or request.get('config')!=module.guest_configuration(config):return result
        identity={k:config[k] for k in IDENTITY};guest=None
        lines=[line[len(PREFIX):] for line in result.stderr.splitlines() if line.startswith(PREFIX)]
        if len(lines)==1:
            try:guest=validate_guest(parse(lines[0]),identity,action,nonce)
            except Exception:pass
        value=dict(schema='source26-remote-execution-v1',action=action,**identity,remote_exit_code=result.returncode,guest=guest)
        if action in ('stage','run'):module.write_private(evidence/('diagnostic-'+action+'.json'),value)
    except Exception:pass
    return result

def host(application,arguments):
    app=Path(application);need(app.is_absolute() and app.resolve()==app)
    module=load_pinned(app/'deploy/multipass/sury-maintenance-drill.py',HELPER,'source26_instrumented_host')
    need(len(arguments)==2 and arguments[0]=='same-version')
    config=parse(module.private_bytes(Path(arguments[1])))
    need(config['runtime_commit']==SOURCE and config['qualifier_commit']==SOURCE and config['maintenance_helper_sha256']==HELPER and config['operation']==MODE)
    nonce=uuid.uuid4().hex;original=module.command
    module.remote_program=lambda source:guest_program(source,nonce)
    module.command=lambda args,**kwargs:observe_remote(module,original,config,Path(config['evidence_directory']),nonce,args,kwargs)
    sys.argv=[str(app/'deploy/multipass/sury-maintenance-drill.py'),*arguments]
    try:return module.main()
    except KeyboardInterrupt as error:raise SystemExit(143 if isinstance(error,module.MaintenanceTermination) else 130)

def prepare(application,arguments):
    app=Path(application);need(app.is_absolute() and app.resolve()==app)
    module=load_pinned(app/'deploy/multipass/sury-maintenance-prepare.py',PREPARE_SHA,'source26_instrumented_prepare')
    original=module.M.command
    def command(args,**kwargs):
        if len(args)==4 and args[:3]==['bash',str(app/'deploy/multipass/sury-maintenance-verify.sh'),'same-version']:
            args=[sys.executable,'-I','-B',str(HERE/'instrumentation.py'),'host',str(app),*args[2:]]
        return original(args,**kwargs)
    module.M.command=command
    sys.argv=[str(app/'deploy/multipass/sury-maintenance-prepare.py'),*arguments]
    return module.main()

if __name__=='__main__':
    try:
        need(len(sys.argv)>=4 and sys.argv[1] in ('prepare','host'))
        operation=sys.argv[1];application=sys.argv[2];arguments=sys.argv[3:]
        if operation=='host':host(application,arguments)
        else:prepare(application,arguments)
    except KeyboardInterrupt:raise SystemExit(130)
    except Exception as error:
        print('source26 instrumented invocation failed: '+type(error).__name__,file=sys.stderr)
        raise SystemExit(1)
