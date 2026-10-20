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
import inspect
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from contract import HELPER,SOURCE,need,digest,parse,canonical,MODE,context,read_private,stable
_predicates=(HERE/'known-predicates.json').read_bytes()
need(digest(_predicates)=='11991c3c1e040bcb348746601b81d81b8a97687d42d7c13011b47d8273ca9161')
PREDICATES=parse(_predicates)
PREPARE_SHA='180c2da2874de86b2e03741e334a7faba80c7afb080089d12d38117624e32614'
IDENTITY=('source_vm','run_token','runtime_commit','qualifier_commit','maintenance_helper_sha256')
STAGES={'ENTRY','IDENTITY','STAGING','RUN_PREPARE','RUN_BASELINE','RUN_READINESS','RUN_SMOKE','RUN_QUIESCE','RUN_DELIVERY','RUN_FAULT','RUN_RECOVERY','HEALTH','UNKNOWN'}
ERRORS={'NONE','VALUE_ERROR','RUNTIME_ERROR','OS_ERROR','KEY_ERROR','TYPE_ERROR','SUBPROCESS_ERROR','SYSTEM_EXIT','KEYBOARD_INTERRUPT','OTHER'}
PREFIX='NAKPANEL_SAFE_GUEST_V1 '
PREP_STAGES={'host-inputs','actual-roundcube-baseline','cold-retention','signed-provider-baseline','maintenance-handoff','complete','UNKNOWN'}
PREP_SUBSTAGES={'signed-metadata','authenticated-indexes','package-inventory','exact-php-closure','candidate-origin-and-apt-plan','retained-package-archives','baseline-complete',None}
PREP_CATEGORIES={'HOST_IDENTITY','GUEST_PROVIDER_KEY','GUEST_SIGNATURE','GUEST_PACKAGE_INVENTORY','GUEST_DISTRIBUTION_CONTROLS','HOST_PHP_PACKAGES','HOST_SOURCE_MAP','HOST_COMMAND','GUEST_COMMAND'}
SOURCE_LIMITS={'PREPARE':582,'HELPER':1039,'UNKNOWN':0}
GUARD_SITES={'PREPARE': [65, 67, 69, 72, 74, 110, 140, 141, 168, 171, 180, 182, 191, 195, 206, 210, 213, 223, 238, 246, 248, 250, 260, 264, 269, 275, 278, 281, 284, 291, 294, 300, 310, 326, 331, 334, 361, 379, 390, 393, 416, 462, 502, 505, 514, 516, 519, 541, 549, 555, 560], 'HELPER': [66, 67, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 82, 84, 85, 86, 89, 91, 92, 93, 94, 95, 96, 97, 98, 99, 101, 102, 103, 106, 112, 116, 118, 120, 122, 127, 136, 141, 148, 161, 163, 168, 171, 172, 177, 181, 190, 196, 211, 213, 214, 223, 225, 228, 248, 250, 254, 255, 257, 258, 261, 263, 265, 270, 281, 282, 287, 289, 299, 303, 310, 312, 314, 318, 321, 322, 338, 341, 344, 345, 346, 347, 348, 349, 357, 359, 363, 364, 369, 371, 376, 383, 385, 386, 401, 413, 418, 420, 422, 425, 426, 447, 457, 461, 463, 478, 499, 501, 511, 512, 531, 561, 562, 563, 569, 570, 571, 573, 576, 581, 591, 597, 599, 608, 612, 619, 622, 626, 629, 640, 641, 644, 651, 663, 666, 668, 670, 671, 673, 705, 706, 712, 714, 718, 722, 731, 742, 772, 775, 778, 781, 785, 787, 790, 797, 808, 820, 832, 838, 841, 843, 860, 864, 866, 964, 965, 966, 967, 968, 971, 974, 979, 990, 991, 993, 996, 998, 1011, 1015, 1017]}


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

def error_kind(error):
    if error is None:return 'NONE'
    for kind,code in ((ValueError,'VALUE_ERROR'),(RuntimeError,'RUNTIME_ERROR'),(OSError,'OS_ERROR'),(KeyError,'KEY_ERROR'),(TypeError,'TYPE_ERROR'),(subprocess.SubprocessError,'SUBPROCESS_ERROR'),(SystemExit,'SYSTEM_EXIT'),(KeyboardInterrupt,'KEYBOARD_INTERRUPT')):
        if isinstance(error,kind):return code
    return 'OTHER'

def source_location(frames):
    selected=('UNKNOWN',0)
    guard=False
    for unit,line,name in frames:
        if unit=='HELPER' and name=='require':guard=True;continue
        selected=(unit,line)
    predicate=(selected[0]+'_GUARD_'+str(selected[1])) if guard and selected[1] in GUARD_SITES.get(selected[0],[]) else 'UNKNOWN'
    return selected,predicate

class PreparationObserver:
    """Read-only observations within the existing prepare launcher/process group."""
    def __init__(self,module,app,arguments):
        self.module=module;self.app=app;self.root=None;self.custody=None;self.last=None;self.active=None
        self.paths={str(app/'deploy/multipass/sury-maintenance-prepare.py'):'PREPARE',str(app/'deploy/multipass/sury-maintenance-drill.py'):'HELPER'}
        if len(arguments)==5 and arguments[0:2]==['prepare','--execution-receipt'] and arguments[3]=='--private-root':
            execution=Path(arguments[2]);self.root=Path(arguments[4]);self.custody=execution.parent/'custody/prepare'
    def command_site(self):
        frames=[];frame=inspect.currentframe().f_back
        try:
            while frame is not None:
                unit=self.paths.get(frame.f_code.co_filename)
                if unit:frames.append((unit,frame.f_lineno,frame.f_code.co_name))
                frame=frame.f_back
        finally:del frame
        immediate=frames[0] if frames else ('UNKNOWN',0,'')
        caller=next((line for unit,line,name in frames if unit=='PREPARE' and name!='guest'),0)
        if any(unit=='HELPER' and name=='host_identity' for unit,line,name in frames):category='HOST_IDENTITY'
        else:category={389:'GUEST_PROVIDER_KEY',391:'GUEST_SIGNATURE',404:'GUEST_PACKAGE_INVENTORY',407:'HOST_PHP_PACKAGES',412:'GUEST_DISTRIBUTION_CONTROLS'}.get(caller,'GUEST_COMMAND' if immediate[2]=='guest' else 'HOST_SOURCE_MAP' if immediate[2]=='source_map' else 'HOST_COMMAND')
        return dict(category=category,source_unit=immediate[0],source_site=immediate[1],caller_site=caller)
    def emit(self,status,error=None):
        # A lost diagnostic never changes a product call, exception or result.
        try:
            if self.root is None or not self.root.exists():return
            raw,seals=read_private(self.custody,'receipt.json');record=parse(raw);bound=context(record['source_binding'])
            need(record.get('schema')=='source26-prepare-custody-v1' and record.get('status')=='STARTED' and record.get('finished') is False)
            need(record.get('pid')==os.getpid() and record.get('process_group')==os.getpid()==os.getpgrp() and record.get('private_root')==str(self.root))
            nonce=record.get('invocation_id');need(type(nonce) is str and len(nonce)==32 and all(c in '0123456789abcdef' for c in nonce))
            need(bound['runtime_commit']==SOURCE and bound['maintenance_helper_sha256']==HELPER)
            stage='UNKNOWN';substage=None
            preparation=self.root/'preparation.json'
            if preparation.exists():
                current=parse(self.module.M.private_bytes(preparation))
                need(current.get('source_vm') in (None,bound['source_vm']) and current.get('run_token') in (None,bound['run_token']))
                need(current.get('stage') in PREP_STAGES and current.get('substage') in PREP_SUBSTAGES)
                stage=current['stage'];substage=current['substage']
            frames=[];trace=error.__traceback__ if error is not None else None
            while trace is not None:
                unit=self.paths.get(trace.tb_frame.f_code.co_filename)
                if unit:frames.append((unit,trace.tb_lineno,trace.tb_frame.f_code.co_name))
                trace=trace.tb_next
            (unit,site),predicate=source_location(frames)
            if type(error) is not ValueError:predicate='UNKNOWN'
            need(digest((self.app/'deploy/multipass/sury-maintenance-prepare.py').read_bytes())==PREPARE_SHA and digest((self.app/'deploy/multipass/sury-maintenance-drill.py').read_bytes())==HELPER)
            value=dict(schema='source26-early-preparation-v1',phase='PREP',context=bound,invocation_id=nonce,nonce=nonce,pid=os.getpid(),process_group=os.getpgrp(),
                source_sha256=dict(prepare=PREPARE_SHA,helper=HELPER,wrapper=digest((HERE/'instrumentation.py').read_bytes())),
                stage=stage,substage=substage,status=status,
                terminal=dict(source_unit=unit,source_site=site,error_type=error_kind(error),predicate=predicate),last_command=self.last)
            need(stable(seals));self.module.M.write_private(self.root/'early-preparation.json',value)
        except Exception:pass
    def run(self,original,*args,**kwargs):
        # subprocess.run returns only after its leader has been waited/reaped.
        try:result=original(*args,**kwargs)
        except BaseException:
            if self.active is not None:
                self.last=dict(self.active,exit_code=None,completed=False,leader_reaped=None);self.emit('STARTED')
            raise
        if self.active is not None:
            self.last=dict(self.active,exit_code=result.returncode,completed=True,leader_reaped=True);self.emit('STARTED')
        return result

def prepare(application,arguments):
    app=Path(application);need(app.is_absolute() and app.resolve()==app)
    module=load_pinned(app/'deploy/multipass/sury-maintenance-prepare.py',PREPARE_SHA,'source26_instrumented_prepare')
    original=module.M.command;original_run=module.M.subprocess.run;observer=PreparationObserver(module,app,arguments)
    def command(args,**kwargs):
        observer.active=observer.command_site()
        try:
            if len(args)==4 and args[:3]==['bash',str(app/'deploy/multipass/sury-maintenance-verify.sh'),'same-version']:
                args=[sys.executable,'-I','-B',str(HERE/'instrumentation.py'),'host',str(app),*args[2:]]
            return original(args,**kwargs)
        finally:observer.active=None
    module.M.command=command
    module.M.subprocess.run=lambda *args,**kwargs:observer.run(original_run,*args,**kwargs)
    sys.argv=[str(app/'deploy/multipass/sury-maintenance-prepare.py'),*arguments]
    try:
        result=module.main();observer.emit('PASS');return result
    except BaseException as error:
        observer.emit('FAIL',error);raise
    finally:
        module.M.subprocess.run=original_run;module.M.command=original

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
