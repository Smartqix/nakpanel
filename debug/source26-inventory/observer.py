"""Finite observations from trusted code objects; never reads command data."""
import inspect,os,types
from pathlib import Path
import subprocess
from contract import *
ERRORS={'NONE','VALUE_ERROR','RUNTIME_ERROR','OS_ERROR','KEY_ERROR','TYPE_ERROR','SUBPROCESS_ERROR','SYSTEM_EXIT','KEYBOARD_INTERRUPT','OTHER'}
CATEGORIES={'HOST_IDENTITY','GUEST_PROFILE_IDENTITY','GUEST_PACKAGE_INVENTORY','GUEST_DISTRIBUTION_CONTROLS','HOST_PHP_PACKAGES','HOST_COMMAND','GUEST_COMMAND'}
UNITS={'PREPARE','HELPER','DRIVER','UNKNOWN'}
def error_kind(error):
    if error is None:return 'NONE'
    for kind,code in ((ValueError,'VALUE_ERROR'),(RuntimeError,'RUNTIME_ERROR'),(OSError,'OS_ERROR'),(KeyError,'KEY_ERROR'),(TypeError,'TYPE_ERROR'),(subprocess.SubprocessError,'SUBPROCESS_ERROR'),(SystemExit,'SYSTEM_EXIT'),(KeyboardInterrupt,'KEYBOARD_INTERRUPT')):
        if isinstance(error,kind):return code
    return 'OTHER'
def register_code(table,code,unit):
    table[id(code)]=(code,unit)
    for value in code.co_consts:
        if isinstance(value,types.CodeType):register_code(table,value,unit)
def register_module(table,module,unit):
    for value in list(module.__dict__.values()):
        if isinstance(value,types.FunctionType) and value.__module__==module.__name__:register_code(table,value.__code__,unit)
        elif isinstance(value,type) and value.__module__==module.__name__:
            for method in value.__dict__.values():
                if isinstance(method,types.FunctionType):register_code(table,method.__code__,unit)
def trusted_unit(table,code):
    entry=table.get(id(code));return entry[1] if entry is not None and entry[0] is code else None
class Observer:
    def __init__(self,module,extracted,driver_module,root,bound,receipt,guard_sites):
        self.module=module;self.root=Path(root);self.bound=context(bound);self.receipt=receipt;self.guards=guard_sites
        self.trusted={};register_module(self.trusted,module,'PREPARE');register_module(self.trusted,module.M,'HELPER');register_module(self.trusted,driver_module,'DRIVER');register_code(self.trusted,extracted.__code__,'PREPARE')
        self.last=None;self.active=None;self.step='IDENTITY';self.identity=None;self.guest_sha=None
        self.original=module.M.command;self.original_run=module.M.subprocess.run
    def frames(self,trace):
        frames=[]
        while trace is not None:
            unit=trusted_unit(self.trusted,trace.tb_frame.f_code)
            if unit:frames.append((unit,trace.tb_lineno,trace.tb_frame.f_code.co_name))
            trace=trace.tb_next
        return frames
    def location(self,error):
        location=('UNKNOWN',0);guard=False
        for unit,line,name in self.frames(error.__traceback__ if error is not None else None):
            if unit=='HELPER' and name=='require':guard=True;continue
            location=(unit,line)
        unit,site=location
        predicate=unit+'_GUARD_'+str(site) if guard and type(error) is ValueError and site in self.guards.get(unit,[]) else 'UNKNOWN'
        return dict(source_unit=unit,source_site=site,error_type=error_kind(error),predicate=predicate)
    def command_site(self):
        frames=[];frame=inspect.currentframe().f_back
        try:
            while frame is not None:
                unit=trusted_unit(self.trusted,frame.f_code)
                if unit:frames.append((unit,frame.f_lineno,frame.f_code.co_name))
                frame=frame.f_back
        finally:del frame
        immediate=frames[0] if frames else ('UNKNOWN',0,'')
        caller=next((line for unit,line,name in frames if unit=='PREPARE' and name!='guest'),0)
        if any(unit=='HELPER' and name=='host_identity' for unit,line,name in frames):category='HOST_IDENTITY'
        elif self.step=='IDENTITY':category='GUEST_PROFILE_IDENTITY'
        else:category={404:'GUEST_PACKAGE_INVENTORY',407:'HOST_PHP_PACKAGES',412:'GUEST_DISTRIBUTION_CONTROLS'}.get(caller,'GUEST_COMMAND' if immediate[2]=='guest' else 'HOST_COMMAND')
        return dict(category=category,source_unit=immediate[0],source_site=immediate[1],caller_site=caller)
    def emit(self,status,error=None,terminal=False):
        try:
            if not self.root.exists():return
            pins=code_pins()
            value=dict(schema='source26-inventory-observation-v1',scope=SCOPE,context=self.bound,phase='inventory',nonce=self.receipt['invocation_id'],pid=os.getpid(),process_group=os.getpgrp(),status=status,step=self.step,
                source_sha256=dict(prepare=PREPARE,helper=HELPER,driver=pins['driver.py'],observer=pins['observer.py'],inventory_ast=pins['inventory_ast']),guest_source_sha256=self.guest_sha,
                installed_identity=self.identity,block_completed=status=='PASS',terminal=self.location(error),last_command=self.last,claims_full17=False,claims_M_success=False)
            self.module.M.write_private(self.root/('result.json' if terminal else 'observation.json'),value)
        except Exception:pass
    def command(self,args,**kwargs):
        self.active=self.command_site()
        try:return self.original(args,**kwargs)
        finally:self.active=None
    def run(self,*args,**kwargs):
        try:result=self.original_run(*args,**kwargs)
        except BaseException:
            if self.active is not None:self.last=dict(self.active,exit_code=None,completed=False,leader_reaped=None);self.emit('STARTED')
            raise
        if self.active is not None:self.last=dict(self.active,exit_code=result.returncode,completed=True,leader_reaped=True);self.emit('STARTED')
        return result
    def install(self):self.module.M.command=self.command;self.module.M.subprocess.run=self.run
    def restore(self):self.module.M.command=self.original;self.module.M.subprocess.run=self.original_run
