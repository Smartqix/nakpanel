"""Exact source26 inventory AST only; Producer.prepare is never invoked."""
import ast,copy,json,os,sys,time,types
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from contract import *
from observer import Observer,ERRORS
IDENTITY_PREFIX='NAKPANEL_SAFE_INVENTORY_IDENTITY_V1 '
def load_source(app):
    app=Path(app);raw=pinned_source(app/'deploy/multipass/sury-maintenance-prepare.py',PREPARE)
    pinned_source(app/'deploy/multipass/sury-maintenance-drill.py',HELPER)
    module=types.ModuleType('source26_original_inventory');module.__file__=str(app/'deploy/multipass/sury-maintenance-prepare.py')
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    return module,raw

def inventory_ast(raw):
    tree=ast.parse(raw);klass=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Producer')
    original=next(n for n in klass.body if isinstance(n,ast.FunctionDef) and n.name=='collect_baseline')
    config=next(n for n in original.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='config' for t in n.targets))
    block=[n for n in original.body if 403<=n.lineno<=413]
    need([n.lineno for n in block]==[403,404,405,406,407,408,409,410,411,412,413])
    function=copy.deepcopy(original);function.body=copy.deepcopy([config,*block])
    return ast.Module(body=[function],type_ignores=[])
def extract_inventory(module,raw):
    selected=inventory_ast(raw);need(digest(canonical_inventory_ast(selected))==code_pins()['inventory_ast'])
    namespace={};exec(compile(selected,module.__file__,'exec'),module.__dict__,namespace)
    function=namespace['collect_baseline'];need(function.__globals__ is module.__dict__)
    return function

def canonical_inventory_ast(value):
    """Preserve every AST field/location; normalize only empty 3.12 type_params."""
    def encode(node):
        if isinstance(node,ast.AST):
            need(type(node) is getattr(ast,type(node).__name__,None))
            fields=list(node._fields);attributes=list(node._attributes)
            if 'type_params' in fields or 'type_params' in node.__dict__:
                need(type(node) in (ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef) and type(getattr(node,'type_params',None)) is list and not node.type_params)
            need(set(node.__dict__)<=set(fields+attributes+(['type_params'] if type(node) in (ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef) else [])))
            need(all(hasattr(node,name) for name in fields))
            return dict(node=type(node).__name__,fields=[[name,encode(getattr(node,name))] for name in fields if name!='type_params'],attributes=[[name,encode(getattr(node,name,None))] for name in attributes])
        if type(node) is list:return [encode(item) for item in node]
        need(node is None or type(node) in (str,int,bool))
        return node
    return canonical(encode(value))

def guard_sites(raw,helper):
    out={}
    for unit,source in [('PREPARE',raw),('HELPER',helper)]:
        tree=ast.parse(source)
        out[unit]=sorted({n.lineno for n in ast.walk(tree) if isinstance(n,ast.Call) and (isinstance(n.func,ast.Name) and n.func.id=='require' or isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='M' and n.func.attr=='require')})
    return out

def identity_program(source,bound,nonce):
    need(digest(source.encode())==HELPER);bound=context(bound);need(type(nonce) is str and len(nonce)==32 and all(c in '0123456789abcdef' for c in nonce))
    prefix="import json,sys,types,subprocess\nscope={'__name__':'inventory_guest','__file__':'reviewed-inventory-helper'}\nexec(compile("+repr(source)+",'reviewed-inventory-helper','exec'),scope)\nrequest=json.load(sys.stdin)\n"
    code=r'''
trusted={}
def add(code):
 trusted[id(code)]=code
 for child in code.co_consts:
  if isinstance(child,types.CodeType):add(child)
for value in list(scope.values()):
 if isinstance(value,types.FunctionType) and value.__module__=='inventory_guest':add(value.__code__)
 elif isinstance(value,type) and value.__module__=='inventory_guest':
  for method in value.__dict__.values():
   if isinstance(method,types.FunctionType):add(method.__code__)
def emit(error,exit_code):
 site=0;guard=False
 trace=error.__traceback__ if error is not None else None
 while trace is not None:
  if trusted.get(id(trace.tb_frame.f_code)) is trace.tb_frame.f_code:
   if trace.tb_frame.f_code.co_name=='require':guard=True
   else:site=trace.tb_lineno
  trace=trace.tb_next
 kind='NONE' if error is None else 'VALUE_ERROR' if isinstance(error,ValueError) else 'RUNTIME_ERROR' if isinstance(error,RuntimeError) else 'OS_ERROR' if isinstance(error,OSError) else 'KEY_ERROR' if isinstance(error,KeyError) else 'TYPE_ERROR' if isinstance(error,TypeError) else 'SUBPROCESS_ERROR' if isinstance(error,subprocess.SubprocessError) else 'OTHER'
 predicate='HELPER_GUARD_'+str(site) if guard and type(error) is ValueError and site in guards else 'UNKNOWN'
 value=dict(schema='source26-inventory-identity-v1',scope=scope_name,context_sha256=context_sha,nonce=nonce,helper_sha256=helper_sha,status='PASS' if error is None else 'FAIL',exit_code=exit_code,source_unit='HELPER' if site else 'UNKNOWN',source_site=site,error_type=kind,predicate=predicate)
 print(json.dumps(value,sort_keys=True))
try:
 scope['guest_identity'](request['config'])
except Exception as error:
 emit(error,1);sys.exit(1)
else:emit(None,0)
'''
    guards=guard_sites(b'',source.encode())['HELPER']
    return prefix+'guards='+repr(guards)+'\nscope_name='+repr(SCOPE)+'\ncontext_sha='+repr(digest(canonical(bound)))+'\nnonce='+repr(nonce)+'\nhelper_sha='+repr(HELPER)+'\n'+code

def validate_identity(value,bound,nonce,returncode):
    keys={'schema','scope','context_sha256','nonce','helper_sha256','status','exit_code','source_unit','source_site','error_type','predicate'}
    need(type(value) is dict and set(value)==keys and value['schema']=='source26-inventory-identity-v1' and value['scope']==SCOPE)
    need(value['context_sha256']==digest(canonical(context(bound))) and value['nonce']==nonce and value['helper_sha256']==HELPER)
    need(type(value['exit_code']) is int and value['exit_code']==returncode and value['status'] in ('PASS','FAIL') and value['error_type'] in ERRORS)
    need(value['source_unit'] in ('HELPER','UNKNOWN') and type(value['source_site']) is int and 0<=value['source_site']<=1039)
    need(value['predicate']=='UNKNOWN' or value['predicate']=='HELPER_GUARD_'+str(value['source_site']))
    need((value['source_unit']=='UNKNOWN')==(value['source_site']==0))
    if value['status']=='PASS':need(returncode==0 and value['error_type']=='NONE' and value['source_site']==0 and value['predicate']=='UNKNOWN')
    else:need(returncode==1 and value['error_type']!='NONE')
    return value

def current_receipt(root,bound):
    deadline=time.monotonic()+5
    while True:
        try:
            raw,seals=read_private(root.parent/'custody/inventory','receipt.json');record=parse(raw)
            need(record.get('schema')=='source26-inventory-command-custody-v1' and record.get('scope')==SCOPE and record.get('phase')=='inventory' and record.get('source_binding')==bound and record.get('status')=='STARTED' and record.get('finished') is False)
            if record.get('pid') is None and time.monotonic()<deadline:time.sleep(.02);continue
            need(record.get('pid')==os.getpid()==os.getpgrp() and record.get('process_group')==os.getpid() and record.get('private_root')==str(root))
            nonce=record.get('invocation_id');need(type(nonce) is str and len(nonce)==32 and all(c in '0123456789abcdef' for c in nonce) and stable(seals))
            return record
        except FileNotFoundError:
            if time.monotonic()>=deadline:raise
            time.sleep(.02)

def configuration(module,bound,env):
    bundle=Path(env['NAKPANEL_RELEASE_BUNDLE']);manifest_raw=(bundle/'manifest.json').read_bytes();manifest=parse(manifest_raw)
    need(digest(manifest_raw)==bound['manifest_sha256'] and manifest['commit']==SOURCE and manifest['architecture']=='amd64' and manifest['development'] is True)
    need({name:manifest['files']['bin/'+name] for name in ('panel','agent','panelctl')}==bound['installed_binary_sha256'])
    key=Path(env['NAKPANEL_RELEASE_PUBLIC_KEY']);need(digest(key.read_bytes())==PINS['public_key_sha256'])
    need(env.get('NAKPANEL_RUN_TOKEN')==bound['run_token'] and env.get('NAKPANEL_MULTIPASS_VM')==bound['source_vm'] and env.get('NAKPANEL_MULTIPASS_IMAGE')=='26.04' and env.get('NAKPANEL_MULTIPASS_ARCH')=='amd64' and env.get('NAKPANEL_QUALIFICATION_PHP_PROVIDER')=='sury')
    return dict(source_vm=bound['source_vm'],run_token=bound['run_token'],runtime_commit=SOURCE,qualifier_commit=SOURCE,architecture='amd64',profile='ubuntu-26.04-sury',php_provider='sury',operation=MODE,maintenance_id='inv-'+bound['run_token'],allow_development=True,app_version=manifest['version'],manifest_sha256=bound['manifest_sha256'],installed_binary_sha256=bound['installed_binary_sha256'],public_key_sha256=PINS['public_key_sha256'],signature_sha256=digest((bundle/'manifest.sig').read_bytes()),ownership_directory=env['NAKPANEL_OWNERSHIP_DIR'])

def run(private_root):
    root=Path(private_root);need(root.is_absolute() and root.parent.resolve()==root.parent and not root.exists())
    validate_runtime_files();bound=context(parse(read_private(root.parent,'context.json')[0]));receipt=current_receipt(root,bound)
    app=Path(os.environ['GITHUB_WORKSPACE'])/'application';module,raw=load_source(app)
    function=extract_inventory(module,raw);helper=pinned_source(app/'deploy/multipass/sury-maintenance-drill.py',HELPER)
    producer=module.Producer(app,root,root.parent/'inventory-only-no-canonical-receipt',dict(os.environ));producer.config=configuration(module,bound,os.environ);producer.stage='signed-provider-baseline';producer.record()
    observer=Observer(module,function,sys.modules[__name__],root,bound,receipt,guard_sites(raw,helper));observer.install();observer.emit('STARTED')
    try:
        module.M.host_record(producer.config);module.M.host_identity(producer.config,app,producer.env)
        program=identity_program(helper.decode(),bound,receipt['invocation_id']);observer.guest_sha=digest(program.encode())
        result=module.M.command(['multipass','exec',bound['source_vm'],'--','sudo','python3','-c',program],env=producer.env,data=json.dumps(dict(config=producer.config)),timeout=180,check=False)
        identity=validate_identity(parse(result.stdout),bound,receipt['invocation_id'],result.returncode);observer.identity=identity
        need(result.returncode==0 and identity['status']=='PASS')
        observer.step='INVENTORY_BLOCK';function(producer,None)
        producer.record('PASS');observer.emit('PASS',terminal=True)
        return 0
    except BaseException as error:
        producer.record('FAIL');observer.emit('FAIL',error,terminal=True);raise
    finally:observer.restore()
if __name__=='__main__':
    try:
        need(len(sys.argv)==2);raise SystemExit(run(sys.argv[1]))
    except SystemExit:raise
    except KeyboardInterrupt:raise SystemExit(130)
    except BaseException:
        print('inventory-only diagnostic failed',file=sys.stderr);raise SystemExit(1)
