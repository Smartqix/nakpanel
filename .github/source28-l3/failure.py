"""Bounded observations of the existing guest exception and sealed child exit.

Only the exact first read-only tenant ps site and two fixed application unit
listing sites may return bounded stderr; cwd metadata remains ps-only. No stdout, arguments, environment or SQL are returned. Source is
compiled for validation only, never executed by the host projector.
"""
import ast,dis,hashlib,math,os,re,stat,subprocess,sys,types
from pathlib import Path
from l3 import ROOT,SOURCE,PHASES,REASONS,SHA,Refused,need,sha,decode,canonical,regular,physical_dir,publish,roles
SCHEMA='nakpanel-l3-guest-failure-v4'
CATEGORIES={'REFUSED','OS_ERROR','CHILD_ERROR','TIMEOUT','CANCELLED','UNEXPECTED','REMOTE_UNKNOWN'}
FRAME_KEYS={'function','first_line','line','offset','bytecode_sha256','column_start','column_end','end_line'}
DETAIL_KEYS={'schema','capture','category','reason','python_tag','frames','truncated','fixture_check_index','tenant_ps','systemctl_listing'}
MAX_FRAMES=12

def category(error):
 if isinstance(error,Refused):return 'REFUSED'
 if isinstance(error,(KeyboardInterrupt,SystemExit)):return 'CANCELLED'
 if isinstance(error,subprocess.TimeoutExpired):return 'TIMEOUT'
 if isinstance(error,subprocess.CalledProcessError):return 'CHILD_ERROR'
 if isinstance(error,OSError):return 'OS_ERROR'
 return 'UNEXPECTED'

def unavailable(reason,kind='UNEXPECTED'):
 return {'schema':SCHEMA,'capture':'UNAVAILABLE','category':kind if kind in CATEGORIES else 'UNEXPECTED','reason':reason if type(reason) is str and reason in REASONS else 'UNKNOWN','python_tag':sys.implementation.cache_tag,'frames':[],'truncated':False,'fixture_check_index':'UNKNOWN','tenant_ps':None,'systemctl_listing':None}

def tenant_ps_sites(tree):
 sites={}
 for cls in tree.body:
  if not isinstance(cls,ast.ClassDef) or cls.name!='Guest':continue
  for fn in cls.body:
   if not isinstance(fn,ast.FunctionDef) or fn.name not in ('stopped','rootless','command'):continue
   for n in ast.walk(fn):
    if not isinstance(n,ast.Call):continue
    selected=(fn.name=='stopped' and isinstance(n.func,ast.Attribute) and n.func.attr=='rootless' and n.args and isinstance(n.args[0],ast.Constant) and n.args[0].value=='ps') or (fn.name=='rootless' and isinstance(n.func,ast.Attribute) and n.func.attr=='command') or (fn.name=='command' and isinstance(n.func,ast.Name) and n.func.id=='need' and len(n.args)==2 and isinstance(n.args[1],ast.Constant) and n.args[1].value=='CHILD')
    if selected:
     name='Guest.'+fn.name;need(name not in sites,'IDENTITY');sites[name]={'line':n.lineno,'column_start':n.col_offset,'column_end':n.end_col_offset}
 need(set(sites)=={'Guest.stopped','Guest.rootless','Guest.command'},'IDENTITY');return sites

def tenant_ps_call(frame,source,catalog):
 site=catalog['tenant_ps_sites'].get(frame['function'])
 if site is None or frame['line']!=site['line']:return False
 if frame['column_start'] is not None:return (frame['column_start'],frame['column_end'])==(site['column_start'],site['column_end'])
 # Python 3.9 has no column table: these fixed lines have respectively the
 # inner rootless call, sole command call, and final need call.
 for code,name in walk_code(compile(source,str(ROOT/'guest.py'),'exec'),''):
  if name!=frame['function']:continue
  line=None;calls=[]
  for instruction in dis.get_instructions(code):
   if instruction.starts_line is not None:line=instruction.starts_line
   if line==site['line'] and instruction.opname in ('CALL_FUNCTION','CALL_METHOD','CALL_FUNCTION_KW','CALL_FUNCTION_EX'):calls.append(instruction.offset)
  return bool(calls) and frame['offset']==calls[-1 if name=='Guest.command' else 0]
 return False

def tenant_ps_scope(g,command,source,catalog,codes):
 frames=[command,command.f_back,command.f_back.f_back];names=('Guest.command','Guest.rootless','Guest.stopped')
 for frame,name in zip(frames,names):
  trusted=codes.get(id(frame.f_code));need(trusted is not None and trusted[0] is frame.f_code and trusted[1]==name and frame.f_locals.get('self') is g,'IDENTITY')
  if name!='Guest.command':need(tenant_ps_call(point(frame.f_code,name,frame.f_lasti,frame.f_lineno),source,catalog),'IDENTITY')
 c=g.c;need(type(c) is dict and c.get('role') in ('source','target') and c.get('operation') in PHASES and all(type(c.get(k)) is int and c[k]>0 for k in ('subscription_id','application_id')) and type(c.get('username')) is str and re.fullmatch('[a-z_][a-z0-9_-]{0,31}',c['username']),'IDENTITY')
 sid=str(c['subscription_id']);base='/var/lib/nakpanel/containers/sub-'+sid;runtime='/run/nakpanel-containers/sub-'+sid;suffix=['ps','--all','--filter','label=io.nakpanel.application-id='+str(c['application_id']),'--format','json'];expected=['runuser','-u',c['username'],'--','env','HOME='+base+'/home','XDG_DATA_HOME='+base+'/data','XDG_CONFIG_HOME='+base+'/config','XDG_RUNTIME_DIR='+runtime,'TMPDIR='+runtime,'podman',*suffix]
 v=command.f_locals;r=frames[1].f_locals;s=frames[2].f_locals
 need(type(v.get('args')) is list and v['args']==expected and v.get('cwd')=='/' and v.get('env') is None and v.get('data') is None and v.get('accepted')==(0,) and type(v.get('accepted')) is tuple and r.get('args')==tuple(suffix) and s.get('aid')==str(c['application_id']) and s.get('c') is c and r.get('c') is c and all(type(r.get(k)) is int and r[k]>0 for k in ('uid','gid')),'IDENTITY')
 return expected,r['uid'],r['gid']

def tenant_ps_context(g):
 """Observe parent cwd for the fixed ps call; execution cwd is already fixed to /."""
 try:
  command=sys._getframe(1);codes=command.f_globals['FAILURE_CODES'];frames=[command,command.f_back,command.f_back.f_back]
  need(all(codes.get(id(f.f_code))==(f.f_code,name) for f,name in zip(frames,('Guest.command','Guest.rootless','Guest.stopped'))),'IDENTITY')
  source=Path(command.f_code.co_filename).read_bytes();catalog=source_catalog(source);_,uid,gid=tenant_ps_scope(g,command,source,catalog,codes)
 except Exception:return None
 cwd={'status':'UNAVAILABLE','path':None,'ancestors':[]}
 try:
  path=os.getcwd();need(type(path) is str and path.startswith('/') and str(Path(path))==path and '..' not in Path(path).parts and len(path.encode())<=4096 and '\x00' not in path,'IDENTITY');cwd['path']=path;paths=[Path(path),*Path(path).parents]
  for p in paths[:32]:
   s=p.lstat();cwd['ancestors'].append({'path':str(p),'directory':stat.S_ISDIR(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode)})
  if len(paths)<=32:cwd['status']='CAPTURED'
 except Exception:pass
 return {'tenant_uid':uid,'tenant_gid':gid,'execution_cwd':'/','parent_cwd':cwd}

def validate_tenant_ps(p,context):
 need(type(context) is dict and all(type(context.get(k)) is int and context[k]>0 for k in ('subscription_id','application_id')) and type(context.get('username')) is str and re.fullmatch('[a-z_][a-z0-9_-]{0,31}',context['username']),'IDENTITY')
 need(type(p) is dict and set(p)=={'returncode','stderr','stderr_truncated','tenant_uid','tenant_gid','execution_cwd','parent_cwd'} and type(p['returncode']) is int and -255<=p['returncode']<=255 and p['returncode']!=0 and type(p['stderr']) is str and len(canonical(p['stderr']))<=8192 and type(p['stderr_truncated']) is bool and all(type(p[k]) is int and p[k]>0 for k in ('tenant_uid','tenant_gid')),'IDENTITY')
 need(p['execution_cwd']=='/','IDENTITY');cwd=p['parent_cwd'];need(type(cwd) is dict and set(cwd)=={'status','path','ancestors'} and cwd['status'] in ('CAPTURED','UNAVAILABLE') and type(cwd['ancestors']) is list and len(cwd['ancestors'])<=32,'IDENTITY');path=cwd['path']
 if path is None:need(cwd=={'status':'UNAVAILABLE','path':None,'ancestors':[]},'IDENTITY');return True
 need(type(path) is str and path.startswith('/') and str(Path(path))==path and '..' not in Path(path).parts and len(path.encode())<=4096 and '\x00' not in path,'IDENTITY');paths=[str(Path(path)),*[str(p) for p in Path(path).parents]]
 need(len(cwd['ancestors'])<=len(paths) and (cwd['status']!='CAPTURED' or len(cwd['ancestors'])==len(paths)),'IDENTITY')
 for row,expected in zip(cwd['ancestors'],paths):need(type(row) is dict and set(row)=={'path','directory','uid','gid','mode'} and row['path']==expected and type(row['directory']) is bool and all(type(row[k]) is int and row[k]>=0 for k in ('uid','gid','mode')) and row['mode']<=0o7777,'IDENTITY')
 return True

def retain_tenant_ps(g,tb,source,catalog,codes):
 try:
  expected,uid,gid=tenant_ps_scope(g,tb.tb_frame,source,catalog,codes);v=tb.tb_frame.f_locals;result=v.get('result');snapshot=v.get('ps_context');need(type(result) is subprocess.CompletedProcess and result.args==expected and type(result.stderr) is bytes and type(snapshot) is dict and set(snapshot)=={'tenant_uid','tenant_gid','execution_cwd','parent_cwd'} and snapshot['tenant_uid']==uid and snapshot['tenant_gid']==gid,'IDENTITY')
  raw=result.stderr;text=raw[:8192].decode('utf-8','replace');lo=0;hi=len(text)
  while lo<hi:
   mid=(lo+hi+1)//2
   if len(canonical(text[:mid]))<=8192:lo=mid
   else:hi=mid-1
  p=dict(snapshot,returncode=result.returncode,stderr=text[:lo],stderr_truncated=len(raw)>8192 or lo<len(text));validate_tenant_ps(p,g.c);return p
 except Exception:return None

def listing_sites(tree):
 sites={}
 for cls in tree.body:
  if not isinstance(cls,ast.ClassDef) or cls.name!='Guest':continue
  for fn in cls.body:
   if not isinstance(fn,ast.FunctionDef) or fn.name not in ('stopped','row_units','command'):continue
   for n in ast.walk(fn):
    if not isinstance(n,ast.Call):continue
    key=None
    if fn.name=='stopped' and isinstance(n.func,ast.Attribute) and n.func.attr=='row_units':key='stopped'
    if fn.name=='row_units':
     if isinstance(n.func,ast.Attribute) and n.func.attr=='command':key='listing'
     elif isinstance(n.func,ast.Name) and n.func.id=='decode':key='decode'
     elif isinstance(n.func,ast.Name) and n.func.id=='need' and any(isinstance(x,ast.Attribute) and isinstance(x.value,ast.Name) and x.value.id=='listed' and x.attr=='returncode' for x in ast.walk(n)):key='accept'
    if fn.name=='command' and isinstance(n.func,ast.Name) and n.func.id=='need' and len(n.args)==2 and isinstance(n.args[1],ast.Constant) and n.args[1].value=='CHILD':key='command'
    if key:
     need(key not in sites,'IDENTITY');sites[key]={'function':'Guest.'+fn.name,'line':n.lineno,'column_start':n.col_offset,'column_end':n.end_col_offset}
 need(set(sites)=={'stopped','listing','decode','accept','command'},'IDENTITY');return sites

def listing_call(frame,source,catalog,key):
 site=catalog['systemctl_listing_sites'][key]
 if frame['function']!=site['function'] or frame['line']!=site['line']:return False
 if frame['column_start'] is not None:return (frame['column_start'],frame['column_end'])==(site['column_start'],site['column_end'])
 for code,name in walk_code(compile(source,str(ROOT/'guest.py'),'exec'),''):
  if name!=site['function']:continue
  line=None;calls=[]
  for instruction in dis.get_instructions(code):
   if instruction.starts_line is not None:line=instruction.starts_line
   if line==site['line'] and instruction.opname in ('CALL_FUNCTION','CALL_METHOD','CALL_FUNCTION_KW','CALL_FUNCTION_EX'):calls.append(instruction.offset)
  return bool(calls) and frame['offset']==calls[-1 if key in ('command','accept') else 0]
 return False

def retain_systemctl_listing(g,tb,source,catalog,codes):
 """Only two fixed owned-application listing commands can release child stderr."""
 try:
  frame=tb.tb_frame;trusted=codes.get(id(frame.f_code));need(trusted is not None and trusted[0] is frame.f_code,'IDENTITY');name=trusted[1]
  if name=='Guest.command':
   command=frame;row=frame.f_back;stopped=row.f_back;site='COMMAND'
   need(listing_call(point(frame.f_code,name,tb.tb_lasti,tb.tb_lineno),source,catalog,'command'),'IDENTITY')
   need(listing_call(point(row.f_code,'Guest.row_units',row.f_lasti,row.f_lineno),source,catalog,'listing'),'IDENTITY');result=command.f_locals.get('result')
  else:
   need(name=='Guest.row_units','IDENTITY');command=None;row=frame;stopped=row.f_back;site='RESULT';p=point(frame.f_code,name,tb.tb_lasti,tb.tb_lineno)
   need(any(listing_call(p,source,catalog,key) for key in ('decode','accept')),'IDENTITY');result=row.f_locals.get('listed')
  for f,label in ((row,'Guest.row_units'),(stopped,'Guest.stopped')):
   need(codes.get(id(f.f_code))==(f.f_code,label) and f.f_locals.get('self') is g,'IDENTITY')
  need(listing_call(point(stopped.f_code,'Guest.stopped',stopped.f_lasti,stopped.f_lineno),source,catalog,'stopped'),'IDENTITY')
  c=g.c;need(type(c) is dict and c.get('role') in ('source','target') and c.get('operation') in PHASES and all(type(c.get(k)) is int and c[k]>0 for k in ('subscription_id','site_id','application_id')),'IDENTITY')
  owned=roles(c.get('run_id'))[c['role']];need(all(c.get(k)==owned[k] for k in ('vm','token')),'IDENTITY');aid=str(c['application_id']);prefix='nakpanel-app-'+aid+'-g';kind=row.f_locals.get('kind');s=stopped.f_locals
  need(type(kind) is str and kind in ('list-units','list-unit-files') and row.f_locals.get('prefix')==prefix and s.get('prefix')==prefix and s.get('aid')==aid and s.get('c') is c and type(s.get('before')) is dict and type(s['before'].get('id')) is int and s['before']['id']==c['application_id'],'IDENTITY')
  expected=['systemctl',kind,'--all','--no-pager','--output=json',prefix+'*.service'];accepted=(0,1) if kind=='list-unit-files' else (0,)
  need(type(result) is subprocess.CompletedProcess and type(result.args) is list and result.args==expected and type(result.stderr) is bytes,'IDENTITY')
  if command is not None:
   v=command.f_locals;need(v.get('self') is g and type(v.get('args')) is list and v['args']==expected and v.get('cwd') is None and v.get('env') is None and v.get('data') is None and type(v.get('accepted')) is tuple and v['accepted']==accepted,'IDENTITY')
  raw=result.stderr;text=raw[:8192].decode('utf-8','replace');lo=0;hi=len(text)
  while lo<hi:
   mid=(lo+hi+1)//2
   if len(canonical(text[:mid]))<=8192:lo=mid
   else:hi=mid-1
  p={'site':site,'verb':kind,'returncode':result.returncode,'stderr':text[:lo],'stderr_truncated':len(raw)>8192 or lo<len(text)};validate_systemctl_listing(p,c);return p
 except Exception:return None

def validate_systemctl_listing(p,context):
 need(type(context) is dict and context.get('role') in ('source','target') and context.get('operation') in PHASES and all(type(context.get(k)) is int and context[k]>0 for k in ('subscription_id','site_id','application_id')),'IDENTITY');owned=roles(context.get('run_id'))[context['role']];need(all(context.get(k)==owned[k] for k in ('vm','token')),'IDENTITY')
 need(type(p) is dict and set(p)=={'site','verb','returncode','stderr','stderr_truncated'} and p['site'] in ('COMMAND','RESULT') and p['verb'] in ('list-units','list-unit-files') and type(p['returncode']) is int and -255<=p['returncode']<=255 and type(p['stderr']) is str and len(canonical(p['stderr']))<=8192 and type(p['stderr_truncated']) is bool,'IDENTITY')
 accepted=(0,1) if p['verb']=='list-unit-files' else (0,)
 need((p['returncode'] not in accepted) if p['site']=='COMMAND' else (p['returncode'] in accepted),'IDENTITY');return True

def source_catalog(source):
 """Version-independent fixed source regions; no runtime values are inspected."""
 tree=ast.parse(source);ranges={};loop=None;check_ast=None
 def visit(nodes,prefix=''):
  nonlocal loop,check_ast
  for node in nodes:
   if isinstance(node,ast.ClassDef):visit(node.body,prefix+node.name+'.')
   elif isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
    name=prefix+node.name;ranges[name]=[node.lineno,node.end_lineno]
    if name=='Guest.source_fixtures':
     for n in ast.walk(node):
      if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='checks' for t in n.targets):check_ast=hashlib.sha256(ast.dump(n.value,include_attributes=False).encode()).hexdigest()
      if isinstance(n,ast.For) and isinstance(n.target,ast.Name) and n.target.id=='query' and isinstance(n.iter,ast.Name) and n.iter.id=='checks':loop={'function':name,'line':n.body[0].lineno,'count':6}
    visit(node.body,name+'.')
 visit(tree.body);need(loop is not None and check_ast is not None,'IDENTITY');loop['checks_ast_sha256']=check_ast
 return {'schema':'nakpanel-l3-fixed-guest-sites-v4','guest_sha256':hashlib.sha256(source).hexdigest(),'functions':ranges,'fixture_loop':loop,'maximum_frames':MAX_FRAMES,'systemctl_listing_sites':listing_sites(tree),'tenant_ps_sites':tenant_ps_sites(tree)}

def walk_code(code,name):
 yield code,name
 for value in code.co_consts:
  if isinstance(value,types.CodeType):yield from walk_code(value,name+'.'+value.co_name if name else value.co_name)

def trusted_guest_codes(namespace):
 """Freeze actual code identities before dispatch, including nested code."""
 found={}
 for name,value in tuple(namespace.items()):
  if isinstance(value,types.FunctionType) and value.__globals__ is namespace:
   for code,label in walk_code(value.__code__,name):found[id(code)]=(code,label)
  elif isinstance(value,type) and value.__module__==namespace['__name__']:
   for method,fn in vars(value).items():
    if isinstance(fn,types.FunctionType) and fn.__globals__ is namespace:
     for code,label in walk_code(fn.__code__,name+'.'+method):found[id(code)]=(code,label)
 return found

def point(code,name,offset,line):
 options={'show_caches':True} if sys.version_info>=(3,11) else {}
 instructions=list(dis.get_instructions(code,**options));matches=[i for i in instructions if i.offset==offset];need(len(matches)==1,'IDENTITY');instruction=matches[0]
 lines=[(at,n) for at,n in dis.findlinestarts(code) if at<=offset];need(lines and lines[-1][1]==line,'IDENTITY')
 positions=getattr(instruction,'positions',None)
 return {'function':name,'first_line':code.co_firstlineno,'line':line,'offset':offset,'bytecode_sha256':hashlib.sha256(code.co_code).hexdigest(),'column_start':positions.col_offset if positions else None,'column_end':positions.end_col_offset if positions else None,'end_line':positions.end_lineno if positions else None}

def fixture_index(tb,g,catalog):
 """Only the original six-query loop may release an exact closed index."""
 if tb.tb_lineno!=catalog['fixture_loop']['line']:return 'UNKNOWN'
 values=tb.tb_frame.f_locals
 if values.get('self') is not g or values.get('c') is not g.c:return 'UNKNOWN'
 sid=values.get('sid');ident=g.c.get('subscription_id')
 if type(ident) is not int or ident<=0 or type(sid) is not str or sid!=str(ident):return 'UNKNOWN'
 checks=values.get('checks');query=values.get('query')
 expected=["SELECT count(*) FROM mail_domains WHERE domain='current-bootstrap.test'","SELECT count(*) FROM webmail_hosts WHERE hostname='webmail.current-bootstrap.test'","SELECT count(*) FROM subscription_policy_overrides WHERE subscription_id="+sid,"SELECT count(*) FROM application_instances WHERE subscription_id="+sid,"SELECT count(*) FROM service_secrets WHERE scope='backup' AND name='archive-key'","SELECT count(*) FROM server_backup_destinations WHERE name='l3-local'"]
 if type(checks) is not list or len(checks)!=6 or any(type(x) is not str for x in checks) or checks!=expected or len(set(checks))!=6 or type(query) is not str:return 'UNKNOWN'
 indexes=[i for i,item in enumerate(checks) if item is query]
 return indexes[0] if len(indexes)==1 else 'UNKNOWN'

def capture_guest_failure(error,g,receipt,codes,root,kind=None):
 kind=category(error) if kind is None else kind;fallback=unavailable(receipt.get('reason'),kind)
 try:
  root=Path(root);source=regular(root/'guest.py').read_bytes();catalog=decode(regular(root/'guest-sites.json',max_bytes=131072).read_bytes());need(catalog==source_catalog(source) and catalog['guest_sha256']==receipt['program_sha256']==g.c['program_hashes']['guest.py'] and sha(root/'guest-sites.json')==g.c['program_hashes']['guest-sites.json'] and sha(root/'failure.py')==g.c['program_hashes']['failure.py'],'INPUT_DRIFT')
  frames=[];index='UNKNOWN';tenant=None;listing=None;tb=error.__traceback__;count=0
  while tb is not None:
   count+=1;need(count<=256,'IDENTITY');code=tb.tb_frame.f_code;trusted=codes.get(id(code))
   if trusted is not None:
    need(trusted[0] is code,'IDENTITY');name=trusted[1];frames.append(point(code,name,tb.tb_lasti,tb.tb_lineno))
    if name=='Guest.source_fixtures':index=fixture_index(tb,g,catalog)
    if name=='Guest.command' and kind=='REFUSED' and receipt.get('reason')=='CHILD':tenant=retain_tenant_ps(g,tb,source,catalog,codes)
    if kind=='REFUSED' and ((name=='Guest.command' and receipt.get('reason')=='CHILD') or (name=='Guest.row_units' and receipt.get('reason') in ('IDENTITY','STOPPED'))):
     observed=retain_systemctl_listing(g,tb,source,catalog,codes)
     if observed is not None:listing=observed
   elif Path(code.co_filename).resolve()==(root/'guest.py').resolve():raise Refused('IDENTITY')
   tb=tb.tb_next
  need(frames,'IDENTITY');retained=frames[-MAX_FRAMES:]
  if not any(f['function']=='Guest.source_fixtures' and f['line']==catalog['fixture_loop']['line'] for f in retained):index='UNKNOWN'
  result=dict(fallback,capture='CAPTURED',frames=retained,truncated=len(frames)>MAX_FRAMES,fixture_check_index=index,tenant_ps=tenant,systemctl_listing=listing);validate_detail(result,source,catalog,context=g.c);return result
 except BaseException:return fallback

def validate_detail(d,source=None,catalog=None,context=None):
 need(type(d) is dict and set(d)==DETAIL_KEYS and d['schema']==SCHEMA and d['capture'] in ('CAPTURED','UNAVAILABLE') and d['category'] in CATEGORIES and d['reason'] in REASONS and d['python_tag']==sys.implementation.cache_tag and type(d['truncated']) is bool and type(d['frames']) is list and len(d['frames'])<=MAX_FRAMES,'IDENTITY')
 index=d['fixture_check_index'];need(index=='UNKNOWN' or type(index) is int and 0<=index<=5,'IDENTITY')
 if d['capture']=='UNAVAILABLE':need(d['frames']==[] and d['truncated'] is False and index=='UNKNOWN' and d['tenant_ps'] is None and d['systemctl_listing'] is None,'IDENTITY');return True
 source=(ROOT/'guest.py').read_bytes() if source is None else source;catalog=decode((ROOT/'guest-sites.json').read_bytes()) if catalog is None else catalog;need(catalog==source_catalog(source),'INPUT_DRIFT');compiled=list(walk_code(compile(source,str(ROOT/'guest.py'),'exec'),''));need(d['frames'],'IDENTITY')
 for frame in d['frames']:
  need(type(frame) is dict and set(frame)==FRAME_KEYS and type(frame['function']) is str and len(frame['function'])<=160 and all(type(frame[k]) is int and frame[k]>=0 for k in ('first_line','line','offset')) and type(frame['bytecode_sha256']) is str and SHA.fullmatch(frame['bytecode_sha256']),'IDENTITY')
  need(all(frame[k] is None or type(frame[k]) is int and frame[k]>=0 for k in ('column_start','column_end','end_line')),'IDENTITY')
  regions=[span for name,span in catalog['functions'].items() if frame['function']==name or frame['function'].startswith(name+'.')];need(regions and any(lo<=frame['line']<=hi for lo,hi in regions),'IDENTITY')
  candidates=[code for code,name in compiled if name==frame['function'] and code.co_firstlineno==frame['first_line'] and hashlib.sha256(code.co_code).hexdigest()==frame['bytecode_sha256']];need(candidates and any(point(code,frame['function'],frame['offset'],frame['line'])==frame for code in candidates),'IDENTITY')
 if d['systemctl_listing'] is not None:
  p=d['systemctl_listing'];validate_systemctl_listing(p,context);need(d['category']=='REFUSED','IDENTITY')
  if p['site']=='COMMAND':need(d['reason']=='CHILD' and len(d['frames'])>=3 and [f['function'] for f in d['frames'][-3:]]==['Guest.stopped','Guest.row_units','Guest.command'] and all(listing_call(f,source,catalog,k) for f,k in zip(d['frames'][-3:],('stopped','listing','command'))),'IDENTITY')
  else:need(d['reason'] in ('IDENTITY','STOPPED') and len(d['frames'])>=2 and [f['function'] for f in d['frames'][-2:]]==['Guest.stopped','Guest.row_units'] and listing_call(d['frames'][-2],source,catalog,'stopped') and any(listing_call(d['frames'][-1],source,catalog,k) for k in ('decode','accept')),'IDENTITY')
 if d['tenant_ps'] is not None:
  validate_tenant_ps(d['tenant_ps'],context);need(d['category']=='REFUSED' and d['reason']=='CHILD' and len(d['frames'])>=3 and [f['function'] for f in d['frames'][-3:]]==['Guest.stopped','Guest.rootless','Guest.command'] and all(tenant_ps_call(f,source,catalog) for f in d['frames'][-3:]),'IDENTITY')
 if type(index) is int:need(any(f['function']=='Guest.source_fixtures' and f['line']==catalog['fixture_loop']['line'] for f in d['frames']),'IDENTITY')
 return True

def validate_failed_remote(row,c,input_sha,rec):
 need(type(row) is dict and row.get('schema')=='nakpanel-l3-remote-v1' and all(row.get(k)==c[k] for k in ('operation','operation_id','role','vm','token','run_id')) and row.get('source_commit')==SOURCE and row.get('program_sha256')==c['program_hashes']['guest.py'] and row.get('input_sha256')==input_sha,'REMOTE_UNKNOWN')
 need(row.get('known') is True and row.get('status')=='FAIL' and type(row.get('exit_code')) is int and row['exit_code']==1 and row.get('payload') is None and type(row.get('reason')) is str and row['reason'] in REASONS and all(type(row.get(k)) in (int,float) and math.isfinite(row[k]) for k in ('started_monotonic','finished_monotonic')) and row['started_monotonic']<=row['finished_monotonic'],'REMOTE_UNKNOWN')
 need(type(rec) is dict and rec.get('status')=='FAIL' and rec.get('failure_code')=='exit' and type(rec.get('exit_code')) is int and rec['exit_code']==row['exit_code'] and rec.get('process_exited') is True and rec.get('process_group_empty') is True,'REMOTE_UNKNOWN');binding=rec.get('binding');need(type(binding) is dict and all(binding.get(k)==c[k] for k in ('run_id','role','vm','token','operation')) and binding.get('source_commit')==SOURCE,'REMOTE_UNKNOWN');return True

def retain_failed_remote(root,c,input_sha,row,rec,state):
 validate_failed_remote(row,c,input_sha,rec);root=physical_dir(root);phase=c['operation'];need(phase in PHASES,'IDENTITY');snapshot=root/(phase.lower()+'-remote-failed.json');publish(snapshot,row,cap=4*1024*1024);custody=root/'logs'/rec['phase']/'receipt.json';need(decode(regular(custody).read_bytes())==rec,'IDENTITY')
 state['failed_remote']={'phase':phase,'operation_id':c['operation_id'],'role':c['role'],'snapshot_sha256':sha(snapshot),'custody_phase':rec['phase'],'custody_sha256':sha(custody),'intent_sha256':sha(root/(phase.lower()+'-intent.json'))}

def project_failure(root,state):
 root=physical_dir(root);need(state.get('overall')!='PASS' and state.get('remote_known') is True and state.get('drained') is True,'IDENTITY');context=decode(regular(root/'run-context.json').read_bytes());s=root.stat();need(context.get('run_id')==state.get('run_id') and context.get('controller_commit')==state.get('controller_commit') and context.get('source_commit')==SOURCE and context.get('roles')==roles(context.get('run_id')) and context.get('root_identity')==[s.st_dev,s.st_ino] and state.get('context_sha256')==sha(root/'run-context.json'),'IDENTITY')
 ref=state.get('failed_remote');need(type(ref) is dict and set(ref)=={'phase','operation_id','role','snapshot_sha256','custody_phase','custody_sha256','intent_sha256'} and ref['phase'] in PHASES and ref['role'] in ('source','target') and type(ref['custody_phase']) is str and re.fullmatch(r'a[0-9]{3,5}-(?:source|target)',ref['custody_phase']) and type(ref['operation_id']) is str and re.fullmatch('[a-f0-9]{32}',ref['operation_id']) and all(type(ref[k]) is str and SHA.fullmatch(ref[k]) for k in ('snapshot_sha256','custody_sha256','intent_sha256')),'IDENTITY')
 need({'phase':ref['custody_phase'],'sha256':ref['custody_sha256']} in state['custody'],'IDENTITY');custody=root/'logs'/ref['custody_phase'];receipt=regular(custody/'receipt.json');snapshot=regular(root/(ref['phase'].lower()+'-remote-failed.json'));intent=regular(root/(ref['phase'].lower()+'-intent.json'));need(sha(receipt)==ref['custody_sha256'] and sha(snapshot)==ref['snapshot_sha256'] and sha(intent)==ref['intent_sha256'],'IDENTITY');request=decode(intent.read_bytes());c=request['context'];input_sha=hashlib.sha256(canonical(c)).hexdigest();need(request['input_sha256']==input_sha and all(c.get(k)==ref[v] for k,v in [('operation','phase'),('operation_id','operation_id'),('role','role')]) and c.get('run_id')==context['run_id'] and all(c.get(k)==context['roles'][ref['role']][k] for k in ('vm','token')),'IDENTITY')
 for n in ('guest.py','failure.py','guest-sites.json'):need(c['program_hashes'].get(n)==sha(ROOT/n),'INPUT_DRIFT')
 rec=decode(receipt.read_bytes());row=decode(snapshot.read_bytes());validate_failed_remote(row,c,input_sha,rec)
 for name in ('stdout','stderr'):
  log=regular(custody/(name+'.log'),max_bytes=64*1024*1024);proof=rec.get(name);need(type(proof) is dict and proof.get('sha256')==sha(log) and proof.get('bytes')==log.stat().st_size,'IDENTITY')
 need(snapshot.read_bytes()==(custody/'stdout.log').read_bytes(),'IDENTITY');detail=row.get('failure_detail');validate_detail(detail,context=c);need(detail['reason']==row['reason'],'IDENTITY')
 return {'operation':c['operation'],'operation_id':c['operation_id'],'role':c['role'],'program_sha256':row['program_sha256'],'input_sha256':input_sha,'remote_exit_code':1,'host_exit_code':1,'host_reaped':True,'host_drained':True,'failure':detail}
