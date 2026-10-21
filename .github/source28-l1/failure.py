"""Bounded observations of the existing guest exception and sealed child exit.

Only the exact first read-only tenant ps site and two fixed application unit
listing sites may return bounded stderr; cwd metadata remains ps-only. No stdout, arguments, environment or SQL are returned. Source is
compiled for validation only, never executed by the host projector.
"""
import ast,dis,hashlib,math,os,re,stat,subprocess,sys,types
import waitdiag
from pathlib import Path
from l1 import ROOT,SOURCE,PHASES,REASONS,SHA,Refused,need,sha,decode,canonical,regular,physical_dir,publish,roles,validate_restore
SCHEMA='nakpanel-l1-guest-failure-v7'
CATEGORIES={'REFUSED','OS_ERROR','CHILD_ERROR','TIMEOUT','CANCELLED','UNEXPECTED','REMOTE_UNKNOWN'}
FRAME_KEYS={'function','first_line','line','offset','bytecode_sha256','column_start','column_end','end_line'}
DETAIL_KEYS={'schema','capture','category','reason','python_tag','frames','truncated','fixture_check_index','wait_observation','tenant_ps','systemctl_listing','go_config_ancestor','restore_validation','strict_post'}
MAX_FRAMES=12
RESTORE_CORE_FILE='l1.py'
RESTORE_ACTOR='source26-l1'
RESTORE_GUARDS=('OUTER','SUMMARY','SERVICES')
RESTORE_KEYS=('summary','schema_mismatch','services_started')
RESTORE_SUMMARY_KEYS=('manifest','extracted_entries','mariadb_restored','users_created','services_started','schema_mismatch','duration_ms')
RESTORE_SERVICES=('nakpanel-agent.service','nakpanel.service','nginx.service','named.service','stalwart-mail.service','nakpanel-proftpd.service')
RESTORE_TYPES=('ABSENT','NULL','OBJECT','LIST','BOOLEAN','INTEGER','STRING','NUMBER','OTHER')
RESTORE_CODE=validate_restore.__code__

def restore_sites(tree):
 core=(ROOT/RESTORE_CORE_FILE).read_bytes();fn=next(n for n in ast.parse(core).body if isinstance(n,ast.FunctionDef) and n.name=='validate_restore');calls=sorted([n for n in ast.walk(fn) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='need'],key=lambda n:(n.lineno,n.col_offset));need(len(calls)==3,'IDENTITY');guest=[]
 for cls in tree.body:
  if isinstance(cls,ast.ClassDef) and cls.name=='Guest':
   for method in cls.body:
    if isinstance(method,ast.FunctionDef) and method.name=='restore':guest += [n for n in ast.walk(method) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='validate_restore' and ast.dump(n,include_attributes=False)==ast.dump(ast.parse("validate_restore(result,self.c['manifest'])",mode='eval').body,include_attributes=False)]
 need(len(guest)==1,'IDENTITY');n=guest[0];return {'core_sha256':hashlib.sha256(core).hexdigest(),'guest_site':{'function':'Guest.restore','line':n.lineno,'column_start':n.col_offset,'column_end':n.end_col_offset},'predicates':[{'id':label,'function':'validate_restore','line':n.lineno,'column_start':n.col_offset,'column_end':n.end_col_offset} for label,n in zip(RESTORE_GUARDS,calls)]}

def restore_call(frame,source,catalog,guard=None):
 info=catalog['restore_validation_sites'];site=info['guest_site'] if guard is None else next((s for s in info['predicates'] if s['id']==guard),None)
 if site is None or frame['function']!=site['function'] or frame['line']!=site['line']:return False
 if frame['column_start'] is not None:return (frame['column_start'],frame['column_end'])==(site['column_start'],site['column_end'])
 for code,name in walk_code(compile(source,str(ROOT/('guest.py' if guard is None else RESTORE_CORE_FILE)),'exec'),''):
  if name!=site['function']:continue
  instructions=list(dis.get_instructions(code));calls=[];selected=False
  for i,instruction in enumerate(instructions):
   if guard is None:
    if instruction.opname=='LOAD_GLOBAL' and instruction.argval=='validate_restore':selected=True
    elif selected and instruction.opname in ('CALL_FUNCTION','CALL_METHOD','CALL_FUNCTION_KW','CALL_FUNCTION_EX'):return frame['offset']==instruction.offset
   elif instruction.opname=='LOAD_CONST' and instruction.argval=='FORMAT' and i+1<len(instructions) and instructions[i+1].opname=='CALL_FUNCTION' and instructions[i+1].arg==2:calls.append(instructions[i+1].offset)
  return guard is not None and len(calls)==3 and frame['offset']==calls[RESTORE_GUARDS.index(guard)]
 return False

def restore_scope(c):
 need(type(c) is dict and c.get('role')=='target' and c.get('operation')=='RESTORE' and type(c.get('operation_id')) is str and re.fullmatch('[a-f0-9]{32}',c['operation_id']) and type(c.get('manifest')) is dict and type(c.get('program_hashes')) is dict and c['program_hashes'].get(RESTORE_CORE_FILE)==sha(ROOT/RESTORE_CORE_FILE),'IDENTITY');owned=roles(c.get('run_id'))['target'];need(all(c.get(k)==owned[k] for k in ('vm','token')),'IDENTITY');return True

def restore_kind(v):return {type(None):'NULL',dict:'OBJECT',list:'LIST',bool:'BOOLEAN',int:'INTEGER',str:'STRING',float:'NUMBER'}.get(type(v),'OTHER')
def restore_number(v):return v if type(v) is int and -2**63<=v<2**63 else None

def restore_box(value,allowed):
 obj=value if type(value) is dict else {};need(len(obj)<=128,'IDENTITY');return {'type':restore_kind(value),'known_keys':[k for k in allowed if k in obj],'extra_keys':len(set(obj)-set(allowed)) if type(value) is dict else None,'field_types':{k:restore_kind(obj[k]) if k in obj else 'ABSENT' for k in allowed},'schema_mismatch':obj.get('schema_mismatch') if type(obj.get('schema_mismatch')) is bool else None}

def restore_sequence(value,kind):
 out={'type':restore_kind(value),'count':None,'known_names':[],'instance_names':[],'unknown_names':None,'invalid_items':None,'sha256':None}
 if type(value) is not list:return out
 need(len(value)<=128,'IDENTITY');raw=canonical(value);need(len(raw)<=65536,'IDENTITY');known=('np_current_bootstrap','roundcube') if kind=='database' else RESTORE_SERVICES;names=[n for n in value if type(n) is str and n in known];instances=[n for n in value if kind=='service' and type(n) is str and re.fullmatch(r'nakpanel-(?:valkey@[1-9][0-9]{0,18}\.service|task-[1-9][0-9]{0,18}\.timer)',n)];return dict(out,count=len(value),known_names=names,instance_names=instances,unknown_names=sum(type(n) is str for n in value)-len(names)-len(instances),invalid_items=sum(type(n) is not str for n in value),sha256=hashlib.sha256(raw).hexdigest())

def restore_facts(result,manifest):
 r=result if type(result) is dict else {};s=r.get('summary');summary=s if type(s) is dict else {};m=summary.get('manifest');raw=canonical(m) if type(m) is dict else None;need(raw is None or len(raw)<=65536,'IDENTITY');return {'result':restore_box(result,RESTORE_KEYS),'summary':restore_box(s,RESTORE_SUMMARY_KEYS),'manifest_equal':type(m) is dict and m==manifest,'manifest_sha256':hashlib.sha256(raw).hexdigest() if raw is not None else None,'expected_manifest_sha256':hashlib.sha256(canonical(manifest)).hexdigest(),'extracted_entries':restore_number(summary.get('extracted_entries')),'mariadb':restore_sequence(summary.get('mariadb_restored'),'database'),'services':restore_sequence(summary.get('services_started'),'service'),'outer_services':restore_sequence(r.get('services_started'),'service'),'services_equal':summary.get('services_started')==r.get('services_started'),'duration_ms':restore_number(summary.get('duration_ms'))}

def restore_predicate_fails(guard,p):
 if guard=='OUTER':return p['result']['type']!='OBJECT' or p['result']['schema_mismatch'] is not True
 if guard=='SUMMARY':return not(p['summary']['type']=='OBJECT' and p['summary']['schema_mismatch'] is True and p['manifest_equal'] and type(p['extracted_entries']) is int and p['extracted_entries']>0 and p['mariadb']['type']=='LIST' and 'np_current_bootstrap' in p['mariadb']['known_names'])
 services=p['services'];return not(services['type']=='LIST' and p['services_equal'] and set(services['known_names'])==set(RESTORE_SERVICES) and services['instance_names']==[] and services['unknown_names']==0 and services['invalid_items']==0 and type(p['duration_ms']) is int and p['duration_ms']>=0)

def validate_restore_detail(p,c,catalog):
 restore_scope(c);need(type(p) is dict and set(p)=={'predicate','result','summary','manifest_equal','manifest_sha256','expected_manifest_sha256','extracted_entries','mariadb','services','outer_services','services_equal','duration_ms'},'IDENTITY');pred=p['predicate'];need(type(pred) is dict and set(pred)=={'id','frame'} and pred['id'] in RESTORE_GUARDS,'IDENTITY');frame=pred['frame'];core=(ROOT/RESTORE_CORE_FILE).read_bytes();need(catalog['restore_validation_sites']['core_sha256']==hashlib.sha256(core).hexdigest() and type(frame) is dict and set(frame)==FRAME_KEYS,'IDENTITY');need(frame['function']=='validate_restore' and type(frame['offset']) is int and type(frame['line']) is int,'IDENTITY');compiled=[code for code,name in walk_code(compile(core,str(ROOT/RESTORE_CORE_FILE),'exec'),'') if name=='validate_restore'];need(len(compiled)==1 and point(compiled[0],'validate_restore',frame['offset'],frame['line'])==frame and restore_call(frame,core,catalog,pred['id']),'IDENTITY')
 for key,allowed in (('result',RESTORE_KEYS),('summary',RESTORE_SUMMARY_KEYS)):
  v=p[key];need(type(v) is dict and set(v)=={'type','known_keys','extra_keys','field_types','schema_mismatch'} and type(v['type']) is str and v['type'] in RESTORE_TYPES and v['type']!='ABSENT' and type(v['known_keys']) is list and v['known_keys']==[k for k in allowed if k in v['known_keys']] and type(v['field_types']) is dict and set(v['field_types'])==set(allowed) and all(type(t) is str and t in RESTORE_TYPES for t in v['field_types'].values()) and v['known_keys']==[k for k in allowed if v['field_types'][k]!='ABSENT'] and (v['schema_mismatch'] is None or type(v['schema_mismatch']) is bool),'IDENTITY');need((v['type']=='OBJECT' and type(v['extra_keys']) is int and 0<=v['extra_keys']<=128) or (v['type']!='OBJECT' and v['known_keys']==[] and v['extra_keys'] is None),'IDENTITY');need((v['field_types']['schema_mismatch']=='BOOLEAN')==(type(v['schema_mismatch']) is bool),'IDENTITY')
 for key,kind in (('mariadb','database'),('services','service'),('outer_services','service')):
  v=p[key];need(type(v) is dict and set(v)=={'type','count','known_names','instance_names','unknown_names','invalid_items','sha256'} and type(v['type']) is str and v['type'] in RESTORE_TYPES and type(v['known_names']) is list and type(v['instance_names']) is list,'IDENTITY');known=('np_current_bootstrap','roundcube') if kind=='database' else RESTORE_SERVICES;need(len(v['known_names'])<=128 and all(type(n) is str and n in known for n in v['known_names']) and len(v['instance_names'])<=128 and all(kind=='service' and type(n) is str and re.fullmatch(r'nakpanel-(?:valkey@[1-9][0-9]{0,18}\.service|task-[1-9][0-9]{0,18}\.timer)',n) for n in v['instance_names']),'IDENTITY')
  if v['type']=='LIST':need(all(type(v[n]) is int and 0<=v[n]<=128 for n in ('count','unknown_names','invalid_items')) and v['count']==len(v['known_names'])+len(v['instance_names'])+v['unknown_names']+v['invalid_items'] and type(v['sha256']) is str and SHA.fullmatch(v['sha256']),'IDENTITY')
  else:need(v['count'] is None and v['known_names']==[] and v['instance_names']==[] and v['unknown_names'] is None and v['invalid_items'] is None and v['sha256'] is None,'IDENTITY')
 need(all(type(p[n]) is bool for n in ('manifest_equal','services_equal')) and all(p[n] is None or type(p[n]) is int and -2**63<=p[n]<2**63 for n in ('extracted_entries','duration_ms')) and p['expected_manifest_sha256']==hashlib.sha256(canonical(c['manifest'])).hexdigest() and (p['manifest_sha256'] is None or type(p['manifest_sha256']) is str and SHA.fullmatch(p['manifest_sha256'])),'IDENTITY');need(all(not restore_predicate_fails(guard,p) for guard in RESTORE_GUARDS[:RESTORE_GUARDS.index(pred['id'])]) and restore_predicate_fails(pred['id'],p),'IDENTITY');return True

def retain_restore_validation(g,tb,source,catalog,codes):
 try:
  frame=tb.tb_frame;v=frame.f_locals;c=g.c;restore_scope(c);need(codes.get(id(frame.f_code))==(frame.f_code,'Guest.restore') and v.get('self') is g and restore_call(point(frame.f_code,'Guest.restore',tb.tb_lasti,tb.tb_lineno),source,catalog),'IDENTITY');inner=tb.tb_next;last=inner.tb_next;need(inner.tb_frame.f_code is RESTORE_CODE and last is not None and last.tb_next is None and last.tb_frame.f_code is need.__code__ and (last.tb_frame.f_locals.get('test') is False or last.tb_frame.f_locals.get('test') is None) and last.tb_frame.f_locals.get('code')=='FORMAT','IDENTITY');values=inner.tb_frame.f_locals;need(values.get('r') is v.get('result') and values.get('m') is c['manifest'],'IDENTITY');result=v.get('r');need(type(result) is subprocess.CompletedProcess and type(result.returncode) is int and result.returncode==0 and type(result.stdout) is bytes and result.args==['/usr/local/bin/panelctl','--actor',RESTORE_ACTOR,'restore-server','--archive',str(g.root/'archive.nkbk'),'--backup-key-file',str(g.root/'backup.key'),'--allow-schema-mismatch','--skip-converge','--yes','--json'] and decode(result.stdout)==v['result'],'IDENTITY');pnt=point(inner.tb_frame.f_code,'validate_restore',inner.tb_lasti,inner.tb_lineno);core=(ROOT/RESTORE_CORE_FILE).read_bytes();matches=[guard for guard in RESTORE_GUARDS if restore_call(pnt,core,catalog,guard)];need(len(matches)==1,'IDENTITY');p=restore_facts(v['result'],c['manifest']);p['predicate']={'id':matches[0],'frame':pnt};validate_restore_detail(p,c,catalog);return p
 except Exception:return None



STRICT_SITES=('CLI_OUTPUT','RUN_ID','RUN_STATE','JOBS')
STRICT_STATES=('available','cancelled','completed','discarded','pending','retryable','running','scheduled','OTHER')
STRICT_KINDS=('reconcile_system','reconcile_php_application','reconcile_php_workers','converge_subscription','reconcile_applications','converge_application','configure_mail','OTHER')

def strict_post_sites(tree):
 methods=[fn for cls in tree.body if isinstance(cls,ast.ClassDef) and cls.name=='Guest' for fn in cls.body if isinstance(fn,ast.FunctionDef) and fn.name=='strict_post'];need(len(methods)==1,'IDENTITY');calls=sorted([n for n in ast.walk(methods[0]) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='need' and len(n.args)==2 and isinstance(n.args[1],ast.Constant) and n.args[1].value=='STRICT_POST'],key=lambda n:(n.lineno,n.col_offset));need(len(calls)==4,'IDENTITY');return [{'id':label,'function':'Guest.strict_post','line':n.lineno,'column_start':n.col_offset,'column_end':n.end_col_offset} for label,n in zip(STRICT_SITES,calls)]

def strict_post_site(frame,source,catalog):
 sites=catalog['strict_post_sites']
 if frame['function']!='Guest.strict_post':return None
 if frame['column_start'] is not None:return next((s['id'] for s in sites if (frame['line'],frame['column_start'],frame['column_end'])==(s['line'],s['column_start'],s['column_end'])),None)
 for code,name in walk_code(compile(source,str(ROOT/'guest.py'),'exec'),''):
  if name!='Guest.strict_post':continue
  instructions=list(dis.get_instructions(code));calls=[instructions[i+1].offset for i,n in enumerate(instructions[:-1]) if n.opname=='LOAD_CONST' and n.argval=='STRICT_POST' and instructions[i+1].opname=='CALL_FUNCTION' and instructions[i+1].arg==2]
  return STRICT_SITES[calls.index(frame['offset'])] if len(calls)==4 and frame['offset'] in calls else None
 return None

def strict_post_scope(c):
 need(type(c) is dict and c.get('role')=='target' and c.get('operation')=='STRICT_POST' and type(c.get('operation_id')) is str and re.fullmatch('[a-f0-9]{32}',c['operation_id']) and type(c.get('program_hashes')) is dict and c['program_hashes'].get(RESTORE_CORE_FILE)==sha(ROOT/RESTORE_CORE_FILE),'IDENTITY');owned=roles(c.get('run_id'))['target'];need(all(c.get(k)==owned[k] for k in ('vm','token')),'IDENTITY');return True

def strict_post_facts(v):
 result=v.get('result');need(type(result) is subprocess.CompletedProcess and type(result.stdout) is bytes and type(result.stderr) is bytes and type(result.returncode) is int,'IDENTITY');r=v.get('run');run=r if type(r) is dict else {};out={'cli_exit':result.returncode,'cli_summary_matches':re.fullmatch(rb'post-restore convergence finished \([0-9]+ MariaDB users, 0 warnings\)\n',result.stdout) is not None,'cli_warning_absent':b'warning:' not in result.stderr,'id_count':len(v['ids']) if type(v.get('ids')) is list and len(v['ids'])<=1024 else None,'run_id':restore_number(v.get('runid')),'run_status':run.get('status') if type(run.get('status')) is str and run['status'] in ('active','failed','cancelled','pending') else 'OTHER' if type(run.get('status')) is str else None,'sites_total':restore_number(run.get('sites_total')),'sites_ok':restore_number(run.get('sites_ok')),'run_error_empty':run.get('last_error')=='' if type(r) is dict else None,'before_count':len(v['before']) if type(v.get('before')) is list and len(v['before'])<=100000 else None,'jobs_count':len(v['jobs']) if type(v.get('jobs')) is list and len(v['jobs'])<=100000 else None,'new_count':None,'states':None,'kinds':None,'required_system_job':None,'subscription_job':None,'application_sweep_job':None}
 new=v.get('new')
 if type(new) is not list:return out
 need(len(new)<=1024,'IDENTITY');states={s:0 for s in STRICT_STATES};kinds={s:0 for s in STRICT_KINDS};rows=[j if type(j) is dict else {} for j in new]
 for j in rows:states[j.get('state') if type(j.get('state')) is str and j['state'] in STRICT_STATES else 'OTHER']+=1;kinds[j.get('kind') if type(j.get('kind')) is str and j['kind'] in STRICT_KINDS else 'OTHER']+=1
 return dict(out,new_count=len(new),states=states,kinds=kinds,required_system_job=any(j.get('kind')=='reconcile_system' and type(j.get('args')) is dict and j['args'].get('run_id')==v.get('runid') for j in rows),subscription_job=any(j.get('kind')=='converge_subscription' for j in rows),application_sweep_job=any(j.get('kind')=='reconcile_applications' for j in rows))

def validate_strict_post(p,c):
 strict_post_scope(c);need(type(p) is dict and set(p)=={'site','cli_exit','cli_summary_matches','cli_warning_absent','id_count','run_id','run_status','sites_total','sites_ok','run_error_empty','before_count','jobs_count','new_count','states','kinds','required_system_job','subscription_job','application_sweep_job'} and type(p['site']) is str and p['site'] in STRICT_SITES and type(p['cli_exit']) is int and -255<=p['cli_exit']<=255 and all(type(p[k]) is bool for k in ('cli_summary_matches','cli_warning_absent')),'IDENTITY');need(all(p[k] is None or type(p[k]) is int and -2**63<=p[k]<2**63 for k in ('id_count','run_id','sites_total','sites_ok','before_count','jobs_count','new_count')) and (p['run_status'] is None or type(p['run_status']) is str and p['run_status'] in ('active','failed','cancelled','pending','OTHER')) and all(p[k] is None or type(p[k]) is bool for k in ('run_error_empty','required_system_job','subscription_job','application_sweep_job')),'IDENTITY')
 for key,allowed in (('states',STRICT_STATES),('kinds',STRICT_KINDS)):
  if p['new_count'] is None:need(p[key] is None,'IDENTITY')
  else:need(0<=p['new_count']<=1024 and type(p[key]) is dict and set(p[key])==set(allowed) and all(type(n) is int and 0<=n<=1024 for n in p[key].values()) and sum(p[key].values())==p['new_count'],'IDENTITY')
 failures=(not(p['cli_summary_matches'] and p['cli_warning_absent']),p['id_count']!=1,not(p['run_status']=='active' and p['sites_total']==p['sites_ok'] and p['run_error_empty'] is True),not(type(p['new_count']) is int and p['new_count']>0 and p['states']['completed']==p['new_count'] and p['required_system_job'] is True and p['subscription_job'] is True and p['application_sweep_job'] is True));i=STRICT_SITES.index(p['site']);need(all(not failed for failed in failures[:i]) and failures[i],'IDENTITY');return True

def retain_strict_post(g,tb,source,catalog,codes):
 try:
  frame=tb.tb_frame;v=frame.f_locals;c=g.c;strict_post_scope(c);need(codes.get(id(frame.f_code))==(frame.f_code,'Guest.strict_post') and v.get('self') is g,'IDENTITY');site=strict_post_site(point(frame.f_code,'Guest.strict_post',tb.tb_lasti,tb.tb_lineno),source,catalog);inner=tb.tb_next;need(site in STRICT_SITES and inner is not None and inner.tb_next is None and inner.tb_frame.f_code is need.__code__ and inner.tb_frame.f_locals.get('code')=='STRICT_POST','IDENTITY');test=inner.tb_frame.f_locals.get('test');need(test is False or test is None or site=='JOBS' and type(test) is list and test==[] and test is v.get('new'),'IDENTITY');p=dict(strict_post_facts(v),site=site);validate_strict_post(p,c);return p
 except Exception:return None

def category(error):
 if isinstance(error,Refused):return 'REFUSED'
 if isinstance(error,(KeyboardInterrupt,SystemExit)):return 'CANCELLED'
 if isinstance(error,subprocess.TimeoutExpired):return 'TIMEOUT'
 if isinstance(error,subprocess.CalledProcessError):return 'CHILD_ERROR'
 if isinstance(error,OSError):return 'OS_ERROR'
 return 'UNEXPECTED'

def unavailable(reason,kind='UNEXPECTED'):
 return {'schema':SCHEMA,'capture':'UNAVAILABLE','category':kind if kind in CATEGORIES else 'UNEXPECTED','reason':reason if type(reason) is str and reason in REASONS else 'UNKNOWN','python_tag':sys.implementation.cache_tag,'frames':[],'truncated':False,'fixture_check_index':'UNKNOWN','wait_observation':None,'tenant_ps':None,'systemctl_listing':None,'go_config_ancestor':None,'restore_validation':None,'strict_post':None}

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

GO_ANCESTORS={'CONFIG_GO':'/var/lib/nakpanel/.config/go','CONFIG_GIT':'/var/lib/nakpanel/.config/git','CONFIG':'/var/lib/nakpanel/.config','HOME':'/var/lib/nakpanel','VAR_LIB':'/var/lib','VAR':'/var','ROOT':'/'}
GO_PROBES=('/var/lib/nakpanel/.config/go/env','/var/lib/nakpanel/.netrc','/var/lib/nakpanel/.gitconfig','/var/lib/nakpanel/.config/git/config')
GO_CHAINS=(('CONFIG_GO','CONFIG','HOME','VAR_LIB','VAR','ROOT'),('HOME','VAR_LIB','VAR','ROOT'),('HOME','VAR_LIB','VAR','ROOT'),('CONFIG_GIT','CONFIG','HOME','VAR_LIB','VAR','ROOT'))

def go_ancestor_sites(tree):
 sites={};wanted={'go_ancestors':'need','go_config_absent':'go_ancestors','Guest.trust_files':'go_config_absent','Guest.target_baseline':'trust_files'}
 def visit(nodes,prefix=''):
  for node in nodes:
   if isinstance(node,ast.ClassDef):visit(node.body,prefix+node.name+'.')
   elif isinstance(node,ast.FunctionDef) and prefix+node.name in wanted:
    name=prefix+node.name
    for n in ast.walk(node):
     if isinstance(n,ast.Call) and ((isinstance(n.func,ast.Name) and n.func.id==wanted[name]) or (isinstance(n.func,ast.Attribute) and n.func.attr==wanted[name])):
      need(name not in sites,'IDENTITY');sites[name]={'line':n.lineno,'column_start':n.col_offset,'column_end':n.end_col_offset}
 visit(tree.body);need(set(sites)==set(wanted),'IDENTITY');return sites

def go_ancestor_call(frame,source,catalog):
 site=catalog['go_config_ancestor_sites'].get(frame['function'])
 if site is None or frame['line']!=site['line']:return False
 if frame['column_start'] is not None:return (frame['column_start'],frame['column_end'])==(site['column_start'],site['column_end'])
 # On Python3.9, go_ancestors is followed only by absent(p) on its
 # fixed caller line; the other three selected calls are last on their line.
 for code,name in walk_code(compile(source,str(ROOT/'guest.py'),'exec'),''):
  if name!=frame['function']:continue
  line=None;calls=[]
  for instruction in dis.get_instructions(code):
   if instruction.starts_line is not None:line=instruction.starts_line
   if line==site['line'] and instruction.opname in ('CALL_FUNCTION','CALL_METHOD','CALL_FUNCTION_KW','CALL_FUNCTION_EX'):calls.append(instruction.offset)
  index=-2 if name=='go_config_absent' else -1
  return len(calls)>=abs(index) and frame['offset']==calls[index]
 return False

def validate_go_ancestor(p,context):
 need(type(context) is dict and context.get('role')=='target' and context.get('operation')=='TARGET_BASELINE' and type(context.get('operation_id')) is str and re.fullmatch('[0-9a-f]{32}',context['operation_id']),'IDENTITY');owned=roles(context.get('run_id'))['target'];need(all(context.get(k)==owned[k] for k in ('vm','token')),'IDENTITY')
 need(type(p) is dict and set(p)=={'probe','ancestor','type','directory','uid','gid','mode','uidset'} and type(p['probe']) is int and 0<=p['probe']<4 and type(p['ancestor']) is str and p['ancestor'] in GO_CHAINS[p['probe']] and p['type'] in ('DIRECTORY','REGULAR','SYMLINK','OTHER') and type(p['directory']) is bool and p['directory']==(p['type']=='DIRECTORY'),'IDENTITY')
 need(all(type(p[k]) is int and 0<=p[k]<=0xffffffff for k in ('uid','gid')) and type(p['mode']) is int and 0<=p['mode']<=0o7777 and type(p['uidset']) is list and len(p['uidset'])==3 and all(type(x) is int and 0<=x<=0xffffffff for x in p['uidset']) and p['uidset'][0]==0 and p['uidset'][2]>0,'IDENTITY')
 need(not (p['directory'] and p['uid'] in p['uidset'] and not p['mode']&0o022),'IDENTITY');return True

def retain_go_ancestor(g,tb,source,catalog,codes):
 """Only cached lstat facts at the original failed target-config predicate."""
 try:
  safe=tb.tb_frame;config=safe.f_back;trust=config.f_back;baseline=trust.f_back;frames=(safe,config,trust,baseline);names=('go_ancestors','go_config_absent','Guest.trust_files','Guest.target_baseline')
  for i,(frame,name) in enumerate(zip(frames,names)):
   entry=codes.get(id(frame.f_code));need(entry is not None and entry[0] is frame.f_code and entry[1]==name,'IDENTITY');p=point(frame.f_code,name,tb.tb_lasti if i==0 else frame.f_lasti,tb.tb_lineno if i==0 else frame.f_lineno);need(go_ancestor_call(p,source,catalog),'IDENTITY')
  need(trust.f_locals.get('self') is g and baseline.f_locals.get('self') is g and g.operation=='TARGET_BASELINE','IDENTITY');c=g.c;v=safe.f_locals;cv=config.f_locals;home=Path('/var/lib/nakpanel');boundary=Path('/')
  need(cv.get('home')==home and cv.get('boundary')==boundary and v.get('boundary')==boundary and cv.get('stage')==Path(c.get('migration_stage',str(g.root))),'IDENTITY');probe=cv.get('p');need(type(probe) is type(home) and str(probe) in GO_PROBES,'IDENTITY');index=GO_PROBES.index(str(probe));need(v.get('path')==probe.parent and v.get('p')==probe.parent,'IDENTITY')
  x=v.get('x');s=v.get('s');uidset=v.get('uidset');manager=trust.f_locals.get('uid');need(type(x) is type(home) and type(s) is os.stat_result and type(s.st_mode) is int and 0<=s.st_mode<=0o177777 and type(uidset) is tuple and len(uidset)==3 and type(manager) is int and 0<manager<=0xffffffff and uidset[2]==manager,'IDENTITY');matches=[name for name in GO_CHAINS[index] if x==Path(GO_ANCESTORS[name])];need(len(matches)==1,'IDENTITY')
  kind='DIRECTORY' if stat.S_ISDIR(s.st_mode) else 'REGULAR' if stat.S_ISREG(s.st_mode) else 'SYMLINK' if stat.S_ISLNK(s.st_mode) else 'OTHER';result={'probe':index,'ancestor':matches[0],'type':kind,'directory':kind=='DIRECTORY','uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'uidset':list(uidset)};validate_go_ancestor(result,c);return result
 except Exception:return None

def source_catalog(source):
 """Version-independent fixed source regions; no runtime values are inspected."""
 tree=ast.parse(source);ranges={};loop=None;check_ast=None;application_wait=None;wait_timeout=None
 def visit(nodes,prefix=''):
  nonlocal loop,check_ast,application_wait,wait_timeout
  for node in nodes:
   if isinstance(node,ast.ClassDef):visit(node.body,prefix+node.name+'.')
   elif isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
    name=prefix+node.name;ranges[name]=[node.lineno,node.end_lineno]
    if name=='Guest.source_fixtures':
     for n in ast.walk(node):
      if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='checks' for t in n.targets):check_ast=hashlib.sha256(ast.dump(n.value,include_attributes=False).encode()).hexdigest()
      if isinstance(n,ast.For) and isinstance(n.target,ast.Name) and n.target.id=='query' and isinstance(n.iter,ast.Name) and n.iter.id=='checks':loop={'function':name,'line':n.body[0].lineno,'count':6}
    if name=='Guest.source_fixtures':
     for n in ast.walk(node):
      if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='self' and n.func.attr=='wait' and n.args and isinstance(n.args[0],ast.BinOp) and isinstance(n.args[0].left,ast.Constant) and n.args[0].left.value=='SELECT convergence_status FROM application_instances WHERE id=':application_wait={'line':n.lineno,'column_start':n.col_offset,'column_end':n.end_col_offset}
    if name=='Guest.wait':
     for n in ast.walk(node):
      if isinstance(n,ast.Raise) and isinstance(n.exc,ast.Call) and isinstance(n.exc.func,ast.Name) and n.exc.func.id=='Refused':wait_timeout={'line':n.lineno}
    visit(node.body,name+'.')
 visit(tree.body);need(loop is not None and check_ast is not None and application_wait is not None and wait_timeout is not None,'IDENTITY');loop['checks_ast_sha256']=check_ast
 return {'schema':'nakpanel-l1-fixed-guest-sites-v7','guest_sha256':hashlib.sha256(source).hexdigest(),'functions':ranges,'fixture_loop':loop,'maximum_frames':MAX_FRAMES,'go_config_ancestor_sites':go_ancestor_sites(tree),'systemctl_listing_sites':listing_sites(tree),'tenant_ps_sites':tenant_ps_sites(tree),'application_wait':application_wait,'wait_timeout':wait_timeout,'restore_validation_sites':restore_sites(tree),'strict_post_sites':strict_post_sites(tree)}

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
 expected=["SELECT count(*) FROM mail_domains WHERE domain='current-bootstrap.test'","SELECT count(*) FROM webmail_hosts WHERE hostname='webmail.current-bootstrap.test'","SELECT count(*) FROM subscription_policy_overrides WHERE subscription_id="+sid,"SELECT count(*) FROM application_instances WHERE subscription_id="+sid,"SELECT count(*) FROM service_secrets WHERE scope='backup' AND name='archive-key'","SELECT count(*) FROM server_backup_destinations WHERE name='l1-local'"]
 if type(checks) is not list or len(checks)!=6 or any(type(x) is not str for x in checks) or checks!=expected or len(set(checks))!=6 or type(query) is not str:return 'UNKNOWN'
 indexes=[i for i,item in enumerate(checks) if item is query]
 return indexes[0] if len(indexes)==1 else 'UNKNOWN'

def capture_guest_failure(error,g,receipt,codes,root,kind=None):
 kind=category(error) if kind is None else kind;fallback=unavailable(receipt.get('reason'),kind)
 try:
  root=Path(root);source=regular(root/'guest.py').read_bytes();catalog=decode(regular(root/'guest-sites.json',max_bytes=131072).read_bytes());need(catalog==source_catalog(source) and catalog['guest_sha256']==receipt['program_sha256']==g.c['program_hashes']['guest.py'] and sha(root/'guest-sites.json')==g.c['program_hashes']['guest-sites.json'] and sha(root/'failure.py')==g.c['program_hashes']['failure.py'] and sha(root/'waitdiag.py')==g.c['program_hashes']['waitdiag.py'],'INPUT_DRIFT')
  frames=[];index='UNKNOWN';wait=None;tenant=None;listing=None;ancestor=None;restore=None;strict=None;tb=error.__traceback__;count=0
  while tb is not None:
   count+=1;need(count<=256,'IDENTITY');code=tb.tb_frame.f_code;trusted=codes.get(id(code))
   if trusted is not None:
    need(trusted[0] is code,'IDENTITY');name=trusted[1];frames.append(point(code,name,tb.tb_lasti,tb.tb_lineno))
    if name=='Guest.source_fixtures':index=fixture_index(tb,g,catalog)
    if name=='Guest.strict_post' and kind=='REFUSED' and receipt.get('reason')=='STRICT_POST':strict=retain_strict_post(g,tb,source,catalog,codes)
    if name=='Guest.restore' and kind=='REFUSED' and receipt.get('reason')=='FORMAT':restore=retain_restore_validation(g,tb,source,catalog,codes)
    if name=='Guest.command' and kind=='REFUSED' and receipt.get('reason')=='CHILD':tenant=retain_tenant_ps(g,tb,source,catalog,codes)
    if name=='go_ancestors' and kind=='REFUSED' and receipt.get('reason')=='GO_TRUST':ancestor=retain_go_ancestor(g,tb,source,catalog,codes)
    if kind=='REFUSED' and ((name=='Guest.command' and receipt.get('reason')=='CHILD') or (name=='Guest.row_units' and receipt.get('reason') in ('IDENTITY','STOPPED'))):
     observed=retain_systemctl_listing(g,tb,source,catalog,codes)
     if observed is not None:listing=observed
    if name=='Guest.wait' and kind=='REFUSED' and receipt.get('reason')=='PHYSICAL' and tb.tb_lineno==catalog['wait_timeout']['line']:
     values=tb.tb_frame.f_locals;candidate=getattr(g,'wait_observation',None)
     try:
      waitdiag.validate_record(candidate,g.c);need(values.get('self') is g and type(values.get('query')) is str and values.get('count')==candidate['samples'] and type(values.get('count')) is int and candidate['last_value']==(values.get('last') if type(values.get('last')) is str and values['last'] in waitdiag.WAIT_VALUES else 'NO_SAMPLE' if values.get('count')==0 else 'OTHER') and candidate['termination']==('OPERATION_DEADLINE' if values.get('end')==g.deadline else 'WAIT_DEADLINE'),'IDENTITY')
      if candidate['scope'] is not None:need(values['query']=='SELECT convergence_status FROM application_instances WHERE id='+str(candidate['scope']['application_id']),'IDENTITY')
      wait=candidate
     except Exception:pass
   elif Path(code.co_filename).resolve()==(root/'guest.py').resolve():raise Refused('IDENTITY')
   tb=tb.tb_next
  need(frames,'IDENTITY');retained=frames[-MAX_FRAMES:]
  if not any(f['function']=='Guest.source_fixtures' and f['line']==catalog['fixture_loop']['line'] for f in retained):index='UNKNOWN'
  result=dict(fallback,strict_post=strict,restore_validation=restore,capture='CAPTURED',frames=retained,truncated=len(frames)>MAX_FRAMES,fixture_check_index=index,wait_observation=wait,tenant_ps=tenant,systemctl_listing=listing,go_config_ancestor=ancestor);validate_detail(result,source,catalog,context=g.c);return result
 except BaseException:return fallback

def application_call(frame,source,catalog):
 site=catalog['application_wait']
 if frame['function']!='Guest.source_fixtures' or frame['line']!=site['line']:return False
 if frame['column_start'] is not None:return (frame['column_start'],frame['column_end'])==(site['column_start'],site['column_end'])
 for code,name in walk_code(compile(source,str(ROOT/'guest.py'),'exec'),''):
  if name!='Guest.source_fixtures':continue
  selected=False
  for instruction in dis.get_instructions(code):
   if instruction.opname=='LOAD_CONST' and instruction.argval=='SELECT convergence_status FROM application_instances WHERE id=':selected=True
   elif selected and instruction.opname=='CALL_METHOD':return frame['offset']==instruction.offset
 return False

def validate_detail(d,source=None,catalog=None,context=None):
 need(type(d) is dict and set(d)==DETAIL_KEYS and d['schema']==SCHEMA and d['capture'] in ('CAPTURED','UNAVAILABLE') and d['category'] in CATEGORIES and d['reason'] in REASONS and d['python_tag']==sys.implementation.cache_tag and type(d['truncated']) is bool and type(d['frames']) is list and len(d['frames'])<=MAX_FRAMES,'IDENTITY')
 index=d['fixture_check_index'];need(index=='UNKNOWN' or type(index) is int and 0<=index<=5,'IDENTITY')
 if d['capture']=='UNAVAILABLE':need(d['frames']==[] and d['truncated'] is False and index=='UNKNOWN' and d['wait_observation'] is None and d['tenant_ps'] is None and d['systemctl_listing'] is None and d['go_config_ancestor'] is None and d['restore_validation'] is None and d['strict_post'] is None,'IDENTITY');return True
 source=(ROOT/'guest.py').read_bytes() if source is None else source;catalog=decode((ROOT/'guest-sites.json').read_bytes()) if catalog is None else catalog;need(catalog==source_catalog(source),'INPUT_DRIFT');compiled=list(walk_code(compile(source,str(ROOT/'guest.py'),'exec'),''));need(d['frames'],'IDENTITY')
 for frame in d['frames']:
  need(type(frame) is dict and set(frame)==FRAME_KEYS and type(frame['function']) is str and len(frame['function'])<=160 and all(type(frame[k]) is int and frame[k]>=0 for k in ('first_line','line','offset')) and type(frame['bytecode_sha256']) is str and SHA.fullmatch(frame['bytecode_sha256']),'IDENTITY')
  need(all(frame[k] is None or type(frame[k]) is int and frame[k]>=0 for k in ('column_start','column_end','end_line')),'IDENTITY')
  regions=[span for name,span in catalog['functions'].items() if frame['function']==name or frame['function'].startswith(name+'.')];need(regions and any(lo<=frame['line']<=hi for lo,hi in regions),'IDENTITY')
  candidates=[code for code,name in compiled if name==frame['function'] and code.co_firstlineno==frame['first_line'] and hashlib.sha256(code.co_code).hexdigest()==frame['bytecode_sha256']];need(candidates and any(point(code,frame['function'],frame['offset'],frame['line'])==frame for code in candidates),'IDENTITY')
 if d['go_config_ancestor'] is not None:
  validate_go_ancestor(d['go_config_ancestor'],context);need(d['category']=='REFUSED' and d['reason']=='GO_TRUST' and len(d['frames'])>=4 and [f['function'] for f in d['frames'][-4:]]==['Guest.target_baseline','Guest.trust_files','go_config_absent','go_ancestors'] and all(go_ancestor_call(f,source,catalog) for f in d['frames'][-4:]),'IDENTITY')
 if d['systemctl_listing'] is not None:
  p=d['systemctl_listing'];validate_systemctl_listing(p,context);need(d['category']=='REFUSED','IDENTITY')
  if p['site']=='COMMAND':need(d['reason']=='CHILD' and len(d['frames'])>=3 and [f['function'] for f in d['frames'][-3:]]==['Guest.stopped','Guest.row_units','Guest.command'] and all(listing_call(f,source,catalog,k) for f,k in zip(d['frames'][-3:],('stopped','listing','command'))),'IDENTITY')
  else:need(d['reason'] in ('IDENTITY','STOPPED') and len(d['frames'])>=2 and [f['function'] for f in d['frames'][-2:]]==['Guest.stopped','Guest.row_units'] and listing_call(d['frames'][-2],source,catalog,'stopped') and any(listing_call(d['frames'][-1],source,catalog,k) for k in ('decode','accept')),'IDENTITY')
 if d['tenant_ps'] is not None:
  validate_tenant_ps(d['tenant_ps'],context);need(d['category']=='REFUSED' and d['reason']=='CHILD' and len(d['frames'])>=3 and [f['function'] for f in d['frames'][-3:]]==['Guest.stopped','Guest.rootless','Guest.command'] and all(tenant_ps_call(f,source,catalog) for f in d['frames'][-3:]),'IDENTITY')
 if d['wait_observation'] is not None:
  waitdiag.validate_record(d['wait_observation'],context);need(d['category']=='REFUSED' and d['reason']=='PHYSICAL' and any(f['function']=='Guest.wait' and f['line']==catalog['wait_timeout']['line'] for f in d['frames']),'IDENTITY')
  if d['wait_observation']['site']=='SOURCE_APPLICATION_CONVERGENCE':need(any(application_call(f,source,catalog) for f in d['frames']),'IDENTITY')
 if d['restore_validation'] is not None:
  validate_restore_detail(d['restore_validation'],context,catalog);need(d['category']=='REFUSED' and d['reason']=='FORMAT' and restore_call(d['frames'][-1],source,catalog),'IDENTITY')
 if d['strict_post'] is not None:
  validate_strict_post(d['strict_post'],context);need(d['category']=='REFUSED' and d['reason']=='STRICT_POST' and strict_post_site(d['frames'][-1],source,catalog)==d['strict_post']['site'],'IDENTITY')
 if type(index) is int:need(any(f['function']=='Guest.source_fixtures' and f['line']==catalog['fixture_loop']['line'] for f in d['frames']),'IDENTITY')
 return True

def validate_failed_remote(row,c,input_sha,rec):
 need(type(row) is dict and row.get('schema')=='nakpanel-l1-remote-v1' and all(row.get(k)==c[k] for k in ('operation','operation_id','role','vm','token','run_id')) and row.get('source_commit')==SOURCE and row.get('program_sha256')==c['program_hashes']['guest.py'] and row.get('input_sha256')==input_sha,'REMOTE_UNKNOWN')
 need(row.get('known') is True and row.get('status')=='FAIL' and type(row.get('exit_code')) is int and row['exit_code']==1 and row.get('payload') is None and type(row.get('reason')) is str and row['reason'] in REASONS and all(type(row.get(k)) in (int,float) and math.isfinite(row[k]) for k in ('started_monotonic','finished_monotonic')) and row['started_monotonic']<=row['finished_monotonic'],'REMOTE_UNKNOWN')
 need(type(rec) is dict and rec.get('status')=='FAIL' and rec.get('failure_code')=='exit' and type(rec.get('exit_code')) is int and rec['exit_code']==row['exit_code'] and rec.get('process_exited') is True and rec.get('process_group_empty') is True,'REMOTE_UNKNOWN');binding=rec.get('binding');need(type(binding) is dict and all(binding.get(k)==c[k] for k in ('run_id','role','vm','token','operation')) and binding.get('source_commit')==SOURCE,'REMOTE_UNKNOWN');return True

def retain_failed_remote(root,c,input_sha,row,rec,state):
 validate_failed_remote(row,c,input_sha,rec);root=physical_dir(root);phase=c['operation'];need(phase in PHASES,'IDENTITY');snapshot=root/(phase.lower()+'-remote-failed.json');publish(snapshot,row,cap=4*1024*1024);custody=root/'logs'/rec['phase']/'receipt.json';need(decode(regular(custody).read_bytes())==rec,'IDENTITY')
 state['failed_remote']={'phase':phase,'operation_id':c['operation_id'],'role':c['role'],'snapshot_sha256':sha(snapshot),'custody_phase':rec['phase'],'custody_sha256':sha(custody),'intent_sha256':sha(root/(phase.lower()+'-intent.json'))}

def project_failure(root,state):
 root=physical_dir(root);need(state.get('overall')!='PASS' and state.get('remote_known') is True and state.get('drained') is True,'IDENTITY');context=decode(regular(root/'run-context.json').read_bytes());s=root.stat();need(context.get('run_id')==state.get('run_id') and context.get('controller_commit')==state.get('controller_commit') and context.get('source_commit')==SOURCE and context.get('roles')==roles(context.get('run_id')) and context.get('root_identity')==[s.st_dev,s.st_ino] and state.get('context_sha256')==sha(root/'run-context.json'),'IDENTITY')
 ref=state.get('failed_remote');need(type(ref) is dict and set(ref)=={'phase','operation_id','role','snapshot_sha256','custody_phase','custody_sha256','intent_sha256'} and ref['phase'] in PHASES and ref['role'] in ('source','target') and type(ref['custody_phase']) is str and re.fullmatch(r'a[0-9]{3,5}-(?:source|target)',ref['custody_phase']) and type(ref['operation_id']) is str and re.fullmatch('[a-f0-9]{32}',ref['operation_id']) and all(type(ref[k]) is str and SHA.fullmatch(ref[k]) for k in ('snapshot_sha256','custody_sha256','intent_sha256')),'IDENTITY')
 need({'phase':ref['custody_phase'],'sha256':ref['custody_sha256']} in state['custody'],'IDENTITY');custody=root/'logs'/ref['custody_phase'];receipt=regular(custody/'receipt.json');snapshot=regular(root/(ref['phase'].lower()+'-remote-failed.json'));intent=regular(root/(ref['phase'].lower()+'-intent.json'));need(sha(receipt)==ref['custody_sha256'] and sha(snapshot)==ref['snapshot_sha256'] and sha(intent)==ref['intent_sha256'],'IDENTITY');request=decode(intent.read_bytes());c=request['context'];input_sha=hashlib.sha256(canonical(c)).hexdigest();need(request['input_sha256']==input_sha and all(c.get(k)==ref[v] for k,v in [('operation','phase'),('operation_id','operation_id'),('role','role')]) and c.get('run_id')==context['run_id'] and all(c.get(k)==context['roles'][ref['role']][k] for k in ('vm','token')),'IDENTITY')
 for n in ('guest.py','failure.py','guest-sites.json','waitdiag.py'):need(c['program_hashes'].get(n)==sha(ROOT/n),'INPUT_DRIFT')
 rec=decode(receipt.read_bytes());row=decode(snapshot.read_bytes());validate_failed_remote(row,c,input_sha,rec)
 for name in ('stdout','stderr'):
  log=regular(custody/(name+'.log'),max_bytes=64*1024*1024);proof=rec.get(name);need(type(proof) is dict and proof.get('sha256')==sha(log) and proof.get('bytes')==log.stat().st_size,'IDENTITY')
 need(snapshot.read_bytes()==(custody/'stdout.log').read_bytes(),'IDENTITY');detail=row.get('failure_detail');validate_detail(detail,context=c);need(detail['reason']==row['reason'],'IDENTITY')
 return {'operation':c['operation'],'operation_id':c['operation_id'],'role':c['role'],'program_sha256':row['program_sha256'],'input_sha256':input_sha,'remote_exit_code':1,'host_exit_code':1,'host_reaped':True,'host_drained':True,'failure':detail}
