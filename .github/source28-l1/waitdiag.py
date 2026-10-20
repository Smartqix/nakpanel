"""Finite timeout observations. No mutation, arbitrary entities or plaintext errors."""
import errno,hashlib,os,re,stat,time
from l1 import IMAGE_REF,SHA,Refused,canonical,decode,need,roles
SCOPE_KEYS={'application_id','subscription_id','site_id','desired_revision','username','run_id','binding'}
WAIT_VALUES={'pending','in_sync','failed','active','completed'}
UNAVAILABLE={'SCOPE_UNAVAILABLE','BUDGET_EXHAUSTED','CAPTURE_FAILED','PARENT_UNAVAILABLE','OS_ERROR'}
LABELS=('root','var','lib','panel','containers','namespace','home','data','config','run','runtime_root','runtime')

def positive(x):return type(x) is int and 0<x<2**63

def context_binding(c):
 need(type(c) is dict and c.get('operation')=='SOURCE_FIXTURES' and c.get('role')=='source' and type(c.get('operation_id')) is str and re.fullmatch('[a-f0-9]{32}',c['operation_id']) is not None,'IDENTITY')
 selected=roles(c.get('run_id'))['source'];need(all(c.get(k)==selected[k] for k in ('vm','token')),'IDENTITY')
 hashes=c.get('program_hashes');need(type(hashes) is dict and hashes and all(type(n) is str and type(v) is str and SHA.fullmatch(v) for n,v in hashes.items()),'IDENTITY')
 return hashlib.sha256(canonical({k:c[k] for k in ('run_id','role','vm','token','operation','operation_id','program_hashes')})).hexdigest()

def validate_scope(s,c=None):
 need(type(s) is dict and set(s)==SCOPE_KEYS and all(positive(s[k]) for k in ('application_id','subscription_id','site_id','desired_revision')) and type(s['username']) is str and re.fullmatch('[a-z][a-z0-9_-]{2,31}',s['username']) and type(s['run_id']) is str and type(s['binding']) is str and SHA.fullmatch(s['binding']),'IDENTITY');roles(s['run_id'])
 if c is not None:
  need(s['binding']==context_binding(c) and s['run_id']==c['run_id'],'IDENTITY')
  for k in ('application_id','subscription_id','site_id','username'):
   if k in c:need(type(c[k]) is type(s[k]) and c[k]==s[k],'IDENTITY')
 return True

def owned_scope(c,row):
 try:
  binding=context_binding(c);need(type(row) is dict and all(positive(c.get(k)) and type(row.get(k)) is int and row[k]==c[k] for k in ('subscription_id','site_id')) and positive(row.get('id')) and positive(row.get('desired_revision')) and row.get('name')=='l1-stopped-'+c['run_id'] and row.get('runtime')=='oci' and row.get('desired_state')=='stopped' and row.get('image_ref')==IMAGE_REF,'IDENTITY')
  s={k:row[k] for k in ('subscription_id','site_id','desired_revision')};s.update(application_id=row['id'],username=c.get('username'),run_id=c['run_id'],binding=binding);validate_scope(s,c);return s
 except Exception:return None

def unavailable(reason):return {'status':'UNAVAILABLE','reason':reason}

def error_sql(value):
 return "jsonb_build_object('category',CASE WHEN COALESCE("+value+",'')='' THEN 'EMPTY' ELSE 'OTHER' END,'bytes',octet_length(COALESCE("+value+",'')),'sha256',encode(sha256(convert_to(COALESCE("+value+",''),'UTF8')),'hex'))"

def enum_sql(value,values):
 return 'CASE WHEN '+value+' IN ('+','.join("'"+x+"'" for x in values)+") THEN "+value+" ELSE 'OTHER' END"

def database_sql(s):
 validate_scope(s);aid=str(s['application_id']);sid=str(s['subscription_id']);site=str(s['site_id']);revision=str(s['desired_revision']);name='l1-stopped-'+s['run_id']
 appfields="'id',a.id,'subscription_id',a.subscription_id,'site_id',a.site_id,'desired_revision',a.desired_revision,'applied_revision',a.applied_revision,'active_generation',a.active_generation"
 for key,values in [('desired_state',['running','stopped']),('applied_state',['pending','running','stopped','failed']),('convergence_status',['pending','in_sync','failed']),('observed_state',['unknown','starting','healthy','unhealthy','stopped','missing','failed'])]:appfields+=",'"+key+"',"+enum_sql('a.'+key,values)
 appfields+=",'last_error',"+error_sql('a.last_error')+",'observed_message',"+error_sql('a.observed_message')
 last="CASE WHEN jsonb_typeof(j.errors[array_upper(j.errors,1)])='object' AND jsonb_typeof(j.errors[array_upper(j.errors,1)]->'error')='string' THEN j.errors[array_upper(j.errors,1)]->>'error' ELSE '' END"
 jobs="'id',j.id,'application_id',(j.args->>'application_id')::bigint,'revision',(j.args->>'revision')::bigint,'subscription_revision',COALESCE((j.args->>'subscription_revision')::bigint,0),'state',"+enum_sql('j.state::text',['available','pending','cancelled','completed','discarded','retryable','running','scheduled'])+",'queue',"+enum_sql('j.queue',['heavy'])+",'attempt',j.attempt,'max_attempts',j.max_attempts,'error_count',COALESCE(cardinality(j.errors),0),'last_error',"+error_sql(last)
 return "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='2s'; SET LOCAL lock_timeout='500ms';\nWITH owned AS (SELECT a.* FROM application_instances a WHERE a.id="+aid+' AND a.subscription_id='+sid+' AND a.site_id='+site+" AND a.name='"+name+"'), matched_jobs AS (SELECT j.* FROM river_job j WHERE j.kind='converge_application' AND j.args->>'application_id'='"+aid+"' AND j.args->>'revision'='"+revision+"' ORDER BY j.id LIMIT 9)\nSELECT jsonb_build_object('status','CAPTURED','app',COALESCE((SELECT jsonb_agg(jsonb_build_object("+appfields+")) FROM owned a),'[]'::jsonb),'generation',COALESCE((SELECT jsonb_agg(jsonb_build_object('application_id',g.application_id,'desired_revision',g.desired_revision,'status',"+enum_sql('g.status',['pending','starting','healthy','failed','retired','rolled_back'])+",'health_message',"+error_sql('g.health_message')+")) FROM application_generations g JOIN owned a ON a.id=g.application_id WHERE g.desired_revision="+revision+"),'[]'::jsonb),'jobs',COALESCE((SELECT jsonb_agg(jsonb_build_object("+jobs+") ORDER BY j.id) FROM (SELECT id,args,state,queue,attempt,max_attempts,errors FROM matched_jobs ORDER BY id LIMIT 8) j),'[]'::jsonb),'overflow',(SELECT count(*)>8 FROM matched_jobs)); COMMIT;"

def validate_error(e):
 need(type(e) is dict and set(e)=={'category','bytes','sha256'} and e['category'] in ('EMPTY','OTHER') and type(e['bytes']) is int and 0<=e['bytes']<2**63 and type(e['sha256']) is str and SHA.fullmatch(e['sha256']) and ((e['bytes']==0 and e['category']=='EMPTY' and e['sha256']==hashlib.sha256(b'').hexdigest()) or e['bytes']>0 and e['category']=='OTHER'),'IDENTITY')

def validate_database(d,s):
 validate_scope(s);need(type(d) is dict and set(d)=={'status','app','generation','jobs','overflow'} and d['status']=='CAPTURED' and type(d['app']) is list and len(d['app'])<=1 and type(d['generation']) is list and len(d['generation'])<=1 and type(d['jobs']) is list and len(d['jobs'])<=8 and type(d['overflow']) is bool and (not d['overflow'] or len(d['jobs'])==8),'IDENTITY')
 for a in d['app']:
  need(type(a) is dict and set(a)=={'id','subscription_id','site_id','desired_revision','applied_revision','active_generation','desired_state','applied_state','convergence_status','observed_state','last_error','observed_message'} and type(a['id']) is int and a['id']==s['application_id'] and all(type(a[k]) is int and a[k]==s[k] for k in ('subscription_id','site_id')) and positive(a['desired_revision']) and all(type(a[k]) is int and 0<=a[k]<2**63 for k in ('applied_revision','active_generation')),'IDENTITY')
  for key,values in [('desired_state',{'running','stopped','OTHER'}),('applied_state',{'pending','running','stopped','failed','OTHER'}),('convergence_status',{'pending','in_sync','failed','OTHER'}),('observed_state',{'unknown','starting','healthy','unhealthy','stopped','missing','failed','OTHER'})]:need(type(a[key]) is str and a[key] in values,'IDENTITY')
  validate_error(a['last_error']);validate_error(a['observed_message'])
 for g in d['generation']:
  need(type(g) is dict and set(g)=={'application_id','desired_revision','status','health_message'} and type(g['application_id']) is int and g['application_id']==s['application_id'] and type(g['desired_revision']) is int and g['desired_revision']==s['desired_revision'] and g['status'] in ('pending','starting','healthy','failed','retired','rolled_back','OTHER'),'IDENTITY');validate_error(g['health_message'])
 ids=[]
 for j in d['jobs']:
  need(type(j) is dict and set(j)=={'id','application_id','revision','subscription_revision','state','queue','attempt','max_attempts','error_count','last_error'} and positive(j['id']) and type(j['application_id']) is int and j['application_id']==s['application_id'] and type(j['revision']) is int and j['revision']==s['desired_revision'] and all(type(j[k]) is int and 0<=j[k]<2**63 for k in ('subscription_revision','attempt','error_count')) and type(j['max_attempts']) is int and 0<j['max_attempts']<=32767 and j['state'] in ('available','pending','cancelled','completed','discarded','retryable','running','scheduled','OTHER') and j['queue'] in ('heavy','OTHER'),'IDENTITY');validate_error(j['last_error']);ids.append(j['id'])
 need(ids==sorted(set(ids)) and (d['app'] or not d['generation']),'IDENTITY');return True

def database_capture(g,s,cap):
 need(type(cap) in (int,float) and 0<cap<=3,'IDENTITY');sql=database_sql(s)
 result=g.command(['runuser','-u','postgres','--','psql','-XAtq','-v','ON_ERROR_STOP=1','-d','nakpanel','-c',sql],cap=cap);need(type(result.stdout) is bytes and len(result.stdout)<=65536,'IDENTITY');d=decode(result.stdout);validate_database(d,s);return d

def facts(s):
 typ='directory' if stat.S_ISDIR(s.st_mode) else 'symlink' if stat.S_ISLNK(s.st_mode) else 'regular' if stat.S_ISREG(s.st_mode) else 'other'
 return {'dev':s.st_dev,'ino':s.st_ino,'type':typ,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid}

def fs_errno(e):return errno.errorcode.get(e.errno,'OTHER') if e.errno in (errno.EACCES,errno.EPERM,errno.ENOENT,errno.ENOTDIR,errno.ELOOP,errno.ESTALE,errno.EIO,errno.EMFILE,errno.ENFILE) else 'OTHER'

def namespace_paths(s):
 validate_scope(s);name='sub-'+str(s['subscription_id'])
 return [('root',None,'/'),('var','root','var'),('lib','var','lib'),('panel','lib','nakpanel'),('containers','panel','containers'),('namespace','containers',name),('home','namespace','home'),('data','namespace','data'),('config','namespace','config'),('run','root','run'),('runtime_root','run','nakpanel-containers'),('runtime','runtime_root',name)]

def namespace_open(s,*,fs=os,clock=time.monotonic,deadline):
 if clock()>=deadline:return unavailable('BUDGET_EXHAUSTED'),[]
 handles=[];fds={};rows=[];opened=[]
 try:
  for label,parent,name in namespace_paths(s):
   fd=None;parentfd=fds.get(parent);row={'name':label,'status':'PARENT_UNAVAILABLE','facts':None,'errno':None}
   if clock()>=deadline:row['status']='BUDGET_EXHAUSTED'
   elif parent is None or parentfd is not None:
    try:
     info=fs.stat(name,dir_fd=parentfd,follow_symlinks=False);row.update(status='PRESENT',facts=facts(info))
     if not stat.S_ISDIR(info.st_mode):row['status']='SYMLINK' if stat.S_ISLNK(info.st_mode) else 'NOT_DIRECTORY'
     else:
      fd=fs.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd);opened.append(fd)
      if facts(fs.fstat(fd))!=row['facts']:row['status']='CHANGED'
    except OSError as e:row.update(status='MISSING' if e.errno==errno.ENOENT else 'OS_ERROR',errno=fs_errno(e))
   handles.append({'name':label,'parentfd':parentfd,'component':name,'fd':fd,'before':dict(row)});rows.append(row)
   if fd is not None and row['status']=='PRESENT':fds[label]=fd
  return {'status':'CAPTURED','locations':rows,'stable':all(r['status'] not in ('CHANGED','OS_ERROR','BUDGET_EXHAUSTED','PARENT_UNAVAILABLE') for r in rows)},handles
 except BaseException:
  for fd in reversed(opened):
   try:fs.close(fd)
   except OSError:pass
  raise

def namespace_finish(handles,*,fs=os,clock=time.monotonic,deadline):
 rows=[]
 try:
  for h in handles:
   row=dict(h['before'])
   if clock()>=deadline:row.update(status='BUDGET_EXHAUSTED',facts=None,errno=None)
   elif row['status'] not in ('PARENT_UNAVAILABLE','BUDGET_EXHAUSTED'):
    try:
     current=facts(fs.stat(h['component'],dir_fd=h['parentfd'],follow_symlinks=False))
     if current!=row['facts'] or h['fd'] is not None and facts(fs.fstat(h['fd']))!=current:row.update(status='CHANGED',facts=current,errno=None)
    except OSError as e:
     if not (row['status']=='MISSING' and e.errno==errno.ENOENT):row.update(status='CHANGED',facts=None,errno=fs_errno(e))
   rows.append(row)
  return {'status':'CAPTURED','locations':rows,'stable':all(r['status'] not in ('CHANGED','OS_ERROR','BUDGET_EXHAUSTED','PARENT_UNAVAILABLE') for r in rows)}
 finally:
  for h in reversed(handles):
   if h['fd'] is not None:
    try:fs.close(h['fd'])
    except OSError:pass

def validate_namespace(d):
 need(type(d) is dict and set(d)=={'status','locations','stable'} and d['status']=='CAPTURED' and type(d['stable']) is bool and type(d['locations']) is list and len(d['locations'])==12 and [x.get('name') for x in d['locations']]==list(LABELS),'IDENTITY')
 for r in d['locations']:
  need(type(r) is dict and set(r)=={'name','status','facts','errno'} and r['status'] in ('PRESENT','MISSING','SYMLINK','NOT_DIRECTORY','CHANGED','PARENT_UNAVAILABLE','OS_ERROR','BUDGET_EXHAUSTED') and r['errno'] in (None,'EACCES','EPERM','ENOENT','ENOTDIR','ELOOP','ESTALE','EIO','EMFILE','ENFILE','OTHER'),'IDENTITY')
  f=r['facts']
  if f is not None:need(type(f) is dict and set(f)=={'dev','ino','type','mode','uid','gid'} and all(type(f[k]) is int and 0<=f[k]<2**64 for k in ('dev','ino','mode','uid','gid')) and f['ino']>0 and f['mode']<=0o7777 and f['type'] in ('directory','symlink','regular','other'),'IDENTITY')
  if r['status'] in ('PRESENT','SYMLINK','NOT_DIRECTORY'):need(f is not None,'IDENTITY')
  if r['status']=='PRESENT':need(f['type']=='directory' and r['errno'] is None,'IDENTITY')
  if r['status']=='SYMLINK':need(f['type']=='symlink' and r['errno'] is None,'IDENTITY')
  if r['status']=='NOT_DIRECTORY':need(f['type'] not in ('directory','symlink') and r['errno'] is None,'IDENTITY')
  if r['status'] in ('PARENT_UNAVAILABLE','BUDGET_EXHAUSTED'):need(f is None and r['errno'] is None,'IDENTITY')
  if r['status']=='MISSING':need(f is None and r['errno']=='ENOENT','IDENTITY')
 need(d['stable']==all(r['status'] not in ('CHANGED','OS_ERROR','BUDGET_EXHAUSTED','PARENT_UNAVAILABLE') for r in d['locations']),'IDENTITY');return True

def timeout_record(g,query,last,count,end,*,scope=None,clock=time.monotonic):
 now=clock();record={'schema':'nakpanel-l1-wait-observation-v1','site':'OTHER_WAIT','last_value':last if type(last) is str and last in WAIT_VALUES else 'NO_SAMPLE' if count==0 else 'OTHER','samples':count,'termination':'OPERATION_DEADLINE' if end==g.deadline else 'WAIT_DEADLINE','scope':None,'database':unavailable('SCOPE_UNAVAILABLE'),'namespace_before':unavailable('SCOPE_UNAVAILABLE'),'namespace_after':unavailable('SCOPE_UNAVAILABLE')}
 try:
  validate_scope(scope,g.c)
  if query!='SELECT convergence_status FROM application_instances WHERE id='+str(scope['application_id']):return record
 except Exception:return record
 record.update(site='SOURCE_APPLICATION_CONVERGENCE',scope=dict(scope));cap=min(3,g.deadline-now)
 if cap<=0:
  for key in ('database','namespace_before','namespace_after'):record[key]=unavailable('BUDGET_EXHAUSTED')
  return record
 deadline=min(g.deadline,now+3);handles=[]
 try:
  record['namespace_before'],handles=namespace_open(scope,clock=clock,deadline=deadline)
  remaining=deadline-clock()
  record['database']=database_capture(g,scope,remaining) if remaining>0 else unavailable('BUDGET_EXHAUSTED')
  if clock()>deadline:record['database']=unavailable('BUDGET_EXHAUSTED')
 except Exception:record['database']=unavailable('CAPTURE_FAILED')
 finally:
  if handles:
   try:record['namespace_after']=namespace_finish(handles,clock=clock,deadline=deadline)
   except Exception:record['namespace_after']=unavailable('CAPTURE_FAILED')
  elif record['namespace_before']['status']=='CAPTURED':record['namespace_after']=unavailable('CAPTURE_FAILED')
  else:record['namespace_after']=dict(record['namespace_before'])
 return record

def validate_record(d,c=None):
 need(type(d) is dict and set(d)=={'schema','site','last_value','samples','termination','scope','database','namespace_before','namespace_after'} and d['schema']=='nakpanel-l1-wait-observation-v1' and d['site'] in ('OTHER_WAIT','SOURCE_APPLICATION_CONVERGENCE') and d['last_value'] in WAIT_VALUES|{'OTHER','NO_SAMPLE'} and type(d['samples']) is int and 0<=d['samples']<=4500 and (d['last_value']=='NO_SAMPLE')==(d['samples']==0) and d['termination'] in ('OPERATION_DEADLINE','WAIT_DEADLINE'),'IDENTITY')
 if d['site']=='SOURCE_APPLICATION_CONVERGENCE':validate_scope(d['scope'],c)
 else:need(d['scope'] is None,'IDENTITY')
 for key in ('database','namespace_before','namespace_after'):
  row=d[key];need(type(row) is dict,'IDENTITY')
  if row.get('status')=='UNAVAILABLE':need(set(row)=={'status','reason'} and row['reason'] in UNAVAILABLE,'IDENTITY')
  else:
   need(d['site']=='SOURCE_APPLICATION_CONVERGENCE','IDENTITY')
   if key=='database':validate_database(row,d['scope'])
   else:validate_namespace(row)
 return True
