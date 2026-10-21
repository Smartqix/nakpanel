#!/usr/bin/env python3
"""Closed guest phase program. Context and private data arrive solely on stdin."""
import configparser,grp,hashlib,http.cookiejar,importlib.util,json,os,pwd,re,shutil,socket,ssl,stat,subprocess,sys,tarfile,tempfile,time,urllib.error,urllib.parse,urllib.request
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from l1 import *
from failure import capture_guest_failure,trusted_guest_codes,unavailable,tenant_ps_context
import waitdiag
from legacy_source_namespace import NamespaceRefused,prepare_source_namespace
ACTION_ALIASES={'SOURCE_FIXTURES':'source_fixtures','BACKUP':'backup','AUTHENTICATE':'authenticate','RESTORE':'restore','AFTER_RETURN':'invocations','PLANNED_STOP':'stop','QUIET':'quiet','STAGE':'stage','GOOSE':'goose','RIVER':'river','NORMAL_START':'start','STRICT_POST':'strict_post','TARGET_BASELINE':'target_baseline'}
UNITS=('nakpanel.service','nakpanel-agent.service','nginx.service','postgresql.service','mariadb.service','named.service','stalwart-mail.service')
JOB_KINDS=('reconcile_system','reconcile_php_application','reconcile_php_workers','converge_subscription','reconcile_applications','converge_application','configure_mail')

def intent_sql():
 cols=contracts()['assertions']['desired_tables'];need(set(cols)==set(TABLES),'INTENT')
 q=["BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL TIME ZONE 'UTC'; SET LOCAL statement_timeout='30s';"]
 for table in TABLES:q.append("SELECT jsonb_build_object('table','"+table+"','count',count(*),'sha256',encode(sha256(convert_to(COALESCE(jsonb_agg(to_jsonb(q) ORDER BY id),'[]'::jsonb)::text,'UTF8')),'hex')) FROM (SELECT "+cols[table]+' FROM '+table+') q;')
 q.append('COMMIT;');return '\n'.join(q)
def application_form(c):
 return {'site_id':c['site_id'],'return_to':'site-containers','name':'l1-stopped-'+c['run_id'],'runtime':'oci','desired_state':'stopped','route_mode':'prefix','route_prefix':'/l1-stopped/','container_port':8080,'health_kind':'tcp','health_timeout_seconds':5,'environment':'{}','secrets':'{}','image_ref':IMAGE_REF}
def absent(path):
 try:Path(path).lstat()
 except FileNotFoundError:return True
 raise Refused('GO_TRUST')
def safe_ancestors(path,uidset=(0,),boundary=Path('/')):
 p=Path(path)
 for x in [p,*p.parents]:
  try:s=x.lstat()
  except FileNotFoundError:continue
  need(stat.S_ISDIR(s.st_mode) and s.st_uid in uidset and not s.st_mode&0o022,'GO_TRUST')
  if x==boundary:break
 return True
def go_tool_path(found,exact,resolved):
 # Accept distro aliases only when the selected PATH node is the same trusted file.
 try:
  need(exact in ('/usr/bin/make','/usr/bin/git','/bin/sh') and type(found) is str,'GO_TRUST');p=Path(found);resolved=Path(resolved)
  need(p.is_absolute() and p.parent in (Path('/bin'),Path('/usr/bin')) and p.parent.resolve()==Path(exact).parent.resolve() and Path(exact).resolve()==resolved and p.resolve()==resolved,'GO_TRUST')
  for node in (p,p.parent,Path(exact),Path(exact).parent):
   s=node.lstat();need(s.st_uid==0 and (stat.S_ISLNK(s.st_mode) and s.st_nlink==1 or stat.S_ISREG(s.st_mode) and node in (p,Path(exact)) or stat.S_ISDIR(s.st_mode) and node in (p.parent,Path(exact).parent)),'GO_TRUST')
  safe_ancestors(p.parent.resolve());regular(resolved,uid=0,private=False);a=p.stat();b=resolved.stat();need((a.st_dev,a.st_ino)==(b.st_dev,b.st_ino),'GO_TRUST');return True
 except (OSError,ValueError,Refused):return False

def go_nss_sources():
 # Enumeration is complete only for the selected local account providers.
 try:
  safe_ancestors(Path('/etc'));p=regular('/etc/nsswitch.conf',uid=0,private=False,max_bytes=65536);sources={}
  for line in p.read_text().splitlines():
   line=line.split('#',1)[0].strip()
   if not line or ':' not in line:continue
   name,value=line.split(':',1);name=name.strip()
   if name not in ('passwd','group'):continue
   need(name not in sources,'GO_TRUST');tokens=value.split();need(tokens in (['files'],['files','systemd']),'GO_TRUST');sources[name]=tokens
  need(set(sources)=={'passwd','group'},'GO_TRUST');return sources
 except (OSError,UnicodeError,KeyError,ValueError):raise Refused('GO_TRUST') from None

def go_private_group():
 try:
  sources=go_nss_sources();user=pwd.getpwnam('nakpanel');group=grp.getgrnam('nakpanel');users=pwd.getpwall();groups=grp.getgrall()
  need(user.pw_name=='nakpanel' and type(user.pw_uid) is int and 0<user.pw_uid<=0xffffffff and type(user.pw_gid) is int and 0<user.pw_gid<=0xffffffff and user.pw_dir=='/var/lib/nakpanel' and group.gr_name=='nakpanel' and type(group.gr_gid) is int and group.gr_gid==user.pw_gid,'GO_TRUST')
  need(type(users) is list and type(groups) is list and all(type(u.pw_name) is str and all(type(v) is int and 0<=v<=0xffffffff for v in (u.pw_uid,u.pw_gid)) for u in users) and all(type(g.gr_name) is str and type(g.gr_gid) is int and 0<=g.gr_gid<=0xffffffff for g in groups) and type(group.gr_mem) is list and all(type(n) is str for n in group.gr_mem),'GO_TRUST')
  named=[u for u in users if u.pw_name=='nakpanel' or u.pw_uid==user.pw_uid];named_groups=[g for g in groups if g.gr_name=='nakpanel' or g.gr_gid==group.gr_gid]
  need(len(named)==1 and named[0]==user and len(named_groups)==1 and named_groups[0]==group,'GO_TRUST')
  primary=sorted(u.pw_name for u in users if u.pw_gid==group.gr_gid);supplementary=sorted(group.gr_mem)
  need(primary==['nakpanel'] and supplementary in ([],['nakpanel']),'GO_TRUST')
  result={'account':'nakpanel','group':'nakpanel','uid':user.pw_uid,'gid':group.gr_gid,'primary_members':primary,'supplementary_members':supplementary,'nss_sources':sources}
  need(go_group_shape(result),'GO_TRUST');return result
 except (OSError,KeyError,ValueError,TypeError,AttributeError):raise Refused('GO_TRUST') from None

def go_group_shape(group):
 return type(group) is dict and set(group)=={'account','group','uid','gid','primary_members','supplementary_members','nss_sources'} and group['account']==group['group']=='nakpanel' and all(type(group[k]) is int and 0<group[k]<=0xffffffff for k in ('uid','gid')) and group['primary_members']==['nakpanel'] and group['supplementary_members'] in ([],['nakpanel']) and type(group['nss_sources']) is dict and set(group['nss_sources'])=={'passwd','group'} and all(v in (['files'],['files','systemd']) for v in group['nss_sources'].values())

def go_private_mode(path,uid,gid,mode,group):
 slots=[Path('/var/lib/nakpanel')/n for n in ('.config','.config/go','go','go/pkg','go/pkg/mod','.cache','.cache/go-build')]
 return go_group_shape(group) and Path(path) in slots and uid==group['uid'] and gid==group['gid'] and type(mode) is int and bool(mode&0o020) and not mode&0o7002

def go_private_directory(path,info,group):
 if not stat.S_ISDIR(info.st_mode) or not go_private_mode(path,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode),group):return False
 def identity(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid)
 fd=None
 try:
  fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);sealed=identity(info)
  if identity(os.fstat(fd))!=sealed:return False
  names=os.listxattr(fd)
  if type(names) is not list or not all(type(n) is str for n in names) or any(n in names for n in ('system.posix_acl_access','system.posix_acl_default')):return False
  return identity(os.fstat(fd))==sealed and identity(Path(path).lstat())==sealed
 except (OSError,ValueError,TypeError,AttributeError):return False
 finally:
  if fd is not None:os.close(fd)

def go_directory_safe(path,s,uidset,group):
 return stat.S_ISDIR(s.st_mode) and s.st_uid in uidset and (not s.st_mode&0o022 or go_private_directory(path,s,group))

def go_ancestors(path,uidset=(0,),boundary=Path('/'),group=None):
 p=Path(path)
 for x in [p,*p.parents]:
  try:s=x.lstat()
  except FileNotFoundError:continue
  need(go_directory_safe(x,s,uidset,group),'GO_TRUST')
  if x==boundary:break
 return True

def go_config_absent(home,stage,boundary=Path('/'),group=None):
 home,stage,boundary=map(Path,(home,stage,boundary))
 for p in (home/'.config/go/env',home/'.netrc',home/'.gitconfig',home/'.config/git/config'):
  go_ancestors(p.parent,(0,os.getuid(),pwd.getpwnam('nakpanel').pw_uid) if home==Path('/var/lib/nakpanel') else (0,os.getuid()),boundary=boundary,group=group);absent(p)
 for p in [stage,*stage.parents]:
  for n in ('go.work','go.work.sum'):absent(p/n)
  if p==boundary:break
 return True
def expected_go(stage,compiler_available=True):
 return {'GOENV':'/var/lib/nakpanel/.config/go/env','GOPROXY':'https://proxy.golang.org,direct','GOSUMDB':'sum.golang.org','GONOSUMDB':'','GOPRIVATE':'','GONOPROXY':'','GOINSECURE':'','GOFLAGS':'','GOVCS':'','GOEXPERIMENT':'','GOAUTH':'netrc','GOTOOLCHAIN':'go1.26.9','GOROOT':'/usr/local/go','GOVERSION':'go1.26.9','GOTOOLDIR':'/usr/local/go/pkg/tool/linux_amd64','GOMOD':stage+'/go.mod','GOWORK':'','GOPATH':'/var/lib/nakpanel/go','GOMODCACHE':'/var/lib/nakpanel/go/pkg/mod','GOCACHE':'/var/lib/nakpanel/.cache/go-build','GOTMPDIR':'','GOOS':'linux','GOARCH':'amd64','GOHOSTOS':'linux','GOHOSTARCH':'amd64','GOFIPS140':'off','CGO_ENABLED':'1' if compiler_available else '0','CC':'gcc','CXX':'g++','GOGCCFLAGS':'-fPIC -m64 -pthread -Wl,--no-gc-sections -fmessage-length=0 -ffile-prefix-map=/tmp/go-build=/tmp/go-build -gno-record-gcc-switches'}
def validate_go_effective(x,stage,compiler_available=True):
 expected=expected_go(stage,compiler_available=compiler_available);need(type(x) is dict and set(x)==set(expected),'GO_TRUST')
 for k,v in expected.items():
  if k=='GOGCCFLAGS':
   # Go inserts an ephemeral work directory; all other compiler flags are fixed.
   need(type(x[k]) is str and re.fullmatch(r'-fPIC -m64 -pthread -Wl,--no-gc-sections -fmessage-length=0 -ffile-prefix-map=/tmp/go-build[0-9]*=/tmp/go-build -gno-record-gcc-switches',x[k]),'GO_TRUST')
  else:need(x[k]==v,'GO_TRUST')
 return True
def validate_git_config(text):
 p=configparser.ConfigParser(interpolation=None,strict=True)
 try:p.read_string(text)
 except configparser.Error:raise Refused('GO_TRUST') from None
 need(set(p.sections())<= {'core','remote "origin"'} and 'core' in p and 'remote "origin"' in p,'GO_TRUST')
 need(dict(p['core'])=={'repositoryformatversion':'0','filemode':'true','bare':'true'},'GO_TRUST')
 remote=dict(p['remote "origin"']);need(set(remote)<={'url','fetch'} and 'url' in remote and re.fullmatch(r'https://[A-Za-z0-9.-]+/[A-Za-z0-9._~/-]+(?:\.git)?',remote['url']) is not None and '@' not in remote['url'],'GO_TRUST')
 if 'fetch' in remote:need(remote['fetch']=='+refs/heads/*:refs/remotes/origin/*','GO_TRUST')
 return True

def validate_rootless_layout(parent,leaves,uid,gid):
 need(type(parent) is dict and parent=={'directory':True,'uid':0,'gid':0,'mode':0o711},'STOPPED')
 need(type(uid) is int and uid>0 and type(gid) is int and gid>0 and type(leaves) is dict and set(leaves)=={'home','data','config','runtime'},'STOPPED')
 for row in leaves.values():need(row=={'directory':True,'uid':uid,'gid':gid,'mode':0o700},'STOPPED')
 return True

def directory_fact(path):
 s=Path(path).lstat();return {'directory':stat.S_ISDIR(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode)}

def cache_root_facts(paths,uid,boundary=Path('/'),group=None):
 facts={}
 for path in paths:
  p=Path(path);go_ancestors(p,(0,uid),boundary=boundary,group=group)
  try:info=p.lstat()
  except FileNotFoundError:facts[str(p)]={'present':False};continue
  need(go_directory_safe(p,info,(0,uid),group),'GO_TRUST')
  facts[str(p)]={'present':True,'dev':info.st_dev,'ino':info.st_ino,'type':'directory','mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid}
 return facts

def validate_cache_roots(baseline,current,created,allow_new,origin,group=None):
 need(type(baseline) is dict and baseline and len(baseline)<=16 and type(current) is dict and set(current)==set(baseline) and type(created) is dict and set(created)<=set(baseline) and origin in ('go-env','goose-up','river-up') and (group is None or go_group_shape(group)),'GO_TRUST')
 result=dict(created)
 def descriptor(row,path):
  need(type(row) is dict and type(row.get('present')) is bool,'GO_TRUST')
  if row['present']:
   need(set(row)=={'present','dev','ino','type','mode','uid','gid'} and row['type']=='directory' and all(type(row[k]) is int and row[k]>=0 for k in ('dev','ino','mode','uid','gid')) and row['ino']>0 and (not row['mode']&0o022 or go_private_mode(path,row['uid'],row['gid'],row['mode'],group)),'GO_TRUST')
  else:need(row=={'present':False},'GO_TRUST')
 for path,original in baseline.items():
  actual=current[path];descriptor(original,path);descriptor(actual,path)
  if original['present']:
   need(path not in created and actual==original,'GO_TRUST');continue
  if path in created:
   record=created[path];need(type(record) is dict and set(record)=={'origin','identity'} and record['origin'] in ('go-env','goose-up','river-up'),'GO_TRUST');descriptor(record['identity'],path);need(record['identity']['present'] is True and actual==record['identity'],'GO_TRUST')
  elif actual['present']:
   need(allow_new is True,'GO_TRUST');result[path]={'origin':origin,'identity':dict(actual)}
 return result

class RemoteUnknown(BaseException):pass
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):return None
class Guest:
 def __init__(self,c,root):
  self.c=c;self.root=Path(root);self.counter=0;self.operation=c['operation'];self.deadline=time.monotonic()+c['seconds'];self.known=True
 def remaining(self,cap=600):need(self.deadline-time.monotonic()>0,'DEADLINE');return min(cap,self.deadline-time.monotonic())
 def command(self,args,*,data=None,env=None,cwd=None,accepted=(0,),cap=600):
  self.counter+=1;p=self.root/('cmd-'+str(self.counter));p.mkdir(mode=0o700)
  start=time.monotonic();ps_context=tenant_ps_context(self)
  try:
   result=subprocess.run(list(map(str,args)),input=data,capture_output=True,env=env,cwd=cwd,timeout=self.remaining(cap))
  except subprocess.TimeoutExpired as e:
   self.known=False
   for name,b in (('stdout',e.stdout or b''),('stderr',e.stderr or b'')):(p/name).write_bytes(b);(p/name).chmod(0o600)
   raise RemoteUnknown()
  for name,b in (('stdout',result.stdout),('stderr',result.stderr)):(p/name).write_bytes(b);(p/name).chmod(0o600)
  publish(p/'receipt.json',{'argv_sha256':hashlib.sha256(canonical(list(map(str,args)))).hexdigest(),'exit_code':result.returncode,'start_monotonic':start,'end_monotonic':time.monotonic(),'cwd_sha256':hashlib.sha256(str(cwd).encode()).hexdigest()})
  self.remaining();need(result.returncode in accepted,'CHILD');return result
 def text(self,args,**kw):return self.command(args,**kw).stdout.decode().strip()
 def pg(self,sql):return self.text(['runuser','-u','postgres','--','psql','-XAtq','-v','ON_ERROR_STOP=1','-d','nakpanel','-c',sql],cap=40)
 def row(self,sql):return decode(self.pg(sql))
 def cli(self,*args,root=False):
  prefix=[] if root else ['runuser','-u','nakpanel','--','env','NAKPANEL_DATABASE_URL=postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable','NAKPANEL_AGENT_SOCKET=/run/nakpanel/agent.sock','NAKPANEL_SECRET_KEY_FILE=/etc/nakpanel/secret-keys.json']
  return self.command(prefix+['/usr/local/bin/panelctl','--actor','source26-l1',*args],cap=1200,**({'cwd':'/'} if root else {}))
 def wait(self,query,expected,seconds=300):
  end=min(self.deadline,time.monotonic()+seconds);last=None;count=0
  while time.monotonic()<end:
   last=self.pg(query);count+=1
   if last==expected:return
   time.sleep(min(1,end-time.monotonic()))
  self.wait_observation=waitdiag.timeout_record(self,query,last,count,end,scope=getattr(self,'application_wait_scope',None),clock=time.monotonic)
  raise Refused('PHYSICAL')
 def identity(self,current=True):
  c=self.c;need(os.getuid()==0,'IDENTITY');physical_dir(self.root,uid=0);need(Path('/etc/nakpanel-qualification-owner').lstat().st_uid==0 and stat.S_IMODE(Path('/etc/nakpanel-qualification-owner').lstat().st_mode)==0o600 and not Path('/etc/nakpanel-qualification-owner').is_symlink() and Path('/etc/nakpanel-qualification-owner').read_text().strip()==c['token'],'IDENTITY')
  osrelease=dict(x.split('=',1) for x in Path('/etc/os-release').read_text().splitlines() if '=' in x);need(osrelease.get('ID','').strip('"')=='ubuntu' and osrelease.get('VERSION_ID','').strip('"')=='24.04' and self.text(['dpkg','--print-architecture'])=='amd64','IDENTITY')
  memory={x.split(':')[0]:int(x.split()[1])*1024 for x in Path('/proc/meminfo').read_text().splitlines()};device=self.text(['findmnt','-n','-o','SOURCE','/']);need(re.fullmatch('/dev/[A-Za-z0-9_-]+',device) is not None,'IDENTITY');parent=self.text(['lsblk','-ndo','PKNAME',device]);need(re.fullmatch('[A-Za-z0-9_-]+',parent) is not None,'IDENTITY');disk=int(self.text(['lsblk','-bdno','SIZE','/dev/'+parent]));validate_allocation(os.cpu_count(),memory['MemTotal'],disk)
  binaries={}
  for n,p in {'panel':'nakpanel-panel','agent':'nakpanel-agent','panelctl':'panelctl'}.items():binaries[n]=sha(regular('/usr/local/bin/'+p,uid=0,private=False))
  need(binaries==c['binaries'],'IDENTITY')
  platform_path=Path('/etc/nakpanel/platform.json');platform=None
  if platform_path.exists():
   regular(platform_path,uid=0,private=False);platform=decode(platform_path.read_bytes())
  if current:
   need(type(platform) is dict and platform.get('profile')=='ubuntu-24.04' and platform.get('architecture')=='amd64' and platform.get('internal_php_version')=='8.3' and platform.get('bootstrap_pending') is False,'IDENTITY')
   if c.get('platform_sha256'):need(sha(platform_path)==c['platform_sha256'],'IDENTITY')
  return {'allocation':{'cpus':os.cpu_count(),'memory_bytes':memory['MemTotal'],'root_disk_bytes':disk},'binaries':binaries,'platform':platform,'platform_sha256':sha(platform_path) if platform_path.exists() else None,'legacy_bootstrap_present':Path('/etc/nakpanel/platform-bootstrap-pending').exists(),'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'hostname':self.text(['hostname']),'schema':int(self.pg('SELECT max(version_id) FROM goose_db_version WHERE is_applied'))}
 def invocation(self):
  out={}
  for u in UNITS[:2]:
   text=self.text(['systemctl','show',u,'--property=InvocationID,ExecMainStartTimestampMonotonic,ActiveState,SubState','--no-pager'])
   out[u]=dict(x.split('=',1) for x in text.splitlines() if '=' in x)
  return {'at_utc':datetime.now(timezone.utc).isoformat(),'monotonic':time.monotonic(),'units':out,'complete_history':False}
 def admin(self):
  jar=http.cookiejar.CookieJar();context=ssl._create_unverified_context();login=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),urllib.request.HTTPSHandler(context=context))
  response=login.open('https://127.0.0.1:7443/login',urllib.parse.urlencode({'email':'admin@nakpanel.test','password':'NakpanelAdmin!2026'}).encode(),timeout=self.remaining(30));body=response.read();need(b'data-np-role="admin"' in body,'PHYSICAL')
  token=next((c.value for c in jar if c.name=='nakpanel_session'),None);need(token is not None,'PHYSICAL');csrf=hashlib.sha256(('nakpanel-csrf-v1:'+token).encode()).hexdigest()
  opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),urllib.request.HTTPSHandler(context=context),NoRedirect())
  def post(path,values,codes=(303,)):
   request=urllib.request.Request('https://127.0.0.1:7443/'+path,data=urllib.parse.urlencode(values).encode(),headers={'X-Nakpanel-CSRF':csrf})
   try:r=opener.open(request,timeout=self.remaining(60))
   except urllib.error.HTTPError as e:r=e
   status=r.status;location=r.headers.get('Location','');r.read(65536);r.close();need(status in codes,'PHYSICAL')
   if status==303:need(location.startswith('/') and not location.startswith('//') and '\n' not in location,'PHYSICAL')
   return {'status':status,'location_sha256':hashlib.sha256(location.encode()).hexdigest()}
  return post
 def discover(self):
  c=self.c
  rows=self.row("SELECT COALESCE(jsonb_agg(jsonb_build_object('site_id',s.id,'subscription_id',s.subscription_id,'username',a.username,'customer_id',sub.customer_id,'plan_id',sub.plan_id) ORDER BY s.id),'[]'::jsonb) FROM sites s JOIN subscriptions sub ON sub.id=s.subscription_id JOIN subscription_system_accounts a ON a.subscription_id=sub.id JOIN customers cust ON cust.id=sub.customer_id JOIN plans p ON p.id=sub.plan_id WHERE s.domain='current-bootstrap.test' AND s.status='active' AND s.desired_status='active' AND sub.status='active' AND cust.status='active' AND a.desired_state='active' AND a.convergence_status='in_sync' AND sub.name="+q('Qualification Bootstrap '+c['token'])+' AND p.name='+q('Qualification Mail '+c['token']))
  need(type(rows) is list and len(rows)==1,'PHYSICAL');r=rows[0]
  for k in ('site_id','subscription_id','customer_id','plan_id'):need(type(r.get(k)) is int and r[k]>0,'IDENTITY')
  need(type(r.get('username')) is str and re.fullmatch('[a-z][a-z0-9_-]{2,31}',r['username']),'IDENTITY');c.update(r);return r
 def jobs(self,kind,identity,revision):
  col='application_id' if kind=='converge_application' else 'subscription_id';need(kind in ('converge_application','converge_subscription'),'IDENTITY')
  return self.row("SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'kind',kind,'state',state,'"+col+"',(args->>'"+col+"')::bigint,'revision',(args->>'revision')::bigint) ORDER BY id),'[]'::jsonb) FROM river_job WHERE kind="+q(kind)+" AND args->>'"+col+"'="+q(identity)+" AND args->>'revision'="+q(revision))
 def app_row(self):
  c=self.c;rows=self.row("SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY a.id),'[]'::jsonb) FROM application_instances a WHERE subscription_id="+str(c['subscription_id'])+' AND site_id='+str(c['site_id'])+' AND name='+q('l1-stopped-'+c['run_id']))
  need(type(rows) is list and len(rows)==1,'STOPPED');return rows[0]
 def prepare_source_namespace(self,account):
  try:return prepare_source_namespace(self.c,account,chain='l1',deadline=self.deadline)
  except NamespaceRefused:raise Refused('PHYSICAL') from None
 def source_fixtures(self):
  c=self.c;self.identity(False);need(int(self.pg('SELECT max(version_id) FROM goose_db_version WHERE is_applied'))==SCHEMA55,'FORMAT');self.discover();sid=str(c['subscription_id']);site=str(c['site_id'])
  checks=["SELECT count(*) FROM mail_domains WHERE domain='current-bootstrap.test'","SELECT count(*) FROM webmail_hosts WHERE hostname='webmail.current-bootstrap.test'","SELECT count(*) FROM subscription_policy_overrides WHERE subscription_id="+sid,"SELECT count(*) FROM application_instances WHERE subscription_id="+sid,"SELECT count(*) FROM service_secrets WHERE scope='backup' AND name='archive-key'","SELECT count(*) FROM server_backup_destinations WHERE name='l1-local'"]
  for query in checks:need(self.pg(query)=='0','PHYSICAL')
  self.cli('mail','enable','current-bootstrap.test');self.cli('mail','add','l1@current-bootstrap.test','--password','Phase29Mail!2026');self.wait("SELECT convergence_status FROM mail_domains WHERE domain='current-bootstrap.test'",'in_sync');post=self.admin();post('webmail',{'domain':'current-bootstrap.test'},(202,303));self.wait("SELECT status FROM webmail_hosts WHERE hostname='webmail.current-bootstrap.test'",'active')
  policy=contracts()['stopped']['policy_request']['form']['policy_patch'];old_ent=self.pg("SELECT encode(sha256(convert_to((to_jsonb(e)-'updated_at')::text,'UTF8')),'hex') FROM subscription_entitlements e WHERE subscription_id="+sid)
  before=self.row("SELECT COALESCE(jsonb_agg(id ORDER BY id),'[]'::jsonb) FROM river_job WHERE kind='converge_subscription'");post('subscriptions/'+sid+'/policy',{'policy_patch':json.dumps(policy)})
  self.wait('SELECT convergence_status FROM subscription_system_accounts WHERE subscription_id='+sid,'in_sync');account=self.row('SELECT to_jsonb(a) FROM subscription_system_accounts a WHERE subscription_id='+sid);need(account['desired_revision']==account['applied_revision'],'PHYSICAL');jobs=self.jobs('converge_subscription',sid,account['desired_revision']);new=[j for j in jobs if j['id'] not in before];need(len(new)==1,'PHYSICAL');self.wait('SELECT state FROM river_job WHERE id='+str(new[0]['id']),'completed',30);new=self.jobs('converge_subscription',sid,account['desired_revision']);new=[j for j in new if j['id'] not in before];need(len(new)==1 and new[0]['state']=='completed','PHYSICAL')
  need(self.row('SELECT policy_patch FROM subscription_policy_overrides WHERE subscription_id='+sid)==policy,'INTENT');need(old_ent==self.pg("SELECT encode(sha256(convert_to((to_jsonb(e)-'updated_at')::text,'UTF8')),'hex') FROM subscription_entitlements e WHERE subscription_id="+sid),'INTENT');c['policy_job']=new[0]
  c['source_namespace_precondition']=self.prepare_source_namespace(account)
  post('subscriptions/'+sid+'/applications',application_form(c));row=self.app_row();c['application_id']=row['id'];self.application_wait_scope=waitdiag.owned_scope(c,row);self.wait('SELECT convergence_status FROM application_instances WHERE id='+str(row['id']),'in_sync');row=self.app_row();jobs=self.jobs('converge_application',row['id'],row['desired_revision']);need(len(jobs)==1,'STOPPED');self.wait('SELECT state FROM river_job WHERE id='+str(jobs[0]['id']),'completed',30);jobs=self.jobs('converge_application',row['id'],row['desired_revision']);need(len(jobs)==1 and jobs[0]['state']=='completed','STOPPED');c['source_application_job']=jobs[0]
  tenant=Path('/home/'+c['username']+'/domains/current-bootstrap.test/public_html/l1-canary.txt');need(not tenant.exists() and not tenant.is_symlink(),'PHYSICAL');marker=('nakpanel-l1-'+c['run_id']+'\n').encode();tenant.write_bytes(marker);u=pwd.getpwnam(c['username']);os.chown(tenant,u.pw_uid,u.pw_gid);tenant.chmod(0o644);c['tenant_file']=str(tenant)
  self.command(['mariadb','--batch','--skip-column-names','np_current_bootstrap','-e',"CREATE TABLE nakpanel_l1_canary(id INT PRIMARY KEY,v VARCHAR(160) NOT NULL); INSERT INTO nakpanel_l1_canary VALUES(1,"+q('nakpanel-l1-'+c['run_id'])+");"])
  self.canary('seed')
  # Key and disabled manual destination are preparation, before immutable baseline.
  result=self.cli('backup-server','key','init');keys=re.findall(rb'(?m)^nkbk1-[A-Z2-7]{52}$',result.stdout);need(len(keys)==1,'ARTIFACT');key=self.root/'backup.key';key.write_bytes(keys[0]+b'\n');key.chmod(0o600)
  self.cli('backup-server','destination','add','--name','l1-local','--kind','local','--disabled','--retention-count','3','--retention-days','0')
  c['roundcube_source']=self.roundcube();return {k:v for k,v in c.items() if k not in ('operation','operation_id','seconds','program_hashes')}
 def canary(self,mode):
  p=self.root/'phase29-imap-canary.py';need(sha(p)==contracts()['helpers']['deploy/multipass/phase29-imap-canary.py'],'INPUT_DRIFT');spec=importlib.util.spec_from_file_location('l1_phase29',p);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);mod.run_canary(mode,'l1@current-bootstrap.test','Phase29Mail!2026');return mod.success_receipt(mode).decode()
 def roundcube(self):
  paths=[p for p in Path('/etc/roundcube').rglob('*') if p.is_file() and not p.is_symlink()];need(paths,'PHYSICAL')
  hashes={str(p):sha(p) for p in paths};dsn=self.text(['php','-r',"include '/etc/roundcube/config.inc.php'; echo json_encode(['dsn'=>$config['db_dsnw']??null]);"]);raw=decode(dsn);need(type(raw) is dict and type(raw.get('dsn')) is str,'PHYSICAL');parsed=urllib.parse.urlparse(raw['dsn']);return {'backend':parsed.scheme,'host':parsed.hostname,'database':parsed.path,'config_sha256':hashlib.sha256(canonical(hashes)).hexdigest(),'config_files':hashes,'des_key_sha256':sha('/var/lib/nakpanel/roundcube-des-key')}
 def snapshot(self):
  raw=self.pg(intent_sql());intent={}
  for line in raw.splitlines():
   if not line:continue
   r=decode(line);need(type(r) is dict and set(r)=={'table','count','sha256'} and r['table'] in TABLES and r['table'] not in intent,'INTENT');intent[r['table']]={k:r[k] for k in ('count','sha256')}
  validate_intent(intent);return intent
 def rootless(self,*args):
  c=self.c;base='/var/lib/nakpanel/containers/sub-'+str(c['subscription_id']);runtime='/run/nakpanel-containers/sub-'+str(c['subscription_id'])
  account=pwd.getpwnam(c['username']);uid,gid=account.pw_uid,account.pw_gid
  manager=pwd.getpwnam('nakpanel');panel=Path('/var/lib/nakpanel');boundary=panel/'containers'
  need(manager.pw_name=='nakpanel' and type(manager.pw_uid) is int and manager.pw_uid>0 and manager.pw_uid!=uid and type(manager.pw_gid) is int and manager.pw_gid>0 and manager.pw_dir==str(panel),'GO_TRUST')
  need(directory_fact(panel)=={'directory':True,'uid':manager.pw_uid,'gid':manager.pw_gid,'mode':0o755},'GO_TRUST');safe_ancestors(panel.parent)
  parent=Path(base);safe_ancestors(parent,(0,uid),boundary=boundary);parent_fact=directory_fact(parent);leaves={}
  for name,p in {'home':Path(base+'/home'),'data':Path(base+'/data'),'config':Path(base+'/config'),'runtime':Path(runtime)}.items():
   safe_ancestors(p,(0,uid),boundary=boundary);leaves[name]=directory_fact(p)
  validate_rootless_layout(parent_fact,leaves,uid,gid);self.rootless_metadata={'namespace':parent_fact,'leaves':leaves}
  return self.command(['runuser','-u',c['username'],'--','env','HOME='+base+'/home','XDG_DATA_HOME='+base+'/data','XDG_CONFIG_HOME='+base+'/config','XDG_RUNTIME_DIR='+runtime,'TMPDIR='+runtime,'podman',*args],cwd='/')
 def parent_facts(self):
  c=self.c
  row=self.row("SELECT jsonb_build_object('subscription_id',sub.id,'site_id',s.id,'username',a.username,'account_desired_state',a.desired_state,'site_desired_status',s.desired_status,'subscription_status',sub.status,'customer_status',cust.status,'account_revision',a.desired_revision) FROM sites s JOIN subscriptions sub ON sub.id=s.subscription_id JOIN customers cust ON cust.id=sub.customer_id JOIN subscription_system_accounts a ON a.subscription_id=sub.id WHERE s.id="+str(c['site_id'])+' AND sub.id='+str(c['subscription_id']))
  validate_parent_facts(row,c);return row
 def stopped(self):
  c=self.c;parents_before=self.parent_facts();before=self.app_row();need(before['id']==c['application_id'],'STOPPED');aid=str(before['id']);prefix='nakpanel-app-'+aid+'-g';jobs=self.jobs('converge_application',before['id'],before['desired_revision']);need(jobs and all(j['state']=='completed' for j in jobs),'STOPPED');job=next((x for x in jobs if x['id']==c.get('source_application_job',{}).get('id')),jobs[0])
  if c.get('strict_jobs'):
   required={j['id'] for j in c['strict_jobs']['jobs'] if j['kind']=='converge_application'};current=[x for x in jobs if x['id'] in required];need(current,'STRICT_POST');job=current[0]
  ps=decode(self.rootless('ps','--all','--filter','label=io.nakpanel.application-id='+aid,'--format','json').stdout);need(type(ps) is list,'STOPPED');containers=[]
  for r in ps:
   ident=r.get('Id') or r.get('ID');need(type(ident) is str and re.fullmatch('[a-f0-9]{12,64}',ident),'STOPPED');ins=decode(self.rootless('inspect',ident).stdout);need(type(ins) is list and len(ins)==1,'STOPPED');r=ins[0];need(r.get('Config',{}).get('Labels',{}).get('io.nakpanel.application-id')==aid,'STOPPED');state=r.get('State',{});containers.append({'name':r.get('Name','').lstrip('/'),'application_id':before['id'],'running':state.get('Running'),'pid':state.get('Pid')})
  unit_rows=self.row_units(prefix);listeners=[];ss=self.text(['ss','-H','-ltnp']);port=before['endpoint_port'];need(type(port) is int and 20000<=port<=24999,'STOPPED')
  for line in ss.splitlines():
   fields=line.split();need(len(fields)>=4,'STOPPED');local=fields[3];m=re.search(r':([0-9]+)$',local)
   if m and int(m[1]) in (port,port+5000):listeners.append(int(m[1]))
  pending=int(self.pg("SELECT count(*) FROM river_job WHERE kind='converge_application' AND args->>'application_id'="+q(aid)+" AND state NOT IN ('completed','discarded','cancelled')"));after=self.app_row();desired=lambda r:{k:v for k,v in r.items() if k not in contracts()['assertions']['application_observed_exclusions']}
  physical={'store':self.rootless_metadata,'inspection_ok':True,'containers':containers,'units':unit_rows,'listeners':listeners,'port':port,'alternate_port':port+5000,'bracket_equal':desired(before)==desired(after),'pending':pending};validate_stopped(after,physical,job,c);parents_after=self.parent_facts();need(parents_before==parents_after,'STOPPED');return {'row':after,'parents':parents_after,'job':job,'physical':physical}
 def row_units(self,prefix):
  names=set()
  for kind in ('list-units','list-unit-files'):
   listed=self.command(['systemctl',kind,'--all','--no-pager','--output=json',prefix+'*.service'],accepted=(0,1) if kind=='list-unit-files' else (0,))
   raw=decode(listed.stdout)
   need(type(raw) is list and (listed.returncode==0 or (kind=='list-unit-files' and listed.returncode==1 and raw==[] and listed.stderr==b'')),'STOPPED')
   for r in raw:
    name=r.get('unit_file') if kind=='list-unit-files' else r.get('unit');need(type(name) is str and re.fullmatch(re.escape(prefix)+r'[1-9][0-9]*\.service',name),'STOPPED');names.add(name)
  result=[]
  for name in sorted(names):
   fields=dict(x.split('=',1) for x in self.text(['systemctl','show',name,'--property=ActiveState,SubState,MainPID,LoadState','--no-pager']).splitlines() if '=' in x);need(fields.get('LoadState')=='loaded' and fields.get('SubState')=='dead','STOPPED');result.append({'active':fields.get('ActiveState'),'pid':int(fields.get('MainPID','-1'))})
  return result
 def file_fact(self,path):
  p=Path(path);s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1,'PHYSICAL');return {'sha256':sha(p),'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'bytes':s.st_size}
 def physical(self,active=True):
  c=self.c;u=pwd.getpwnam(c['username']);subs={}
  for kind in ('subuid','subgid'):
   rows=[x for x in Path('/etc/'+kind).read_text().splitlines() if x.startswith(c['username']+':')];need(len(rows)==1,'PHYSICAL');subs[kind]=rows[0]
  cert='/var/lib/nakpanel/certs/current-bootstrap.test/fullchain.pem';key='/var/lib/nakpanel/certs/current-bootstrap.test/privkey.pem'
  files={p:self.file_fact(p) for p in (c['tenant_file'],'/etc/nakpanel/secret-keys.json',cert,key)}
  maria=lambda sql:self.text(['mariadb','--batch','--skip-column-names','np_current_bootstrap','-e',sql])
  database={'rows':maria('SELECT id,v FROM nakpanel_l1_canary ORDER BY id'),'collation':maria("SELECT DEFAULT_CHARACTER_SET_NAME,DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='np_current_bootstrap'"),'column':maria("SELECT CHARACTER_SET_NAME,COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='np_current_bootstrap' AND TABLE_NAME='nakpanel_l1_canary' AND COLUMN_NAME='v'"),'grants':maria("SHOW GRANTS FOR 'npu_current_bootstrap'@'localhost'")}
  need(database['rows']=='1\tnakpanel-l1-'+c['run_id'] and all(database.values()),'PHYSICAL')
  # Actual restored tenant password authenticates; system reads must be denied.
  opt=self.root/'maria-client.cnf';need(not opt.exists(),'PHYSICAL');opt.write_text('[client]\nuser=npu_current_bootstrap\npassword=NakpanelBootstrap_2026\n');opt.chmod(0o600)
  try:
   need(self.text(['mariadb','--defaults-extra-file='+str(opt),'-N','-B','np_current_bootstrap','-e','SELECT v FROM nakpanel_l1_canary WHERE id=1'])=='nakpanel-l1-'+c['run_id'],'PHYSICAL')
   denied=self.command(['mariadb','--defaults-extra-file='+str(opt),'-N','-B','-e','SELECT User FROM mysql.user'],accepted=(1,));need(denied.returncode==1,'PHYSICAL')
  finally:opt.unlink()
  if active:
   self.canary('assert')
   for u_name in UNITS:need(self.text(['systemctl','is-active',u_name])=='active','PHYSICAL')
   need(self.text(['systemctl','--failed','--no-legend','--plain'])=='','PHYSICAL')
   for args in (['nginx','-t'],['named-checkconf'],['sshd','-t']):self.command(args)
   # Trust the exact restored certificate, connect explicitly to this target.
   ctx=ssl.create_default_context(cafile=cert)
   with socket.create_connection(('127.0.0.1',443),timeout=self.remaining(20)) as raw:
    with ctx.wrap_socket(raw,server_hostname='current-bootstrap.test') as ch:
     ch.sendall(b'GET /l1-canary.txt HTTP/1.0\r\nHost: current-bootstrap.test\r\n\r\n');body=b''
     while True:
      b=ch.recv(4096)
      if not b:break
      body+=b;need(len(body)<65536,'PHYSICAL')
     need(b' 200 ' in body.split(b'\r\n',1)[0] and body.split(b'\r\n\r\n',1)[1]==('nakpanel-l1-'+c['run_id']+'\n').encode(),'PHYSICAL')
   # DNS values remain source intent; query the actual target explicitly.
   need(self.text(['dig','+short','@127.0.0.1','current-bootstrap.test','A'])!='','PHYSICAL')
  return {'identity':{'name':c['username'],'uid':u.pw_uid,'gid':u.pw_gid,**subs},'files':files,'database':database,'imap_asserted':active,'tls_asserted':active}
 def observe(self,active=True):
  id=self.identity(self.c['role']=='target');intent=self.snapshot();stopped=self.stopped();physical=self.physical(active)
  if self.c.get('baseline'):
   base=self.c['baseline'];same_intent(base['intent'],intent);need(base['physical']['identity']==physical['identity'] and base['physical']['files']==physical['files'] and base['physical']['database']==physical['database'],'PHYSICAL');old={k:v for k,v in base['stopped']['row'].items() if k not in contracts()['assertions']['application_observed_exclusions']};new={k:v for k,v in stopped['row'].items() if k not in contracts()['assertions']['application_observed_exclusions']};need(old==new and base['stopped']['parents']==stopped['parents'],'INTENT')
  return {'identity':id,'intent':intent,'stopped':stopped,'physical':physical,'invocation':self.invocation()}
 def backup(self):
  self.identity(False);c=self.c;need(self.pg("SELECT count(*) FROM server_backups b JOIN server_backup_destinations d ON d.id=b.destination_id WHERE d.name='l1-local'")=='0','ARTIFACT')
  dest=self.row("SELECT to_jsonb(d) FROM server_backup_destinations d WHERE name='l1-local'");need(dest['enabled'] is False and dest['include_mail_data'] is True and dest['retention_count']==3 and dest['retention_days']==0,'ARTIFACT')
  result=self.cli('backup-server','run','--destination','l1-local','--wait','--timeout','10m');ids=re.findall(rb'Server backup ([1-9][0-9]*) queued for destination l1-local\.',result.stdout);need(len(ids)==1,'ARTIFACT');ident=int(ids[0]);row=self.row('SELECT to_jsonb(b) FROM server_backups b WHERE id='+str(ident));need(row['status']=='active' and row['scheduled'] is False and row['verified_at'] and row['completed_at'] and row['last_error']=='','ARTIFACT');v=row['verify_detail'];need(type(v) is dict and set(v)=={'entries','bytes','pg_restore_list_ok','duration_ms'} and v['pg_restore_list_ok'] is True and type(v['entries']) is int and v['entries']>0 and type(v['bytes']) is int and v['bytes']>0,'ARTIFACT')
  jobs=self.row("SELECT COALESCE(jsonb_agg(to_jsonb(j) ORDER BY id),'[]'::jsonb) FROM river_job j WHERE kind='server_backup' AND args->>'server_backup_id'="+q(ident));need(len(jobs)==1,'ARTIFACT');self.wait('SELECT state FROM river_job WHERE id='+str(jobs[0]['id']),'completed',30);jobs=self.row("SELECT jsonb_agg(to_jsonb(j)) FROM river_job j WHERE id="+str(jobs[0]['id']));need(len(jobs)==1 and jobs[0]['state']=='completed' and jobs[0]['attempt']==1 and jobs[0]['max_attempts']==2,'ARTIFACT');need(re.fullmatch(r'[A-Za-z0-9_.-]+\.nkbk',row['archive_name']) is not None,'ARTIFACT');archive=Path('/var/lib/nakpanel/server-backups')/row['archive_name'];safe_ancestors(archive.parent,(0,pwd.getpwnam('nakpanel').pw_uid));user=self.text(['systemctl','show','nakpanel-agent.service','--property=User','--value']) or 'root';uid=pwd.getpwnam(user).pw_uid;regular(archive,uid=uid);before=self.file_fact(archive);need(before['sha256']==row['checksum_sha256'] and before['bytes']==row['size_bytes'],'ARTIFACT')
  # Same opened physical file is copied once; post-copy identity/hash must agree.
  with archive.open('rb') as src:
   s=os.fstat(src.fileno());copy=self.root/'archive.nkbk'
   with copy.open('xb') as dst:shutil.copyfileobj(src,dst);dst.flush();os.fsync(dst.fileno())
   copy.chmod(0o600);need((s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==tuple(getattr(os.fstat(src.fileno()),k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')),'ARTIFACT')
  need(self.file_fact(archive)==before and sha(copy)==row['checksum_sha256'],'ARTIFACT');return {'row':row,'job':{'id':jobs[0]['id'],'attempt':1,'max_attempts':2,'state':'completed'},'archive':self.file_fact(copy),'key':self.file_fact(self.root/'backup.key'),'key_fingerprint':row['key_fingerprint']}
 def authenticate(self):
  for n,expected in (('archive.nkbk',self.c['archive_sha256']),('backup.key',self.c['key_sha256'])):need(sha(regular(self.root/n,uid=0))==expected,'ARTIFACT')
  pre=decode(self.cli('restore-server','--archive',str(self.root/'archive.nkbk'),'--backup-key-file',str(self.root/'backup.key'),'--check-only',root=True).stdout);validate_preflight(pre,self.c['source_hostname']);need(pre['manifest'].get('key_fingerprint')==self.c['key_fingerprint'] and 'np_current_bootstrap' in pre['manifest'].get('tenant_databases',[]) and pre['manifest'].get('include_mail_data') is True,'FORMAT');need(self.identity()['schema']==SCHEMA56,'FORMAT');return pre
 def restore(self):
  before=self.invocation();r=self.cli('restore-server','--archive',str(self.root/'archive.nkbk'),'--backup-key-file',str(self.root/'backup.key'),'--allow-schema-mismatch','--skip-converge','--yes','--json',root=True);result=decode(r.stdout);validate_restore(result,self.c['manifest']);return {'result':result,'before':before,'after':self.invocation(),'actual_cli_exit':r.returncode,'return_utc':datetime.now(timezone.utc).isoformat(),'return_monotonic':time.monotonic(),'quiescent_before_stop':False}
 def stop(self):
  before=self.invocation();self.command(['systemctl','stop','nakpanel.service','nakpanel-agent.service'],cap=120);after=self.invocation()
  for u in UNITS[:2]:need(after['units'][u].get('ActiveState')=='inactive' and after['units'][u].get('SubState')=='dead','PHYSICAL')
  return {'stop_start':before,'stop_complete':after,'declared_disposable_execution_window':True,'quiescent_before_stop':False,'transient_writes_excluded':False}
 def quiet_observation(self):
  states={}
  for u in UNITS+('apt-daily.service','apt-daily-upgrade.service'):
   fields=dict(x.split('=',1) for x in self.text(['systemctl','show',u,'--property=Id,LoadState,ActiveState,SubState,Result,Job','--no-pager']).splitlines() if '=' in x);need(fields.get('Id')==u and fields.get('LoadState')=='loaded' and fields.get('Result')=='success' and fields.get('Job') in ('','0'),'PHYSICAL');stopped=u in UNITS[:2] or u.startswith('apt-');need(fields.get('ActiveState')==('inactive' if stopped else 'active') and fields.get('SubState') in (('dead',) if stopped else ('running','exited')),'PHYSICAL');states[u]=fields
  need(self.text(['systemctl','--failed','--no-legend','--plain'])=='','PHYSICAL');need(decode(self.command(['systemctl','list-jobs','--no-pager','--output=json']).stdout)==[],'PHYSICAL');need(self.pg('SELECT 1')=='1' and self.text(['mariadb','-N','-B','-e','SELECT 1'])=='1','PHYSICAL');return states
 def quiet(self):
  end=min(self.deadline,time.monotonic()+120)
  while time.monotonic()<end:
   try:before=self.quiet_observation()
   except Refused:time.sleep(1);continue
   quiet_start=time.monotonic();need(end-quiet_start>=4,'PHYSICAL');time.sleep(4)
   need(time.monotonic()-quiet_start>=4 and time.monotonic()<end,'PHYSICAL');after=self.quiet_observation();self.remaining()
   need(time.monotonic()<end and before==after,'PHYSICAL');schema=int(self.pg('SELECT max(version_id) FROM goose_db_version WHERE is_applied'));self.remaining();quiet_end=time.monotonic()
   need(quiet_end<end and quiet_end-quiet_start>=4 and schema==SCHEMA55,'PHYSICAL');return {'quiet_seconds':quiet_end-quiet_start,'quiet_start_monotonic':quiet_start,'quiet_end_monotonic':quiet_end,'schema':SCHEMA55,'panel_agent_inactive':True}
  raise Refused('PHYSICAL')
 def stage(self):
  source=Path(self.c['guest_bundle']);manifest=decode(regular(source/'manifest.json',uid=0,private=False).read_bytes());need(sha(source/'manifest.json')==contracts()['binding']['artifact']['current_manifest_sha256'],'ARTIFACT');files=contracts()['sources']['selected_signed_migration_subset'];need(len(files)==71 and all(manifest['files'].get(k)==v for k,v in files.items()),'ARTIFACT');physical_dir(source,uid=0,private=False);stage=Path(tempfile.mkdtemp(prefix='.l1-migrations.',dir='/var/lib/nakpanel'));uid=pwd.getpwnam('nakpanel').pw_uid;gid=pwd.getpwnam('nakpanel').pw_gid
  for name,h in files.items():
   p=source/name;safe_ancestors(p.parent,(0,));regular(p,uid=0,private=False,max_bytes=8*1024*1024);need(sha(p)==h,'ARTIFACT');dest=stage/name;dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
   with p.open('rb') as src,dest.open('xb') as out:shutil.copyfileobj(src,out)
   dest.chmod(0o600);os.chown(dest,uid,gid)
  for p in [*stage.rglob('*'),stage]:
   if p.is_dir():p.chmod(0o700);os.chown(p,uid,gid)
  self.verify_stage(str(stage));return {'stage':str(stage),'files':71,'max_schema':SCHEMA56}
 def verify_stage(self,stage):
  migration_argv(stage,'goose-up');p=Path(stage);uid=pwd.getpwnam('nakpanel').pw_uid;physical_dir(p,uid=uid);expected=contracts()['sources']['selected_signed_migration_subset'];actual={str(x.relative_to(p)) for x in p.rglob('*') if x.is_file()};need(actual==set(expected),'GO_TRUST')
  for name,h in expected.items():need(sha(regular(p/name,uid=uid))==h,'GO_TRUST');safe_ancestors((p/name).parent,(0,uid))
  return True
 def trust_files(self,official=False):
  # Refuse physical configuration before invoking any Go command.
  home=Path('/var/lib/nakpanel');stage=Path(self.c.get('migration_stage',str(self.root)));uid=pwd.getpwnam('nakpanel').pw_uid;group=go_private_group();go_config_absent(home,stage,group=group)
  for p in ('/etc/gitconfig','/root/.gitconfig','/root/.config/git/config','/root/.netrc'):absent(p)
  cache_roots=cache_root_facts((home/'go',home/'go/pkg',home/'go/pkg/mod',home/'.cache',home/'.cache/go-build'),uid,group=group)
  for p in Path('/var/lib/nakpanel/go/pkg/mod/cache/vcs').glob('*/config'):
   regular(p,uid=uid,private=False);validate_git_config(p.read_text())
  for p in ('/etc/pki/tls/certs','/etc/ssl/ca-bundle.pem','/etc/pki/tls/cacert.pem','/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem','/etc/ssl/cert.pem'):absent(p)
  for p in (Path('/usr/local/share/ca-certificates'),Path('/etc/ssl/certs')):safe_ancestors(p)
  need(not [p for p in Path('/usr/local/share/ca-certificates').rglob('*') if p.is_file()],'GO_TRUST')
  trust={'go_private_group':group}
  for directory in ('/usr/share/ca-certificates','/etc/ssl/certs'):
   for p in sorted(Path(directory).rglob('*')):
    if p.is_symlink():
     target=p.resolve();need(str(target).startswith(('/usr/share/ca-certificates/','/etc/ssl/certs/')) and target.is_file(),'GO_TRUST');regular(target,uid=0,private=False);trust[str(p)]={'target':str(target),'sha256':sha(target)}
    elif p.is_file():regular(p,uid=0,private=False);trust[str(p)]={'sha256':sha(p)}
  for n in ('make','git','sh'):
   exact={'make':'/usr/bin/make','git':'/usr/bin/git','sh':'/bin/sh'}[n];resolved=Path(exact).resolve();regular(resolved,uid=0,private=False);need(go_tool_path(shutil.which(n,path=PREFIX['PATH']),exact,resolved),'GO_TRUST');owner=self.text(['dpkg-query','-S',str(resolved)]);need(owner and ':' in owner,'GO_TRUST');trust[exact]={'target':str(resolved),'sha256':sha(resolved)}
  packages={'ca-certificates','git','make','dash'}
  for n in ('gcc','g++','sudo','env','python3'):
   path=shutil.which(n,path=PREFIX['PATH']);trust['tool-'+n]={'present':path is not None}
   if path:
    resolved=Path(path).resolve();regular(resolved,uid=0,private=False);owner=self.text(['dpkg-query','-S',str(resolved)]).split(':',1)[0];need(owner and re.fullmatch('[a-z0-9+.-]+',owner),'GO_TRUST');packages.add(owner);trust['tool-'+n].update(target=str(resolved),sha256=sha(resolved))
  need(shutil.which('hg',path=PREFIX['PATH']) is None,'GO_TRUST')
  verify=self.command(['dpkg','--verify',*sorted(packages)],accepted=(0,1));need(verify.returncode==0 and verify.stdout==b'' and verify.stderr==b'','GO_TRUST')
  go_root=Path('/usr/local/go');physical_dir(go_root,uid=0,private=False);inventory={}
  for p in sorted(go_root.rglob('*')):
   need(not p.is_symlink(),'GO_TRUST')
   if p.is_file():regular(p,uid=0,private=False);inventory[str(p.relative_to(go_root))]=sha(p)
   elif p.is_dir():physical_dir(p,uid=0,private=False)
  need(inventory and 'bin/go' in inventory and 'go.env' in inventory,'GO_TRUST')
  if official:
   # Fixed official endpoint, TLS through the measured ordinary Noble trust.
   data=urllib.request.urlopen('https://go.dev/dl/?mode=json&include=all',timeout=self.remaining(30)).read(16*1024*1024+1);need(len(data)<=16*1024*1024,'GO_TRUST');rows=decode(data);matches=[f for r in rows if r.get('version')=='go1.26.9' for f in r.get('files',[]) if f.get('filename')=='go1.26.9.linux-amd64.tar.gz'];need(len(matches)==1 and SHA.fullmatch(matches[0].get('sha256','')),'GO_TRUST');archive=self.root/'official-go.tar.gz';need(not archive.exists(),'GO_TRUST')
   with urllib.request.urlopen('https://go.dev/dl/go1.26.9.linux-amd64.tar.gz',timeout=self.remaining(120)) as src,archive.open('xb') as dst:shutil.copyfileobj(src,dst)
   archive.chmod(0o600);need(sha(archive)==matches[0]['sha256'],'GO_TRUST');expected={}
   with tarfile.open(archive,'r|gz') as tar:
    for item in tar:
     need((item.name=='go' and item.isdir()) or (item.name.startswith('go/') and '..' not in Path(item.name).parts and (item.isdir() or item.isfile())),'GO_TRUST')
     if item.isfile():expected[item.name[3:]]=hashlib.sha256(tar.extractfile(item).read()).hexdigest()
   need(expected==inventory,'GO_TRUST');trust['official_go_archive_sha256']=matches[0]['sha256'];archive.unlink()
  return {'go_inventory':inventory,'trust':trust,'go_root':'/usr/local/go','cache_roots':cache_roots}
 def target_baseline(self):
  identity=self.identity();need(identity['schema']==SCHEMA56,'FORMAT');baseline=self.trust_files(True);return {'identity':identity,'trust_baseline':baseline}
 def verify_trust(self,observation,allow_new=False,origin='go-env'):
  base=self.c['trust_baseline'];need(observation['go_inventory']==base['go_inventory'] and observation['trust']=={k:v for k,v in base['trust'].items() if k!='official_go_archive_sha256'},'GO_TRUST')
  self.c['cache_creations']=validate_cache_roots(base['cache_roots'],observation['cache_roots'],self.c.get('cache_creations',{}),allow_new,origin,group=observation['trust']['go_private_group'])
 def go_preflight(self):
  c=self.c;stage=c['migration_stage'];self.verify_stage(stage)
  validate_go_exports(dict(os.environ),canonical_shell=pwd.getpwuid(os.getuid()).pw_shell)
  before=self.trust_files();self.verify_trust(before)
  prefix=migration_argv(stage,'goose-up')[:-4]
  actual=decode(self.command(prefix+['/usr/bin/python3','-I','-B','-c','import os,json;print(json.dumps(dict(os.environ)))'],cwd=stage,cap=30).stdout);validate_go_exports(actual,True,canonical_shell=pwd.getpwnam('nakpanel').pw_shell)
  fields=contracts()['go']['observe_fields'];effective=decode(self.command(prefix+['/usr/local/go/bin/go','env','-json',*fields],cwd=stage,cap=30).stdout);validate_go_effective(effective,stage,compiler_available=before['trust']['tool-gcc']['present'])
  need(self.text(prefix+['/usr/local/go/bin/go','version'],cwd=stage,cap=30)=='go version go1.26.9 linux/amd64','GO_TRUST');after_env=self.trust_files();self.verify_trust(after_env,True,'go-env');return after_env
 def migrate(self,target):
  self.go_preflight();self.command(migration_argv(self.c['migration_stage'],target),cwd=self.c['migration_stage'],cap=1200);self.verify_stage(self.c['migration_stage']);after=self.trust_files();self.verify_trust(after,True,target);need(int(self.pg('SELECT max(version_id) FROM goose_db_version WHERE is_applied'))==SCHEMA56,'FORMAT');return {'target':target,'schema':SCHEMA56,'trust_verified':True,'stage_files_unchanged':True,'cache_creations':self.c.get('cache_creations',{})}
 def strict_post(self):
  before=self.row("SELECT COALESCE(jsonb_agg(id ORDER BY id),'[]'::jsonb) FROM river_job");result=self.cli('restore-server-post','--strict','--archive-host',self.c['source_hostname'],'--entries',str(self.c['extracted_entries']));need(re.fullmatch(rb'post-restore convergence finished \([0-9]+ MariaDB users, 0 warnings\)\n',result.stdout) is not None and b'warning:' not in result.stderr,'STRICT_POST');ids=re.findall(rb'reconciliation run ([1-9][0-9]*) queued',result.stderr);need(len(ids)==1,'STRICT_POST');runid=int(ids[0]);run=self.row('SELECT to_jsonb(r) FROM reconciliation_runs r WHERE id='+str(runid));need(run['status']=='active' and run['sites_total']==run['sites_ok'] and run['last_error']=='','STRICT_POST')
  jobs=self.row("SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'kind',kind,'state',state,'args',args) ORDER BY id),'[]'::jsonb) FROM river_job WHERE kind IN ("+','.join(q(k) for k in JOB_KINDS)+") AND created_at >= (SELECT created_at FROM reconciliation_runs WHERE id="+str(runid)+')');new=[j for j in jobs if j['id'] not in before];need(new and all(j['state']=='completed' for j in new) and any(j['kind']=='reconcile_system' and j['args'].get('run_id')==runid for j in new) and any(j['kind']=='converge_subscription' for j in new) and any(j['kind']=='reconcile_applications' for j in new),'STRICT_POST');return {'run_id':runid,'jobs':new,'warnings':0,'database_validation_in_strict_cli':True,'exit_code':result.returncode}
 def active_readiness(self):
  p=Path('/var/lib/nakpanel-qualification')/self.c['token']/'source/deploy/multipass/qualification_maintenance_ready.py'
  need(sha(regular(p,uid=0,private=False))==contracts()['helpers']['deploy/multipass/qualification_maintenance_ready.py'],'INPUT_DRIFT')
  self.command(['/usr/bin/python3','-I','-B',str(p)],cap=600)
 def dispatch(self):
  op=self.operation
  if op=='SOURCE_FIXTURES':return self.source_fixtures()
  self.identity(self.c['role']=='target')
  if op=='TARGET_BASELINE':return self.target_baseline()
  if op in ('INITIAL','BOOT1','BOOT2'):self.active_readiness();return self.observe(True)
  if op in ('SOURCE_BEFORE','SOURCE_AFTER'):return self.observe(True)
  if op in ('STOPPED_BEFORE','STOPPED_AFTER'):return self.observe(False)
  if op=='BACKUP':return self.backup()
  if op=='AUTHENTICATE':return self.authenticate()
  if op=='RESTORE':return self.restore()
  if op=='AFTER_RETURN':return self.invocation()
  if op=='PLANNED_STOP':return self.stop()
  if op=='QUIET':return self.quiet()
  if op=='STAGE':return self.stage()
  if op=='GOOSE':return self.migrate('goose-up')
  if op=='RIVER':return self.migrate('river-up')
  if op=='NORMAL_START':self.command(['systemctl','start','nakpanel-agent.service','nakpanel.service'],cap=120);return {'normal_start_once':True}
  if op=='STRICT_POST':return self.strict_post()
  raise Refused('IDENTITY')
def q(v):return "'"+str(v).replace("'","''")+"'"
def main():
 root=Path(__file__).resolve().parent;os.umask(0o077);raw=sys.stdin.buffer.read(4*1024*1024+1);need(len(raw)<=4*1024*1024,'IDENTITY');c=decode(raw);need(type(c) is dict and c.get('operation') in PHASES and c.get('role') in ('source','target') and type(c.get('operation_id')) is str and re.fullmatch('[0-9a-f]{32}',c['operation_id']) and type(c.get('seconds')) is int and 0<c['seconds']<=4500,'IDENTITY');selected=roles(c.get('run_id'))[c['role']];need(c['vm']==selected['vm'] and c['token']==selected['token'],'IDENTITY')
 for n,h in c['program_hashes'].items():need(safe_name(n) and sha(regular(root/n,uid=0))==h,'INPUT_DRIFT')
 opdir=root/c['operation_id'];opdir.mkdir(mode=0o700);g=Guest(c,opdir);g.root=root # shared sealed programs/data; command log names get operation prefix below
 g.counter=int(c['operation_index'])*1000
 started=time.monotonic();receipt={'schema':'nakpanel-l1-remote-v1','operation':c['operation'],'operation_id':c['operation_id'],'role':c['role'],'vm':c['vm'],'token':c['token'],'run_id':c['run_id'],'source_commit':SOURCE,'program_sha256':sha(root/'guest.py'),'input_sha256':hashlib.sha256(raw).hexdigest(),'started_utc':datetime.now(timezone.utc).isoformat(),'started_monotonic':started,'known':False,'status':'STARTED','exit_code':None,'payload':None}
 publish(opdir/'intent.json',receipt,cap=4*1024*1024)
 try:receipt['payload']=g.dispatch();receipt.update(known=True,status='PASS',exit_code=0)
 except RemoteUnknown as e:
  receipt.update(known=False,status='UNKNOWN',exit_code=None,reason='REMOTE_UNKNOWN')
  try:receipt['failure_detail']=capture_guest_failure(e,g,receipt,FAILURE_CODES,root,kind='REMOTE_UNKNOWN')
  except BaseException:receipt['failure_detail']=unavailable('REMOTE_UNKNOWN','REMOTE_UNKNOWN')
 except BaseException as e:
  receipt.update(known=g.known,status='FAIL',exit_code=1,reason=e.code if isinstance(e,Refused) else 'UNKNOWN')
  try:receipt['failure_detail']=capture_guest_failure(e,g,receipt,FAILURE_CODES,root)
  except BaseException:receipt['failure_detail']=unavailable(receipt['reason'])
 receipt.update(finished_utc=datetime.now(timezone.utc).isoformat(),finished_monotonic=time.monotonic());publish(opdir/'terminal.json',receipt,cap=4*1024*1024);sys.stdout.buffer.write(canonical(receipt));return 0 if receipt['status']=='PASS' else 1
FAILURE_CODES=trusted_guest_codes(globals())
if __name__=='__main__':raise SystemExit(main())
