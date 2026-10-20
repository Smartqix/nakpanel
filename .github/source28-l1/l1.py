#!/usr/bin/env python3
"""Fixed L1 qualification. Import is inert. Runtime needs external root admission.

The packet carries no execution authority. The outer trusted workflow/root must
pin the exact controller commit/tree/parent and every changed blob before run.
"""
import argparse, hashlib, json, math, os, re, stat, sys, tempfile, time
from pathlib import Path, PurePosixPath
from datetime import datetime, timezone
sys.dont_write_bytecode=True
SOURCE='6378b0ae9d15f17481b080926af7fb0bf0761724'
TREE='e0971772916ef3aee3ee7cb23b65645a2b2272fc'
PRIOR='ef8b5a7ebc0462cb90a1ae5b8fa98e4a3af46466'
IMAGE_REF='docker.io/library/nginx@sha256:959ae6b898852db82e5b29b929388e59914f42be0a8f4d44c89a4c1f53b49208'
BRANCH='ricky/source28-legacy-format1-v8'
REPO='Smartqix/nakpanel'
REPO_ID=1292416194
SCHEMA55=20261015000055
SCHEMA56=20261018000056
SHA=re.compile(r'[0-9a-f]{64}')
COMMIT=re.compile(r'[0-9a-f]{40}')
ROOT=Path(__file__).resolve().parent
CAPS={'stage':15*60,'source':75*60,'backup':20*60,'cold':3*60,'target':60*60,'recovery':60*60,'boot1':20*60,'boot2':20*60,'projection':2*60,'cleanup':10*60,'upload':5*60}
PHASES=('SOURCE_INSTALL','SOURCE_FIXTURES','SOURCE_BEFORE','BACKUP','SOURCE_AFTER','SOURCE_COLD','TARGET_INSTALL','TARGET_BASELINE','TRANSFER','AUTHENTICATE','RESTORE','AFTER_RETURN','PLANNED_STOP','STOPPED_BEFORE','QUIET','STAGE','GOOSE','RIVER','STOPPED_AFTER','NORMAL_START','STRICT_POST','INITIAL','R9_INITIAL','REBOOT1','BOOT1','R9_BOOT1','REBOOT2','BOOT2','R9_BOOT2')
REASONS={'PENDING','ADMISSION','IDENTITY','ARTIFACT','INPUT_DRIFT','DEADLINE','CHILD','REMOTE_UNKNOWN','FORMAT','INTENT','STOPPED','GO_TRUST','STRICT_POST','PHYSICAL','R9','BOOT','CLEANUP','PUBLICATION','UNKNOWN'}

class Refused(ValueError):
 def __init__(self,code='UNKNOWN'): self.code=code if code in REASONS else 'UNKNOWN';super().__init__(self.code)
def need(test,code='UNKNOWN'):
 if not test:raise Refused(code)
def sha(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def canonical(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode()
def pairs(xs):
 d={}
 for k,v in xs:need(k not in d,'IDENTITY');d[k]=v
 return d
def decode(b):
 try:return json.loads(b,object_pairs_hook=pairs)
 except (ValueError,UnicodeError):raise Refused('IDENTITY') from None
def regular(p,uid=None,private=True,max_bytes=None):
 p=Path(p);s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==(os.getuid() if uid is None else uid) and not s.st_mode&(0o077 if private else 0o022),'IDENTITY')
 if max_bytes is not None:need(s.st_size<=max_bytes,'IDENTITY')
 return p
def physical_dir(p,uid=None,private=True):
 p=Path(p);need(p.is_absolute() and p.resolve()==p,'IDENTITY');s=p.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==(os.getuid() if uid is None else uid) and not s.st_mode&(0o077 if private else 0o022),'IDENTITY');return p
def publish(path,v,cap=65536):
 p=Path(path);data=canonical(v);need(len(data)<=cap,'PUBLICATION');physical_dir(p.parent)
 fd,n=tempfile.mkstemp(prefix='.'+p.name+'.',dir=p.parent)
 try:
  os.fchmod(fd,0o600)
  with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
  os.replace(n,p);d=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(d)
  finally:os.close(d)
 finally:
  if os.path.exists(n):os.unlink(n)
def safe_name(n):return type(n) is str and bool(n) and not PurePosixPath(n).is_absolute() and '..' not in PurePosixPath(n).parts and str(PurePosixPath(n))==n and '\\' not in n and not any(c in n for c in '\n\r\0')
def roles(run):
 need(type(run) is str and re.fullmatch('[1-9][0-9]{0,13}',run) is not None,'ADMISSION')
 return {role:{'token':'l1-'+run+'-1-'+suffix,'vm':'nakpanel-24-04-amd64-l1-'+run+'-1-'+suffix} for role,suffix in [('source','s'),('target','t')]}
def contracts():return decode((ROOT/'contracts.json').read_bytes())
# SQL text comes from the immutable reviewed projection contract.
TABLES=('addon_plans','application_instances','application_manifest_revisions','application_presets','databases','dns_records','dns_zones','ftp_accounts','mail_domains','mailboxes','php_applications','php_deployments','php_environment_bindings','php_workers','plan_revisions','plan_service_presets','plans','service_secrets','sftp_access_identities','site_policy_overrides','sites','subscription_addons','subscription_entitlements','subscription_policy_overrides','subscriptions','webmail_hosts')
def validate_intent(x):
 need(type(x) is dict and set(x)==set(TABLES),'INTENT')
 for row in x.values():need(type(row) is dict and set(row)=={'count','sha256'} and type(row['count']) is int and 0<=row['count']<=100000 and type(row['sha256']) is str and SHA.fullmatch(row['sha256']),'INTENT')
 return True
def same_intent(a,b):validate_intent(a);validate_intent(b);need(a==b,'INTENT');return True
def validate_stopped(row,physical,job,c):
 need(type(row) is dict and type(physical) is dict and type(job) is dict,'STOPPED')
 need(type(row.get('id')) is int and row['id']>0 and row['id']==c['application_id'] and row.get('site_id')==c['site_id'] and row.get('subscription_id')==c['subscription_id'],'STOPPED')
 need(row.get('name')=='l1-stopped-'+c['run_id'] and row.get('runtime')=='oci' and row.get('image_ref')==IMAGE_REF and row.get('desired_state')=='stopped' and row.get('delete_requested') is False,'STOPPED')
 rev=row.get('desired_revision');need(type(rev) is int and rev>0 and row.get('applied_revision')==rev and row.get('applied_state')=='stopped' and row.get('convergence_status')=='in_sync' and row.get('last_error')=='' and row.get('observed_state') in ('stopped','missing'),'STOPPED')
 need(type(job.get('id')) is int and job['id']>0 and job.get('kind')=='converge_application' and job.get('state')=='completed' and job.get('application_id')==row['id'] and job.get('revision')==rev,'STOPPED')
 need(physical.get('inspection_ok') is True and physical.get('bracket_equal') is True and type(physical.get('pending')) is int and physical['pending']==0,'STOPPED')
 p=physical.get('port');need(type(p) is int and 20000<=p<=24999 and physical.get('alternate_port')==p+5000,'STOPPED')
 need(type(physical.get('containers')) is list and type(physical.get('units')) is list and physical.get('listeners')==[],'STOPPED')
 for container in physical['containers']:
  need(type(container) is dict and container.get('running') is False and type(container.get('pid')) is int and container['pid']==0 and container.get('application_id')==row['id'] and type(container.get('name')) is str and re.fullmatch('nakpanel-app-'+str(row['id'])+'-g[1-9][0-9]*',container['name']),'STOPPED')
 for unit in physical['units']:need(type(unit) is dict and unit.get('active')=='inactive' and unit.get('pid')==0,'STOPPED')
 return True
def validate_parent_facts(f,c):
 need(type(f) is dict and all(f.get(k)==c[k] for k in ('subscription_id','site_id','username')) and type(f.get('account_revision')) is int and f['account_revision']>0,'STOPPED')
 need(all(f.get(k)=='active' for k in ('account_desired_state','site_desired_status','subscription_status','customer_status')),'STOPPED');return True
def validate_allocation(cpus,memory,root_disk):
 need(type(cpus) is int and cpus==2 and type(memory) is int and 4.5*2**30<=memory<=5*2**30 and type(root_disk) is int and root_disk==32*2**30,'IDENTITY');return True
GO_ALLOW={'GODEBUG':'','GOPROXY':'https://proxy.golang.org,direct','GOSUMDB':'sum.golang.org'}
DENY={'SSL_CERT_FILE','SSL_CERT_DIR','CURL_CA_BUNDLE','REQUESTS_CA_BUNDLE','SSLKEYLOGFILE','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','http_proxy','https_proxy','all_proxy','no_proxy','GCM_INTERACTIVE','NETRC','XDG_CONFIG_HOME','MAKEFLAGS','GNUMAKEFLAGS','MAKEFILES','MFLAGS','SHELL','ENV','BASH_ENV','CDPATH','LD_PRELOAD','LD_LIBRARY_PATH','CC','CXX','PKG_CONFIG','AR','RANLIB','FC','LDFLAGS','CFLAGS','CPPFLAGS','CXXFLAGS','GCC_EXEC_PREFIX','COMPILER_PATH','LIBRARY_PATH','CPATH','C_INCLUDE_PATH','CPLUS_INCLUDE_PATH','OBJC_INCLUDE_PATH','AS','LD','NM','OBJC','OBJCFLAGS'}
PREFIX={'HOME':'/var/lib/nakpanel','PATH':'/usr/local/go/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','GOTOOLCHAIN':'go1.26.9','DB_DSN':'postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable','GODEBUG':'http2client=0'}
def validate_go_exports(env,prefixed=False,canonical_shell=None):
 need(type(env) is dict and all(type(k) is str and type(v) is str for k,v in env.items()),'GO_TRUST')
 for k,v in env.items():
  if k=='SHELL' and canonical_shell in ('/usr/sbin/nologin','/bin/bash'):
   need(v==canonical_shell,'GO_TRUST');continue
  if k.startswith(('GO','GIT_','SSH_','CGO_')) or k in DENY:
   allow=dict(GO_ALLOW)
   if prefixed:allow.update({k:v for k,v in PREFIX.items() if k.startswith('GO')})
   need(k in allow and v==allow[k],'GO_TRUST')
 if prefixed:need(all(env.get(k)==v for k,v in PREFIX.items()),'GO_TRUST')
 return True
def migration_argv(stage,target):
 need(type(stage) is str and re.fullmatch(r'/var/lib/nakpanel/\.l1-migrations\.[A-Za-z0-9]+',stage) and target in ('goose-up','river-up'),'GO_TRUST')
 return ['sudo','-u','nakpanel','env',*[k+'='+v for k,v in PREFIX.items()],'make','-C',stage,target]
def validate_preflight(pre,host):
 need(type(pre) is dict and pre.get('compatible') is True,'FORMAT');m=pre.get('manifest');need(type(m) is dict,'FORMAT')
 need(type(m.get('format_version')) is int and m['format_version']==1 and 'platform' not in m and m.get('hostname')==host and m.get('goose_version')==SCHEMA55 and m.get('panel_version')=='29.0.0+'+PRIOR and m.get('include_mail_data') is True,'FORMAT');need(m.get('trees')==contracts()['legacy_archive_trees'],'FORMAT');target=pre.get('target');need(type(target) is dict and all(target.get(k)==v for k,v in {'os_id':'ubuntu','version_id':'24.04','profile':'ubuntu-24.04','architecture':'amd64','internal_php_version':'8.3'}.items()),'FORMAT');return True
def validate_restore(r,m):
 need(type(r) is dict and r.get('schema_mismatch') is True,'FORMAT');s=r.get('summary');need(type(s) is dict and s.get('schema_mismatch') is True and s.get('manifest')==m and type(s.get('extracted_entries')) is int and s['extracted_entries']>0 and type(s.get('mariadb_restored')) is list and 'np_current_bootstrap' in s['mariadb_restored'],'FORMAT');need(type(s.get('services_started')) is list and s['services_started']==r.get('services_started') and set(s['services_started'])=={'nakpanel-agent.service','nakpanel.service','nginx.service','named.service','stalwart-mail.service','nakpanel-proftpd.service'} and type(s.get('duration_ms')) is int and s['duration_ms']>=0,'FORMAT');return True
class Graph:
 def __init__(self):self.done=[];self.failed=None;self.remote_known=True;self.drained=True
 def complete(self,phase,receipt):
  need(self.failed is None and phase in PHASES and phase not in self.done and PHASES.index(phase)==len(self.done),'IDENTITY');need(receipt.get('known') is True,'REMOTE_UNKNOWN');self.done.append(phase)
 def unknown(self,phase):self.failed=phase;self.remote_known=False
 @property
 def cleanup_allowed(self):return self.remote_known and self.drained
class Budget:
 def __init__(self,clock=time.monotonic):self.clock=clock;self.start=clock();self.ends={}
 def allowance(self,phase):
  need(phase in CAPS,'DEADLINE');now=self.clock();self.ends.setdefault(phase,now+CAPS[phase]);global_end=self.start+(290 if phase in ('cleanup','upload') else 275)*60
  remaining=min(self.ends[phase],global_end)-now;need(math.isfinite(remaining) and remaining>2,'DEADLINE');return remaining-1
 def check(self,phase):self.allowance(phase)
def validate_admission(a,env,expected):
 need(type(a) is dict and a.get('state')=='AUTHORIZED','PENDING')
 keys={'schema','state','source_commit','source_tree','controller_commit','controller_tree','controller_parent','branch','event','repository','repository_id','public','run_attempt','root_approval_sha256','valid_from','expires_at','packet','helpers','changed_blobs','allow_failure_cleanup'}
 need(set(a)==keys and a['schema']=='nakpanel-l1-root-admission-v1' and type(expected) is str and SHA.fullmatch(expected),'ADMISSION')
 identity_only=a['controller_commit'] is None and a['controller_tree'] is None
 need(identity_only or (type(a['controller_commit']) is str and COMMIT.fullmatch(a['controller_commit']) and type(a['controller_tree']) is str and COMMIT.fullmatch(a['controller_tree'])),'ADMISSION')
 need(a['source_commit']==SOURCE and a['source_tree']==TREE and a['controller_parent']==SOURCE and a['root_approval_sha256']==expected,'ADMISSION')
 need(a['repository']==REPO and type(a['repository_id']) is int and a['repository_id']==REPO_ID and a['public'] is True and a['branch']==BRANCH and a['event']=='push' and type(a['run_attempt']) is int and a['run_attempt']==1 and a['allow_failure_cleanup'] is True,'ADMISSION')
 now=datetime.now(timezone.utc)
 try:start=datetime.fromisoformat(a['valid_from'].replace('Z','+00:00'));end=datetime.fromisoformat(a['expires_at'].replace('Z','+00:00'))
 except (ValueError,AttributeError):raise Refused('ADMISSION') from None
 need(start.tzinfo is not None and end.tzinfo is not None and start<=now<end and 0<(end-start).total_seconds()<=86400,'ADMISSION')
 for k in ('packet','helpers','changed_blobs'):
  need(type(a[k]) is dict and a[k] and all(safe_name(n) and type(h) is str and SHA.fullmatch(h) for n,h in a[k].items()),'ADMISSION')
 need(env.get('GITHUB_REPOSITORY')==REPO and env.get('GITHUB_REPOSITORY_ID')==str(REPO_ID) and env.get('GITHUB_EVENT_NAME')=='push' and env.get('GITHUB_REF')=='refs/heads/'+BRANCH and env.get('GITHUB_RUN_ATTEMPT')=='1' and type(env.get('GITHUB_SHA')) is str and COMMIT.fullmatch(env['GITHUB_SHA']) and (identity_only or env['GITHUB_SHA']==a['controller_commit']) and env.get('RUNNER_OS')=='Linux' and env.get('RUNNER_ARCH')=='X64' and env.get('RUNNER_ENVIRONMENT')=='github-hosted' and env.get('GITHUB_ACTIONS')=='true','ADMISSION');roles(env.get('GITHUB_RUN_ID'));a=dict(a);a['workflow_bound_externally']=identity_only
 if identity_only:a['controller_commit']=env['GITHUB_SHA']
 return a

def safe_result(s,failure_root=None):
 boots=s.get('boots',[]);boots=boots if type(boots) is list else []
 valid_boots=1<=len(boots)<=3 and all(type(b) is str and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',b) for b in boots) and len(set(boots))==len(boots)
 passed=s.get('overall')=='PASS' and s.get('covered') is True and s.get('strict') is True and s.get('r9_count')==3 and valid_boots and len(boots)==3 and s.get('cleanup') is True and s.get('remote_known') is True and s.get('drained') is True
 r={'schema':'nakpanel-l1-result-v1','overall_integration':'PASS' if passed else 'FAIL','covered_format1':'PASS' if s.get('covered') is True else 'PENDING','strict_post':s.get('strict') is True,'target_r9_completed':s.get('r9_count') if type(s.get('r9_count')) is int and 0<=s['r9_count']<=3 else 0,'target_restarts_completed':len(boots)-1 if valid_boots else 0,'reason':s.get('reason') if s.get('reason') in REASONS else 'UNKNOWN','source_commit':SOURCE,'prior_commit':PRIOR,'image_ref':IMAGE_REF,'image_coverage':'CONFIG_ONLY_STOPPED','old_roundcube_database_preservation':False,'format3':'PENDING','production_qualified':False,'full17_claim':False,'cleanup_confirmed':s.get('cleanup') is True,'remote_work_known':s.get('remote_known') is True,'host_drained':s.get('drained') is True,'phases':[]}
 phase_rows={}
 for row in s.get('phases',[])[:64]:
  if type(row) is dict and row.get('phase') in PHASES and row.get('status') in ('PASS','FAIL','UNKNOWN','PENDING'):phase_rows[row['phase']]=row['status']
 r['phases']=[{'phase':phase,'status':phase_rows.get(phase,'PENDING')} for phase in PHASES]
 for key in ('run_id','controller_commit','controller_tree','archive_sha256','manifest_sha256'):
  value=s.get(key)
  if type(value) is str and ((key=='run_id' and re.fullmatch('[1-9][0-9]{0,13}',value)) or (key in ('controller_commit','controller_tree') and COMMIT.fullmatch(value)) or (key.endswith('sha256') and SHA.fullmatch(value))):r[key]=value
 if type(s.get('archive_bytes')) is int and 0<s['archive_bytes']<=64*1024*1024:r['archive_bytes']=s['archive_bytes']
 if valid_boots:r['boot_ids']=boots
 if s.get('format1_authenticated') is True:r.update(format_version=1,platform_provenance_present=False,archive_schema=SCHEMA55,installed_target_schema=SCHEMA56)
 if s.get('failed_remote') is not None or s.get('failed_remote_capture')=='UNAVAILABLE':
  r['guest_failure_capture']='UNAVAILABLE'
  if failure_root is not None:
   try:
    from failure import project_failure
    diagnostic=project_failure(failure_root,s);r['guest_failure']=diagnostic;r['guest_failure_capture']=diagnostic['failure']['capture']
   except Exception:pass
 return r

def main():
 p=argparse.ArgumentParser();p.add_argument('action',choices=['validate','run']);p.add_argument('--admission',required=True);p.add_argument('--admission-sha256',required=True);p.add_argument('--root-approval-sha256',required=True);p.add_argument('--application');p.add_argument('--operator');args=p.parse_args()
 try:
  ap=regular(args.admission,max_bytes=262144);need(sha(ap)==args.admission_sha256,'ADMISSION');a=validate_admission(decode(ap.read_bytes()),dict(os.environ),args.root_approval_sha256)
  if args.action=='validate':return 0
  for name,h in a['packet'].items():need(safe_name(name) and sha(regular(ROOT/name,private=False))==h,'INPUT_DRIFT')
  sys.path.insert(0,str(ROOT))
  from l1_runtime import Coordinator
  Coordinator(a,args.application,args.operator).execute();return 0
 except BaseException:
  print('L1 refused or failed; private hosted evidence retained',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
