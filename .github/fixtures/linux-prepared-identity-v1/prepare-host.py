"""INERT preparation for a separately admitted disposable-host dummy experiment."""
import argparse,hashlib,json,os,platform,re,stat,sys,time,types
from pathlib import Path
from datetime import datetime,timezone
HERE=Path(__file__).resolve().parent
SOURCE='1627bba3c681a884255eb91452dbba74a43ebbdc'
DIAGNOSTIC_SHA='6956ff0b6189cd624bc92ff886f330ae080b23d5a4827043b9c55c0e4ecae687'
UNITS={'PANEL':'nakpanel.service','AGENT':'nakpanel-agent.service'}
PROPS=('--property=LoadState','--property=ActiveState','--property=SubState','--property=MainPID','--property=InvocationID','--property=FragmentPath')
FIXED_ENV={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'}
DIRECTORIES=(('ROOT',None,None),('USR',0,'usr'),('USR_LOCAL',1,'local'),('USR_LOCAL_BIN',2,'bin'),('USR_SHARE',1,'share'),('ETC',0,'etc'),('USR_SHARE_ZONEINFO',4,'zoneinfo'),('USR_SHARE_ZONEINFO_ETC',6,'Etc'))
NORMALIZE=((3,'/usr/local/bin'),(4,'/usr/share'),(6,'/usr/share/zoneinfo'),(7,'/usr/share/zoneinfo/Etc'))
OLD_RUNS={'39357893933','39361557934'}
OLD_CONTEXTS={'9b8df258056eb3fcaa9018d2b4d77cdb5cda1e7ad53132e96785406e1ce1c8bd','06e5a1f03f97f6f26a77660ef12456d1752e2fab99ca4a4ca7d37c09037760c4'}
OLD_HEADS={SOURCE,'f89eacc8caaebeefed24d82fdc03759a5c0c347e','2dcdfd7f5632eb64e161717b32b77fe2361a499d'}
OLD_REFS={'refs/heads/ricky/linux-identity-adapter-candidate26-v1','refs/heads/ricky/linux-preflight-diagnostic-candidate26-v1'}
CODES={'ENTRY_REFUSED','HOST_CONTEXT_REFUSED','PREEXISTING_UNIT_PATH','TARGET_PRESENT','ACCOUNT_PRESENT','UNIT_QUERY_REFUSED','UNIT_QUERY_ERROR','SOURCE_REFUSED','DIR_OPEN_REFUSED','DIR_SHAPE_REFUSED','DIRECTORY_SEAL_CHANGED','CHMOD_REFUSED','POSTCONDITION_REFUSED','PREPARATION_TIMEOUT','UNKNOWN'}
class Refused(Exception):
 def __init__(self,code):self.code=code if code in CODES else 'UNKNOWN'
def need(v,code):
 if not v:raise Refused(code)
def now():return datetime.now(timezone.utc).isoformat()
def fresh_report():
 return {'schema':'nakpanel-dummy-host-preparation-v1','fixture':True,'uses_fixture_executables':True,'scope':'HOST_PREPARATION_ONLY','host_context_provenance':'EXTERNAL_WORKFLOW_ADMISSION_REQUIRED','server_qualification':False,'appsource_runtime':False,'day0_baseline':False,'adapter_collected':False,'projector_executed':False,'VM_or_KVM_actions':False,'application_source_commit':SOURCE,'original_historical_cause':'UNKNOWN','started_at':now(),'finished_at':None,'preparation_completed':False,'mode_change_attempted':False,'hardened':False,'before_mode':None,'after_mode':None,'directory_contents_attested':False,'mode_restore_attempted':False,'cleanup_scope':'FIXTURE_RESOURCES_ONLY_EXCLUDES_HOST_DIRECTORY_MODE','guards':[],'normalizations':[],'failure':None}
def seal(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def harden_existing(root,uid,gid,io,out):
 """Only four fixed disposable-host targets; audit every held/named node first."""
 flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC;opened=[]
 def named(entry):
  fd,parent,name,before=entry
  return io.stat(name,dir_fd=parent,follow_symlinks=False)if parent is not None else io.stat(root,follow_symlinks=False)
 def unchanged(entry):need(seal(io.fstat(entry[0]))==entry[3]and seal(named(entry))==entry[3],'DIRECTORY_SEAL_CHANGED')
 try:
  for i,(label,parent_index,name)in enumerate(DIRECTORIES):
   parent=opened[parent_index][0]if parent_index is not None else None;name=root if parent is None else name
   try:fd=io.open(name,flags,dir_fd=parent)if parent is not None else io.open(name,flags)
   except OSError:raise Refused('DIR_OPEN_REFUSED')from None
   entry=(fd,parent,name,None);opened.append(entry);s=io.fstat(fd)
   need(stat.S_ISDIR(s.st_mode)and s.st_uid==uid and s.st_gid==gid and stat.S_IMODE(s.st_mode)in((0o755,0o777)if i in(3,4,6,7)else(0o755,)),'DIR_SHAPE_REFUSED')
   entry=(fd,parent,name,seal(s));opened[-1]=entry;need(seal(named(entry))==entry[3],'DIRECTORY_SEAL_CHANGED')
   out['guards'].append({'predicate':'DIRECTORY_TRUST','label':label,'type':'DIRECTORY','uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'named_fd_equal':True})
  out['normalizations']=[{'label':DIRECTORIES[i][0],'path':path,'before_mode':stat.S_IMODE(opened[i][3][2]),'after_mode':None,'mode_change_attempted':False,'hardened':False}for i,path in NORMALIZE]
  out['before_mode']=out['normalizations'][0]['before_mode']
  for row,(i,_)in zip(out['normalizations'],NORMALIZE):
   # No target changes until all fixed nodes and original absence checks pass.
   for entry in opened:unchanged(entry)
   target=opened[i];before=target[3]
   if row['before_mode']==0o777:
    row['mode_change_attempted']=True;out['mode_change_attempted']=True
    try:io.fchmod(target[0],0o755)
    except OSError:raise Refused('CHMOD_REFUSED')from None
   after=io.fstat(target[0]);actual=seal(after);need(actual==seal(named(target)),'POSTCONDITION_REFUSED')
   if row['mode_change_attempted']:
    need(actual[:2]==before[:2]and actual[2]==(stat.S_IFDIR|0o755)and actual[3:8]==before[3:8]and actual[8]>=before[8],'POSTCONDITION_REFUSED')
   else:need(actual==before,'POSTCONDITION_REFUSED')
   # Retain only this exact, validated transition; never rebaseline other nodes.
   opened[i]=(target[0],target[1],target[2],actual)
   for entry in reversed(opened):unchanged(entry)
   row['after_mode']=stat.S_IMODE(after.st_mode);row['hardened']=row['mode_change_attempted'];out['hardened']=any(r['hardened']for r in out['normalizations'])
   if i==3:out['after_mode']=row['after_mode']
  return tuple(entry[3]for entry in opened)
 finally:
  for entry in reversed(opened):io.close(entry[0])

def verify_canonical_completion(root,uid,gid,io,expected):
 """Freshly reopen the fixed namespace against exact validated identities."""
 need(type(expected)is tuple and len(expected)==len(DIRECTORIES),'DIRECTORY_SEAL_CHANGED')
 flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC;opened=[]
 def named(entry):
  fd,parent,name,want=entry
  return io.stat(name,dir_fd=parent,follow_symlinks=False)if parent is not None else io.stat(root,follow_symlinks=False)
 try:
  for i,(_,parent_index,name)in enumerate(DIRECTORIES):
   parent=opened[parent_index][0]if parent_index is not None else None;name=root if parent is None else name
   try:fd=io.open(name,flags,dir_fd=parent)if parent is not None else io.open(name,flags)
   except OSError:raise Refused('DIR_OPEN_REFUSED')from None
   entry=(fd,parent,name,expected[i]);opened.append(entry);s=io.fstat(fd)
   need(stat.S_ISDIR(s.st_mode)and s.st_uid==uid and s.st_gid==gid and stat.S_IMODE(s.st_mode)==0o755,'DIRECTORY_SEAL_CHANGED')
   need(seal(s)==expected[i]and seal(named(entry))==expected[i],'DIRECTORY_SEAL_CHANGED')
  for entry in reversed(opened):
   need(seal(io.fstat(entry[0]))==entry[3]and seal(named(entry))==entry[3],'DIRECTORY_SEAL_CHANGED')
 finally:
  for entry in reversed(opened):io.close(entry[0])

def unit_projection(result,role):
 need(role in UNITS,'UNIT_QUERY_ERROR')
 rc=result.returncode if type(getattr(result,'returncode',None))is int and -255<=result.returncode<=255 else None
 p={'predicate':'MANAGER_UNIT_ABSENT','role':role,'returncode':rc,'query_class':'UNKNOWN','fields_unique_six':False,'LoadState':'OTHER','ActiveState':'OTHER','SubState':'OTHER','MainPID_zero':None,'InvocationID_empty':None,'FragmentPath_empty':None,'absent_exact':False}
 if type(getattr(result,'stdout',None))is not bytes or type(getattr(result,'stderr',None))is not bytes or len(result.stdout)+len(result.stderr)>32768:return p
 try:
  pairs=[line.split('=',1)for line in result.stdout.decode('ascii').splitlines()]
  if not all(len(x)==2 for x in pairs):return p
  q=dict(pairs)
  if len(pairs)!=6 or len(q)!=6 or set(q)!={'LoadState','ActiveState','SubState','MainPID','InvocationID','FragmentPath'}:return p
 except (UnicodeError,ValueError):return p
 p.update(fields_unique_six=True,LoadState=q['LoadState']if q['LoadState']in {'not-found','loaded','error','masked'}else'OTHER',ActiveState=q['ActiveState']if q['ActiveState']in {'active','inactive','failed','activating','deactivating'}else'OTHER',SubState=q['SubState']if q['SubState']in {'dead','running','exited','failed','waiting'}else'OTHER',MainPID_zero=q['MainPID']=='0',InvocationID_empty=q['InvocationID']=='',FragmentPath_empty=q['FragmentPath']=='')
 p['absent_exact']=rc in (0,1)and q=={'LoadState':'not-found','ActiveState':'inactive','SubState':'dead','MainPID':'0','InvocationID':'','FragmentPath':''}
 if p['absent_exact']:p['query_class']='ABSENT_EXACT'
 return p

def load_diagnostic():
 path=HERE/'diagnostic.py';fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and not a.st_mode&0o022 and 0<a.st_size<65536,'SOURCE_REFUSED');raw=b''
  while len(raw)<=65536:
   b=os.read(fd,65536)
   if not b:break
   raw+=b
  need(seal(a)==seal(os.fstat(fd))and seal(a)==seal(os.lstat(path))and len(raw)==a.st_size and hashlib.sha256(raw).hexdigest()==DIAGNOSTIC_SHA,'SOURCE_REFUSED')
 finally:os.close(fd)
 m=types.ModuleType('frozen_readonly_diagnostic');m.__file__=str(path);exec(compile(raw,str(path),'exec'),m.__dict__);return m
class RuntimeBackend:
 root=Path('/');uid=0;gid=0;fs=os
 def __init__(self):
  import pwd,grp
  self.pwd=pwd;self.grp=grp;self.deadline=time.monotonic()+20;self.diagnostic=None
 def bounded(self):need(time.monotonic()<self.deadline,'PREPARATION_TIMEOUT')
 def host_ok(self):
  return sys.platform=='linux'and platform.machine()=='x86_64'and os.geteuid()==0 and Path('/proc/1/comm').read_bytes()==b'systemd\n'and '\nID=ubuntu\n'in '\n'+Path('/etc/os-release').read_text()and '\nVERSION_ID="24.04"\n'in '\n'+Path('/etc/os-release').read_text()
 def present(self,path):return os.path.lexists(path)
 def account_present(self,role):
  try:getattr(self.pwd if role=='USER'else self.grp,'getpwnam'if role=='USER'else'getgrnam')('nakpanel');return True
  except KeyError:return False
 def query(self,role):
  self.bounded();need(role in UNITS,'UNIT_QUERY_ERROR')
  if self.diagnostic is None:self.diagnostic=load_diagnostic()
  return self.diagnostic.bounded_run(['/usr/bin/systemctl','show',UNITS[role],*PROPS],stdin=-3,capture_output=True,env=dict(FIXED_ENV),timeout=min(8,self.deadline-time.monotonic()))

def context_ok(c):
 try:
  return set(c)=={'admission_sha','workflow_commit','run_id','attempt','runner_environment','runner_os','runner_arch','event','ref'}and c['runner_environment']=='github-hosted'and c['runner_os']=='Linux'and c['runner_arch']=='X64'and c['event']=='push'and c['attempt']=='1'and type(c['run_id'])is str and re.fullmatch('[1-9][0-9]{0,19}',c['run_id'])and c['run_id']not in OLD_RUNS and type(c['workflow_commit'])is str and re.fullmatch('[a-f0-9]{40}',c['workflow_commit'])and c['workflow_commit']not in OLD_HEADS and type(c['admission_sha'])is str and re.fullmatch('[a-f0-9]{64}',c['admission_sha'])and c['admission_sha']not in OLD_CONTEXTS|{'0'*64}and type(c['ref'])is str and re.fullmatch('refs/heads/ricky/[a-z0-9-]{1,100}',c['ref'])and c['ref']not in OLD_REFS
 except (KeyError,TypeError):return False

def absence_paths(run_id,attempt):
 paths=[]
 for i,base in enumerate(('/etc/systemd/system','/run/systemd/system','/usr/lib/systemd/system','/lib/systemd/system','/usr/local/lib/systemd/system','/etc/systemd/system.control','/run/systemd/system.control','/run/systemd/transient','/run/systemd/generator','/run/systemd/generator.early','/run/systemd/generator.late'),1):
  for role,unit in UNITS.items():
   paths.append(('UNIT_PATH_'+role+'_'+str(i),base+'/'+unit,'PREEXISTING_UNIT_PATH'));paths.append(('DROPIN_PATH_'+role+'_'+str(i),base+'/'+unit+'.d','PREEXISTING_UNIT_PATH'))
 for i,path in enumerate(('/usr/local/bin/nakpanel-panel','/usr/local/bin/nakpanel-agent','/usr/local/bin/nakpanel-panelctl','/etc/nakpanel','/var/lib/nakpanel','/run/nakpanel','/var/mail/nakpanel','/var/spool/mail/nakpanel','/home/nakpanel'),1):paths.append(('TARGET_'+str(i),path,'TARGET_PRESENT'))
 paths.append(('FIXTURE_PRIVATE_ROOT','/var/lib/nakpanel-identity-fixture-'+run_id+'-'+attempt,'TARGET_PRESENT'));return paths

def run_preparation(context,backend=None):
 out=fresh_report();phase='ENTRY';predicate='NEW_EXTERNAL_CONTEXT';b=None
 try:
  need(bool(context_ok(context)),'ENTRY_REFUSED');b=RuntimeBackend()if backend is None else backend
  b.bounded();phase='HOST';predicate='UBUNTU24_ROOT_SYSTEMD';need(b.host_ok(),'HOST_CONTEXT_REFUSED');out['guards'].append({'predicate':predicate,'matches':True})
  phase='ABSENCE'
  for label,path,code in absence_paths(context['run_id'],context['attempt']):
   b.bounded();predicate='FIXED_PATH_ABSENT';present=b.present(path);need(type(present)is bool,'UNKNOWN');out['guards'].append({'predicate':predicate,'label':label,'present':present});need(not present,code)
  for role in ('USER','GROUP'):
   b.bounded();predicate='FIXED_ACCOUNT_ABSENT';present=b.account_present(role);need(type(present)is bool,'UNKNOWN');out['guards'].append({'predicate':predicate,'role':role,'present':present});need(not present,'ACCOUNT_PRESENT')
  phase='UNIT_QUERY';predicate='MANAGER_UNIT_ABSENT'
  for role in UNITS:
   b.bounded()
   try:result=b.query(role)
   except BaseException:
    out['guards'].append({'predicate':predicate,'role':role,'returncode':None,'query_class':'UNKNOWN','fields_unique_six':False,'LoadState':'OTHER','ActiveState':'OTHER','SubState':'OTHER','MainPID_zero':None,'InvocationID_empty':None,'FragmentPath_empty':None,'absent_exact':False});raise Refused('UNIT_QUERY_ERROR')from None
   q=unit_projection(result,role);out['guards'].append(q);need(q['absent_exact'],'UNIT_QUERY_REFUSED')
  b.bounded();phase='DIRECTORY';predicate='FIXED_EXISTING_DIRECTORY_MODES';expected=harden_existing(b.root,b.uid,b.gid,b.fs,out);b.bounded();verify_canonical_completion(b.root,b.uid,b.gid,b.fs,expected);out['preparation_completed']=True
 except BaseException as e:
  out['failure']={'phase':phase,'predicate':predicate,'reason':e.code if isinstance(e,Refused)else'UNKNOWN'}
 out['finished_at']=now()
 if len(out['guards'])>128 or len(json.dumps(out))>65536:
  safe=fresh_report();safe.update(mode_change_attempted=out['mode_change_attempted'],before_mode=out['before_mode'],after_mode=out['after_mode'],failure={'phase':'UNKNOWN','predicate':'UNKNOWN','reason':'UNKNOWN'},finished_at=now());return safe
 return out
class Parser(argparse.ArgumentParser):
 def error(self,message):raise Refused('ENTRY_REFUSED')
def main():
 p=Parser(add_help=False)
 for name in ('admission-sha','workflow-commit','run-id','attempt','runner-environment','runner-os','runner-arch','event','ref'):p.add_argument('--'+name,required=True)
 try:args=p.parse_args();out=run_preparation(vars(args))
 except BaseException:out=fresh_report();out['finished_at']=now();out['failure']={'phase':'ENTRY','predicate':'NEW_EXTERNAL_CONTEXT','reason':'ENTRY_REFUSED'}
 print(json.dumps(out,sort_keys=True,separators=(',',':')));return 0 if out['preparation_completed']else 1
if __name__=='__main__':sys.exit(main())
