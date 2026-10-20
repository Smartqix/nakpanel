"""Private inert preflight-only observation. Never runs a collector or fixture mutation."""
import argparse,ast,errno,hashlib,json,os,platform,selectors,stat,subprocess,sys,time,types
from datetime import datetime,timezone
from pathlib import Path
HERE=Path(__file__).resolve().parent
ORIGINAL_SHA='af98fd413930352bbc144c9847df585432083aabeb75edb577df5bc9c2edc96a'
SOURCE='1627bba3c681a884255eb91452dbba74a43ebbdc'
FIXED_ENV={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'}
PROPERTIES=('--property=LoadState','--property=ActiveState','--property=SubState','--property=MainPID','--property=InvocationID','--property=FragmentPath')
PF_PHASES=['HOST','INIT','OS_RELEASE','ENTRY','ENTRY','ENTRY','SOURCE_INPUTS','SOURCE_INPUTS','SOURCE_INPUTS','SOURCE_INPUTS','BUILD_ELF','PARENT_TRUST','UNIT_PATH_ABSENCE','TARGET_ABSENCE','UNIT_ABSENCE','ACCOUNT_ABSENCE','MANAGER_ENV','UTC_METADATA','UTC_LINK','UTC_METADATA','PRIVATE_ROOT_ABSENCE']
class DiagnosticRefused(Exception):
 def __init__(self,code):self.code=code

def require(value,code='UNSUPPORTED_FAILURE'):
 if not value:raise DiagnosticRefused(code)

def outer():
 return {'schema':'nakpanel-linux-preflight-diagnostic-v1','fixture':True,'read_only_preflight_only':True,'original_conditions_unchanged':True,
 'server_qualification':False,'appsource_runtime':False,'day0_baseline':False,'adapter_collected':False,'projector_executed':False,'services_or_accounts_mutated':False,'VM_or_KVM_actions':False,
 'application_source_commit':SOURCE,'original_driver_sha256':ORIGINAL_SHA,'original_rejecting_predicate':'UNKNOWN','preflight_attempted':False,'preflight_passed':False,'failure':None,'observations':[],'build_sha256':{'dummy':None,'projector':None}}

def bounded_run(argv,**kw):
 """One fixed read-only child: bounded aggregate output, monotonic timeout, no replay."""
 limit=kw['timeout'];deadline=time.monotonic()+limit
 p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=kw['env'],close_fds=True)
 streams={};size=0
 try:
  with selectors.DefaultSelector()as sel:
   for f in (p.stdout,p.stderr):os.set_blocking(f.fileno(),False);sel.register(f,selectors.EVENT_READ);streams[f]=bytearray()
   while sel.get_map():
    left=deadline-time.monotonic();require(left>0,'COMMAND_TIMEOUT')
    events=sel.select(left);require(bool(events),'COMMAND_TIMEOUT')
    for key,_ in events:
     b=os.read(key.fileobj.fileno(),min(65536,32769-size));size+=len(b);require(size<=32768,'OUTPUT_LIMIT')
     if b:streams[key.fileobj].extend(b)
     else:sel.unregister(key.fileobj)
   left=deadline-time.monotonic();require(left>0,'COMMAND_TIMEOUT')
   rc=p.wait(timeout=left)
  return types.SimpleNamespace(returncode=rc,stdout=bytes(streams[p.stdout]),stderr=bytes(streams[p.stderr]))
 except subprocess.TimeoutExpired:raise DiagnosticRefused('COMMAND_TIMEOUT')from None
 finally:
  if p.poll()is None:p.kill();p.wait(timeout=2)
  p.stdout.close();p.stderr.close()

class Backend:
 os=os;Path=Path;pwd=None;grp=None;sys=sys;platform=platform
 def __init__(self):
  import pwd,grp
  self.pwd=pwd;self.grp=grp;self.root=HERE/'original'
 def run(self,argv,**kw):return bounded_run(argv,**kw)

def enum(value,known):return value if value in known else 'OTHER'
class ReadOnlyCommands:
 DEVNULL=subprocess.DEVNULL
 def __init__(self,backend,events):self.backend=backend;self.events=events;self.deadline=time.monotonic()+60
 def run(self,argv,**kw):
  allowed=[['/usr/bin/systemctl','show',u,*PROPERTIES]for u in ('nakpanel.service','nakpanel-agent.service','postgresql.service')]+[['/usr/bin/systemctl','show-environment']]
  require(type(argv)is list and argv in allowed,'COMMAND_NOT_ALLOWED')
  require(set(kw)=={'stdin','capture_output','env','timeout'}and kw['stdin']==subprocess.DEVNULL and kw['capture_output']is True and kw['env']==FIXED_ENV,'COMMAND_NOT_ALLOWED')
  require(type(kw['timeout'])in (float,int)and 0<kw['timeout']<=8 and time.monotonic()+kw['timeout']<=self.deadline,'COMMAND_TIMEOUT')
  r=self.backend.run(argv,**kw)
  require(type(r.returncode)is int and type(r.stdout)is bytes and type(r.stderr)is bytes,'COMMAND_RESULT_SHAPE')
  require(len(r.stdout)+len(r.stderr)<=32768,'OUTPUT_LIMIT')
  if argv[1]=='show-environment':
   lines=r.stdout.splitlines();names=[x.partition(b'=')[0]for x in lines]
   self.events.append({'kind':'MANAGER_ENV','returncode':r.returncode,'TZ_present':any(x.startswith(b'TZ=')for x in lines),'ZONEINFO_present':any(x.startswith(b'ZONEINFO=')for x in lines),'PG_prefix_count':sum(x.startswith(b'PG')for x in names)})
  else:
   pairs=[line.partition(b'=')for line in r.stdout.splitlines()];safe={k:v for k,sep,v in pairs if sep and k in (b'LoadState',b'ActiveState',b'SubState',b'FragmentPath')}
   fragment=safe.get(b'FragmentPath');canonical=('/etc/systemd/system/'+argv[2]).encode()
   self.events.append({'kind':'UNIT_SHOW','role':{'nakpanel.service':'PANEL','nakpanel-agent.service':'AGENT','postgresql.service':'POSTGRES'}[argv[2]],'returncode':r.returncode,
    'LoadState':enum(safe.get(b'LoadState'),(b'not-found',b'loaded',b'error',b'masked')).decode()if safe.get(b'LoadState')in (b'not-found',b'loaded',b'error',b'masked')else 'OTHER',
    'ActiveState':enum(safe.get(b'ActiveState'),(b'active',b'inactive',b'failed',b'activating',b'deactivating')).decode()if safe.get(b'ActiveState')in (b'active',b'inactive',b'failed',b'activating',b'deactivating')else 'OTHER',
    'SubState':safe[b'SubState'].decode()if safe.get(b'SubState')in (b'dead',b'running',b'exited',b'failed',b'waiting')else 'OTHER',
    'FragmentPath':'EMPTY'if fragment==b''else 'CANONICAL'if fragment==canonical else 'OTHER'})
  return r # Exact result bytes and rc reach the original command()/properties() predicates.

class ReadOnlyOS:
 def __init__(self,backend,events,labels,files):self.backend=backend;self.events=events;self.labels=labels;self.files=files;self.path=types.SimpleNamespace(lexists=self.lexists)
 def __getattr__(self,name):
  if name in ('O_RDONLY','O_CLOEXEC','O_NOFOLLOW','O_NONBLOCK'):return getattr(os,name)
  if name in ('read','fstat','close','geteuid'):return getattr(self.backend.os,name)
  raise DiagnosticRefused('READ_API_NOT_ALLOWED')
 def label(self,path):require(str(path)in self.labels,'READ_PATH_NOT_ALLOWED');return self.labels[str(path)]
 def open(self,path,flags):
  self.label(path);require(str(path)in self.files and flags==os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK,'READ_API_NOT_ALLOWED');return self.backend.os.open(path,flags)
 def lstat(self,path):
  label=self.label(path);s=self.backend.os.lstat(path)
  require(all(type(getattr(s,k))is int for k in ('st_mode','st_uid','st_gid','st_nlink','st_size')),'METADATA_SHAPE')
  self.events.append({'kind':'PATH_METADATA','label':label,'type':'DIRECTORY'if stat.S_ISDIR(s.st_mode)else 'REGULAR'if stat.S_ISREG(s.st_mode)else 'SYMLINK'if stat.S_ISLNK(s.st_mode)else 'OTHER','uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'nlink':s.st_nlink})
  return s
 def lexists(self,path):
  label=self.label(path);value=self.backend.os.path.lexists(path);require(type(value)is bool,'METADATA_SHAPE');self.events.append({'kind':'PATH_ABSENCE','label':label,'present':value});return value
 def readlink(self,path):
  require(str(path)=='/etc/localtime','READ_PATH_NOT_ALLOWED');v=self.backend.os.readlink(path);self.events.append({'kind':'UTC_LINK','target':'CANONICAL_UTC'if v=='/usr/share/zoneinfo/Etc/UTC'else 'OTHER'});return v

class Accounts:
 def __init__(self,backend,kind,events):self.backend=backend;self.kind=kind;self.events=events
 def lookup(self,name):
  require(name=='nakpanel','READ_API_NOT_ALLOWED')
  try:r=getattr(self.backend,'getpwnam'if self.kind=='USER'else 'getgrnam')(name)
  except KeyError:self.events.append({'kind':'ACCOUNT_ABSENCE','role':self.kind,'present':False});raise
  self.events.append({'kind':'ACCOUNT_ABSENCE','role':self.kind,'present':True});return r
 def getpwnam(self,name):return self.lookup(name)
 def getgrnam(self,name):return self.lookup(name)

def source_module(root):
 path=root/'fixture_driver.py';fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);require(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and not a.st_mode&0o022 and 0<a.st_size<100000,'SOURCE_REFUSED')
  raw=b''
  while len(raw)<=100000:
   b=os.read(fd,65536)
   if not b:break
   raw+=b
  z=os.fstat(fd);require((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns)and len(raw)==a.st_size and os.lstat(path).st_ino==a.st_ino and hashlib.sha256(raw).hexdigest()==ORIGINAL_SHA,'SOURCE_REFUSED')
 finally:os.close(fd)
 m=types.ModuleType('original_frozen_fixture');m.__file__=str(path);exec(compile(raw,str(path),'exec'),m.__dict__);return m,raw

def predicate_map(raw):
 tree=ast.parse(raw);mapping={}
 for f in ast.walk(tree):
  if isinstance(f,ast.FunctionDef)and f.name in ('preflight','command','properties','read_regular'):
   calls=sorted((x for x in ast.walk(f)if isinstance(x,ast.Call)and isinstance(x.func,ast.Name)and x.func.id=='need'),key=lambda x:(x.lineno,x.col_offset))
   prefix={'preflight':'PF','command':'CMD','properties':'PROP','read_regular':'RR'}[f.name]
   for i,c in enumerate(calls,1):
    key=(f.name,c.lineno);item={'phase':PF_PHASES[i-1]if f.name=='preflight'else 'READ_ONLY_HELPER','predicate':prefix+'_'+str(i).zfill(2),'predicate_scope':'COMPOUND'if isinstance(c.args[0],(ast.BoolOp,ast.Compare,ast.GeneratorExp))else 'EXPRESSION'}
    mapping[key]=item if key not in mapping else {'phase':'UNIT_PROPERTIES','predicate':'UNKNOWN','predicate_scope':'AMBIGUOUS_SAME_LINE'}
 return mapping

def labels_for(root,build,run_id,attempt):
 labels={};files=set()
 for i,path in enumerate(('/etc','/etc/systemd','/etc/systemd/system','/usr','/usr/local','/usr/local/bin','/var','/var/lib','/run'),1):labels[path]='PARENT_'+str(i).zfill(2)
 for i,base in enumerate(('/etc/systemd/system','/run/systemd/system','/usr/lib/systemd/system','/lib/systemd/system','/usr/local/lib/systemd/system','/etc/systemd/system.control','/run/systemd/system.control','/run/systemd/transient','/run/systemd/generator','/run/systemd/generator.early','/run/systemd/generator.late'),1):
  for role,unit in (('PANEL','nakpanel.service'),('AGENT','nakpanel-agent.service')):
   labels[base+'/'+unit]='UNIT_'+role+'_'+str(i).zfill(2);labels[base+'/'+unit+'.d']='DROPIN_'+role+'_'+str(i).zfill(2)
 for i,path in enumerate(('/usr/local/bin/nakpanel-panel','/usr/local/bin/nakpanel-agent','/usr/local/bin/nakpanel-panelctl','/etc/nakpanel','/var/lib/nakpanel','/run/nakpanel','/var/mail/nakpanel','/var/spool/mail/nakpanel','/home/nakpanel'),1):labels[path]='TARGET_'+str(i).zfill(2)
 for i,n in enumerate(('inputs.json','collector.py','custody.py','fixture.go','projector/go.mod','projector/go.sum','projector/main.go','units/nakpanel-agent.service','units/nakpanel.service'),1):q=str(root/n);labels[q]='SOURCE_'+str(i).zfill(2);files.add(q)
 for label,n in (('DUMMY_BUILD','fixture-sleeper'),('PROJECTOR_BUILD','projector')):q=str(build/n);labels[q]=label;files.add(q)
 labels['/etc/localtime']='UTC_LOCALTIME';labels['/var/lib/nakpanel-identity-fixture-'+run_id+'-'+attempt]='PRIVATE_FIXTURE_ROOT'
 return labels,files

def probe(build,run_id,attempt,workflow_commit,admission_sha,backend=None):
 out=outer();backend=Backend()if backend is None else backend;events=out['observations'];m=None;f=None;mapping={}
 try:
  require(re_full('[1-9][0-9]{0,19}',run_id)and re_full('[1-9][0-9]{0,3}',attempt)and re_full('[a-f0-9]{40}',workflow_commit)and re_full('[a-f0-9]{64}',admission_sha)and admission_sha!='0'*64,'ENTRY_REFUSED')
  m,raw=source_module(backend.root);mapping=predicate_map(raw);labels,files=labels_for(backend.root,build,run_id,attempt)
  m.os=ReadOnlyOS(backend,events,labels,files);m.subprocess=ReadOnlyCommands(backend,events);m.Path=backend.Path
  m.sys=backend.sys;m.platform=backend.platform
  m.pwd=Accounts(backend.pwd,'USER',events);m.grp=Accounts(backend.grp,'GROUP',events)
  f=object.__new__(m.Fixture);f.a=types.SimpleNamespace(build_root=str(build),run_id=run_id,attempt=attempt,workflow_commit=workflow_commit,admission_sha=admission_sha);f.out={}
  out['preflight_attempted']=True
  f.preflight() # The ONLY method of the original Fixture invoked by this diagnostic.
  out['preflight_passed']=True
 except BaseException as e:
  info={'phase':'UNKNOWN','predicate':'UNKNOWN','predicate_scope':'UNKNOWN','reason':'UNSUPPORTED_FAILURE'}
  if isinstance(e,DiagnosticRefused):info['reason']=e.code if e.code in {'OUTPUT_LIMIT','COMMAND_TIMEOUT','COMMAND_NOT_ALLOWED','COMMAND_RESULT_SHAPE','READ_API_NOT_ALLOWED','READ_PATH_NOT_ALLOWED','METADATA_SHAPE','SOURCE_REFUSED','ENTRY_REFUSED','PUBLIC_OUTPUT_LIMIT'}else 'UNSUPPORTED_FAILURE'
  elif m is not None and isinstance(e,m.Refused):
   info['reason']='ORIGINAL_PREDICATE_REFUSED';tb=e.__traceback__;found=[]
   while tb:
    if tb.tb_frame.f_code.co_filename==m.__file__:
     k=(tb.tb_frame.f_code.co_name,tb.tb_lineno)
     if k in mapping:found.append(mapping[k])
    tb=tb.tb_next
   if found:info.update(found[-1]);info['preflight_phase']=next((v['phase']for v in found if v['predicate'].startswith('PF_')),'UNKNOWN')
  elif isinstance(e,OSError):info['reason']='READ_OS_ERROR';info['errno']=e.errno if type(e.errno)is int and 0<e.errno<4096 else None
  out['failure']=info
 if f is not None:
  for role,key in (('dummy','fixture_executable_sha256'),('projector','projector_sha256')):
   value=f.out.get(key)
   if re_full('[a-f0-9]{64}',value):out['build_sha256'][role]=value
 if len(events)>256 or len(json.dumps(out))>65536:
  out=outer();out['failure']={'phase':'UNKNOWN','predicate':'UNKNOWN','predicate_scope':'UNKNOWN','reason':'PUBLIC_OUTPUT_LIMIT'}
 return out

def re_full(pattern,value):
 import re
 return type(value)is str and re.fullmatch(pattern,value)is not None

class FixedParser(argparse.ArgumentParser):
 def error(self,message):raise DiagnosticRefused('ENTRY_REFUSED')

def main():
 p=FixedParser(add_help=False);p.add_argument('--admission-sha',required=True);p.add_argument('--build-root');p.add_argument('--run-id');p.add_argument('--attempt');p.add_argument('--workflow-commit');
 try:a=p.parse_args()
 except BaseException:
  r=outer();r['failure']={'phase':'ENTRY','predicate':'UNKNOWN','predicate_scope':'UNKNOWN','reason':'ENTRY_REFUSED'};print(json.dumps(r,sort_keys=True,separators=(',',':')));return 1
 if not re_full('[a-f0-9]{64}',a.admission_sha)or a.admission_sha=='0'*64:
  r=outer();r['failure']={'phase':'ENTRY','predicate':'UNKNOWN','predicate_scope':'UNKNOWN','reason':'ENTRY_PENDING'}
 else:r=probe(Path(a.build_root)if a.build_root else Path('/INVALID'),a.run_id,a.attempt,a.workflow_commit,a.admission_sha)
 print(json.dumps(r,sort_keys=True,separators=(',',':')))
 return 0 if r['preflight_passed']else 1
if __name__=='__main__':sys.exit(main())
