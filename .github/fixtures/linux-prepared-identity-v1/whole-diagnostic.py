"""Fixed three-role dummy diagnostic. No import actions or runtime qualification."""
import argparse,hashlib,json,os,stat,sys,subprocess,types,time,selectors,re,errno
from pathlib import Path
HERE=Path(__file__).resolve().parent
SOURCE='1627bba3c681a884255eb91452dbba74a43ebbdc'
DRIVER_SHA='80dd75d775cc6fdd157895d1c83eda5cef46cb2917569ffe762773d70a8143cf'
PHASES=('PREFLIGHT','SETUP','CASES','CLEANUP')
COMMAND_KINDS=('UNKNOWN','SETUP_GROUPADD','SETUP_USERADD','SETUP_DAEMON_RELOAD','SETUP_START_UNITS','SETUP_REMEMBER_UNIT_PROPERTIES')
SHA=lambda b:hashlib.sha256(b).hexdigest()
_LOADED={}
class Refused(Exception):pass
def need(v):
 if not v:raise Refused('fixed whole diagnostic refused')
def seal(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def sealed_read(path,limit,owner=None,mode=None):
 fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=limit and not before.st_mode&0o022)
  need(owner is None or before.st_uid==owner);need(mode is None or stat.S_IMODE(before.st_mode)==mode);raw=b''
  while len(raw)<=limit:
   b=os.read(fd,min(65536,limit-len(raw)+1))
   if not b:break
   raw+=b
  need(len(raw)==before.st_size and seal(before)==seal(os.fstat(fd))==seal(os.lstat(path)));return raw
 finally:os.close(fd)
SITE_LINES={'need': [32, 33], 'command': [35, 36, 37, 38, 39, 40], 'properties': [42, 43, 44, 45, 46], 'marker': [48, 49, 50], 'read_regular': [52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63], 'fixed_outer': [65, 66, 67, 68, 69, 70, 71, 72, 73, 74], 'Fixture.__init__': [77, 78, 79], 'Fixture.bounded': [80], 'Fixture.record': [81, 82, 83, 84], 'Fixture.save': [85, 86, 87, 88, 89, 90, 91, 92, 93], 'Fixture.owns': [94, 95, 96, 97], 'Fixture.make_dir': [98, 99], 'Fixture.write': [100, 101, 102, 103, 104, 105, 106, 107, 108], 'Fixture.preflight': [109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 141, 142, 143, 144, 145, 147, 148, 149], 'Fixture.setup': [150, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179], 'Fixture.remember_unit': [180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191], 'Fixture.same_unit': [192], 'Fixture.mature': [193, 194, 195, 196, 197, 199, 200, 201], 'Fixture.runtime_before_stop': [202, 203, 204, 205, 206, 207, 208, 210, 211, 212, 213, 214, 215, 216, 217, 218], 'Fixture.receipt': [219, 220, 221, 222], 'Fixture.cases': [223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261], 'Fixture.cleanup': [262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324], 'main': [326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 337, 338, 339, 340, 341], 'interrupt': [332]}
def load_driver(path):
 raw=sealed_read(path,65536);need(SHA(raw)==DRIVER_SHA)
 m=types.ModuleType('sealed_original_fixture');m.__file__=str(path);exec(compile(raw,str(path),'exec'),m.__dict__)
 registry={}
 for name,lines in SITE_LINES.items():
  if name=='interrupt':
   code=next(c for c in m.main.__code__.co_consts if isinstance(c,types.CodeType)and c.co_name=='interrupt')
  else:
   value=m
   for part in name.split('.'):value=getattr(value,part)
   code=value.__code__
  registry[id(code)]=(code,'DRIVER_'+name.replace('.','_').upper(),set(lines))
 _LOADED[id(m)]=(m,registry);return m
class Observer:
 def __init__(self,m):
  need(id(m)in _LOADED and _LOADED[id(m)][0]is m);self.m=m;self.registry=_LOADED[id(m)][1];self.unknown=False;self.primary=None;self.cleanup=None;self.cleanup_return='NOT_RETURNED';self.events={p:{'entered':False,'returned':False,'escaped':False}for p in PHASES};self.originals={}
 def frames(self,error):
  rows=[];tb=error.__traceback__
  while tb is not None and len(rows)<65:rows.append(tb);tb=tb.tb_next
  return rows if len(rows)<=64 and tb is None else []
 def known(self,code):
  q=self.registry.get(id(code));return q if q is not None and q[0]is code else None
 def is_signal(self,error):
  return type(error)is self.m.Interrupted and any((self.known(t.tb_frame.f_code)or(None,None,None))[1]=='DRIVER_INTERRUPT'for t in self.frames(error))
 def project(self,phase,error):
  out={'phase':phase if phase in PHASES else'UNKNOWN','category':'UNKNOWN','function':'UNKNOWN','site':'UNKNOWN','driver_context':'UNKNOWN','predicate_scope':'UNKNOWN','command_exit':None,'command_kind':'UNKNOWN'};rows=self.frames(error)
  if not rows:return out
  contexts=[(t,self.known(t.tb_frame.f_code))for t in rows if self.known(t.tb_frame.f_code)and self.known(t.tb_frame.f_code)[1]!='DRIVER_NEED']
  if contexts:
   t,q=contexts[-1];out['driver_context']=q[1]
  tail=self.known(rows[-1].tb_frame.f_code)
  if self.is_signal(error):out['category']='ORIGINAL_INTERRUPTED'
  elif type(error)is self.m.Refused and tail is not None:out['category']='ORIGINAL_REFUSED'
  elif type(error)is subprocess.TimeoutExpired and any(q[1]=='DRIVER_COMMAND'for _,q in contexts):out['category']='TIMEOUT'
  if tail is not None and contexts:
   t,q=contexts[-1]
   if t.tb_lineno in q[2]:out.update(function=q[1],site=q[1]+'_L'+str(t.tb_lineno).zfill(3),predicate_scope='COMPOUND_SOURCE_LINE')
  if out['category']=='ORIGINAL_REFUSED':
   for t,q in contexts:
    if q[1]=='DRIVER_COMMAND'and t.tb_lineno==39:
     r=t.tb_frame.f_locals.get('r')
     if type(r)is subprocess.CompletedProcess and type(r.returncode)is int and -255<=r.returncode<=255:
      out['command_exit']=r.returncode
      if phase=='SETUP':
       chain=[((self.known(frame.tb_frame.f_code)or(None,'UNKNOWN',None))[1],frame.tb_lineno)for frame in rows[:rows.index(t)]]
       direct={155:'SETUP_GROUPADD',157:'SETUP_USERADD',169:'SETUP_DAEMON_RELOAD',171:'SETUP_START_UNITS'}
       if chain and chain[-1][0]=='DRIVER_FIXTURE_SETUP':out['command_kind']=direct.get(chain[-1][1],'UNKNOWN')
       elif chain[-3:]==[('DRIVER_FIXTURE_SETUP',172),('DRIVER_FIXTURE_REMEMBER_UNIT',181),('DRIVER_PROPERTIES',43)]:out['command_kind']='SETUP_REMEMBER_UNIT_PROPERTIES'
  return out
 def observe(self,phase,state,obj=None):
  if state=='ENTRY':self.events[phase]['entered']=True
  elif state=='RETURN':self.events[phase]['returned']=True
  elif state=='ESCAPE':
   self.events[phase]['escaped']=True;q=self.project(phase,obj)
   if phase=='CLEANUP':
    if self.cleanup is None:self.cleanup=q
   elif self.primary is None:self.primary=q
  elif state=='CLEANUP_RETURN':self.cleanup_return='RETURNED_SUCCESS'if obj.out['cleanup']['success']is True else'RETURNED_FAILURE_WITHOUT_ESCAPING_EXCEPTION'
 def safe(self,phase,state,obj=None):
  try:self.observe(phase,state,obj)
  except BaseException as error:
   if self.is_signal(error):raise
   self.unknown=True
 def install(self):
  need(not self.originals)
  for name in ('preflight','setup','cases','cleanup'):
   saved=getattr(self.m.Fixture,name);self.originals[name]=saved;phase=name.upper()
   def wrap(f,*args,_saved=saved,_phase=phase,**kwargs):
    self.safe(_phase,'ENTRY')
    try:value=_saved(f,*args,**kwargs)
    except BaseException as error:
     try:self.safe(_phase,'ESCAPE',error)
     except BaseException as observed:
      if self.is_signal(observed):raise
      self.unknown=True
     raise
    self.safe(_phase,'RETURN')
    if _phase=='CLEANUP':self.safe(_phase,'CLEANUP_RETURN',f)
    return value
   setattr(self.m.Fixture,name,wrap)
 def restore(self):
  for name,saved in self.originals.items():setattr(self.m.Fixture,name,saved)
 def result(self):return{'primary':self.primary,'cleanup_escape':self.cleanup,'cleanup_return':self.cleanup_return,'observer_unknown':self.unknown,'phases':self.events,'trusted_code_scope':'LOADED_ORIGINAL_DRIVER_ONLY'}

RAW_LIMIT=16384
STDOUT_LIMIT=65536
STDERR_LIMIT=32768
RAW='whole-diagnostic.raw.json'
WAIT='whole-wait.raw.json'
CASE_KEYS=('unset_UTC_no_dropin','explicit_UTC','old_pidfd_restart_refused','real_FIFO_publication_refused','unsafe_root_mode_refused','private_publication')
def bounded_write(fd,raw,writer=os.write):
 end=time.monotonic()+2;position=0;interrupts=0
 while position<len(raw):
  need(time.monotonic()<end)
  try:count=writer(fd,raw[position:])
  except InterruptedError:interrupts+=1;need(interrupts<=32);continue
  need(type(count)is int and 0<count<=len(raw)-position);position+=count
class Record:
 def __init__(self,build,name,owner):
  self.build=build;self.name=name;self.fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=build.fd);self.write=os.write
  try:
   s=os.fstat(self.fd);need(stat.S_ISREG(s.st_mode)and s.st_uid==owner and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_size==0);self.initial=seal(s);self.check(self.initial)
  except BaseException:self.close();raise
 def check(self,want):
  self.build.check();need(seal(os.fstat(self.fd))==want==seal(os.stat(self.name,dir_fd=self.build.fd,follow_symlinks=False)))
 def write_json(self,q):
  raw=(json.dumps(q,sort_keys=True,separators=(',',':'))+'\n').encode();need(0<len(raw)<=RAW_LIMIT);self.check(self.initial);bounded_write(self.fd,raw,self.write)
  os.fsync(self.fd);s=os.fstat(self.fd);need(s.st_size==len(raw)and seal(s)[:6]==self.initial[:6]);self.check(seal(s))
 def close(self):
  if self.fd is not None:fd=self.fd;self.fd=None;os.close(fd)
class BuildFiles:
 def __init__(self,path,expected_builder=None):
  self.path=Path(path);need(self.path.is_absolute()and '..'not in self.path.parts and self.path.resolve()==self.path);self.fd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   s=os.fstat(self.fd);need(stat.S_ISDIR(s.st_mode)and stat.S_IMODE(s.st_mode)==0o700 and(expected_builder is None or s.st_uid==expected_builder));self.identity=seal(s)[:5];self.uid=s.st_uid;self.gid=s.st_gid;self.check()
   for n in ('fixture-sleeper','projector'):
    f=os.open(n,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.fd)
    try:
     b=os.fstat(f);need(stat.S_ISREG(b.st_mode)and b.st_nlink==1 and 0<b.st_size<=32*1024*1024 and not b.st_mode&0o022 and(b.st_uid,b.st_gid)==(self.uid,self.gid));need(seal(b)==seal(os.stat(n,dir_fd=self.fd,follow_symlinks=False)))
    finally:os.close(f)
  except BaseException:self.close();raise
 def check(self):need(seal(os.fstat(self.fd))[:5]==self.identity==seal(os.lstat(self.path))[:5])
 def begin(self,name,owner):need(type(name)is str and name and '/'not in name and name not in('.','..'));self.check();return Record(self,name,owner)
 def read(self,name,limit,owner):
  need(type(name)is str and name and '/'not in name and name not in('.','..'));self.check();raw=sealed_read(self.path/name,limit,owner,0o600);self.check();return raw
 def close(self):
  if self.fd is not None:fd=self.fd;self.fd=None;os.close(fd)
def binding(a):
 need(type(a.run_id)is str and re.fullmatch('[1-9][0-9]{0,19}',a.run_id)and a.run_id not in('39357893933','39361557934','39365827819'))
 need(a.attempt=='1'and type(a.workflow_commit)is str and re.fullmatch('[a-f0-9]{40}',a.workflow_commit)and a.workflow_commit!=SOURCE and type(a.admission_sha)is str and re.fullmatch('[a-f0-9]{64}',a.admission_sha)and a.admission_sha!='0'*64)
 return{'run_id':a.run_id,'attempt':a.attempt,'workflow_commit':a.workflow_commit,'context_sha256':a.admission_sha,'source_commit':SOURCE,'helper_sha256':SHA(sealed_read(HERE/'whole-diagnostic.py',262144)),'original_driver_sha256':DRIVER_SHA}
def original_args(a):return['--build-root',a.build_root,'--run-id',a.run_id,'--attempt',a.attempt,'--workflow-commit',a.workflow_commit,'--admission-sha',a.admission_sha]
def run_original(a,store=None,module=None):
 ctx=binding(a);m=load_driver(HERE/'original/fixture_driver.py')if module is None else module;o=Observer(m);owned=store is None;files=BuildFiles(a.build_root)if owned else store;record=None;outcome={'returned':False,'exit':None};argv=sys.argv
 try:
  try:record=files.begin(RAW,0)
  except Exception:pass
  try:o.install()
  except BaseException as error:
   o.unknown=True
   try:o.restore()
   except BaseException as observed:
    if o.is_signal(observed):raise
    o.unknown=True
   if o.is_signal(error):raise
  sys.argv=[str(HERE/'original/fixture_driver.py'),*original_args(a)]
  try:
   rc=m.main();outcome={'returned':True,'exit':rc};return rc
  finally:
   sys.argv=argv;late=None
   try:o.restore()
   except BaseException as error:
    if o.is_signal(error):late=error
    else:o.unknown=True
   try:
    if record is not None:record.write_json({'schema':'nakpanel-whole-raw-v1','binding':ctx,'original_main':outcome,'observation':o.result()})
   except BaseException as error:
    if o.is_signal(error):raise
   finally:
    if record is not None:
     try:record.close()
     except BaseException as error:
      if o.is_signal(error):raise
   if late is not None:raise late
 finally:
  if owned:
   try:files.close()
   except BaseException as error:
    if o.is_signal(error):raise

def strict(raw,limit):
 need(type(raw)is bytes and 0<len(raw)<=limit)
 def pairs(rows):
  q={}
  for k,v in rows:need(k not in q);q[k]=v
  return q
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda x:need(False))
def observation_valid(o):
 need(type(o)is dict and set(o)=={'primary','cleanup_escape','cleanup_return','observer_unknown','phases','trusted_code_scope'}and type(o['observer_unknown'])is bool and o['trusted_code_scope']=='LOADED_ORIGINAL_DRIVER_ONLY')
 need(o['cleanup_return']in('NOT_RETURNED','RETURNED_SUCCESS','RETURNED_FAILURE_WITHOUT_ESCAPING_EXCEPTION'))
 need(type(o['phases'])is dict and set(o['phases'])==set(PHASES))
 for r in o['phases'].values():need(type(r)is dict and set(r)=={'entered','returned','escaped'}and all(type(v)is bool for v in r.values()))
 enums={'UNKNOWN'}|{'DRIVER_'+name.replace('.','_').upper()for name in SITE_LINES};sites={'UNKNOWN'}|{('DRIVER_'+name.replace('.','_').upper()+'_L'+str(line).zfill(3))for name,lines in SITE_LINES.items()for line in lines}
 for key in('primary','cleanup_escape'):
  r=o[key]
  if r is None:continue
  need(type(r)is dict and set(r)=={'phase','category','function','site','driver_context','predicate_scope','command_exit','command_kind'}and r['phase']in PHASES and r['category']in('UNKNOWN','ORIGINAL_REFUSED','ORIGINAL_INTERRUPTED','TIMEOUT')and r['function']in enums and r['site']in sites and r['driver_context']in enums and r['predicate_scope']in('UNKNOWN','COMPOUND_SOURCE_LINE'))
  need(type(r['command_kind'])is str and r['command_kind']in COMMAND_KINDS)
  need(r['command_exit']is None or type(r['command_exit'])is int and -255<=r['command_exit']<=255)
def wait_valid(wait,ctx):
 need(type(wait)is dict and set(wait)=={'schema','binding','child_exit','wait_completed','stderr_eof','foreground_empty','stderr_overflow','stderr_write_failed','identity','stdout_seal'}and wait['schema']=='nakpanel-whole-wait-v1'and wait['binding']==ctx)
 for k in('wait_completed','stderr_eof','foreground_empty'):need(wait[k]is True)
 for k in('stderr_overflow','stderr_write_failed'):need(type(wait[k])is bool)
 need(type(wait['child_exit'])is int and -255<=wait['child_exit']<=255)
 identity=wait['identity'];need(type(identity)is dict and set(identity)=={'pid','pgid','start_ticks'}and all(type(v)is int for v in identity.values())and identity['pid']==identity['pgid']>1 and identity['start_ticks']>0)
 need(type(wait['stdout_seal'])is list and len(wait['stdout_seal'])==9 and all(type(v)is int and v>=0 for v in wait['stdout_seal']))
def combine(ctx,raw,wait,stdout):
 need(type(raw)is dict and set(raw)=={'schema','binding','original_main','observation'}and raw['schema']=='nakpanel-whole-raw-v1'and raw['binding']==ctx)
 wait_valid(wait,ctx)
 main=raw['original_main'];need(type(main)is dict and set(main)=={'returned','exit'}and type(main['returned'])is bool and(main['exit']is None or type(main['exit'])is int and -255<=main['exit']<=255));need(main['returned']==(main['exit']is not None));observation_valid(raw['observation'])
 original=strict(stdout,STDOUT_LIMIT);need(original['schema']=='nakpanel-linux-identity-adapter-fixture-v1'and original['application_source_commit']==SOURCE and original['fixture']is True and original['uses_fixture_executables']is True)
 for k in('server_qualification','appsource_runtime','day0_baseline','real_nakpanel_application_executed'):need(original[k]is False)
 need(type(original['cases'])is dict and set(original['cases'])==set(CASE_KEYS)and all(v is None or type(v)is bool for v in original['cases'].values()))
 c=original['cleanup'];need(type(c)is dict and set(c)=={'attempted','success','remaining_owned_objects'}and type(c['attempted'])is bool and type(c['success'])is bool and(c['remaining_owned_objects']is None or type(c['remaining_owned_objects'])is int and 0<=c['remaining_owned_objects']<=1000))
 passed=main['returned']and main['exit']==wait['child_exit']==0 and original['fixture_completed']is True and all(v is True for v in original['cases'].values())and c['success']is True and not raw['observation']['observer_unknown']and raw['observation']['primary']is None and raw['observation']['cleanup_escape']is None and not wait['stderr_overflow']and not wait['stderr_write_failed']
 return{'schema':'nakpanel-whole-fixture-diagnostic-v1','fixture':True,'uses_fixture_executables':True,'server_qualification':False,'appsource_runtime':False,'day0_baseline':False,'source_commit':SOURCE,'binding':ctx,'original_stdout_sha256':SHA(stdout),'original_main_returned':main['returned'],'original_main_exit':main['exit'],'actual_child_exit':wait['child_exit'],'original_cases':original['cases'],'original_cleanup':c,'observation':raw['observation'],'experiment_passed':bool(passed),'claim':'DUMMY_DIAGNOSTIC_ONLY'}

def failure_projection(ctx,wait,status,stdout=None):
 need(status in('RAW_MISSING','RAW_INVALID','PUBLICATION_REFUSED','UNKNOWN'))
 rc=wait.get('child_exit');need(rc is None or type(rc)is int and -255<=rc<=255)
 return{'schema':'nakpanel-whole-fixture-diagnostic-transport-v1','fixture':True,'uses_fixture_executables':True,'server_qualification':False,'appsource_runtime':False,'day0_baseline':False,'source_commit':SOURCE,'binding':ctx,'diagnostic_status':status,'original_stdout_sha256':SHA(stdout)if stdout is not None else None,'original_main_returned':False,'original_main_exit':None,'actual_child_exit':rc,'experiment_passed':False,'claim':'DUMMY_DIAGNOSTIC_ONLY'}
def public_valid(q,ctx):
 base={'schema','fixture','uses_fixture_executables','server_qualification','appsource_runtime','day0_baseline','source_commit','binding','original_stdout_sha256','original_main_returned','original_main_exit','actual_child_exit','experiment_passed','claim'}
 need(type(q)is dict and q['binding']==ctx and q['fixture']is True and q['uses_fixture_executables']is True and q['source_commit']==SOURCE and q['claim']=='DUMMY_DIAGNOSTIC_ONLY'and all(q[k]is False for k in('server_qualification','appsource_runtime','day0_baseline')))
 need(q['original_stdout_sha256']is None or type(q['original_stdout_sha256'])is str and re.fullmatch('[a-f0-9]{64}',q['original_stdout_sha256']))
 need(type(q['original_main_returned'])is bool and type(q['experiment_passed'])is bool)
 for key in('original_main_exit','actual_child_exit'):need(q[key]is None or type(q[key])is int and -255<=q[key]<=255)
 if q['schema']=='nakpanel-whole-fixture-diagnostic-transport-v1':need(set(q)==base|{'diagnostic_status'}and q['diagnostic_status']in('RAW_MISSING','RAW_INVALID','PUBLICATION_REFUSED','UNKNOWN')and q['experiment_passed']is False and q['original_main_returned']is False and q['original_main_exit']is None)
 else:
  need(q['schema']=='nakpanel-whole-fixture-diagnostic-v1'and set(q)==base|{'original_cases','original_cleanup','observation','raw_diagnostic_sha256','wait_receipt_sha256'})
  observation_valid(q['observation']);need(set(q['original_cases'])==set(CASE_KEYS)and all(v is None or type(v)is bool for v in q['original_cases'].values()))
  c=q['original_cleanup'];need(type(c)is dict and set(c)=={'attempted','success','remaining_owned_objects'}and type(c['attempted'])is bool and type(c['success'])is bool and(c['remaining_owned_objects']is None or type(c['remaining_owned_objects'])is int and 0<=c['remaining_owned_objects']<=1000))
  for k in('raw_diagnostic_sha256','wait_receipt_sha256'):need(type(q[k])is str and re.fullmatch('[a-f0-9]{64}',q[k]))
  if q['experiment_passed']:need(q['original_main_returned']and q['original_main_exit']==q['actual_child_exit']==0 and not q['observation']['observer_unknown']and all(v is True for v in q['original_cases'].values())and c['success'])
 return q

def proc_fields(raw):
 need(type(raw)is bytes and 0<len(raw)<=8192)
 try:
  first,tail=raw.rsplit(b')',1);pid=int(first.split(b'(',1)[0]);fields=tail.split();pgid=int(fields[2]);ticks=int(fields[19]);need(pid>1 and pgid>1 and ticks>0);return{'pid':pid,'pgid':pgid,'start_ticks':ticks}
 except (ValueError,IndexError):raise Refused('fixed process identity refused')from None
def proc_inventory_fields(raw):
 need(type(raw)is bytes and 0<len(raw)<=8192)
 try:
  first,tail=raw.rsplit(b')',1);prefix,_=first.split(b'(',1);fields=tail.split();match=re.fullmatch(rb'([1-9][0-9]*) ',prefix);need(match is not None)
  need(len(fields)>19 and re.fullmatch(rb'(0|[1-9][0-9]*)',fields[2])is not None and re.fullmatch(rb'(0|[1-9][0-9]*)',fields[19])is not None)
  return{'pid':int(match.group(1)),'pgid':int(fields[2]),'start_ticks':int(fields[19])}
 except(ValueError,IndexError):raise Refused('fixed inventory refused')from None
class Runtime:
 def __init__(self,proc_root=Path('/proc')):self.proc_root=proc_root;self.prefix_write=os.write
 def spawn(self,argv,stdout):return subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=stdout,stderr=subprocess.PIPE,start_new_session=True)
 def identity(self,process):
  try:q=proc_fields((self.proc_root/str(process.pid)/'stat').read_bytes());need(q['pid']==q['pgid']==process.pid);return q
  except (OSError,Refused):return None
 def empty(self,identity):
  if type(identity)is not dict:return False
  owned=identity.copy()
  if set(owned)!={'pid','pgid','start_ticks'}or not all(type(v)is int for v in owned.values())or not(owned['pid']==owned['pgid']>1 and owned['start_ticks']>0):return False
  pgid=owned['pgid']
  try:
   for d in self.proc_root.iterdir():
    if not d.name.isdigit():continue
    try:q=proc_inventory_fields((d/'stat').read_bytes())
    except FileNotFoundError:continue
    need(str(q['pid'])==d.name)
    if q['pgid']==pgid:return False
   try:os.killpg(pgid,0)
   except OSError as error:return type(error.errno)is int and error.errno==errno.ESRCH
   return False
  except(OSError,Refused):return False
 def drain(self,process,private_fd,deadline):
  out={'child_exit':None,'wait_completed':False,'stderr_eof':False,'stderr_overflow':False,'stderr_write_failed':False};kept=0;total=0
  with selectors.DefaultSelector()as selector:
   selector.register(process.stderr,selectors.EVENT_READ)
   while time.monotonic()<deadline:
    ready=selector.select(min(0.1,max(0,deadline-time.monotonic())))
    if not ready:continue
    data=os.read(process.stderr.fileno(),65536)
    if not data:out['stderr_eof']=True;break
    total+=len(data);out['stderr_overflow']=total>STDERR_LIMIT
    if not out['stderr_write_failed']and kept<STDERR_LIMIT:
     prefix=data[:STDERR_LIMIT-kept];position=0
     try:
      while position<len(prefix):
       count=self.prefix_write(private_fd,prefix[position:]);need(type(count)is int and 0<count<=len(prefix)-position);position+=count;kept+=count
     except BaseException:out['stderr_write_failed']=True
  process.stderr.close()
  if out['stderr_eof']:
   try:out['child_exit']=process.wait(timeout=max(0.001,deadline-time.monotonic()));out['wait_completed']=True
   except subprocess.TimeoutExpired:pass
  return out
 def publish(self,argv):return subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=15)

def private_directory(path,owner):
 p=Path(path);need(p.is_absolute()and '..'not in p.parts and p.resolve()==p);s=os.lstat(p);need(stat.S_ISDIR(s.st_mode)and s.st_uid==owner and stat.S_IMODE(s.st_mode)==0o700);return p

class OutputRoot:
 def __init__(self,path,owner):
  self.path=private_directory(path,owner);self.owner=owner;self.fd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:self.identity=seal(os.fstat(self.fd))[:5];self.check()
  except BaseException:self.close();raise
 def check(self,full=None):
  current=seal(os.fstat(self.fd));named=seal(os.lstat(self.path));need(current[:5]==self.identity==named[:5]and stat.S_ISDIR(current[2])and stat.S_IMODE(current[2])==0o700 and current[3]==self.owner and self.path.resolve()==self.path)
  if full is not None:need(current==named==full)
 def open(self,name,readable=False):
  need(name in('fixture.json','whole-diagnostic.json'));self.check();fd=os.open(name,(os.O_RDWR if readable else os.O_WRONLY)|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.fd)
  try:
   s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and s.st_uid==self.owner and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_size==0);need(seal(s)==seal(os.stat(name,dir_fd=self.fd,follow_symlinks=False)));self.check();return fd
  except BaseException:os.close(fd);raise
 def publish(self,data):
  need(type(data)is bytes and 0<len(data)<=RAW_LIMIT);name='whole-diagnostic.json';fd=self.open(name,True);initial=seal(os.fstat(fd));root_seal=seal(os.fstat(self.fd));self.check(root_seal);expected=None;digest=SHA(data)
  def check():
   need(seal(os.fstat(fd))==expected==seal(os.stat(name,dir_fd=self.fd,follow_symlinks=False)))
   actual=os.pread(fd,len(data)+1,0);need(actual==data and SHA(actual)==digest)
   need(seal(os.fstat(fd))==expected==seal(os.stat(name,dir_fd=self.fd,follow_symlinks=False)));self.check(root_seal)
  try:
   bounded_write(fd,data);written=seal(os.fstat(fd));need(written[:6]==initial[:6]and written[6]==len(data));expected=written;check()
   # Keep this already validated full seal; fsync must never become a new baseline.
   os.fsync(fd);os.fsync(self.fd);check()
  finally:os.close(fd)
  need(seal(os.stat(name,dir_fd=self.fd,follow_symlinks=False))==expected);self.check(root_seal)
 def close(self):
  if self.fd is not None:fd=self.fd;self.fd=None;os.close(fd)

def publish_after_wait(a):
 ctx=binding(a);files=BuildFiles(a.build_root)
 try:
  wait_raw=files.read(WAIT,RAW_LIMIT,files.uid);wait=strict(wait_raw,RAW_LIMIT)
  wait_valid(wait,ctx)
  public=private_directory(a.public_root,files.uid);path=public/'fixture.json';need(list(seal(os.lstat(path)))==wait['stdout_seal']);stdout=sealed_read(path,STDOUT_LIMIT,files.uid,0o600);need(list(seal(os.lstat(path)))==wait['stdout_seal'])
  try:raw_bytes=files.read(RAW,RAW_LIMIT,0)
  except FileNotFoundError:return failure_projection(ctx,wait,'RAW_MISSING',stdout)
  try:q=combine(ctx,strict(raw_bytes,RAW_LIMIT),wait,stdout)
  except Exception:return failure_projection(ctx,wait,'RAW_INVALID',stdout)
  q.update(raw_diagnostic_sha256=SHA(raw_bytes),wait_receipt_sha256=SHA(wait_raw));return public_valid(q,ctx)
 finally:files.close()

def role_argv(a,role):return['--role',role,'--public-root',a.public_root,*original_args(a)]
def exclusive(path):return os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
def supervise(a,runtime=None):
 ctx=binding(a);runtime=Runtime()if runtime is None else runtime;files=BuildFiles(a.build_root,os.getuid());anchor=None;out=None;private=None;record=None;result=None;identity=None;wait=None
 try:
  anchor=OutputRoot(a.public_root,os.getuid());public=anchor.path;out=anchor.open('fixture.json');private=exclusive(files.path/'whole-stderr.private');record=files.begin(WAIT,os.getuid());deadline=time.monotonic()+185
  process=runtime.spawn(['sudo','-n','timeout','--kill-after=30s','150s','/usr/bin/python3','-I','-B',str(HERE/'whole-diagnostic.py'),*role_argv(a,'run-original')],out)
  try:identity=runtime.identity(process)
  except BaseException:identity=None
  try:result=runtime.drain(process,private,deadline)
  except BaseException:result={'child_exit':None,'wait_completed':False,'stderr_eof':False,'stderr_overflow':False,'stderr_write_failed':True}
  os.fsync(out);os.close(out);out=None;os.fsync(private);os.close(private);private=None;anchor.check()
  clear=False
  if identity is not None and result['wait_completed']is True and result['stderr_eof']is True:clear=runtime.empty(identity)
  wait={'schema':'nakpanel-whole-wait-v1','binding':ctx,**result,'foreground_empty':clear is True,'identity':identity,'stdout_seal':list(seal(os.lstat(public/'fixture.json')))};record.write_json(wait);record.close();record=None
  if not(result['wait_completed']is True and result['stderr_eof']is True and clear is True):return 76
  completed=runtime.publish(['sudo','-n','timeout','--kill-after=5s','10s','/usr/bin/python3','-I','-B',str(HERE/'whole-diagnostic.py'),*role_argv(a,'publish-after-wait')])
  fd=exclusive(files.path/'whole-publisher-stderr.private')
  try:
   prefix=completed.stderr[:STDERR_LIMIT];bounded_write(fd,prefix)
   os.fsync(fd)
  finally:os.close(fd)
  need(completed.returncode==0);q=public_valid(strict(completed.stdout,RAW_LIMIT),ctx);need(q['actual_child_exit']==result['child_exit']);data=(json.dumps(q,sort_keys=True,separators=(',',':'))+'\n').encode();need(len(data)<=RAW_LIMIT)
  try:anchor.publish(data)
  except Refused:return 76
  return 0 if q['experiment_passed']and result['child_exit']==0 else 1
 finally:
  if record is not None:
   try:record.close()
   except BaseException:pass
  for fd in(out,private):
   if fd is not None:
    try:os.close(fd)
    except BaseException:pass
  if anchor is not None:anchor.close()
  files.close()

class Parser(argparse.ArgumentParser):
 def error(self,message):raise Refused('fixed entry refused')
def main():
 try:
  p=Parser(add_help=False)
  p.add_argument('--role',required=True,choices=('supervise','run-original','publish-after-wait'))
  for n in('build-root','public-root','run-id','attempt','workflow-commit','admission-sha'):p.add_argument('--'+n,required=True)
  a=p.parse_args();binding(a);need(sys.platform=='linux');need(os.geteuid()!=0 if a.role=='supervise'else os.geteuid()==0)
 except BaseException:return 78
 if a.role=='run-original':return run_original(a)
 try:
  if a.role=='supervise':return supervise(a)
  q=publish_after_wait(a);print(json.dumps(q,sort_keys=True,separators=(',',':')));return 0
 except BaseException:return 78
if __name__=='__main__':sys.exit(main())
