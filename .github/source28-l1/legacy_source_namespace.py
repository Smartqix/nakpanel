"""Exclusive old-source fixture namespace preparation; no target/repair path.

The caller remains responsible for authenticated guest/program custody and the
normal application POST/convergence. Dependencies are injectable for offline
boundary tests, never selected through guest input. No import-time I/O.
"""
import errno,math,os,pwd,re,stat,time

class NamespaceRefused(ValueError):
 def __init__(self):super().__init__('legacy source namespace precondition refused')

def _need(value):
 if not value:raise NamespaceRefused()

def _positive(value):return type(value) is int and 0<value<2**63

def _scope(c,account,chain):
 _need(type(c) is dict and type(account) is dict and type(chain) is str and chain in ('l1','l3'))
 _need(c.get('operation')=='SOURCE_FIXTURES' and c.get('role')=='source' and 'application_id' not in c)
 run=c.get('run_id');_need(type(run) is str and re.fullmatch('[1-9][0-9]{0,13}',run) is not None)
 token=chain+'-'+run+'-1-s';_need(c.get('token')==token and c.get('vm')=='nakpanel-24-04-amd64-'+token)
 _need(type(c.get('operation_id')) is str and re.fullmatch('[a-f0-9]{32}',c['operation_id']) is not None)
 hashes=c.get('program_hashes');_need(type(hashes) is dict and bool(hashes) and all(type(k) is str and type(v) is str and re.fullmatch('[a-f0-9]{64}',v) is not None for k,v in hashes.items()))
 for key in ('subscription_id','site_id','customer_id','plan_id'):_need(_positive(c.get(key)))
 username=c.get('username');_need(type(username) is str and re.fullmatch('[a-z][a-z0-9_-]{2,31}',username) is not None and username not in ('root','nakpanel'))
 _need(type(account.get('subscription_id')) is int and account['subscription_id']==c['subscription_id'] and account.get('username')==username and account.get('home_path')=='/home/'+username)
 _need(_positive(account.get('linux_uid')) and all(account.get(k)==v for k,v in [('desired_state','active'),('applied_state','active'),('convergence_status','in_sync')]))
 _need(_positive(account.get('desired_revision')) and _positive(account.get('applied_revision')) and account['desired_revision']==account['applied_revision'])
 job=c.get('policy_job');_need(type(job) is dict and _positive(job.get('id')) and job.get('kind')=='converge_subscription' and job.get('state')=='completed' and type(job.get('subscription_id')) is int and job['subscription_id']==c['subscription_id'] and _positive(job.get('revision')) and job['revision']==account['desired_revision'])
 return (run,c['operation_id'],tuple(sorted(hashes.items())),c['subscription_id'],c['site_id'],c['customer_id'],c['plan_id'],username,account['linux_uid'],account['desired_revision'],job['id'])

def _accounts(accounts,username,uid):
 tenant=accounts.getpwnam(username);panel=accounts.getpwnam('nakpanel')
 def row(value):
  _need(type(value.pw_name) is str and _positive(value.pw_uid) and _positive(value.pw_gid) and type(value.pw_dir) is str)
  return value.pw_name,value.pw_uid,value.pw_gid,value.pw_dir
 t,p=row(tenant),row(panel)
 _need(t[0]==username and t[1]==uid and t[3]=='/home/'+username and p[0]=='nakpanel' and p[3]=='/var/lib/nakpanel' and t[1]!=p[1])
 return t,p

def _facts(info):
 _need(all(type(getattr(info,k,None)) is int for k in ('st_dev','st_ino','st_mode','st_uid','st_gid')) and info.st_dev>=0 and info.st_ino>0)
 _need(stat.S_ISDIR(info.st_mode) and info.st_uid>=0 and info.st_gid>=0)
 return {'dev':info.st_dev,'ino':info.st_ino,'type':'directory','mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid}

def prepare_source_namespace(c,account,*,chain,deadline,fs=os,accounts=pwd,clock=time.monotonic):
 """Create only an absent sub-SID root, or fail without adoption/retry.

Close all acquired FDs on success, refusal or cancellation. A newly created
namespace may remain on failure; ordinary whole-guest cleanup owns that case.
 """
 opened=[]
 try:
  def budget():
   _need(type(deadline) in (int,float) and math.isfinite(deadline))
   now=clock();_need(type(now) in (int,float) and math.isfinite(now) and 0<=now<deadline)
  budget();scope=_scope(c,account,chain)
  _need(type(fs.geteuid()) is int and fs.geteuid()==0 and type(fs.getegid()) is int and fs.getegid()==0)
  identities=_accounts(accounts,c['username'],account['linux_uid']);tenant,panel=identities
  flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK
  seals=[]
  def named(parent,name):
   budget();return _facts(fs.stat(name,follow_symlinks=False,**({} if parent is None else {'dir_fd':parent})))
  def open_named(parent,name):
   budget();fd=fs.open(name,flags,**({} if parent is None else {'dir_fd':parent}));opened.append(fd)
   budget();value=_facts(fs.fstat(fd));_need(value==named(parent,name));return fd,value
  parent=None
  fixed=(('root','/',0,0,0o755),('var','var',0,0,0o755),('lib','lib',0,0,0o755),('panel','nakpanel',panel[1],panel[2],0o755),('containers','containers',0,0,0o711))
  ancestors={}
  for label,name,uid,gid,mode in fixed:
   fd,value=open_named(parent,name);_need((value['uid'],value['gid'],value['mode'])==(uid,gid,mode));seals.append((parent,name,fd,value));ancestors[label]=dict(value);parent=fd
  name='sub-'+str(c['subscription_id'])
  budget()
  try:fs.stat(name,dir_fd=parent,follow_symlinks=False)
  except OSError as error:_need(error.errno==errno.ENOENT)
  else:raise NamespaceRefused()
  budget();fs.mkdir(name,0o711,dir_fd=parent)
  fd,created=open_named(parent,name)
  _need(created['uid']==0 and created['gid']==0 and not created['mode']&~0o711)
  budget();_need(created==named(parent,name) and created==_facts(fs.fstat(fd)))
  budget();fs.fchmod(fd,0o711)
  budget();final=_facts(fs.fstat(fd));_need((final['uid'],final['gid'],final['mode'])==(0,0,0o711) and all(final[k]==created[k] for k in ('dev','ino','type')) and final==named(parent,name))
  seals.append((parent,name,fd,final))
  for parent,name,fd,value in seals:
   budget();_need(_facts(fs.fstat(fd))==value and named(parent,name)==value)
  budget();_need(_scope(c,account,chain)==scope and _accounts(accounts,c['username'],account['linux_uid'])==identities);budget()
  return {'schema':'nakpanel-legacy-source-namespace-v1','status':'CREATED','subscription_id':c['subscription_id'],'site_id':c['site_id'],'tenant_uid':tenant[1],'tenant_gid':tenant[2],'ancestors':ancestors,'namespace':dict(final)}
 except (OSError,KeyError,TypeError,AttributeError,ValueError):raise NamespaceRefused() from None
 finally:
  for fd in reversed(opened):
   try:fs.close(fd)
   except OSError:pass
