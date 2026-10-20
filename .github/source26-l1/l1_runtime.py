"""Hosted-only fixed coordinator. No live behavior at import time."""
import hashlib,importlib.util,json,os,platform,re,shutil,stat,subprocess,sys,tarfile,time,urllib.error,urllib.parse,urllib.request,uuid,zipfile
from pathlib import Path
from l1 import *
import l1_custody
from failure import retain_failed_remote
PACKET_PREFIX='.github/source26-l1/'
WORKFLOW='.github/workflows/source26-legacy-format1.yml'
RUNTIME_FILES={'l1.py','l1_runtime.py','l1_custody.py','custody_base.py','guest.py','contracts.json','projector.py','failure.py','guest-sites.json','waitdiag.py'}

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):return None

def validate_artifact(a,r,j):
 c=contracts()['bootstrap'];pin=c['artifact'];need(type(a) is dict and all(a.get(k)==v for k,v in pin.items()) and a.get('expired') is False,'ARTIFACT');w=a.get('workflow_run');need(type(w) is dict and w.get('id')==39347496239 and w.get('head_sha')==SOURCE,'ARTIFACT')
 need(type(r) is dict and r.get('id')==39347496239 and r.get('head_sha')==SOURCE and r.get('event')=='workflow_dispatch' and type(r.get('run_attempt')) is int and r['run_attempt']==1 and r.get('status')=='completed','ARTIFACT')
 need(type(j) is dict and j.get('id')==118383538478 and j.get('run_id')==39347496239 and j.get('head_sha')==SOURCE and j.get('status')=='completed' and j.get('conclusion')=='success','ARTIFACT')
 try:expiry=datetime.fromisoformat(a['expires_at'].replace('Z','+00:00'))
 except (ValueError,KeyError):raise Refused('ARTIFACT') from None
 need(datetime.now(timezone.utc)<expiry,'ARTIFACT');return True

def inventory(row,roleset,fresh=False):
 need(type(row) is dict and type(row.get('list')) is list and row.get('errors',[])==[],'IDENTITY');allowed={r['vm'] for r in roleset.values()};names={};running=0
 for r in row['list']:
  need(type(r) is dict and r.get('name') in allowed and r['name'] not in names and r.get('state') in ('Running','Stopped'),'IDENTITY');names[r['name']]=r['state'];running+=r['state']=='Running'
 need(len(names)<=2 and running<=1 and (not fresh or names=={}),'IDENTITY');return names

def validate_remote(row,c,input_sha):
 need(type(row) is dict and row.get('schema')=='nakpanel-l1-remote-v1' and all(row.get(k)==c[k] for k in ('operation','operation_id','role','vm','token','run_id')) and row.get('source_commit')==SOURCE and row.get('program_sha256')==c['program_hashes']['guest.py'] and row.get('input_sha256')==input_sha,'REMOTE_UNKNOWN')
 need(row.get('known') is True and row.get('status')=='PASS' and type(row.get('exit_code')) is int and row['exit_code']==0 and type(row.get('payload')) is dict and type(row.get('started_monotonic')) in (int,float) and type(row.get('finished_monotonic')) in (int,float) and row['started_monotonic']<=row['finished_monotonic'],'REMOTE_UNKNOWN');return True

def r9_failure_projection(raw):
 statuses={'CREATED','AUTHENTICATED','SUBMITTING','SEND_UNCERTAIN','SENT','DELIVERED','PASS','FAIL'}
 reasons={'ambiguous-form','compose-csrf','compose-form','compose-identity','deadline','delivery-changed','delivery-identity','delivery-message-id','delivery-self-recipient','duplicate-delivery','http-page','imap-authentication','imap-candidates','imap-headers','imap-inbox','imap-refresh','imap-search','invalid-endpoint','invalid-local-fixture','login-csrf','preexisting-canary','redirect-limit','response-size','roundcube-body-mismatch','roundcube-login','send-not-confirmed','send-result-uncertain','transport-or-protocol','unsafe-redirect'}
 raw=raw if type(raw) is dict else {}
 return {'send_attempts':raw.get('send_attempts') if type(raw.get('send_attempts')) is int and raw['send_attempts'] in (0,1) else None,'status':raw.get('status') if raw.get('status') in statuses else 'UNKNOWN','reason':raw.get('error') if raw.get('error') in reasons else 'UNKNOWN'}

def extract(path,target,kind):
 need(not target.exists(),'ARTIFACT');target.mkdir(mode=0o700);seen=set();size=0
 if kind=='zip':
  with zipfile.ZipFile(path) as archive:
   for item in archive.infolist():
    n=item.filename.rstrip('/');need(safe_name(n) and n not in seen and not item.flag_bits&1 and ((item.external_attr>>16)&0o170000) in (0,stat.S_IFREG,stat.S_IFDIR),'ARTIFACT');seen.add(n);size+=item.file_size;need(len(seen)<=3000 and size<=2**31,'ARTIFACT');p=target/n
    if item.is_dir():p.mkdir(mode=0o700,parents=True,exist_ok=True)
    else:
     p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
     with archive.open(item) as src,p.open('xb') as dst:shutil.copyfileobj(src,dst)
     p.chmod(0o600)
 else:
  with tarfile.open(path,'r|gz') as archive:
   for item in archive:
    n=item.name.rstrip('/');need(safe_name(n) and n not in seen and (item.isdir() or item.isfile()),'ARTIFACT');seen.add(n);size+=item.size;need(len(seen)<=3000 and size<=2**31,'ARTIFACT');p=target/n
    if item.isdir():p.mkdir(mode=0o700,parents=True,exist_ok=True)
    else:
     p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
     with archive.extractfile(item) as src,p.open('xb') as dst:shutil.copyfileobj(src,dst)
     p.chmod(0o700 if item.mode&0o111 else 0o600)

class Runner:
 def __init__(self,owner):self.owner=owner;self.counter=0;self.last_drained=True;self.rows=[]
 def call(self,budget,args,role='host',operation='stage',data=None,env=None,accepted=(0,),uncertain=False):
  c=self.owner;c.guard(budget);self.counter+=1;phase='a'+str(self.counter).zfill(3)+'-'+role;args=list(map(str,args));environment=dict(env or c.environment());binding={'run_id':c.run_id,'role':role,'vm':c.roles[role]['vm'] if role!='host' else c.roles['source']['vm'],'token':c.roles[role]['token'] if role!='host' else c.roles['source']['token'],'source_commit':SOURCE,'operation':operation}
  if data is not None:
   p=c.root/('input-'+str(self.counter));need(not p.exists(),'IDENTITY');p.write_bytes(data if type(data) is bytes else data.encode());p.chmod(0o600)
   args=[sys.executable,'-I','-B','-c','import os,sys;f=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW);os.dup2(f,0);os.close(f);os.execvpe(sys.argv[2],sys.argv[2:],os.environ)',str(p),*args]
  receipt=None
  try:
   try:receipt=l1_custody.run(c.logs,phase,args,binding=binding,env=environment,timeout_seconds=min(4500,c.budget.allowance(budget)))
   except BaseException:
    p=c.logs/phase/'receipt.json'
    if p.exists():receipt=decode(regular(p).read_bytes())
    if not(type(receipt) is dict and receipt.get('failure_code')=='exit' and receipt.get('exit_code') in accepted and receipt.get('process_group_empty') is True and receipt.get('process_exited') is True):
     if uncertain:c.graph.remote_known=False
     raise
  finally:
   self.last_drained=type(receipt) is dict and receipt.get('process_group_empty') is True and receipt.get('process_exited') is True;c.graph.drained=self.last_drained
   if receipt:self.rows.append(receipt)
  need(receipt['exit_code'] in accepted,'CHILD');out=c.logs/phase/'stdout.log';err=c.logs/phase/'stderr.log';self.verify_stream(out,receipt['stdout']);self.verify_stream(err,receipt['stderr']);c.guard(budget);return receipt,out,err
 def verify_stream(self,p,proof):
  regular(p,max_bytes=64*1024*1024);before=p.stat();need(type(proof) is dict and proof.get('bytes')==before.st_size and proof.get('sha256')==sha(p),'IDENTITY');after=p.stat();need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'IDENTITY')
 def output(self,budget,args,**kw):return self.call(budget,args,**kw)[1].read_bytes()

class Coordinator:
 def __init__(self,a,app,operator):
  self.a=a;self.app=Path(app);self.operator=Path(operator);self.packet=self.operator/PACKET_PREFIX;self.host=dict(os.environ);self.run_id=self.host['GITHUB_RUN_ID'];self.roles=roles(self.run_id);self.budget=Budget();self.graph=Graph();self.state={'overall':'FAIL','covered':False,'strict':False,'r9_count':0,'boots':[],'cleanup':False,'remote_known':True,'drained':True,'reason':'PENDING','phases':[]};self.known={};self.context={};self.pins={};self.bundles={};self.manifests={};self.key=None;self.image=None;self.remote_roots={r:'/root/nakpanel-'+v['token'] for r,v in self.roles.items()};self.root=Path(self.host['RUNNER_TEMP'])/'l1-private';self.public=Path(self.host['RUNNER_TEMP'])/'l1-public';self.logs=self.root/'logs';self.runner=None;self.bootstrap_pass=False
 def environment(self,role=None):
  allowed=('PATH','HOME','LANG','LC_ALL','TMPDIR','RUNNER_TEMP','GITHUB_ENV','GITHUB_ACTIONS','RUNNER_ENVIRONMENT','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_REPOSITORY','GITHUB_SHA')
  e={k:v for k,v in self.host.items() if k in allowed};e['PATH']=str(self.root/'isolated-bin')+':'+e.get('PATH','/usr/bin:/bin');e.update(APP_SOURCE=str(self.app))
  if role:
   selected=self.roles[role];other=self.roles['target' if role=='source' else 'source'];e.update(NAKPANEL_RUN_TOKEN=selected['token'],NAKPANEL_MULTIPASS_VM=selected['vm'],NAKPANEL_MULTIPASS_SOURCE_VM=selected['vm'],NAKPANEL_MULTIPASS_DR_VM=other['vm'],NAKPANEL_OWNERSHIP_DIR=str(self.root/'ownership'),NAKPANEL_MULTIPASS_IMAGE='24.04',NAKPANEL_MULTIPASS_ARCH='amd64',NAKPANEL_QUALIFICATION_PHP_PROVIDER='native',NAKPANEL_QUALIFICATION_VM_CPUS='2',NAKPANEL_QUALIFICATION_VM_MEMORY='5G',NAKPANEL_QUALIFICATION_VM_DISK='32G',NAKPANEL_QUALIFICATION_DR_CPUS='2',NAKPANEL_QUALIFICATION_DR_MEMORY='5G',NAKPANEL_QUALIFICATION_DR_DISK='32G',NAKPANEL_RELEASE_BUNDLE=str(self.bundles[role]),NAKPANEL_RELEASE_PUBLIC_KEY=str(self.key),NAKPANEL_RELEASE_VERSION='29.0.0',NAKPANEL_RELEASE_ALLOW_DEVELOPMENT='1',NAKPANEL_MULTIPASS_IMAGE_SOURCE=str(self.image),NAKPANEL_MULTIPASS_IMAGE_SHA256=contracts()['binding']['image']['sha256'])
   if role=='source':e['NAKPANEL_RELEASE_LEGACY_INSTALLER']='1'
   else:e['NAKPANEL_INSTALL_ONLY']='1'
  return e
 def guard(self,budget):
  self.budget.check(budget)
  for path,h in self.pins.items():need(sha(regular(path,private=False))==h,'INPUT_DRIFT')
 def git(self,root,*args):return self.runner.output('stage',['git','-C',root,*args]).decode().strip()
 def setup(self):
  need(platform.system()=='Linux' and platform.machine() in ('x86_64','amd64'),'ADMISSION');base=physical_dir(Path(self.host['RUNNER_TEMP']),private=False);need(self.root.parent==base and self.public.parent==base and self.app.is_absolute() and self.operator.is_absolute() and self.app.resolve()==self.app and self.operator.resolve()==self.operator and self.app!=self.operator and self.app not in self.operator.parents and self.operator not in self.app.parents,'ADMISSION');need(not self.root.exists() and not self.public.exists(),'ADMISSION');os.umask(0o077);self.root.mkdir(mode=0o700);self.public.mkdir(mode=0o700);self.logs.mkdir(mode=0o700);self.runner=Runner(self)
  # Admission has already been validated in the no-process bootstrap entry.
  need(RUNTIME_FILES<=set(self.a['packet']) and self.a['helpers']==contracts()['helpers'],'ADMISSION')
  for name,h in self.a['packet'].items():need(safe_name(name) and sha(regular(self.packet/name,private=False))==h,'INPUT_DRIFT');self.pins[str(self.packet/name)]=h
  for name,h in self.a['helpers'].items():need(sha(regular(self.app/name,private=False))==h,'INPUT_DRIFT');self.pins[str(self.app/name)]=h
  need(sha(self.packet/'custody_base.py')=='bbe68b69d270aae3a253c2848dee8e4145eb546454d767e00ab2d8392e11b8b3','INPUT_DRIFT')
  need(self.git(self.app,'rev-parse','HEAD')==SOURCE and self.git(self.app,'rev-parse','HEAD^{tree}')==TREE and not self.git(self.app,'status','--porcelain','--untracked-files=all'),'IDENTITY')
  need(self.git(self.operator,'rev-parse','HEAD')==self.a['controller_commit'] and (self.a['controller_tree'] is None or self.git(self.operator,'rev-parse','HEAD^{tree}')==self.a['controller_tree']) and self.git(self.operator,'rev-list','--parents','-n','1','HEAD')==self.a['controller_commit']+' '+SOURCE and not self.git(self.operator,'status','--porcelain','--untracked-files=all'),'IDENTITY')
  names=self.git(self.operator,'diff-tree','--no-commit-id','--name-only','-r','HEAD').splitlines();declared=set(names)-{WORKFLOW} if self.a.get('workflow_bound_externally') else set(names);need(declared==set(self.a['changed_blobs']) and set(names)=={PACKET_PREFIX+n for n in self.a['packet']}|{WORKFLOW},'IDENTITY')
  if self.a['controller_tree'] is None:self.a['controller_tree']=self.git(self.operator,'rev-parse','HEAD^{tree}')
  workflow_row=self.git(self.operator,'ls-tree','HEAD',WORKFLOW).split();need(len(workflow_row)==4 and workflow_row[0]=='100644' and workflow_row[1]=='blob' and workflow_row[3]==WORKFLOW,'IDENTITY')
  for name,h in self.a['changed_blobs'].items():
   raw=self.git(self.operator,'ls-tree','HEAD',name).split();need(len(raw)==4 and raw[0]=='100644' and raw[1]=='blob' and raw[3]==name,'IDENTITY');need(sha(regular(self.operator/name,private=False))==h,'INPUT_DRIFT');self.pins[str(self.operator/name)]=h
  need(self.runner.output('stage',['/bin/bash','-c','(( BASH_VERSINFO[0] >= 5 )) && printf admitted'])==b'admitted','ADMISSION')
  shim=self.root/'isolated-bin';shim.mkdir(mode=0o700);p=shim/'python3';p.write_text('#!/bin/bash\nexec /usr/bin/python3 -I -B "$@"\n');p.chmod(0o700);self.pins[str(p)]=sha(p)
  self.bootstrap_pass=True;context={'run_id':self.run_id,'controller_commit':self.a['controller_commit'],'source_commit':SOURCE,'roles':self.roles,'root_identity':[self.root.stat().st_dev,self.root.stat().st_ino]};publish(self.root/'run-context.json',context);self.state.update(context_sha256=sha(self.root/'run-context.json'),run_id=self.run_id,controller_commit=self.a['controller_commit'],controller_tree=self.a['controller_tree']);publish(self.public/'l1-bootstrap.json',{'schema':'nakpanel-l1-bootstrap-v1','admitted':True,'source_commit':SOURCE,'controller_commit':self.a['controller_commit'],'controller_tree':self.a['controller_tree'],'parent':SOURCE,'run_id':self.run_id,'attempt':1,'roles':self.roles,'image_ref':IMAGE_REF,'image_coverage':'CONFIG_ONLY_STOPPED','runtime_acceptance':False})
 def api(self,path,binary=False):
  need(path in ('/repos/'+REPO,'/repos/'+REPO+'/actions/artifacts/12231269532','/repos/'+REPO+'/actions/runs/39347496239','/repos/'+REPO+'/actions/jobs/118383538478','/repos/'+REPO+'/actions/artifacts/12231269532/zip'),'ARTIFACT');token=self.host.get('GH_TOKEN');need(type(token) is str and token,'ARTIFACT');request=urllib.request.Request('https://api.github.com'+path,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'});opener=urllib.request.build_opener(NoRedirect());response=None
  try:
   try:response=opener.open(request,timeout=min(60,self.budget.allowance('stage')))
   except urllib.error.HTTPError as e:
    if not(binary and e.code in (301,302,303,307,308)):raise Refused('ARTIFACT') from None
    location=e.headers.get('Location','');e.close();u=urllib.parse.urlparse(location);need(u.scheme=='https' and u.username is None and u.password is None and u.hostname and (u.hostname.endswith('.blob.core.windows.net') or u.hostname.endswith('.actions.githubusercontent.com')),'ARTIFACT');response=urllib.request.urlopen(urllib.request.Request(location,headers={'Accept':'application/octet-stream'}),timeout=min(120,self.budget.allowance('stage')))
   if binary:
    p=self.root/'artifact.zip';h=hashlib.sha256();size=0
    with p.open('xb') as dst:
     while True:
      b=response.read(1024*1024)
      if not b:break
      size+=len(b);need(size<=73997080,'ARTIFACT');dst.write(b);h.update(b);self.budget.check('stage')
    p.chmod(0o600);need(size==73997080 and h.hexdigest()==contracts()['binding']['artifact']['sha256'],'ARTIFACT');return p
   data=response.read(4*1024*1024+1);need(len(data)<=4*1024*1024,'ARTIFACT');return decode(data)
  finally:
   if response:response.close()
 def acquire(self):
  repo=self.api('/repos/'+REPO);need(repo.get('id')==REPO_ID and repo.get('full_name')==REPO and repo.get('private') is False,'ARTIFACT');a=self.api('/repos/'+REPO+'/actions/artifacts/12231269532');r=self.api('/repos/'+REPO+'/actions/runs/39347496239');j=self.api('/repos/'+REPO+'/actions/jobs/118383538478');validate_artifact(a,r,j);publish(self.root/'artifact-authentication.json',{'artifact':a,'run':r,'job':j,'repository':repo,'at_utc':datetime.now(timezone.utc).isoformat()},cap=4*1024*1024);archive=self.api('/repos/'+REPO+'/actions/artifacts/12231269532/zip',True);extract(archive,self.root/'download','zip');dl=self.root/'download';self.key=regular(dl/'test-public.pem');need(sha(self.key)==contracts()['binding']['artifact']['public_key_sha256'],'ARTIFACT')
  for role,kind in (('source','prior'),('target','candidate')):
   pin=contracts()['bootstrap']['runtime_sources'][kind];tar=regular(dl/pin['archive']);need(tar.stat().st_size==pin['archive_bytes'] and sha(tar)==pin['archive_sha256'],'ARTIFACT');dest=self.root/('release-'+role);extract(tar,dest,'tar');bundle=dest/'nakpanel-29.0.0-linux-amd64';need(sha(bundle/'manifest.json')==pin['manifest_sha256'],'ARTIFACT');self.runner.call('stage',['/usr/bin/python3','-I','-B',self.app/'deploy/release/verify.py','--bundle',bundle,'--public-key',self.key,'--version','29.0.0','--architecture','amd64','--allow-development']);manifest=decode((bundle/'manifest.json').read_bytes());need(manifest['commit']==pin['commit'] and manifest['development'] is True and manifest['go_toolchain']=='go1.26.9' and len(manifest['files'])==pin['signed_files'],'ARTIFACT');need({n:manifest['files']['bin/'+n] for n in ('panel','agent','panelctl')}==pin['installed_binary_sha256'],'ARTIFACT');self.bundles[role]=bundle;self.manifests[role]=manifest
   for name,h in manifest['files'].items():self.pins[str(bundle/name)]=h
   for p in (bundle/'manifest.json',bundle/'manifest.sig',tar):self.pins[str(p)]=sha(p)
  self.pins[str(self.key)]=sha(self.key);need(all(self.manifests['target']['files'].get(n)==h for n,h in contracts()['sources']['selected_signed_migration_subset'].items()),'ARTIFACT');self.state['artifact_authenticated']=True
 def shell(self,budget,role,body,*args,uncertain=False):
  need(type(body) is str,'IDENTITY');return self.runner.call(budget,['/bin/bash','-ceu','set -euo pipefail; source "$APP_SOURCE/deploy/multipass/common.sh"; '+body,'--',*args],env=self.environment(role),role=role,operation=body.split()[0],uncertain=uncertain)
 def list(self,budget='stage',fresh=False):return inventory(decode(self.runner.output(budget,['multipass','list','--format','json'])),self.roles,fresh)
 def owner(self,role,budget):
  r=self.roles[role];p=self.root/'ownership'/r['token']/r['vm'];need(regular(p).read_text()=='24.04\tamd64\t'+r['token']+'\n','IDENTITY');self.shell(budget,role,'assert_current_vm_identity')
 def hosted(self):
  self.runner.call('stage',['/bin/bash',self.app/'deploy/multipass/prepare-hosted-runner.sh']);lines=Path(self.host['GITHUB_ENV']).read_text().splitlines();paths=[l[7:] for l in lines if l.startswith('TMPDIR=')];need(paths,'IDENTITY');tmp=physical_dir(paths[-1]);need(Path(self.host['RUNNER_TEMP']) in tmp.parents,'IDENTITY');self.host['TMPDIR']=str(tmp)
  # Same unchanged KVM/capacity preflight used by hosted qualification.
  capacity_path=self.root/'host-capacity.json';self.runner.call('stage',['/usr/bin/python3','-I','-B',self.app/'deploy/multipass/hosted-runner-preflight.py','--output',capacity_path]);capacity=decode(regular(capacity_path).read_bytes());need(capacity.get('status')=='PASS' and capacity.get('kvm_api')==12,'ADMISSION')
  self.list(fresh=True)
  pin=contracts()['binding']['image'];metadata=self.root/'download/images/noble';self.runner.call('stage',['gpgv','--keyring','/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg',metadata/'SHA256SUMS.gpg',metadata/'SHA256SUMS']);filename='ubuntu-24.04-server-cloudimg-amd64.img';rows=[line.split()[0] for line in (metadata/'SHA256SUMS').read_text().splitlines() if len(line.split())==2 and line.split()[1].lstrip('*')==filename];need(rows==[pin['sha256']],'ARTIFACT');self.image=self.root/filename;self.runner.call('stage',['curl','--fail','--location','--proto','=https','--proto-redir','=https','--max-time','600','https://cloud-images.ubuntu.com/releases/noble/release-20261017/'+filename,'--output',self.image]);need(sha(self.image)==pin['sha256'],'ARTIFACT');self.pins[str(self.image)]=pin['sha256']
 def install(self,role,budget):
  names=self.list(budget);need(self.roles[role]['vm'] not in names and not (self.root/'ownership'/self.roles[role]['token']).exists(),'IDENTITY')
  if role=='target':need(names.get(self.roles['source']['vm'])=='Stopped' and all(v=='Stopped' for v in names.values()),'IDENTITY')
  self.known[role]=True;self.runner.call(budget,['/bin/bash',self.app/'deploy/multipass/current-install-verify.sh'],role=role,env=self.environment(role),operation='SOURCE_INSTALL' if role=='source' else 'TARGET_INSTALL',uncertain=True);self.owner(role,budget);names=self.list(budget);need(names.get(self.roles[role]['vm'])=='Running' and sum(v=='Running' for v in names.values())==1,'IDENTITY');self.stage_guest(role,budget)
 def stage_guest(self,role,budget):
  self.owner(role,budget);r=self.roles[role];vm=r['vm'];root=self.remote_roots[role];files={n:self.packet/n for n in ('l1.py','guest.py','contracts.json','failure.py','guest-sites.json','waitdiag.py')};files['phase29-imap-canary.py']=self.app/'deploy/multipass/phase29-imap-canary.py';program_hashes={n:sha(p) for n,p in files.items()};staged={}
  for n,p in files.items():
   dest='/home/ubuntu/'+r['token']+'-'+n;self.runner.call(budget,['multipass','transfer',p,vm+':'+dest],role=role,operation='TRANSFER',uncertain=True);staged[n]=dest
  body="""import hashlib,json,os,pathlib,shutil,stat,sys
c=json.loads(sys.stdin.read());root=pathlib.Path(c['root']);root.mkdir(mode=0o700)
for n,p in c['files'].items():
 s=os.lstat(p)
 if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1:raise SystemExit(1)
 if hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()!=c['hashes'][n]:raise SystemExit(1)
 with open(p,'rb') as src,(root/n).open('xb') as dst:shutil.copyfileobj(src,dst)
 os.chmod(root/n,0o600);os.chown(root/n,0,0);os.unlink(p)
print(json.dumps({'staged':True,'token':c['token'],'hashes':c['hashes']}))
"""
  input_data=canonical({'root':root,'files':staged,'hashes':program_hashes,'token':r['token']});program='import io,sys\nsys.stdin=io.StringIO('+repr(input_data.decode())+')\n'+body
  self.graph.remote_known=False
  raw=self.runner.output(budget,['multipass','exec',vm,'--','sudo','/usr/bin/timeout','--kill-after=30s','120s','/usr/bin/python3','-I','-B','-'],role=role,operation='TRANSFER',data=program.encode(),uncertain=True);row=decode(raw);need(row=={'staged':True,'token':r['token'],'hashes':program_hashes},'REMOTE_UNKNOWN');self.graph.remote_known=True
  self.context[role]={'role':role,'run_id':self.run_id,'vm':r['vm'],'token':r['token'],'binaries':{n:self.manifests[role]['files']['bin/'+n] for n in ('panel','agent','panelctl')},'program_hashes':program_hashes,'guest_bundle':'/var/lib/nakpanel-qualification/'+r['token']+'/release'}
 def remote(self,phase,budget,role='target'):
  self.owner(role,budget);c=dict(self.context[role]);c.update(operation=phase,operation_id=uuid.uuid4().hex,operation_index=len(self.graph.done)+1,seconds=min(3600,int(self.budget.allowance(budget))-1));data=canonical(c);input_sha=hashlib.sha256(data).hexdigest();root=self.remote_roots[role];publish(self.root/(phase.lower()+'-intent.json'),{'context':c,'input_sha256':input_sha},cap=4*1024*1024)
  self.graph.remote_known=False
  try:
   rec,out,err=self.runner.call(budget,['multipass','exec',c['vm'],'--','sudo','/usr/bin/timeout','--kill-after=30s',str(c['seconds'])+'s','/usr/bin/python3','-I','-B',root+'/guest.py'],role=role,operation=phase,data=data,accepted=(0,1),uncertain=True);row=decode(out.read_bytes())
   # A known FAIL is terminal but permits owned failure cleanup; unknown never does.
   identity_ok=type(row) is dict and row.get('schema')=='nakpanel-l1-remote-v1' and all(row.get(k)==c[k] for k in ('operation','operation_id','role','vm','token','run_id')) and row.get('input_sha256')==input_sha and row.get('program_sha256')==c['program_hashes']['guest.py'] and row.get('source_commit')==SOURCE
   if not(identity_ok and row.get('known') is True):self.graph.remote_known=False;raise Refused('REMOTE_UNKNOWN')
   self.graph.remote_known=True
   if row.get('status')!='PASS':
    try:retain_failed_remote(self.root,c,input_sha,row,rec,self.state)
    except Exception:self.state['failed_remote_capture']='UNAVAILABLE'
    raise Refused(row.get('reason','UNKNOWN'))
   validate_remote(row,c,input_sha);need(row['exit_code']==rec['exit_code'],'REMOTE_UNKNOWN');publish(self.root/(phase.lower()+'-remote.json'),row,cap=4*1024*1024);return row['payload']
  except BaseException:
   if not self.runner.last_drained:self.graph.remote_known=False
   raise
 def transfer_archive(self):
  source=self.roles['source'];target=self.roles['target'];meta=self.context['source']['backup_meta']
  # Read a fixed private source copy only; source stays cold after export.
  for n in ('archive.nkbk','backup.key'):
   p=self.root/n;need(regular(p).stat().st_size==meta['archive' if n=='archive.nkbk' else 'key']['bytes'] and sha(p)==meta['archive' if n=='archive.nkbk' else 'key']['sha256'],'ARTIFACT');dest='/home/ubuntu/'+target['token']+'-'+n;self.runner.call('recovery',['multipass','transfer',p,target['vm']+':'+dest],role='target',operation='TRANSFER',uncertain=True)
  # No key bytes enter argv/environment: the root copier validates fixed hashes.
  root=self.remote_roots['target'];body="""import hashlib,json,os,pathlib,shutil,stat,sys
c=json.loads(sys.stdin.read())
for n,h in c['hashes'].items():
 p=pathlib.Path('/home/ubuntu/'+c['token']+'-'+n);s=p.lstat()
 if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or hashlib.sha256(p.read_bytes()).hexdigest()!=h:raise SystemExit(1)
 dst=pathlib.Path(c['root'])/n
 with p.open('rb') as a,dst.open('xb') as b:shutil.copyfileobj(a,b)
 os.chmod(dst,0o600);os.chown(dst,0,0);p.unlink()
print(json.dumps({'transferred':True,'hashes':c['hashes']}))
"""
  self.graph.remote_known=False
  c={'token':target['token'],'root':root,'hashes':{n:sha(self.root/n) for n in ('archive.nkbk','backup.key')}};program='import io,sys\nsys.stdin=io.StringIO('+repr(canonical(c).decode())+')\n'+body;raw=self.runner.output('recovery',['multipass','exec',target['vm'],'--','sudo','/usr/bin/timeout','--kill-after=30s','120s','/usr/bin/python3','-I','-B','-'],role='target',operation='TRANSFER',data=program.encode(),uncertain=True);need(decode(raw)=={'transferred':True,'hashes':c['hashes']},'REMOTE_UNKNOWN');self.graph.remote_known=True
  self.context['target'].update(archive_sha256=sha(self.root/'archive.nkbk'),key_sha256=sha(self.root/'backup.key'),key_fingerprint=meta['key_fingerprint'],source_hostname=self.context['source']['baseline']['identity']['hostname'])
 def export_archive(self):
  r=self.roles['source'];meta=self.context['source']['backup_meta']
  for n,key in (('archive.nkbk','archive'),('backup.key','key')):
   rec,out,err=self.runner.call('backup',['multipass','exec',r['vm'],'--','sudo','cat',self.remote_roots['source']+'/'+n],role='source',operation='TRANSFER');need(out.stat().st_size==meta[key]['bytes'] and sha(out)==meta[key]['sha256'],'ARTIFACT');dest=self.root/n;need(not dest.exists(),'IDENTITY');shutil.copyfile(out,dest);dest.chmod(0o600);need(sha(dest)==meta[key]['sha256'],'ARTIFACT');self.pins[str(dest)]=sha(dest)
 def cold(self):
  self.owner('source','cold');self.runner.call('cold',['multipass','stop',self.roles['source']['vm']],role='source',operation='SOURCE_COLD',uncertain=True);need(self.list('cold').get(self.roles['source']['vm'])=='Stopped','IDENTITY')
 def r9(self,label,budget):
  self.owner('target',budget);case=self.root/('r9-'+label);case.mkdir(mode=0o700);env=self.environment('target');env.update(NAKPANEL_INTERNAL_TOOLS_SITE_ID=str(self.context['target']['site_id']),NAKPANEL_INTERNAL_TOOLS_MAILBOX='l1@current-bootstrap.test',NAKPANEL_INTERNAL_TOOLS_RECEIPT=str(case/'roundcube-send-read.json'));receipt=None
  try:
   receipt,out,err=self.runner.call(budget,['/bin/bash',self.app/'deploy/multipass/internal-tools-verify.sh','--roundcube-only'],role='target',operation='R9_'+label.upper(),env=env,accepted=(0,1),uncertain=True)
   need(receipt['exit_code']==0,'R9')
   flows=list(case.glob('.roundcube-flow.*'));need(len(flows)==1,'R9');flow=physical_dir(flows[0]);raw_files=list(flow.glob('roundcube-send-read-*.json'));need(len(raw_files)==1,'R9');companions=[regular(p,max_bytes=65536) for p in [*raw_files,flow/'installed-before.txt',flow/'installed-after.txt']];companion_hashes={str(p):sha(p) for p in companions};envelope=regular(case/'roundcube-send-read.json',max_bytes=65536);data=envelope.read_bytes();helper=self.app/'deploy/multipass/roundcube-send-read.py';spec=importlib.util.spec_from_file_location('l1_r9_producer',helper);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);bindings={'source_vm':self.roles['target']['vm'],'run_token':self.roles['target']['token'],'release':'24.04','architecture':'amd64','profile':'ubuntu-24.04','php_provider':'native','app_version':'29.0.0'};revalidated=case/'revalidated.json';mod.enrich(flow,self.bundles['target']/'manifest.json',flow/'installed-before.txt',flow/'installed-after.txt',revalidated,self.app/'deploy/multipass/internal-tools-verify.sh',bindings);need(revalidated.read_bytes()==data and all(sha(regular(p,max_bytes=65536))==h for p,h in companion_hashes.items()),'R9');e=decode(data);need(e['runtime_commit']==SOURCE and e['installed_binary_sha256']==self.context['target']['binaries'] and e['raw_receipt']['recipient_sha256']==hashlib.sha256(b'l1@current-bootstrap.test').hexdigest(),'R9');self.guard(budget)
   # Preserve original safe envelope bytes; separate truthful L1 execution receipt.
   dst=self.public/('l1-r9-'+label+'.json');need(not dst.exists(),'PUBLICATION');dst.write_bytes(data);dst.chmod(0o600);execution={'schema':'nakpanel-l1-r9-execution-v1','label':label,'success':True,'actual_exit':receipt['exit_code'],'host_drained':receipt['process_group_empty'],'source_commit':SOURCE,'run_id':self.run_id,'role':'target','token':self.roles['target']['token'],'vm':self.roles['target']['vm'],'command_sha256':receipt['command_sha256'],'envelope_sha256':sha(dst),'send_attempts':1,'one_send_limit':True};publish(self.public/('l1-r9-'+label+'.execution.json'),execution);self.state['r9_count']+=1
  except BaseException:
   # Diagnostic fields only from the single fresh flow of this drained invocation.
   diagnostic=r9_failure_projection({})
   try:
    if receipt is not None and receipt['process_group_empty'] is True and receipt['process_exited'] is True:
     flows=list(case.glob('.roundcube-flow.*'));need(len(flows)==1,'R9');flow=physical_dir(flows[0]);raws=list(flow.glob('roundcube-send-read-*.json'));need(len(raws)==1,'R9');p=regular(raws[0],max_bytes=16384);raw_bytes=p.read_bytes();raw=decode(raw_bytes);need(canonical(raw)==raw_bytes and raw.get('schema')=='nakpanel-roundcube-send-read-v1' and raw.get('qualifier_helper_sha256')==sha(self.app/'deploy/multipass/roundcube-send-read.py') and raw.get('recipient_sha256')==hashlib.sha256(b'l1@current-bootstrap.test').hexdigest(),'R9');diagnostic=r9_failure_projection(raw)
   except BaseException:pass
   failure={'schema':'nakpanel-l1-r9-execution-v1','label':label,'success':False,'actual_exit':receipt['exit_code'] if receipt else None,'host_drained':self.runner.last_drained,'run_id':self.run_id,'role':'target','token':self.roles['target']['token'],'vm':self.roles['target']['vm'],**diagnostic}
   if not (self.public/('l1-r9-'+label+'.execution.json')).exists():publish(self.public/('l1-r9-'+label+'.execution.json'),failure)
   self.state['reason']='R9';raise
 def reboot(self,num,budget):
  self.owner('target',budget);self.runner.call(budget,['multipass','restart',self.roles['target']['vm']],role='target',operation='REBOOT'+str(num),uncertain=True);self.owner('target',budget);need(self.list(budget).get(self.roles['source']['vm'])=='Stopped','IDENTITY')
 def cleanup(self):
  if not self.graph.cleanup_allowed:self.state['cleanup']=False;return False
  if self.runner is None:return False
  for role in ('target','source'):
   if role not in self.known:continue
   names=self.list('cleanup')
   if self.roles[role]['vm'] not in names:continue
   # Guest identity cannot be checked cold: start only for token validation,
   # never while another guest runs. This is owned cleanup, outside measurement.
   if names[self.roles[role]['vm']]=='Stopped':
    if any(v=='Running' for v in names.values()):
     other='source' if role=='target' else 'target';self.owner(other,'cleanup');self.runner.call('cleanup',['multipass','stop',self.roles[other]['vm']],role=other,operation='cleanup',uncertain=True)
    self.runner.call('cleanup',['multipass','start',self.roles[role]['vm']],role=role,operation='cleanup',uncertain=True)
   self.owner(role,'cleanup');self.shell('cleanup',role,'destroy_owned_vm "$1" "$NAKPANEL_RUN_TOKEN"',self.roles[role]['vm'],uncertain=True);need(self.roles[role]['vm'] not in self.list('cleanup'),'CLEANUP')
  self.state['cleanup']=True;return True
 def complete(self,phase,payload=None):self.graph.complete(phase,{'known':True});self.state['phases'].append({'phase':phase,'status':'PASS'})
 def execute(self):
  current='setup';error=None
  try:
   self.setup();self.acquire();self.hosted()
   current='SOURCE_INSTALL';self.install('source','source');self.complete(current)
   current='SOURCE_FIXTURES';self.context['source'].update(self.remote(current,'source','source'));self.complete(current)
   current='SOURCE_BEFORE';base=self.remote(current,'backup','source');self.context['source']['baseline']=base;self.complete(current)
   current='BACKUP';self.context['source']['backup_meta']=self.remote(current,'backup','source');self.export_archive();self.complete(current)
   current='SOURCE_AFTER';self.remote(current,'backup','source');self.complete(current)
   current='SOURCE_COLD';self.cold();self.complete(current)
   current='TARGET_INSTALL';self.install('target','target');self.complete(current)
   current='TARGET_BASELINE';target=self.remote(current,'target');self.context['target'].update(platform_sha256=target['identity']['platform_sha256'],trust_baseline=target['trust_baseline']);self.complete(current)
   # Only frozen dynamic IDs/physical baseline are carried; no fixture is rebuilt.
   for key in ('site_id','subscription_id','customer_id','plan_id','username','application_id','source_application_job','tenant_file','baseline','roundcube_source'):self.context['target'][key]=self.context['source'][key]
   current='TRANSFER';self.transfer_archive();self.complete(current)
   current='AUTHENTICATE';pre=self.remote(current,'recovery');self.context['target']['manifest']=pre['manifest'];self.state.update(format1_authenticated=True,archive_sha256=self.context['target']['archive_sha256'],archive_bytes=self.context['source']['backup_meta']['archive']['bytes'],manifest_sha256=contracts()['binding']['artifact']['current_manifest_sha256']);self.complete(current)
   current='RESTORE';rest=self.remote(current,'recovery');self.context['target']['extracted_entries']=rest['result']['summary']['extracted_entries'];self.state['restore_interval']=rest;self.complete(current)
   current='AFTER_RETURN';self.state['after_return']=self.remote(current,'recovery');self.complete(current)
   current='PLANNED_STOP';self.state['stop_interval']=self.remote(current,'recovery');self.complete(current)
   for phase in ('STOPPED_BEFORE','QUIET','STAGE','GOOSE','RIVER','STOPPED_AFTER','NORMAL_START','STRICT_POST','INITIAL'):
    current=phase;payload=self.remote(phase,'recovery')
    if phase=='STAGE':self.context['target']['migration_stage']=payload['stage']
    if phase in ('GOOSE','RIVER'):self.context['target']['cache_creations']=payload['cache_creations']
    if phase=='STRICT_POST':self.state['strict']=True;self.context['target']['strict_jobs']=payload
    if phase=='INITIAL':self.state['covered']=True;self.state['boots'].append(payload['identity']['boot_id'])
    self.complete(current)
   current='R9_INITIAL';self.r9('initial','recovery');self.complete(current)
   for num in (1,2):
    budget='boot'+str(num);current='REBOOT'+str(num);self.reboot(num,budget);self.complete(current);current='BOOT'+str(num);payload=self.remote(current,budget);need(payload['identity']['boot_id'] not in self.state['boots'],'BOOT');self.state['boots'].append(payload['identity']['boot_id']);self.complete(current);current='R9_BOOT'+str(num);self.r9('boot'+str(num),budget);self.complete(current)
   self.guard('projection');self.state['overall']='PASS';self.state['reason']='UNKNOWN'
  except BaseException as e:
   error=e;self.state['overall']='FAIL';self.state['reason']=e.code if isinstance(e,Refused) else self.state.get('reason','UNKNOWN');self.graph.failed=current
   if current in PHASES:self.state['phases'].append({'phase':current,'status':'FAIL' if self.graph.remote_known else 'UNKNOWN'})
  finally:
   # Classify before cleanup; cleanup cannot promote failed measurement.
   self.state.update(remote_known=self.graph.remote_known,drained=self.graph.drained)
   try:self.cleanup()
   except BaseException:self.state['cleanup']=False;self.state['overall']='FAIL';self.state['reason']='CLEANUP'
   self.state.update(remote_known=self.graph.remote_known,drained=self.graph.drained)
   if self.root.exists():
    self.state['custody']=[{'phase':r['phase'],'sha256':sha(self.logs/r['phase']/'receipt.json')} for r in self.runner.rows] if self.runner else []
    publish(self.root/'private-result.json',self.state,cap=8*1024*1024)
   if self.public.exists():
    publish(self.public/'l1-cleanup.json',{'schema':'nakpanel-l1-cleanup-v1','confirmed':self.state['cleanup'],'remote_work_known':self.graph.remote_known,'host_drained':self.graph.drained,'runner_gc_is_cleanup_proof':False});
    try:
     from projector import project
     projected=project(self.root,{'run_id':self.run_id,'controller_commit':self.a['controller_commit']},self.state)
    except BaseException:self.state['overall']='FAIL';self.state['reason']='PUBLICATION';projected=safe_result(self.state)
    publish(self.public/'l1-result.json',projected)
  if error is not None:raise error
  need(safe_result(self.state)['overall_integration']=='PASS','CLEANUP');return safe_result(self.state)
