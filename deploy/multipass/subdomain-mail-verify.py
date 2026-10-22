#!/usr/bin/env python3
"""Bounded hosted subdomain-mail acceptance; no release operations."""
import hashlib,http.cookiejar,json,os,re,secrets,signal,ssl,subprocess,sys,tarfile,time,traceback
from pathlib import Path
import urllib.error,urllib.parse,urllib.request
SOURCE=Path(__file__).resolve().parents[2]
IMAGE_SHA='8800651811af9a85465ad1d552add729947bb16488dddb4a9b5305a3d97332b2'
def require(value,message):
 if not value:raise ValueError(message)
def hosted_guard():
 require(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted','disposable GitHub hosted runner required')
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write(path,value):
 path=Path(path);temporary=path.with_suffix('.tmp')
 with temporary.open('w') as f:json.dump(value,f,sort_keys=True);f.write('\n')
 temporary.chmod(0o600);temporary.replace(path)
def extract_release(archive,directory):
 with tarfile.open(archive) as stream:
  for member in stream.getmembers():
   p=Path(member.name)
   require(not p.is_absolute() and '..' not in p.parts and (member.isfile() or member.isdir()),'unsafe release member')
  stream.extractall(directory,filter='data')
def check_identity(manifest,commit):
 require(re.fullmatch('[a-f0-9]{40}',commit) and manifest.get('commit')==commit,'candidate source differs')
 require(manifest.get('architecture')=='amd64' and manifest.get('development') is True,'AMD64 development artifact required')
def prepare(directory):
 hosted_guard();directory=Path(directory).resolve()
 meta=json.loads((directory/'bundles.json').read_text())
 require(meta.get('architecture')=='amd64' and meta.get('development') is True,'invalid artifact metadata')
 commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
 require(commit==os.environ['GITHUB_SHA'],'checkout differs from dispatch')
 entry=meta['candidate'];version=(SOURCE/'VERSION').read_text().strip();name='nakpanel-'+version+'-linux-amd64'
 require(entry==dict(version=version,commit=commit,archive='candidate/'+name+'.tar.gz',directory='candidate/'+name),'unexpected artifact identity')
 archive=directory/entry['archive'];key=directory/'test-public.pem'
 extract_release(archive,directory/'candidate');bundle=directory/entry['directory']
 check_identity(json.loads((bundle/'manifest.json').read_text()),commit)
 subprocess.run([sys.executable,str(SOURCE/'deploy/release/verify.py'),'--bundle',str(bundle),'--public-key',str(key),'--version',version,'--architecture','amd64','--allow-development'],check=True)
 image=json.loads((directory/'images.json').read_text())['26.04']
 require(image==dict(url='https://cloud-images.ubuntu.com/releases/resolute/release-20260927/ubuntu-26.04-server-cloudimg-amd64.img',sha256=IMAGE_SHA,serial='20260927',suite='resolute'),'pinned Resolute image differs')
 sums=directory/'images/resolute'
 subprocess.run(['gpgv','--keyring','/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg',str(sums/'SHA256SUMS.gpg'),str(sums/'SHA256SUMS')],check=True)
 require([x.split()[0] for x in (sums/'SHA256SUMS').read_text().splitlines() if x.split()[-1].lstrip('*')=='ubuntu-26.04-server-cloudimg-amd64.img']==[IMAGE_SHA],'signed image hash differs')
 target=directory/'ubuntu-26.04-server-cloudimg-amd64.img'
 subprocess.run(['curl','--fail','--location','--retry','2','--max-time','300','--proto','=https','--proto-redir','=https',image['url'],'-o',str(target)],check=True)
 require(sha(target)==IMAGE_SHA,'image bytes differ')
 evidence=Path(os.environ['RUNNER_TEMP'])/'subdomain-mail-evidence';evidence.mkdir(mode=0o700,exist_ok=True)
 write(evidence/'artifact.json',dict(commit=commit,archive_sha256=sha(archive),manifest_sha256=sha(bundle/'manifest.json'),key_sha256=sha(key),image=image))
 with open(os.environ['GITHUB_ENV'],'a') as f:
  for k,v in dict(NAKPANEL_RELEASE_BUNDLE=bundle,NAKPANEL_RELEASE_PUBLIC_KEY=key,NAKPANEL_RELEASE_VERSION=version,NAKPANEL_RELEASE_ALLOW_DEVELOPMENT='1',NAKPANEL_MULTIPASS_IMAGE_SOURCE=target,NAKPANEL_MULTIPASS_IMAGE_SHA256=IMAGE_SHA).items():
   require('\n' not in str(v),'unsafe export');f.write(k+'='+str(v)+'\n')
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None
class HTTP:
 def __init__(self,base):
  self.base=base;self.cookies=http.cookiejar.CookieJar()
  self.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookies),urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),NoRedirect())
 def request(self,path,fields=None,ok=(200,202,303)):
  headers={'Accept':'application/json','X-Nakpanel-SPA':'true','Referer':self.base+'/'}
  session=next((c.value for c in self.cookies if c.name=='nakpanel_session'),'')
  if fields is not None and session:headers['X-Nakpanel-CSRF']=hashlib.sha256(('nakpanel-csrf-v1:'+session).encode()).hexdigest()
  req=urllib.request.Request(self.base+path,data=urllib.parse.urlencode(fields,doseq=True).encode() if fields is not None else None,headers=headers)
  try:response=self.opener.open(req,timeout=30)
  except urllib.error.HTTPError as e:response=e
  with response:code=response.code;body=response.read(2**20)
  require(code in ok,'HTTP '+path+' returned '+str(code))
  return code,body
 def login(self,email,password):self.request('/login',dict(email=email,password=password))
class Drill:
 def __init__(self):
  hosted_guard()
  run=os.environ['GITHUB_RUN_ID'];attempt=os.environ['GITHUB_RUN_ATTEMPT']
  require(run.isdecimal() and attempt.isdecimal(),'invalid run identity')
  self.token='submail-'+run+'-'+attempt;self.vm='nakpanel-26-04-amd64-'+self.token
  root=Path(os.environ['RUNNER_TEMP']);self.private=root/'subdomain-mail-private';self.private.mkdir(mode=0o700)
  self.evidence=root/'subdomain-mail-evidence';self.evidence.mkdir(mode=0o700,exist_ok=True)
  self.env=dict(os.environ,NAKPANEL_RUN_TOKEN=self.token,NAKPANEL_MULTIPASS_VM=self.vm,NAKPANEL_MULTIPASS_SOURCE_VM=self.vm,NAKPANEL_MULTIPASS_DR_VM=self.vm+'-dr',NAKPANEL_MULTIPASS_IMAGE='26.04',NAKPANEL_MULTIPASS_ARCH='amd64',NAKPANEL_QUALIFICATION_PHP_PROVIDER='sury',NAKPANEL_OWNERSHIP_DIR=str(self.private/'owners'),NAKPANEL_REMOTE_SRC='/var/lib/nakpanel-qualification/'+self.token+'/source')
  self.state=dict(scope='SUBDOMAIN_MAIL_ONLY',status='STARTED',commit=os.environ['GITHUB_SHA'],run_token=self.token,guest=self.vm,release='26.04',architecture='amd64',checks=[],promotion_eligible=False,merged=False,deployed=False)
  self.sequence=0;self.deadline=time.monotonic()+2700
  with open(os.environ['GITHUB_ENV'],'a') as f:
   for k in ('NAKPANEL_RUN_TOKEN','NAKPANEL_MULTIPASS_VM','NAKPANEL_MULTIPASS_SOURCE_VM','NAKPANEL_MULTIPASS_DR_VM','NAKPANEL_OWNERSHIP_DIR','NAKPANEL_REMOTE_SRC'):f.write(k+'='+self.env[k]+'\n')
 def cmd(self,args,data=None,env=None,timeout=180):
  self.sequence+=1
  r=subprocess.run(args,input=data,text=True,capture_output=True,timeout=timeout,env=env or self.env)
  log=self.private/('command-%03d.log'%self.sequence);log.write_text(r.stdout+r.stderr);log.chmod(0o600)
  if r.returncode:
   excerpt=(r.stdout[-4000:]+'\n'+r.stderr[-4000:]).replace('NakpanelAdmin!2026','[synthetic-secret]')
   excerpt=re.sub(r'Np![A-Za-z0-9_-]+','[synthetic-secret]',excerpt)
   (self.evidence/'failure-diagnostic.log').write_text(excerpt)
  require(r.returncode==0,'command failed: '+Path(args[0]).name+' exit='+str(r.returncode)+' private-log='+log.name)
  return r.stdout
 def shell(self,function,*args):return self.cmd(['bash','-c','set -euo pipefail; source "$1"; shift; "$@"','_',str(SOURCE/'deploy/multipass/common.sh'),function,*args])
 def guest(self,*args,data=None):return self.cmd(['multipass','exec',self.vm,'--',*args],data=data)
 def db(self,query):return self.guest('sudo','-u','postgres','psql','-XqAt','-d','nakpanel','-v','ON_ERROR_STOP=1','-c',query).strip()
 def stage(self,name):
  remaining=int(self.deadline-time.monotonic());require(remaining>0,'overall acceptance budget exhausted')
  signal.alarm(min(2400 if name=='fresh-signed-install' else 600,remaining))
  self.state.update(stage=name,updated_at=time.time());write(self.evidence/'result.json',self.state);print('subdomain-mail: '+name,flush=True)
 def passed(self,name):
  self.state['checks'].append(name);write(self.evidence/'result.json',self.state)
 def wait(self,query,want,seconds=240):
  deadline=time.monotonic()+seconds
  while True:
   actual=self.db(query)
   if actual==str(want):return
   require(time.monotonic()<deadline,'convergence timed out: expected '+str(want)+' observed '+actual[:120]);time.sleep(2)
 def post(self,path,**fields):return self.http.request(path,fields)
 def mail(self,site,sub,enabled=True,domain_id=0):
  self.post('/subscriptions/'+str(sub)+'/mail-domains',resource_id=domain_id,site_id=site,enabled='true' if enabled else 'false',dkim='true',dmarc_policy='none')
  return int(self.db('SELECT id FROM mail_domains WHERE site_id='+str(site)))
 def account(self,domain,sub,address):
  password='Np!'+secrets.token_urlsafe(24)
  self.post('/subscriptions/'+str(sub)+'/mailboxes',mail_domain_id=domain,local_part='preserve',password=password,quota_mb=32,enabled='true')
  self.post('/subscriptions/'+str(sub)+'/mail-aliases',mail_domain_id=domain,local_part='preserve-alias',destinations='preserve@'+address)
  return dict(address='preserve@'+address,password=password,domain=address)
 def ready(self,domain,enabled=True):
  self.wait("SELECT convergence_status||':'||effective_enabled FROM mail_domains WHERE id="+str(domain),'in_sync:'+str(enabled).lower())
 def protocol(self,mode,accounts,expected=None):
  out=self.guest('sudo','python3',self.env['NAKPANEL_REMOTE_SRC']+'/deploy/multipass/subdomain-mail-protocol.py',data=json.dumps(dict(token=self.token,mode=mode,accounts=accounts,expected=expected)))
  return json.loads(out)
 def canaries(self,semantic=False):
  ids=','.join(map(str,(self.parent,self.sibling)))
  return self.db("SELECT md5(jsonb_build_array((SELECT jsonb_agg(to_jsonb(m) ORDER BY m.id) FROM mailboxes m JOIN mail_domains d ON d.id=m.mail_domain_id WHERE d.site_id IN ("+ids+")),(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id) FROM mail_aliases a JOIN mail_domains d ON d.id=a.mail_domain_id WHERE d.site_id IN ("+ids+")),(SELECT jsonb_agg("+("jsonb_build_array(r.owner_site_id,r.host,r.record_type,r.value,r.priority,r.ttl) ORDER BY r.host,r.record_type,r.value" if semantic else "to_jsonb(r) ORDER BY r.id")+") FROM dns_records r WHERE r.owner_site_id IN ("+ids+")))::text)")
 def run(self):
  self.stage('fresh-signed-install')
  self.shell('init_qualification_run')
  self.cmd(['bash',str(SOURCE/'deploy/multipass/current-install-verify.sh')],timeout=2400)
  self.shell('assert_current_vm_identity');self.shell('assert_qualification_installed_release')
  self.ip=self.shell('vm_ip').strip();self.http=HTTP('https://'+self.ip+':7443');self.http.login('admin@nakpanel.test','NakpanelAdmin!2026')
  actual=self.guest('bash','-c','. /etc/os-release; printf "%s:%s:%s" "$ID" "$VERSION_ID" "$VERSION_CODENAME"').strip()
  require(actual=='ubuntu:26.04:resolute','unsupported actual guest OS')
  php={}
  for minor in ('8.3','8.4','8.5'):
   version=self.guest('sudo','/usr/bin/php'+minor,'-r','echo PHP_VERSION;').strip()
   require(version.startswith(minor+'.'),'missing PHP '+minor);php[minor]=version
  self.state.update(actual_os=actual,php=php)
  self.guest('systemctl','is-active','php8.3-fpm','php8.4-fpm','php8.5-fpm')
  self.stage('owned-fixtures')
  self.parent=int(self.db("SELECT id FROM sites WHERE domain='current-bootstrap.test'"))
  self.sub=int(self.db('SELECT subscription_id FROM sites WHERE id='+str(self.parent)))
  self.customer=int(self.db('SELECT customer_id FROM subscriptions WHERE id='+str(self.sub)))
  self.plan=int(self.db('SELECT plan_id FROM subscriptions WHERE id='+str(self.sub)))
  self.post('/subscriptions/'+str(self.sub)+'/policy',policy_patch=json.dumps({'resources':{'max_mail_aliases':4}}))
  for label in ('shop','news'):self.post('/sites/'+str(self.parent)+'/subdomains',label=label,issue_certificate='false')
  self.child=int(self.db("SELECT id FROM sites WHERE domain='shop.current-bootstrap.test'"))
  self.sibling=int(self.db("SELECT id FROM sites WHERE domain='news.current-bootstrap.test'"))
  for site in (self.child,self.sibling):self.wait('SELECT status FROM sites WHERE id='+str(site),'active')
  foreign_email=self.token+'@nakpanel.test';foreign_password='Np!'+secrets.token_urlsafe(24)
  self.post('/customers',customer_email=foreign_email,customer_name=self.token,enable_login='true',password=foreign_password)
  foreign_customer=int(self.db("SELECT id FROM customers WHERE email='"+foreign_email+"'"))
  self.post('/subscriptions',customer_mode='existing',customer_id=foreign_customer,plan_id=self.plan,subscription_name=self.token)
  foreign_sub=int(self.db('SELECT id FROM subscriptions WHERE customer_id='+str(foreign_customer)))
  self.post('/subscriptions/'+str(foreign_sub)+'/policy',policy_patch=json.dumps({'resources':{'max_mail_aliases':4}}))
  self.post('/sites',subscription_id=foreign_sub,domain='foreign-submail.test',php_version='8.4',issue_certificate='false')
  foreign_site=int(self.db("SELECT id FROM sites WHERE domain='foreign-submail.test'"));self.wait('SELECT status FROM sites WHERE id='+str(foreign_site),'active')
  self.accounts=[];self.domains={}
  for site,sub,domain in ((self.parent,self.sub,'current-bootstrap.test'),(self.sibling,self.sub,'news.current-bootstrap.test'),(foreign_site,foreign_sub,'foreign-submail.test')):
   mid=self.mail(site,sub);self.domains[site]=mid;self.accounts.append(self.account(mid,sub,domain));self.ready(mid)
  self.domains[self.child]=self.mail(self.child,self.sub);self.ready(self.domains[self.child])
  self.stage('child-browser-mailbox-alias')
  admin_password=self.private/'admin-password';admin_password.write_text('NakpanelAdmin!2026');admin_password.chmod(0o600)
  state=self.private/'child-mail.json'
  env=dict(self.env,NAKPANEL_QA_URL=self.http.base,NAKPANEL_QA_SITE_ID=str(self.child),NAKPANEL_QA_GUEST_IP=self.ip,NAKPANEL_QA_IGNORE_HTTPS_ERRORS='1',NAKPANEL_QA_SUPPORT_CUSTOMER_ID=str(self.customer),NAKPANEL_QA_MAIL_STATE=str(state),NAKPANEL_QA_EMAIL='admin@nakpanel.test',NAKPANEL_QA_PASSWORD_FILE=str(admin_password),NAKPANEL_QA_STAGE='prepare')
  self.cmd(['node',str(SOURCE/'deploy/multipass/mail-workspace-live-verify.cjs')],env=env,timeout=300)
  child=json.loads(state.read_text());require(child['domain']=='shop.current-bootstrap.test','browser mailbox lost child identity')
  self.child_account={k:child[k] for k in ('address','password','domain')};self.accounts.append(self.child_account);self.ready(self.domains[self.child])
  self.cmd(['multipass','exec',self.vm,'--','sudo','env','NAKPANEL_QA_MAIL_CA_FILE=/etc/stalwart/tls/cert.pem','bash','-c','export NAKPANEL_QA_MAIL_HOST="$(hostname -f)"; exec python3 "$1"','_',self.env['NAKPANEL_REMOTE_SRC']+'/deploy/multipass/mail-workspace-protocol-verify.py'],data=json.dumps(child))
  self.expected=self.protocol('seed',self.accounts);before=self.canaries()
  self.state['message_canaries']=[dict(address=a['address'],**p) for a,p in zip(self.accounts,self.expected)]
  self.state['initial_parent_sibling_fingerprint']=before
  self.passed('child browser CRUD, rotated password denial, SMTP TLS/STARTTLS, alias delivery and IMAP retrieval')
  self.stage('roundcube-child')
  self.post('/webmail',domain=child['domain']);self.wait("SELECT status FROM webmail_hosts WHERE hostname='webmail."+child['domain']+"'",'active')
  password=self.private/'roundcube-password';password.write_text(child['password']);password.chmod(0o600)
  ca=self.private/'mail-ca.pem';ca.write_text(self.guest('sudo','cat','/etc/stalwart/tls/cert.pem'))
  self.cmd([sys.executable,str(SOURCE/'deploy/multipass/roundcube-send-read.py'),'--base-url','http://'+self.ip,'--host','webmail.'+child['domain'],'--mailbox',child['address'],'--password-file',str(password),'--imap-ca-file',str(ca),'--receipt-dir',str(self.private/'roundcube')],timeout=180)
  self.passed('child Roundcube login, compose, local delivery and rendered message')
  self.stage('quotas-and-foreign-requests')
  mid=self.domains[self.child];prefix='/subscriptions/'+str(self.sub)
  extra=dict(mail_domain_id=mid,local_part='last-slot',password='Np!'+secrets.token_urlsafe(24),quota_mb=128,enabled='true')
  self.http.request(prefix+'/mailboxes',extra)
  require(self.db('SELECT quota_mb FROM mailboxes WHERE mail_domain_id='+str(mid)+" AND local_part='last-slot'")=='64','mailbox storage cap bypassed')
  self.http.request(prefix+'/mailboxes',dict(extra,local_part='over-limit'),ok=(400,409,422))
  require(self.db('SELECT count(*) FROM mailboxes m JOIN mail_domains d ON d.id=m.mail_domain_id WHERE d.subscription_id='+str(self.sub))=='4','shared mailbox quota bypassed')
  alias=dict(mail_domain_id=mid,local_part='last-slot',destinations=child['address'])
  self.http.request(prefix+'/mail-aliases',alias)
  self.http.request(prefix+'/mail-aliases',dict(alias,local_part='over-limit'),ok=(400,409,422))
  self.http.request(prefix+'/mailboxes',dict(extra,mail_domain_id=self.domains[foreign_site],local_part='forbidden'),ok=(400,403,404))
  isolated=HTTP(self.http.base);isolated.login(foreign_email,foreign_password)
  isolated.request('/sites/'+str(self.child)+'?tab=mail',ok=(404,))
  isolated.request(prefix+'/mailboxes',dict(extra,local_part='forbidden'),ok=(400,403,404))
  require(self.canaries()==before,'quota/foreign operation mutated parent/sibling resources')
  self.passed('shared mailbox/alias counts, finite storage cap and forbidden foreign read/write')
  self.stage('disable-suspend-reactivate')
  self.mail(self.child,self.sub,False,mid);self.ready(mid,False)
  self.protocol('denied',[self.child_account]);self.protocol('verify',self.accounts[:3],self.expected[:3])
  self.mail(self.child,self.sub,True,mid);self.ready(mid)
  self.protocol('verify',self.accounts,self.expected)
  require(self.canaries()==before,'child mail toggle mutated parent/sibling resources')
  before_semantic=self.canaries(True)
  subscription_name=self.db('SELECT name FROM subscriptions WHERE id='+str(self.sub))
  for status in ('suspended','active'):
   self.post(prefix+'/status',customer_id=self.customer,plan_id=self.plan,subscription_name=subscription_name,status=status,sync_mode='synced')
   for site in (self.parent,self.child,self.sibling):self.ready(self.domains[site],status=='active')
   if status=='suspended':
    self.protocol('denied',[self.accounts[0],self.accounts[1],self.child_account]);self.protocol('verify',[self.accounts[2]],[self.expected[2]])
   else:self.protocol('verify',self.accounts,self.expected)
  require(self.canaries(True)==before_semantic,'lifecycle failed to restore parent/sibling resource intent')
  before=self.canaries()
  self.passed('child disable/re-enable and subscription suspension/reactivation preserve actual messages and parent/sibling resources')
  self.stage('reviewed-child-removal')
  code,body=self.http.request('/sites/'+str(self.child)+'/removal/preview');preview=json.loads(body)
  require(preview['allowed'] is True and 'mail' in body.decode().lower(),'mail removal preview missing')
  removal=dict(request_id=preview['request_id'],approval=preview['approval'],confirm_domain=child['domain'])
  self.http.request('/sites/'+str(self.child)+'/remove',removal,ok=(400,409,422))
  require(self.db('SELECT removal_state FROM sites WHERE id='+str(self.child))=='none','unconfirmed child deletion mutated state')
  code,body=self.http.request('/sites/'+str(self.child)+'/remove',dict(removal,acknowledge_permanent='true',include_children='true'))
  operation=json.loads(body)['operation_id'];require(type(operation) is int and operation>0,'removal operation missing')
  deadline=time.monotonic()+360
  while True:
   code,body=self.http.request('/site-removals/'+str(operation)+'/status');result=json.loads(body)
   if result['state']=='completed':break
   require(result['state']!='failed' and time.monotonic()<deadline,'reviewed child cleanup did not complete');time.sleep(2)
  require(self.canaries()==before,'child removal mutated parent/sibling resources')
  self.state['final_parent_sibling_fingerprint']=self.canaries()
  self.protocol('verify',self.accounts[:3],self.expected[:3])
  self.passed('confirmed child cleanup only; parent/sibling mailbox, alias, DNS and message canaries unchanged')
  self.shell('assert_current_vm_identity');self.shell('assert_qualification_installed_release')
  self.guest('systemctl','is-active','php8.3-fpm','php8.4-fpm','php8.5-fpm')
  self.state['status']='PASS';self.stage('complete')
def main():
 hosted_guard()
 if len(sys.argv)==3 and sys.argv[1]=='prepare':prepare(sys.argv[2]);return
 require(sys.argv[1:]==['run'],'expected prepare DIRECTORY or run')
 drill=Drill()
 def alarm(*args):raise TimeoutError('acceptance gate budget exceeded')
 signal.signal(signal.SIGALRM,alarm);signal.alarm(2700)
 try:drill.run()
 except BaseException as e:
  drill.state.update(status='FAIL',error_type=type(e).__name__,error=str(e) if isinstance(e,(ValueError,TimeoutError)) else 'private diagnostics retained',failure_frames=[dict(function=f.name,line=f.lineno) for f in traceback.extract_tb(e.__traceback__) if Path(f.filename)==Path(__file__)])
  write(drill.evidence/'result.json',drill.state);print(json.dumps(drill.state),flush=True);raise SystemExit(1) from None
 finally:signal.alarm(0)
if __name__=='__main__':main()
