#!/usr/bin/env python3
"""Current-version Operations acceptance on one owned disposable Resolute guest."""
import hashlib,importlib.util,json,os,re,secrets,shutil,signal,subprocess,sys,time,traceback
from pathlib import Path
import urllib.error,urllib.request,http.client

SOURCE=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('current_hosted',Path(__file__).with_name('subdomain-mail-verify.py'))
shared=importlib.util.module_from_spec(spec);spec.loader.exec_module(shared)
require,write,HTTP=shared.require,shared.write,shared.HTTP

def json_request(http,path,body=None,ok=(200,202,204)):
 headers={'Accept':'application/json','X-Nakpanel-SPA':'true','Referer':http.base+'/'}
 data=None
 if body is not None:
  session=next(c.value for c in http.cookies if c.name=='nakpanel_session')
  headers.update({'Content-Type':'application/json','X-Nakpanel-CSRF':hashlib.sha256(('nakpanel-csrf-v1:'+session).encode()).hexdigest()})
  data=json.dumps(body).encode()
 try:response=http.opener.open(urllib.request.Request(http.base+path,data=data,headers=headers),timeout=30)
 except urllib.error.HTTPError as error:response=error
 with response:code=response.code;raw=response.read(2**20)
 require(code in ok,'operations API '+path+' returned '+str(code))
 return json.loads(raw) if raw else None

def require_php(version,loaded,fpm,minor,required):
 require(version.startswith(minor+'.'),'missing required PHP '+minor)
 require(set(x.casefold() for x in required)<=set(x.casefold() for x in loaded),'required CLI extensions missing for '+minor)
 require(all(re.search(r'^'+re.escape(x)+r'\s*$',fpm,re.I|re.M) for x in required),'required FPM extensions missing for '+minor)

def prepare(directory):
 # Reuse the current signed-candidate/image verifier, not the mail scenario.
 shared.prepare(directory)
 evidence=Path(os.environ['RUNNER_TEMP'])/'operations-evidence';evidence.mkdir(mode=0o700,exist_ok=True)
 shutil.copy2(evidence.parent/'subdomain-mail-evidence/artifact.json',evidence/'artifact.json')

class Drill(shared.Drill):
 def __init__(self):
  shared.hosted_guard();run=os.environ['GITHUB_RUN_ID'];attempt=os.environ['GITHUB_RUN_ATTEMPT']
  require(run.isdecimal() and attempt.isdecimal(),'invalid run identity')
  self.token='operations-'+run+'-'+attempt;self.vm='nakpanel-26-04-amd64-'+self.token
  root=Path(os.environ['RUNNER_TEMP']);self.private=root/'operations-private';self.private.mkdir(mode=0o700)
  self.evidence=root/'operations-evidence';self.evidence.mkdir(mode=0o700,exist_ok=True)
  self.env=dict(os.environ,NAKPANEL_RUN_TOKEN=self.token,NAKPANEL_MULTIPASS_VM=self.vm,NAKPANEL_MULTIPASS_SOURCE_VM=self.vm,NAKPANEL_MULTIPASS_DR_VM=self.vm+'-dr',NAKPANEL_MULTIPASS_IMAGE='26.04',NAKPANEL_MULTIPASS_ARCH='amd64',NAKPANEL_QUALIFICATION_PHP_PROVIDER='sury',NAKPANEL_QUALIFICATION_APT_NO_TRANSLATIONS='1',NAKPANEL_OWNERSHIP_DIR=str(self.private/'owners'),NAKPANEL_REMOTE_SRC='/var/lib/nakpanel-qualification/'+self.token+'/source')
  self.state=dict(scope='OPERATIONS_ONLY',status='STARTED',commit=os.environ['GITHUB_SHA'],run_token=self.token,guest=self.vm,release='26.04',architecture='amd64',checks=[],promotion_eligible=False,merged=False,deployed=False)
  self.sequence=0;self.deadline=time.monotonic()+2700
  with open(os.environ['GITHUB_ENV'],'a') as stream:
   for key in ('NAKPANEL_RUN_TOKEN','NAKPANEL_MULTIPASS_VM','NAKPANEL_MULTIPASS_SOURCE_VM','NAKPANEL_MULTIPASS_DR_VM','NAKPANEL_OWNERSHIP_DIR','NAKPANEL_REMOTE_SRC'):stream.write(key+'='+self.env[key]+'\n')
 def stage(self,name):
  remaining=int(self.deadline-time.monotonic());require(remaining>0,'overall operations budget exhausted')
  signal.alarm(min(2400 if name=='fresh-signed-install' else 600,remaining))
  self.state.update(stage=name,updated_at=time.time());write(self.evidence/'result.json',self.state);print('operations: '+name,flush=True)
 def api(self,path,body=None,ok=(200,202,204),actor=None):return json_request(actor or self.http,path,body,ok)
 def until(self,read,predicate,label,seconds=180):
  end=time.monotonic()+seconds
  while True:
   try:value=read()
   except (urllib.error.URLError,ConnectionError,TimeoutError,http.client.RemoteDisconnected):
    require(time.monotonic()<end,'timed out reconnecting: '+label);time.sleep(2);continue
   if predicate(value):return value
   require(time.monotonic()<end,'timed out: '+label);time.sleep(2)
 def operation_for_run(self,run):return int(self.db("SELECT a.operation_id FROM operation_attempts a JOIN river_job j ON j.id=a.river_job_id WHERE j.kind='run_scheduled_task' AND j.args->>'run_id'='"+str(run)+"' ORDER BY a.id DESC LIMIT 1"))
 def create_task(self,name,command):
  self.post('/subscriptions/'+str(self.sub)+'/scheduled-tasks',site_id=self.site,name=name,schedule='0 0 1 1 *',command=command,timeout_seconds=30,enabled='true',kind='command',timezone='UTC')
  return int(self.db("SELECT id FROM scheduled_tasks WHERE subscription_id="+str(self.sub)+" AND name='"+name+"'"))
 def run_task(self,task,want='failed'):
  self.post('/subscriptions/'+str(self.sub)+'/scheduled-tasks/'+str(task)+'/run')
  run=int(self.db('SELECT max(id) FROM scheduled_task_runs WHERE task_id='+str(task)))
  self.wait('SELECT status FROM scheduled_task_runs WHERE id='+str(run),want,90)
  op=self.operation_for_run(run);detail=self.until(lambda:self.api('/api/workspace/operations/tasks/'+str(op)),lambda d:d['operation']['state'] in ('failed','succeeded','cancelled'),'durable task result')
  require(detail['operation']['state']==('failed' if want in ('failed','timed_out') else 'succeeded'),'queue completion obscured command outcome')
  return op
 def bootstrap(self):
  self.stage('fresh-signed-install');self.shell('init_qualification_run')
  self.cmd(['bash',str(SOURCE/'deploy/multipass/current-install-verify.sh')],timeout=2400)
  self.shell('assert_current_vm_identity');self.shell('assert_qualification_installed_release')
  self.ip=self.shell('vm_ip').strip();self.http=HTTP('https://'+self.ip+':7443');self.http.login('admin@nakpanel.test','NakpanelAdmin!2026')
  actual=self.guest('bash','-c','. /etc/os-release; printf "%s:%s:%s" "$ID" "$VERSION_ID" "$VERSION_CODENAME"').strip();require(actual=='ubuntu:26.04:resolute','unsupported guest OS')
  source=(SOURCE/'internal/agent/ops/php_capabilities.go').read_text();required=re.findall(r'"([^"]+)"',re.search(r'var requiredPHPExtensions = \[\]string\{(.*?)\}',source,re.S).group(1))
  versions={}
  for minor in ('8.3','8.4','8.5'):
   version=self.guest('sudo','/usr/bin/php'+minor,'-r','echo PHP_VERSION;').strip()
   loaded=json.loads(self.guest('sudo','/usr/bin/php'+minor,'-r','echo json_encode(get_loaded_extensions());'))
   fpm=self.guest('sudo','/usr/sbin/php-fpm'+minor,'-i');require_php(version,loaded,fpm,minor,required);versions[minor]=version
  self.guest('systemctl','is-active','php8.3-fpm','php8.4-fpm','php8.5-fpm')
  self.state.update(actual_os=actual,php=versions,required_extensions=required);self.passed('signed current installation, Ubuntu 26.04 and all PHP 8.3/8.4/8.5 CLI/FPM extensions')
 def fixtures(self):
  self.stage('owned-fixtures')
  self.site=int(self.db("SELECT id FROM sites WHERE domain='current-bootstrap.test'"));self.sub=int(self.db('SELECT subscription_id FROM sites WHERE id='+str(self.site)));self.customer=int(self.db('SELECT customer_id FROM subscriptions WHERE id='+str(self.sub)))
  self.post('/subscriptions/'+str(self.sub)+'/policy',policy_patch=json.dumps({'permissions':{'scheduled_tasks':True},'resources':{'max_scheduled_tasks':6},'backups':{'enabled':True,'schedule':'manual'}}))
  self.wait('SELECT status FROM sites WHERE id='+str(self.site),'active')
  docroot=self.db('SELECT document_root FROM sites WHERE id='+str(self.site));user=self.db('SELECT username FROM sites WHERE id='+str(self.site));self.canary=docroot+'/operations-canary.txt'
  self.guest('sudo','-u',user,'python3','-c','import sys;open(sys.argv[1],"x").write(sys.argv[2])',self.canary,self.token)
  self.canary_hash=self.guest('sudo','sha256sum',self.canary).split()[0]
  self.post('/backups',subscription_id=self.sub,domain='current-bootstrap.test')
  baseline=int(self.db('SELECT max(id) FROM backups WHERE site_id='+str(self.site)))
  self.wait('SELECT status FROM backups WHERE id='+str(baseline),'active',180)
  self.archives=json.loads(self.db("SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'path',archive_path,'checksum',checksum_sha256)),'[]'::jsonb) FROM backups WHERE status='active'"))
  require(len(self.archives)>0,'baseline archive is required for preservation checks')
  for archive in self.archives:require(self.guest('sudo','sha256sum',archive['path']).split()[0]==archive['checksum'],'initial archive checksum differs')
  self.second_email=self.token+'-admin@nakpanel.test'
  self.second_id=int(self.db("INSERT INTO users(email,password_hash,role) SELECT '"+self.second_email+"',password_hash,'admin' FROM users WHERE email='admin@nakpanel.test' RETURNING id"))
  self.second=HTTP(self.http.base);self.second.login(self.second_email,'NakpanelAdmin!2026')
  self.foreign_email=self.token+'-client@nakpanel.test';self.foreign_password='Np!'+secrets.token_urlsafe(24)
  self.post('/customers',customer_email=self.foreign_email,customer_name=self.token,enable_login='true',password=self.foreign_password)
  self.foreign=HTTP(self.http.base);self.foreign.login(self.foreign_email,self.foreign_password)
  self.a=self.create_task('operations-failure-a','/bin/false');self.b=self.create_task('operations-failure-b','/bin/false');self.success_task=self.create_task('operations-success','/bin/true')
 def failures(self):
  self.stage('actual-task-failures-and-dedupe')
  a=self.run_task(self.a);self.run_task(self.a);self.run_task(self.b)
  self.wait("SELECT count(*) FROM issues WHERE resource_kind='site' AND resource_id="+str(self.site)+" AND kind='operation_failed' AND condition IN ('run_scheduled_task:task:"+str(self.a)+"','run_scheduled_task:task:"+str(self.b)+"')",2)
  self.issue_a=int(self.db("SELECT id FROM issues WHERE resource_kind='site' AND resource_id="+str(self.site)+" AND condition='run_scheduled_task:task:"+str(self.a)+"'"))
  self.wait('SELECT occurrences FROM issues WHERE id='+str(self.issue_a),2)
  self.until(lambda:self.db('SELECT count(*) FROM notifications WHERE issue_id='+str(self.issue_a)),lambda v:v=='1','one inbox entry per incident')
  self.notification=int(self.db('SELECT id FROM notifications WHERE issue_id='+str(self.issue_a)))
  for path in ('issues/'+str(self.issue_a),'tasks/'+str(a)):
   self.api('/api/workspace/operations/'+path,ok=(404,),actor=self.foreign)
  self.passed('actual Run now workers, semantic failure, repeated incident dedupe, independent task identity and foreign detail denial')
 def backup_failure(self):
  self.stage('backup-failure-and-unverified-recovery')
  self.guest('sudo','systemctl','stop','nakpanel-agent')
  try:
   self.post('/backups',subscription_id=self.sub,domain='current-bootstrap.test')
   self.backup=int(self.db('SELECT max(id) FROM backups WHERE site_id='+str(self.site)))
   job=int(self.db("SELECT id FROM river_job WHERE kind='create_backup' AND args->>'backup_id'='"+str(self.backup)+"' ORDER BY id DESC LIMIT 1"))
   # Bound only this fault-injected job's retry policy. Never fabricate terminal state.
   self.db('UPDATE river_job SET max_attempts=1 WHERE id='+str(job))
   self.until(lambda:self.db('SELECT state FROM river_job WHERE id='+str(job)),lambda v:v in ('retryable','discarded'),'actual agent-disconnection failure')
   if self.db('SELECT state FROM river_job WHERE id='+str(job))=='retryable':self.db("UPDATE river_job SET state='available',scheduled_at=now() WHERE id="+str(job))
   self.wait('SELECT state FROM river_job WHERE id='+str(job),'discarded',120)
   self.backup_issue=int(self.db("SELECT id FROM issues WHERE resource_kind='site' AND resource_id="+str(self.site)+" AND kind='backup' AND resolved_at IS NULL"))
   self.api('/api/workspace/operations/issues/'+str(self.backup_issue)+'/verify',{})
   self.until(lambda:self.api('/api/workspace/operations/issues/'+str(self.backup_issue)),lambda i:i.get('last_check_at') and i['last_check_status']!='checking','failed independent verification')
   require(not self.api('/api/workspace/operations/issues/'+str(self.backup_issue)).get('resolved_at'),'failed verification resolved the issue')
  finally:self.guest('sudo','systemctl','start','nakpanel-agent')
  self.until(lambda:self.api('/api/workspace/operations/issues/'+str(self.backup_issue)+'/preflight'),lambda p:p.get('allowed'),'recovery preflight after agent restart')
  self.passed('real disconnected-agent backup failure and unsuccessful independent check leave the issue open')
 def browser(self):
  self.stage('real-browser-notifications-tasks-settings-and-recovery')
  private=self.private/'browser-input.json';write(private,dict(base=self.http.base,ip=self.ip,email='admin@nakpanel.test',password='NakpanelAdmin!2026',site=self.site,subscription=self.sub,customer=self.customer,issue=self.issue_a,notification=self.notification,backup_issue=self.backup_issue,success_task=self.success_task))
  env=dict(self.env,NAKPANEL_OPERATIONS_INPUT=str(private),NAKPANEL_OPERATIONS_EVIDENCE=str(self.evidence))
  self.cmd(['node',str(SOURCE/'deploy/multipass/operations-browser-verify.cjs')],env=env,timeout=540)
  browser=json.loads((self.evidence/'browser.json').read_text());require(browser.get('passed') is True,'real browser acceptance failed')
  receipt=self.db('SELECT count(*) FROM notification_receipts WHERE notification_id='+str(self.notification)+' AND user_id=(SELECT id FROM users WHERE email=\'admin@nakpanel.test\')')
  require(receipt=='1','opened notification did not record its personal receipt')
  require(self.db('SELECT count(*) FROM notification_receipts WHERE notification_id='+str(self.notification)+' AND user_id='+str(self.second_id))=='0','opening shared another viewer receipt')
  original=self.api('/api/workspace/operations/issues/'+str(self.issue_a));require(not original.get('acknowledged_at') and not original.get('resolved_at'),'opening acknowledged or resolved the issue')
  self.passed('real desktop/mobile UI, personal read-on-open, direct support settings links, twelve offline results, navigation and typed backup recovery with original attempts retained')
 def delivery(self):
  self.stage('bounded-loopback-smtp-failure-and-recovery')
  root=self.env['NAKPANEL_REMOTE_SRC'];state='/var/lib/nakpanel-qualification/'+self.token+'/smtp'
  self.guest('sudo','install','-d','-m','0700',state)
  self.guest('sudo','python3','-c','import sys;open(sys.argv[1],"x").write("reject")',state+'/mode')
  self.guest('sudo','systemd-run','--unit=nakpanel-operations-smtp','--collect','/usr/bin/python3',root+'/deploy/multipass/operations-smtp-capture.py','--state-dir',state)
  self.guest('sudo','bash','-c','set -e; install -d /etc/systemd/system/nakpanel.service.d; test ! -e /etc/systemd/system/nakpanel.service.d/operations.conf; printf "%s\\n" "[Service]" "Environment=NAKPANEL_SMTP_HOST=127.0.0.1" "Environment=NAKPANEL_SMTP_PORT=2525" "Environment=NAKPANEL_SMTP_TLS_MODE=none" "Environment=NAKPANEL_SMTP_FROM=panel@operations.test" >/etc/systemd/system/nakpanel.service.d/operations.conf; systemctl daemon-reload; systemctl restart nakpanel')
  self.until(lambda:self.http.request('/healthz')[0],lambda code:code==200,'panel after SMTP configuration')
  self.api('/api/workspace/operations/delivery-policy',{'enabled':True});self.api('/api/workspace/operations/preferences',{'email_mode':'immediate'})
  task=self.create_task('operations-smtp-failure','/bin/false');self.run_task(task)
  self.until(lambda:self.db('SELECT count(*) FROM notification_email_batches'),lambda n:int(n)>0,'email batch')
  batch=int(self.db('SELECT min(id) FROM notification_email_batches'))
  for count in range(1,9):
   observed=int(self.db('SELECT attempts FROM notification_email_batches WHERE id='+str(batch)))
   if observed<count:
    self.db('UPDATE notification_email_batches SET next_attempt_at=now() WHERE id='+str(batch))
    self.db("INSERT INTO river_job(kind,args,queue,max_attempts) VALUES('deliver_notifications','{}','system',1)")
   self.until(lambda:self.db('SELECT attempts FROM notification_email_batches WHERE id='+str(batch)),lambda n:int(n)>=count,'bounded SMTP attempt '+str(count),90)
  self.db('UPDATE notification_email_batches SET next_attempt_at=now() WHERE id='+str(batch));self.db("INSERT INTO river_job(kind,args,queue,max_attempts) VALUES('deliver_notifications','{}','system',1)")
  time.sleep(3);require(self.db('SELECT attempts FROM notification_email_batches WHERE id='+str(batch))=='8','SMTP attempts exceeded the bound')
  require(self.db('SELECT count(*) FROM notification_email_batches')=='1','delivery failure generated recursive mail')
  delivery=int(self.db("SELECT id FROM issues WHERE kind='notification_delivery' AND resolved_at IS NULL ORDER BY id DESC LIMIT 1"));self.api('/api/workspace/operations/issues/'+str(delivery),ok=(404,),actor=self.second)
  self.guest('sudo','python3','-c','import sys;open(sys.argv[1],"w").write("accept")',state+'/mode')
  task2=self.create_task('operations-smtp-accept','/bin/false');self.run_task(task2)
  self.until(lambda:self.db('SELECT count(*) FROM notification_email_batches'),lambda n:int(n)==2,'new acceptance batch')
  self.db("INSERT INTO river_job(kind,args,queue,max_attempts) VALUES('deliver_notifications','{}','system',1)")
  self.until(lambda:self.db("SELECT count(*) FROM notification_email_batches WHERE status='accepted'"),lambda n:n=='1','SMTP DATA acceptance despite QUIT disconnect',90)
  self.wait('SELECT (resolved_at IS NOT NULL)::text FROM issues WHERE id='+str(delivery),'true',60)
  require(self.db("SELECT count(*) FROM notification_email_items x JOIN notifications n ON n.id=x.notification_id JOIN issues i ON i.id=n.issue_id WHERE i.kind='notification_delivery'")=='0','delivery issue escaped recursion suppression')
  receipts=[json.loads(line) for line in self.guest('sudo','cat',state+'/receipts.jsonl').splitlines()]
  require(sum(r['accepted'] for r in receipts)==1 and all('admin@nakpanel.test' in r['recipient'] for r in receipts),'SMTP fixture received an unexpected acceptance or audience')
  write(self.evidence/'smtp.json',dict(failed_attempt_bound=8,accepted_after_quit_disconnect=1,external_mail_sent=False,receipts=receipts))
  require('Accepted by SMTP' in self.api('/api/workspace/operations/preferences')['delivery_health'],'delivery health mislabeled acceptance')
  require(not self.api('/api/workspace/operations/issues/'+str(self.issue_a)).get('resolved_at'),'SMTP acceptance resolved an unrelated task failure')
  self.passed('eight bounded SMTP failures, no mail loop, private delivery issue and SMTP-only recovery after DATA acceptance/QUIT disconnect')
 def preserve(self):
  self.stage('preservation-and-final-readiness')
  require(self.guest('sudo','sha256sum',self.canary).split()[0]==self.canary_hash,'website canary changed')
  for archive in self.archives:require(self.guest('sudo','sha256sum',archive['path']).split()[0]==archive['checksum'],'existing archive changed')
  require(self.guest('sudo','mariadb','--batch','--skip-column-names','np_current_bootstrap','-e','SELECT value FROM nakpanel_qualification_canary WHERE id=1').strip()=='current-bootstrap-mariadb-canary','database canary changed')
  self.guest('systemctl','is-active','nakpanel','nakpanel-agent','php8.3-fpm','php8.4-fpm','php8.5-fpm')
  self.passed('original website/database/archive canaries preserved; panel, agent and three PHP FPM services active')
 def run(self):
  self.bootstrap();self.fixtures();self.failures();self.backup_failure();self.browser();self.delivery();self.preserve()

def main():
 if len(sys.argv)==3 and sys.argv[1]=='prepare':prepare(sys.argv[2]);return
 require(sys.argv[1:]==['run'],'expected prepare DIRECTORY or run');drill=Drill()
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('bounded stage expired')))
 try:drill.run();drill.state.update(status='PASS',stage='complete')
 except Exception as error:
  drill.state.update(status='FAIL',error_type=type(error).__name__,error=str(error) if isinstance(error,(ValueError,TimeoutError)) else 'private diagnostics retained',failure_frames=[dict(function=f.name,line=f.lineno) for f in traceback.extract_tb(error.__traceback__) if Path(f.filename)==Path(__file__)])
 finally:signal.alarm(0);write(drill.evidence/'result.json',drill.state);print(json.dumps(drill.state),flush=True)
 if drill.state['status']!='PASS':raise SystemExit(1)

if __name__=='__main__':main()
