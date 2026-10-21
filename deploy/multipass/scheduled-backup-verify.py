#!/usr/bin/env python3
"""Focused real scheduled backup/restore verification; never full qualification."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import time
import traceback

SOURCE=Path(__file__).resolve().parents[2]
BASELINE={
    'commit':'63c00f6006df3bba1ca9ef474e0f350ff7835165',
    'archive_sha256':'daed8aae60f859882a896e1cd321d975ccd6ef9b9276e53ad1f90b97419aa194',
    'manifest_sha256':'31b264e7ed4810687196b7fbb4c78713460cb9590e12f7f9dd3edaf4a682adc6',
    'public_key_sha256':'23e246427ffacccafee7aaac5af736b23a2ddf069c098b062796e8b050ed324d',
}
BASELINE_RUN=39652821843
IMAGE_SHA='8800651811af9a85465ad1d552add729947bb16488dddb4a9b5305a3d97332b2'
MINORS=('8.3','8.4','8.5')
ALLOWED={'.github/workflows/ubuntu-hosted-qualification.yml',
    'deploy/multipass/scheduled-backup-verify.py','deploy/multipass/scheduled-backup-verify.sh',
    'deploy/multipass/scheduled_backup_test.py','deploy/multipass/scheduled_backup_test.go'}


def require(value,message):
    if not value:raise ValueError(message)


def now():return datetime.now(timezone.utc)
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path,value):
    path=Path(path)
    temporary=path.with_suffix('.tmp')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:json.dump(value,stream,sort_keys=True);stream.write('\n')
    os.replace(temporary,path)


def write_failure(path,state,error):
    frames=[{'function':f.name,'line':f.lineno} for f in traceback.extract_tb(error.__traceback__) if Path(f.filename)==Path(__file__)]
    write_json(path,dict(state,status='FAIL',error_type=type(error).__name__,failure_frames=frames))


def check_changed_paths(paths):
    require(all(p in ALLOWED or (p.endswith('.md') and '..' not in Path(p).parts) for p in paths),
        'runtime sources changed; Phase 3 evidence cannot be reused')


def check_baseline(identity):
    require(identity==BASELINE,'accepted Phase 3 artifact identity differs')


def timestamp(value):
    require(isinstance(value,str),'missing backup timestamp')
    result=datetime.fromisoformat(value.replace('Z','+00:00'))
    require(result.tzinfo is not None,'backup timestamp lacks timezone')
    return result


def check_scheduled_backup(proof,destination,since):
    require(type(proof.get('id')) is int and proof['id']>0,'backup ID missing')
    require(proof.get('destination_id')==destination and proof.get('destination_name')=='phase4-local','unrelated backup destination')
    require(proof.get('scheduled') is True and proof.get('scheduler_audit') is True,'actual scheduler attribution required')
    require(proof.get('status')=='active' and proof.get('river_state')=='completed','backup and River job must complete')
    created=timestamp(proof.get('created_at'));verified=timestamp(proof.get('verified_at'));completed=timestamp(proof.get('completed_at'))
    require(since<=created<=verified<=completed,'stale or inconsistent backup timestamps')
    require(type(proof.get('size_bytes')) is int and proof['size_bytes']>0 and re.fullmatch(r'[a-f0-9]{64}',proof.get('sha256','')),'archive identity missing')
    detail=proof.get('verify_detail',{})
    require(detail.get('pg_restore_list_ok') is True and type(detail.get('entries')) is int and detail['entries']>0,'archive verification incomplete')


def check_php_sites(observed,expected):
    require(set(observed)==set(expected)==set(MINORS),'all hosting PHP minors required')
    for minor,proof in observed.items():
        require(proof.get('sha256')==expected[minor]['sha256'],'restored tenant file differs')
        require(all(isinstance(proof.get(k),str) and proof[k].startswith(minor+'.') for k in ('cli_version','http_version')),'actual PHP interpreter differs')
        require(type(proof.get('uid')) is int and proof['uid']==proof.get('user_uid') and proof['uid']>0,'tenant PHP must run as its nonroot owner')
        require(proof.get('php_version')==proof.get('desired_php_version')==minor and proof.get('status')=='active','restored PHP intent differs')


def hosted_guard():
    require(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted','disposable hosted runner required')


def export(values):
    with open(os.environ['GITHUB_ENV'],'a') as stream:
        for key,value in values.items():
            require('\n' not in str(value),'unsafe exported value')
            stream.write(key+'='+str(value)+'\n')


def prepare(directory):
    """Reuse authenticated bytes already accepted by Phase 3, with no rebuild."""
    def command(args):return subprocess.run(args,check=True,capture_output=True,text=True).stdout
    require(not command(['git','status','--porcelain','--untracked-files=no']).strip(),'qualification needs committed sources')
    check_changed_paths(command(['git','diff','--name-only',BASELINE['commit'],'HEAD']).splitlines())
    accepted=json.loads(command(['gh','run','view',str(BASELINE_RUN),'--repo','Smartqix/nakpanel','--json','headSha,status,conclusion']))
    require(accepted==dict(headSha=BASELINE['commit'],status='completed',conclusion='success'),'accepted baseline run differs')
    directory=Path(directory).resolve();meta=json.loads((directory/'bundles.json').read_text())
    require(meta.get('architecture')=='amd64' and meta.get('development') is True,'AMD64 development baseline required')
    entry=meta['candidate'];require(entry['version']=='29.0.0' and entry['commit']==BASELINE['commit'],'baseline release differs')
    require(entry['archive']=='candidate/nakpanel-29.0.0-linux-amd64.tar.gz' and entry['directory']=='candidate/nakpanel-29.0.0-linux-amd64','unexpected baseline paths')
    archive=directory/entry['archive'];key=directory/'test-public.pem'
    require(sha(archive)==BASELINE['archive_sha256'] and sha(key)==BASELINE['public_key_sha256'],'baseline archive/key bytes differ')
    with tarfile.open(archive) as source:
        for member in source.getmembers():
            path=Path(member.name)
            require(not path.is_absolute() and '..' not in path.parts and not member.issym() and not member.islnk() and (member.isfile() or member.isdir()),'unsafe release archive member')
        source.extractall(directory/'candidate',filter='data')
    bundle=directory/entry['directory'];manifest=bundle/'manifest.json'
    check_baseline(dict(commit=entry['commit'],archive_sha256=sha(archive),manifest_sha256=sha(manifest),public_key_sha256=sha(key)))
    command([sys.executable,str(SOURCE/'deploy/release/verify.py'),'--bundle',str(bundle),'--public-key',str(key),'--version','29.0.0','--architecture','amd64','--allow-development'])
    images=json.loads((directory/'images.json').read_text());image=images['26.04']
    require(image==dict(url='https://cloud-images.ubuntu.com/releases/resolute/release-20260927/ubuntu-26.04-server-cloudimg-amd64.img',sha256=IMAGE_SHA,serial='20260927',suite='resolute'),'pinned Ubuntu image differs')
    sums=directory/'images/resolute'
    command(['gpgv','--keyring','/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg',str(sums/'SHA256SUMS.gpg'),str(sums/'SHA256SUMS')])
    filename='ubuntu-26.04-server-cloudimg-amd64.img'
    require([line.split()[0] for line in (sums/'SHA256SUMS').read_text().splitlines() if line.split()[-1].lstrip('*')==filename]==[IMAGE_SHA],'signed Ubuntu image hash differs')
    target=directory/filename
    command(['curl','--fail','--location','--retry','3','--proto','=https','--proto-redir','=https',image['url'],'--output',str(target)])
    require(sha(target)==IMAGE_SHA,'downloaded Ubuntu image bytes differ')
    export(dict(NAKPANEL_RELEASE_BUNDLE=bundle,NAKPANEL_RELEASE_PUBLIC_KEY=key,NAKPANEL_RELEASE_VERSION='29.0.0',
        NAKPANEL_RELEASE_ALLOW_DEVELOPMENT='1',NAKPANEL_MULTIPASS_IMAGE_SOURCE=target,NAKPANEL_MULTIPASS_IMAGE_SHA256=IMAGE_SHA))


class Drill:
    def __init__(self):
        run=os.environ['GITHUB_RUN_ID'];attempt=os.environ['GITHUB_RUN_ATTEMPT']
        require(run.isdecimal() and attempt.isdecimal(),'invalid hosted run identity')
        self.token='scheduled-'+run+'-'+attempt
        self.source='nakpanel-26-04-amd64-'+self.token;self.dr=self.source+'-dr'
        self.evidence=Path(os.environ['RUNNER_TEMP'])/'scheduled-backup-evidence';self.evidence.mkdir(mode=0o700,exist_ok=True)
        self.private=Path(os.environ['RUNNER_TEMP'])/'scheduled-backup-private';self.private.mkdir(mode=0o700)
        self.env=dict(os.environ,NAKPANEL_RUN_TOKEN=self.token,NAKPANEL_MULTIPASS_VM=self.source,
            NAKPANEL_MULTIPASS_SOURCE_VM=self.source,NAKPANEL_MULTIPASS_DR_VM=self.dr,
            NAKPANEL_MULTIPASS_IMAGE='26.04',NAKPANEL_MULTIPASS_ARCH='amd64',NAKPANEL_QUALIFICATION_PHP_PROVIDER='sury',
            NAKPANEL_REMOTE_SRC='/var/lib/nakpanel-qualification/'+self.token+'/source',NAKPANEL_OWNERSHIP_DIR=str(self.private/'owners'))
        self.sequence=0
        self.state=dict(schema='nakpanel-scheduled-backup-result-v1',scope='SCHEDULED_BACKUP_RESTORE_ONLY',status='STARTED',
            source_vm=self.source,dr_vm=self.dr,run_token=self.token,release='26.04',architecture='amd64',php=list(MINORS),
            baseline_run=BASELINE_RUN,runtime_commit=BASELINE['commit'],baseline_identity=BASELINE,
            qualifier_commit=self.cmd(['git','rev-parse','HEAD']).strip(),promotion_eligible=False,merged=False,deployed=False)

    def cmd(self,args,*,data=None,env=None,timeout=180,check=True):
        self.sequence+=1
        result=subprocess.run(args,input=data,capture_output=True,text=True,env=env or self.env,timeout=timeout)
        log=self.private/('command-'+str(self.sequence).zfill(3)+'.log')
        fd=os.open(log,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as stream:stream.write(result.stdout);stream.write(result.stderr)
        if check and result.returncode:raise subprocess.CalledProcessError(result.returncode,args)
        return result.stdout

    def stage(self,name,**values):
        self.state.update(stage=name,updated_at=now().isoformat(),**values)
        write_json(self.evidence/'result.json',self.state)
        print('scheduled-backup: '+name,flush=True)

    def shell(self,function,*args,vm=None):
        env=dict(self.env,NAKPANEL_MULTIPASS_VM=vm or self.source)
        return self.cmd(['bash','-c','set -euo pipefail; source "$1"; shift; "$@"','_',str(SOURCE/'deploy/multipass/common.sh'),function,*args],env=env)

    def guest(self,vm,*args,data=None,timeout=180):
        return self.cmd(['multipass','exec',vm,'--',*args],data=data,timeout=timeout)

    def db(self,vm,query):
        return self.guest(vm,'sudo','-u','postgres','psql','-XqAt','-d','nakpanel','-v','ON_ERROR_STOP=1','-c',query).strip()

    def cli(self,vm,*args):
        return self.guest(vm,'sudo','-u','nakpanel','env','NAKPANEL_DATABASE_URL=postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable',
            'NAKPANEL_SECRET_KEY_FILE=/etc/nakpanel/secret-keys.json','panelctl','--actor','phase4',*args)

    def identity(self,vm):
        self.shell('assert_vm_identity',vm,'26.04','amd64',self.token)
        self.shell('assert_qualification_installed_release',vm,vm=vm)

    def ip(self,vm):return self.shell('vm_ip',vm=vm).strip()

    def install(self,vm,only=False):
        self.cmd(['bash',str(SOURCE/'deploy/multipass/current-install-verify.sh')],
            env=dict(self.env,NAKPANEL_MULTIPASS_VM=vm,NAKPANEL_INSTALL_ONLY='1' if only else '0'),timeout=3000)
        self.identity(vm)

    def sites(self,vm):
        return json.loads(self.db(vm,"SELECT coalesce(json_agg(x ORDER BY x.php_version),'[]') FROM (SELECT id,domain,username,document_root,php_version,desired_php_version,status FROM sites WHERE domain IN ('current-bootstrap.test','scheduled84.test','scheduled85.test')) x"))

    def seed(self):
        ip=self.ip(self.source);cookie=self.private/'admin.cookies'
        login=self.cmd(['curl','-skfL','--max-time','30','-c',str(cookie),'-d','email=admin@nakpanel.test','-d','password=NakpanelAdmin!2026','https://'+ip+':7443/login'])
        require('data-np-role="admin"' in login,'fixture administrator login failed')
        csrf=self.shell('csrf_token',str(cookie)).strip()
        subscription=self.db(self.source,"SELECT subscription_id FROM sites WHERE domain='current-bootstrap.test'")
        require(subscription.isdecimal(),'owned bootstrap subscription missing')
        for minor,domain in [('8.4','scheduled84.test'),('8.5','scheduled85.test')]:
            code=self.cmd(['curl','-sk','--max-time','30','-o',str(self.private/'response'),'-w','%{http_code}',
                '-b',str(cookie),'-H','X-Nakpanel-CSRF: '+csrf,'-H','X-Nakpanel-SPA: true',
                '-d','subscription_id='+subscription,'-d','domain='+domain,'-d','php_version='+minor,'-d','issue_certificate=false','https://'+ip+':7443/sites'])
            require(code in ('202','303'),'PHP fixture creation failed')
        deadline=time.monotonic()+240
        while True:
            rows=self.sites(self.source)
            if len(rows)==3 and {r['php_version'] for r in rows}==set(MINORS) and all(r['status']=='active' and r['desired_php_version']==r['php_version'] for r in rows):break
            require(time.monotonic()<deadline,'PHP fixtures did not converge');time.sleep(2)
        self.expected={}
        for row in rows:
            minor=row['php_version'];username=row['username'];root=Path(row['document_root'])
            require(re.fullmatch(r'[a-z][a-z0-9_-]{0,31}',username) and root.is_absolute() and '..' not in root.parts and str(root).startswith('/home/'+username+'/'),'unsafe fixture document root')
            body="<?php echo json_encode(['run'=>'"+self.token+"','version'=>PHP_VERSION,'uid'=>posix_geteuid()]);"
            path=str(root/('nakpanel-'+self.token+'.php'))
            code="import json,os,pwd,sys; v=json.load(sys.stdin); u=pwd.getpwnam(v['user']); f=os.open(v['path'],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644); os.write(f,v['body'].encode()); os.fchown(f,u.pw_uid,u.pw_gid); os.fchmod(f,0o644); os.close(f)"
            self.guest(self.source,'sudo','python3','-c',code,data=json.dumps(dict(user=username,path=path,body=body)))
            self.expected[minor]=dict(row,path=path,sha256=hashlib.sha256(body.encode()).hexdigest())
        self.db(self.source,"CREATE TABLE nakpanel_qualification_backup_canary (value text NOT NULL); INSERT INTO nakpanel_qualification_backup_canary VALUES ('"+self.token+"')")
        self.guest(self.source,'sudo','mariadb','np_current_bootstrap','-e',"UPDATE nakpanel_qualification_canary SET value='"+self.token+"' WHERE id=1")

    def health(self,vm):
        self.identity(vm);ip=self.ip(vm)
        self.guest(vm,'sudo','systemctl','is-active','--quiet','nakpanel','nakpanel-agent','nginx','postgresql','mariadb',*['php'+m+'-fpm' for m in MINORS])
        failed=self.guest(vm,'sudo','systemctl','--failed','--no-legend','--plain','--no-pager')
        require(not failed.strip(),'restored guest has failed systemd units')
        require(self.db(vm,'SELECT value FROM nakpanel_qualification_backup_canary')==self.token,'control database canary differs')
        require(self.guest(vm,'sudo','mariadb','--batch','--skip-column-names','np_current_bootstrap','-e','SELECT value FROM nakpanel_qualification_canary WHERE id=1').strip()==self.token,'MariaDB canary differs')
        observed={}
        for row in self.sites(vm):
            minor=row['php_version'];require(minor in self.expected,'unexpected restored PHP selection')
            expected=self.expected[minor]
            require(all(row[k]==expected[k] for k in ('id','domain','username','document_root')),'restored site identity differs')
            file_sha=self.guest(vm,'sudo','sha256sum',expected['path']).split()[0]
            cli=self.guest(vm,'/usr/bin/php'+minor,'-r','echo PHP_VERSION;').strip()
            uid=int(self.guest(vm,'id','-u',row['username']).strip())
            output=self.cmd(['curl','-skfL','--max-time','20','--resolve',row['domain']+':80:'+ip,'--resolve',row['domain']+':443:'+ip,
                'http://'+row['domain']+'/'+Path(expected['path']).name])
            data=json.loads(output);require(data.get('run')==self.token,'tenant HTTP canary differs')
            observed[minor]=dict(sha256=file_sha,cli_version=cli,http_version=data.get('version'),uid=data.get('uid'),user_uid=uid,
                php_version=minor,desired_php_version=row['desired_php_version'],status=row['status'])
        check_php_sites(observed,self.expected)
        boot=self.guest(vm,'cat','/proc/sys/kernel/random/boot_id').strip()
        return dict(status='HEALTHY',boot_id=boot,php=observed,control_database_canary=True,mariadb_canary=True,service_repair_performed=False)

    def wait_health(self,vm):
        deadline=time.monotonic()+180
        while True:
            try:return self.health(vm)
            except (ValueError,subprocess.SubprocessError):
                if time.monotonic()>=deadline:raise
                time.sleep(3)

    def destination(self,vm,disabled=False):
        args=['backup-server','destination','update' if disabled else 'add','--name','phase4-local','--kind','local','--schedule','* * * * *','--retention-count','7']
        if disabled:args+=['--disabled']
        self.cli(vm,*args)
        value=self.db(vm,"SELECT id FROM server_backup_destinations WHERE name='phase4-local'")
        require(value.isdecimal(),'scheduled destination missing');return int(value)

    def scheduled(self,vm,destination,since):
        deadline=time.monotonic()+900
        while True:
            rows=json.loads(self.db(vm,"""SELECT coalesce(json_agg(x ORDER BY x.id),'[]') FROM (
SELECT b.id,b.destination_id,d.name destination_name,b.scheduled,b.status,b.checksum_sha256 sha256,b.size_bytes,b.archive_name,
b.created_at,b.completed_at,b.verified_at,b.verify_detail,
(SELECT state::text FROM river_job WHERE kind='server_backup' AND args->>'server_backup_id'=b.id::text ORDER BY id DESC LIMIT 1) river_state,
EXISTS(SELECT 1 FROM audit_events a WHERE a.action='server.backup_requested' AND a.actor_label='scheduler'
AND a.metadata->>'backup_id'=b.id::text AND a.metadata->'scheduled'='true'::jsonb) scheduler_audit
FROM server_backups b JOIN server_backup_destinations d ON d.id=b.destination_id
WHERE b.destination_id="""+str(destination)+" AND b.created_at>='"+since.isoformat()+"'::timestamptz) x"))
            for row in rows:
                require(row['status']!='failed','actual scheduled backup failed')
                try:check_scheduled_backup(row,destination,since)
                except ValueError:continue
                return row
            require(time.monotonic()<deadline,'verified scheduler backup not observed within 15 minutes')
            time.sleep(5)

    def execute(self):
        self.stage('ownership-initialization')
        self.shell('init_qualification_run')
        export({k:self.env[k] for k in ('NAKPANEL_RUN_TOKEN','NAKPANEL_MULTIPASS_VM','NAKPANEL_MULTIPASS_SOURCE_VM','NAKPANEL_MULTIPASS_DR_VM','NAKPANEL_OWNERSHIP_DIR')})
        export({'NAKPANEL_CI_OWNERSHIP_READY':'1'})
        self.stage('source-install');self.install(self.source)
        self.stage('source-canaries');self.seed();self.state['source_health']=self.health(self.source)
        self.stage('source-scheduler')
        key_output=self.cli(self.source,'backup-server','key','init')
        keys=re.findall(r'^nkbk1-[A-Z2-7]{52}$',key_output,re.M);require(len(keys)==1,'exact backup key initialization failed')
        key=self.private/'archive.key';key.write_text(keys[0]+'\n');key.chmod(0o600)
        since=now();destination=self.destination(self.source)
        backup=self.scheduled(self.source,destination,since);self.destination(self.source,disabled=True)
        self.state['source_backup']=backup
        require(re.fullmatch(r'[A-Za-z0-9._-]+\.nkbk',backup['archive_name']) is not None,'unsafe archive name')
        archive=self.private/'scheduled.nkbk';remote='/tmp/'+self.token+'.nkbk'
        self.guest(self.source,'sudo','install','-m','0600','-o','ubuntu','/var/lib/nakpanel/server-backups/'+backup['archive_name'],remote)
        self.cmd(['multipass','transfer',self.source+':'+remote,str(archive)],timeout=300)
        require(sha(archive)==backup['sha256'] and archive.stat().st_size==backup['size_bytes'],'selected scheduled archive bytes differ')
        self.stage('fresh-restore-install');self.install(self.dr,only=True)
        self.cmd(['multipass','transfer',str(archive),self.dr+':'+remote],timeout=300)
        remote_key='/tmp/'+self.token+'.key';self.cmd(['multipass','transfer',str(key),self.dr+':'+remote_key])
        actual=self.guest(self.dr,'sudo','sha256sum',remote).split()[0];require(actual==backup['sha256'],'transferred archive bytes differ')
        self.stage('restore-scheduled-archive')
        self.guest(self.dr,'sudo','env','NAKPANEL_SECRET_KEY_FILE=/etc/nakpanel/secret-keys.json','panelctl','--actor','phase4-restore','restore-server',
            '--archive',remote,'--backup-key-file',remote_key,'--yes',timeout=1800)
        self.guest(self.dr,'sudo','rm','--',remote_key,remote)
        self.stage('restored-data-validation');self.state['restored_health']=self.wait_health(self.dr)
        self.stage('restored-reboot');self.cmd(['multipass','restart',self.dr],timeout=300);self.shell('wait_for_cloud_init',self.dr)
        self.state['reboot_health']=self.wait_health(self.dr)
        require(self.state['reboot_health']['boot_id']!=self.state['restored_health']['boot_id'],'actual new restore boot required')
        self.stage('restored-postboot-scheduler')
        since=now();restored_destination=self.db(self.dr,"SELECT id FROM server_backup_destinations WHERE name='phase4-local' AND enabled AND schedule_cron='* * * * *'")
        require(restored_destination.isdecimal(),'restored schedule or enabled state differs')
        self.state['restored_postboot_backup']=self.scheduled(self.dr,int(restored_destination),since)
        self.destination(self.dr,disabled=True)
        self.stage('complete',status='PASS',actual_restore=True,postboot_scheduler_verified=True,
            unchanged_checks_reused_from=BASELINE_RUN,legacy_tests_run=False)


def main():
    hosted_guard();os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=('prepare','run'));parser.add_argument('baseline_directory',nargs='?')
    args=parser.parse_args()
    evidence=Path(os.environ['RUNNER_TEMP'])/'scheduled-backup-evidence';evidence.mkdir(mode=0o700,exist_ok=True)
    if args.operation=='prepare':
        state=dict(schema='nakpanel-scheduled-backup-preparation-v1',stage='baseline-authentication')
        try:prepare(args.baseline_directory)
        except BaseException as error:write_failure(evidence/'preparation.json',state,error);raise
        write_json(evidence/'preparation.json',dict(state,status='PASS',baseline_run=BASELINE_RUN,**BASELINE))
    else:
        drill=Drill()
        try:drill.execute()
        except BaseException as error:write_failure(evidence/'result.json',drill.state,error);raise


if __name__=='__main__':
    try:main()
    except BaseException as error:
        print('Scheduled backup verification failed: '+type(error).__name__,file=sys.stderr)
        sys.exit(1)
