#!/usr/bin/env python3
"""R0/R1 only: signed Resolute installation and synthetic subscription ingress."""
import hashlib, http.cookiejar, importlib.util, json, os, re, secrets, shutil, signal, ssl, stat, subprocess, sys, time, traceback
from pathlib import Path
import urllib.parse, urllib.request

SOURCE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('plesk_shared', Path(__file__).with_name('subdomain-mail-verify.py'))
shared = importlib.util.module_from_spec(spec); spec.loader.exec_module(shared)
require, write = shared.require, shared.write


def validate_inventory(data):
    require(data.get('dataset_kind') == 'synthetic_requirements_inventory' and data.get('real_customers_assessed') == 0 and data.get('source_servers_contacted') == 0, 'synthetic inventory required')
    require(data.get('target_contract') == dict(os='Ubuntu 26.04 LTS', codename='resolute', php_provider='sury', hosting_php=['8.3','8.4','8.5'], internal_php='8.5'), 'full Resolute multi-PHP contract required')
    cases = data.get('cases', [])
    for key in ('id', 'customer_ref', 'domain'):
        require(len({case[key] for case in cases}) == len(cases), 'duplicate source identity')
    require(all(re.fullmatch(r'[a-z0-9-]+\.test', case['domain']) and case.get('evidence_status') == 'synthetic_only' for case in cases), 'reserved synthetic domains required')
    selected = [case for case in cases if case['id'] in ('S01','S02','S03')]
    require([(case['id'], case['source_php'], case['source_db_engine']) for case in selected] == [('S01','8.3','mariadb'),('S02','8.4','mariadb'),('S03','8.5','mariadb')], 'only S01/S02/S03 supported baselines are authorized')
    return selected


def redact(text, values):
    for value in values:
        if value: text = text.replace(value, '[fixture-secret]')
    text = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----', '[private-key]', text, flags=re.S)
    return text[-6000:]


def read_admin_password(path):
    path=Path(path);info=path.lstat()
    require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==0o600 and info.st_uid==os.getuid(),'private administrator credential file required')
    value=path.read_text().rstrip('\r\n')
    require(12<=len(value)<=128 and not any(char in value for char in ('\n','\r','\x00')),'invalid private administrator credential')
    return value


def firewall_rules(token, mac, bridge):
    require(re.fullmatch(r'p2-[0-9]+-[0-9]+', token) and re.fullmatch(r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}', mac) and re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', bridge), 'unsafe containment identity')
    table = token.replace('-', '_')
    return table, f'''table inet {table} {{
 comment "nakpanel-plesk-r0:{token}"
 chain guest_forward {{
  type filter hook forward priority -310; policy accept;
  iifname "{bridge}" ether saddr {mac} counter reject with icmpx type admin-prohibited
 }}
 chain guest_host {{
  type filter hook input priority -310; policy accept;
  iifname "{bridge}" ether saddr {mac} meta l4proto tcp ct direction reply ct state established,related accept
  iifname "{bridge}" ether saddr {mac} udp sport 68 udp dport 67 accept
  iifname "{bridge}" ether saddr {mac} udp dport 53 counter reject with icmpx type admin-prohibited comment "nakpanel-rehearsal-dns-deny"
  iifname "{bridge}" ether saddr {mac} counter reject with icmpx type admin-prohibited
 }}
}}
'''


def verify_manifest(expected, observed, uid):
    require(bool(expected), 'empty source manifest cannot prove preservation')
    for name, entry in expected.items():
        require(name in observed, 'missing imported file: '+name)
        require(observed[name].get('uid') == uid, 'incorrect mapped file owner: '+name)
        require(all(observed[name].get(key) == value for key, value in entry.items()), 'file bytes/mode/link differ: '+name)


class TrustedHTTP(shared.HTTP):
    def __init__(self, base, ca):
        require(base.startswith('https://'), 'HTTPS required')
        self.base = base; self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookies), urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))), shared.NoRedirect())


def prepare(directory):
    password=os.environ.get('NAKPANEL_REHEARSAL_ADMIN_PASSWORD','').rstrip('\r\n')
    require(12<=len(password)<=128 and not any(char in password for char in ('\n','\r','\x00')),'approved private administrator credential missing')
    shared.prepare(directory)
    evidence = Path(os.environ['RUNNER_TEMP'])/'plesk-rehearsal-evidence'; evidence.mkdir(mode=0o700, exist_ok=True)
    shutil.copy2(evidence.parent/'subdomain-mail-evidence/artifact.json', evidence/'artifact.json')
    private = evidence.parent/'plesk-rehearsal-private'; private.mkdir(mode=0o700, exist_ok=True)
    credential=private/'admin-password';credential.write_text(password);credential.chmod(0o600)
    for name, url in [('wordpress.zip','https://wordpress.org/wordpress-7.1.zip'), ('wordpress-checksums.json','https://api.wordpress.org/core/checksums/1.0/?version=7.1&locale=en_US')]:
        subprocess.run(['curl','--fail','--location','--retry','2','--max-time','180','--proto','=https','--proto-redir','=https',url,'-o',str(private/name)], check=True)
    import zipfile
    sums = json.loads((private/'wordpress-checksums.json').read_text())['checksums']
    require(len(sums)>1000, 'nonempty official WordPress checksum inventory required')
    with zipfile.ZipFile(private/'wordpress.zip') as archive:
        require(len(archive.infolist())<10000 and sum(item.file_size for item in archive.infolist())<150<<20, 'WordPress source exceeds fixture bounds')
        for name, digest in sums.items():
            require(hashlib.md5(archive.read('wordpress/'+name)).hexdigest() == digest, 'WordPress source checksum differs: '+name)
    write(evidence/'wordpress-source.json', dict(version='7.1', sha256=shared.sha(private/'wordpress.zip'), checksum_manifest_sha256=shared.sha(private/'wordpress-checksums.json'), verified_files=len(sums)))


class Drill(shared.Drill):
    def __init__(self):
        shared.hosted_guard(); run=os.environ['GITHUB_RUN_ID']; attempt=os.environ['GITHUB_RUN_ATTEMPT']
        require(run.isdecimal() and attempt.isdecimal(), 'invalid run identity')
        self.token='p2-'+run+'-'+attempt; self.vm='nakpanel-26-04-amd64-'+self.token
        base=Path(os.environ['RUNNER_TEMP']); self.private=base/'plesk-rehearsal-private'; self.evidence=base/'plesk-rehearsal-evidence'
        self.private.mkdir(mode=0o700, exist_ok=True); self.evidence.mkdir(mode=0o700, exist_ok=True)
        self.env=dict(os.environ, NAKPANEL_RUN_TOKEN=self.token, NAKPANEL_MULTIPASS_VM=self.vm, NAKPANEL_MULTIPASS_SOURCE_VM=self.vm, NAKPANEL_MULTIPASS_DR_VM=self.vm+'-dr', NAKPANEL_MULTIPASS_IMAGE='26.04', NAKPANEL_MULTIPASS_ARCH='amd64', NAKPANEL_QUALIFICATION_PHP_PROVIDER='sury', NAKPANEL_INSTALL_ONLY='1', NAKPANEL_QUALIFICATION_APT_NO_TRANSLATIONS='1', NAKPANEL_OWNERSHIP_DIR=str(self.private/'owners'), NAKPANEL_REMOTE_SRC='/var/lib/nakpanel-qualification/'+self.token+'/source')
        self.state=dict(scope='PLESK_SYNTHETIC_R0_R1_ONLY', status='STARTED', commit=os.environ['GITHUB_SHA'], run_token=self.token, guest=self.vm, checks=[], cases=[], promotion_eligible=False, real_customers=0, later_rehearsals_run=[], deployed=False)
        self.admin_password=read_admin_password(self.private/'admin-password')
        self.env['NAKPANEL_QUALIFICATION_ADMIN_PASSWORD_FILE']=str(self.private/'admin-password')
        self.sequence=0; self.deadline=time.monotonic()+4200; self.secret_values=[self.admin_password]; self.records=[]
        with open(os.environ['GITHUB_ENV'],'a') as stream:
            for key in ('NAKPANEL_RUN_TOKEN','NAKPANEL_MULTIPASS_VM','NAKPANEL_MULTIPASS_SOURCE_VM','NAKPANEL_MULTIPASS_DR_VM','NAKPANEL_OWNERSHIP_DIR','NAKPANEL_REMOTE_SRC'): stream.write(key+'='+self.env[key]+'\n')
    def cmd(self,args,data=None,env=None,timeout=180):
        self.sequence+=1
        result=subprocess.run(args,input=data,text=True,capture_output=True,timeout=timeout,env=env or self.env)
        log=self.private/('command-%04d.log'%self.sequence); log.write_text(result.stdout+result.stderr); log.chmod(0o600)
        if result.returncode:
            write(self.evidence/'failure-diagnostic.json', dict(program=Path(args[0]).name,exit_code=result.returncode,diagnostic=redact(result.stdout+result.stderr,self.secret_values)))
        require(result.returncode==0, 'command failed: '+Path(args[0]).name+' exit='+str(result.returncode)+' private-log='+log.name)
        return result.stdout
    def capture_failure(self):
        # Read diagnostics only after validating the exact owned guest identity.
        # Keep raw streams private; public excerpts use the same secret scrubber.
        try:
            self.shell('assert_current_vm_identity')
            records=[]
            for args in (['sudo','cat','/var/lib/nakpanel-qualification/'+self.token+'/fixtures/progress.json'], ['ps','-eo','user,pid,ppid,etime,comm,wchan:25'], ['sudo','journalctl','-u','nakpanel','-u','nakpanel-agent','--no-pager','-n','80','--since','15 minutes ago'], ['sudo','journalctl','-u','stalwart-mail','--no-pager','-n','60','--since','10 minutes ago'], ['sudo','journalctl','-u','nakpanel-php-fpm@*.service','--no-pager','-n','100','--since','15 minutes ago'], ['sudo','journalctl','-k','--no-pager','-n','40'], ['free','-b'], ['sudo','systemctl','show','nakpanel-php-fpm@1.service','nakpanel-php-fpm@2.service','nakpanel-php-fpm@3.service','--property=ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,MainPID,NRestarts,MemoryCurrent,MemoryPeak,MemoryMax'], ['sudo','python3','-c',"from pathlib import Path;import json;print(json.dumps({p.name:p.read_text(errors='replace')[-4000:] for p in sorted(Path('/var/log/php-fpm').glob('*.error.log'))[:10] if p.is_file() and not p.is_symlink()}))"], ['sudo','timeout','35s','strace','-f','-T','-s','96','-e','trace=network,poll,ppoll,clock_nanosleep','/usr/sbin/php-fpm8.5','-tt','-y','/etc/nakpanel/php-fpm/sites/3.conf'], ['systemctl','--failed','--no-legend','--no-pager']):
                try:
                    result=subprocess.run(['multipass','exec',self.vm,'--',*args],text=True,capture_output=True,timeout=40 if 'strace' in args else 15,env=self.env)
                    records.append(dict(program=args[0],exit_code=result.returncode,diagnostic=redact(result.stdout+result.stderr,self.secret_values)))
                except subprocess.TimeoutExpired as error:
                    def stream(value):return value.decode(errors='replace') if isinstance(value,bytes) else value or ''
                    records.append(dict(program=args[0],exit_code='timeout',diagnostic=redact(stream(error.stdout)+stream(error.stderr),self.secret_values)))
            observed=subprocess.run(['sudo','nft','-j','list','table','inet',self.table],text=True,capture_output=True,timeout=15,env=self.env)
            records.append(dict(program='host-owned-nft-table',exit_code=observed.returncode,diagnostic=redact(observed.stdout+observed.stderr,self.secret_values)))
            write(self.evidence/'guest-failure-diagnostic.json',records)
        except Exception as error:
            write(self.evidence/'guest-failure-diagnostic.json',dict(capture_error=redact(str(error),self.secret_values)))
    def stage(self,name):
        remaining=int(self.deadline-time.monotonic()); require(remaining>0,'rehearsal deadline exceeded')
        signal.alarm(min(2400 if name=='fresh-signed-install' else 900,remaining))
        self.state.update(stage=name,updated_at=time.time()); write(self.evidence/'result.json',self.state); print('plesk-r0-r1: '+name,flush=True)
    def helper(self, action, record=None):
        return json.loads(self.cmd(['multipass','exec',self.vm,'--','sudo','python3',self.env['NAKPANEL_REMOTE_SRC']+'/deploy/multipass/plesk-rehearsal-guest.py',action],data=json.dumps(dict(token=self.token,record=record or {})),timeout=600 if action=='source' else 240))
    def password(self):
        value='P2_'+secrets.token_urlsafe(24); self.secret_values.append(value); return value
    def until(self,fn,predicate,label,seconds=180):
        end=time.monotonic()+seconds
        while True:
            value=fn()
            if predicate(value): return value
            require(time.monotonic()<end,'timed out: '+label); time.sleep(2)
    def api(self,path,fields=None,client=None,ok=(200,202,303)):
        return (client or self.http).request(path,fields,ok)
    def upload(self,record,path):
        client=record['client']; boundary='p2_'+secrets.token_hex(12)
        raw=(f'--{boundary}\r\nContent-Disposition: form-data; name="files"; filename="rehearsal.zip"\r\nContent-Type: application/zip\r\n\r\n').encode()+Path(path).read_bytes()+f'\r\n--{boundary}--\r\n'.encode()
        session=next(c.value for c in client.cookies if c.name=='nakpanel_session')
        headers={'Content-Type':'multipart/form-data; boundary='+boundary,'Accept':'application/json','X-Nakpanel-CSRF':hashlib.sha256(('nakpanel-csrf-v1:'+session).encode()).hexdigest(),'X-Nakpanel-SPA':'true','Referer':client.base+'/'}
        with client.opener.open(urllib.request.Request(client.base+'/sites/'+str(record['site'])+'/files/upload?path=',data=raw,headers=headers),timeout=180) as response:
            require(response.status==200 and json.load(response).get('ok') is True,'scoped archive upload failed')
        prefix='/sites/'+str(record['site'])+'/files/'
        self.api(prefix+'extract',dict(file_path='rehearsal.zip',destination='',overwrite='true'),client)
        self.api(prefix+'delete',{'paths':['rehearsal.zip']},client)
    def curl(self,record,path='/',fields=None,cookie=None,ok=(200,)):
        args=['curl','--silent','--show-error','--connect-timeout','5','--max-time','45','--proto','=https','--proto-redir','=https','--cacert',str(self.ca),'--resolve',record['domain']+':443:'+self.ip,'-w','\n%{http_code}']
        if cookie: args+=['-b',str(cookie),'-c',str(cookie)]
        if fields is not None: args+=['--data-binary','@-']
        raw=self.cmd(args+['https://'+record['domain']+path],data=urllib.parse.urlencode(fields).encode().decode() if fields is not None else None,timeout=60)
        body,code=raw.rsplit('\n',1); require(int(code) in ok,'site '+record['id']+' HTTP '+code+' for '+path); return body
    def containment(self,users):
        before=self.denial_count()
        for user in users:
            raw=self.guest('sudo','-u',user,'python3','-c',"import subprocess,json; p=subprocess.run(['curl','--silent','--connect-timeout','2','--max-time','3','https://1.1.1.1/'],capture_output=True); print(json.dumps({'blocked':p.returncode!=0}))")
            require(json.loads(raw)['blocked'],'guest external TCP connection was permitted')
        require(self.denial_count()>before,'containment probes did not hit actual firewall denial counters')
        self.state.setdefault('containment_probes',[]).append(dict(users=users,denial_counter=self.denial_count()))
    def denial_count(self,dns_only=False):
        rules=json.loads(self.cmd(['sudo','nft','-j','list','table','inet',self.table]))
        return sum(expr['counter']['packets'] for item in rules['nftables'] if not dns_only or item.get('rule',{}).get('comment')=='nakpanel-rehearsal-dns-deny' for expr in item.get('rule',{}).get('expr',[]) if 'counter' in expr)
    def verify_dns_denial(self):
        before=self.denial_count(dns_only=True);dns=self.helper('containment-dns');after=self.denial_count(dns_only=True)
        proof=dict(dns,denial_counter_before=before,denial_counter_after=after)
        self.state.setdefault('dns_containment_probes',[]).append(proof)
        require(dns['response_bytes'] is None and after>before,'contained UDP DNS probe failed: '+json.dumps(proof))
    def bootstrap(self):
        self.stage('fresh-signed-install'); self.shell('init_qualification_run')
        self.cmd(['bash',str(SOURCE/'deploy/multipass/current-install-verify.sh')],timeout=2400)
        self.shell('assert_current_vm_identity'); self.shell('assert_qualification_installed_release')
        self.ip=self.shell('vm_ip').strip()
        require(self.guest('bash','-c','. /etc/os-release; printf "%s:%s:%s" "$ID" "$VERSION_ID" "$VERSION_CODENAME"').strip()=='ubuntu:26.04:resolute','unsupported actual guest OS')
        self.guest('sudo','apt-get','-o','DPkg::Lock::Timeout=120','install','-y','--no-install-recommends','strace')
        self.stage('R0-trusted-endpoints-and-source-identity')
        self.helper('trust',{'ip':self.ip})
        self.ca=self.private/'fixture-ca.crt'; self.ca.write_text(self.guest('sudo','cat','/var/lib/nakpanel-qualification/'+self.token+'/fixture-ca/root.crt'))
        self.http=TrustedHTTP('https://'+self.ip+':7443',self.ca); self.http.login('admin@nakpanel.test',self.admin_password)
        self.state['fixture_ca_sha256']=shared.sha(self.ca)
        actual=self.helper('runtimes'); self.state['runtime_inventory']=actual
        self.inventory=json.loads((SOURCE/'docs/migration/fixtures/plesk-customers.synthetic.json').read_text()); self.cases=validate_inventory(self.inventory)
        self.state['inventory_sha256']=shared.sha(SOURCE/'docs/migration/fixtures/plesk-customers.synthetic.json')
        self.state['private_dns']=self.helper('offline-dns')
        self.stage('R0-host-enforced-egress-containment')
        route=json.loads(self.cmd(['ip','-j','route','get',self.ip]))[0]; bridge=route['dev']
        self.mac=self.guest('bash','-c','cat /sys/class/net/$(ip -j route get 1.1.1.1 | python3 -c \'import json,sys;print(json.load(sys.stdin)[0]["dev"])\')/address').strip()
        self.table,rules=firewall_rules(self.token,self.mac,bridge)
        rulefile=self.private/'containment.nft';rulefile.write_text(rules)
        probe=subprocess.run(['sudo','nft','list','table','inet',self.table],capture_output=True)
        require(probe.returncode!=0,'containment table already exists')
        self.cmd(['sudo','nft','--check','--file',str(rulefile)]); self.cmd(['sudo','nft','--file',str(rulefile)])
        write(self.private/'firewall.json',dict(token=self.token,table=self.table,mac=self.mac,bridge=bridge))
        self.containment(['root'])
        self.state['offline_php_startup']=self.helper('offline-dns-check')
        self.verify_dns_denial()
        self.state['source_fixture_identity']=dict(kind='private synthetic exports in the owned guest',token=self.token,plesk_server=False)
        self.passed('R0: signed current Resolute installation, all PHP CLI/FPM extensions, trusted HTTPS and actual host-enforced egress denials')
    def provision(self):
        self.stage('R1-three-independent-subscriptions')
        plan='Plesk R1 '+self.token
        self.api('/plans',dict(name=plan,description='Synthetic R0/R1 only',disk_mb=3072,max_sites=3,max_subdomains=1,max_databases=3,bandwidth_mb=-1,max_mailboxes=4,max_ftp_accounts=3,max_backups=5,backup_storage_mb=3072,backup_retention_days=2,site_disk_quota_mb=1024,php_allowlist='8.3,8.4,8.5',default_php_version='8.4',php_max_children=2,php_memory_mb=256,hosting_enabled='true',allow_tls='true',allow_backups='true',allow_php_settings='true',allow_sftp='true',allow_scheduled_tasks='true',allow_mail='true',allow_dns='true',allow_composer='true',is_active='true'))
        plan_id=int(self.db("SELECT id FROM plans WHERE name='"+plan+"'"))
        for case in self.cases:
            record=dict(case); record.update(email=case['id'].lower()+'@rehearsal.test',login_password=self.password(),db_password=self.password(),app_password=self.password(),wp_password=self.password())
            self.api('/customers',dict(customer_email=record['email'],customer_name=case['customer_ref'],enable_login='true',password=record['login_password']))
            customer=int(self.db("SELECT id FROM customers WHERE email='"+record['email']+"'"));record['customer']=customer
            self.api('/subscriptions',dict(customer_mode='existing',customer_id=customer,plan_id=plan_id,subscription_name=record['id']))
            sub=int(self.db('SELECT id FROM subscriptions WHERE customer_id='+str(customer))); record['sub']=sub
            self.wait('SELECT convergence_status FROM subscription_system_accounts WHERE subscription_id='+str(sub),'in_sync')
            require(int(self.db('SELECT max_subdomains FROM subscription_entitlements WHERE subscription_id='+str(sub)))>=1,'dummy plan does not allow its declared mail child')
            self.api('/subscriptions/'+str(sub)+'/policy',dict(policy_patch=json.dumps({'resources':{'max_sftp_identities':3,'max_scheduled_tasks':3,'max_mail_aliases':4},'permissions':{'sftp':True,'scheduled_tasks':True},'access':{'shell_mode':'sftp','sftp_only':True},'backups':{'enabled':True,'schedule':'manual'}})))
            self.api('/sites',dict(subscription_id=sub,domain=record['domain'],php_version=record['source_php'],issue_certificate='false'))
            site=int(self.db("SELECT id FROM sites WHERE domain='"+record['domain']+"'"));record['site']=site
            self.wait('SELECT status||\':\'||php_version||\':\'||settings_status FROM sites WHERE id='+str(site),'active:'+record['source_php']+':in_sync')
            details=json.loads(self.db('SELECT json_build_object(\'username\',username,\'root\',document_root,\'uid\',(SELECT linux_uid FROM subscription_system_accounts WHERE subscription_id=sites.subscription_id)) FROM sites WHERE id='+str(site)));record.update(details)
            require(re.fullmatch(r'nps[0-9]+',record['username']) and Path(record['root']).is_relative_to('/home/'+record['username']), 'unexpected target filesystem identity')
            client=TrustedHTTP(self.http.base,self.ca);client.login(record['email'],record['login_password']);record['client']=client
            record['db_name']='p2_'+record['id'].lower();record['db_user']=record['db_name']
            self.api('/databases',dict(subscription_id=sub,site_id=site,engine='mariadb',db_name=record['db_name'],db_user=record['db_user'],password=record['db_password']),client)
            record['database']=int(self.db("SELECT id FROM databases WHERE subscription_id="+str(sub)+" AND db_name='"+record['db_name']+"'"));self.wait('SELECT status FROM databases WHERE id='+str(record['database']),'active')
            key=self.private/(record['id']+'-sftp'); self.cmd(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)]);record['key']=str(key)
            self.api('/subscriptions/'+str(sub)+'/sftp',dict(name='R1 import',public_key=Path(str(key)+'.pub').read_text(),relative_root='domains/'+record['domain']+'/public_html',enabled='true'))
            self.wait('SELECT convergence_status FROM subscription_system_accounts WHERE subscription_id='+str(sub),'in_sync')
            self.helper('certificate',self.serializable(record))
            self.guest('sudo','-u','nakpanel','env','NAKPANEL_DATABASE_URL=postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable','panelctl','--actor','r1','ssl','set-custom',record['domain'],'--cert','/run/plesk-rehearsal-certificates/'+record['id']+'.crt','--key','/run/plesk-rehearsal-certificates/'+record['id']+'.key','--yes')
            self.wait('SELECT tls_status FROM sites WHERE id='+str(site),'active')
            self.records.append(record)
        self.containment([record['username'] for record in self.records])
        self.passed('R1: three separate owners/subscriptions, exact PHP minors, scoped database principals and SFTP identities')
    def serializable(self, record):
        return {key:value for key,value in record.items() if key!='client'}
    def sftp(self,record,batch,success=True):
        known=self.private/'known-hosts'
        if not known.exists(): known.write_text(self.ip+' '+self.guest('sudo','cat','/etc/ssh/ssh_host_ed25519_key.pub').strip()+'\n')
        args=['sftp','-q','-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oIdentitiesOnly=yes','-oUserKnownHostsFile='+str(known),'-oConnectTimeout=10','-i',record['key'],'-b','-',record['username']+'@'+self.ip]
        if success:return self.cmd(args,data=batch,timeout=120)
        result=subprocess.run(args,input=batch,text=True,capture_output=True,timeout=30,env=self.env);require(result.returncode!=0,'SFTP escaped subscription confinement')
    def imports(self):
        self.stage('R1-owned-file-and-logical-SQL-imports')
        self.guest('sudo','install','-m','0600','-o','root','-g','root','/dev/null','/tmp/'+self.token+'-wordpress.zip')
        self.cmd(['multipass','transfer',str(self.private/'wordpress.zip'),self.vm+':/tmp/'+self.token+'-wordpress-upload.zip'])
        self.guest('sudo','mv','/tmp/'+self.token+'-wordpress-upload.zip','/tmp/'+self.token+'-wordpress.zip')
        require(self.guest('sudo','sha256sum','/tmp/'+self.token+'-wordpress.zip').split()[0]==shared.sha(self.private/'wordpress.zip'),'WordPress source changed in transfer')
        for record in self.records:
            source=self.helper('source',self.serializable(record));record['source']=source
            archive=self.private/(record['id']+'.zip');self.cmd(['multipass','transfer',self.vm+':'+source['archive'],str(archive)])
            require(shared.sha(archive)==source['archive_sha256'],'source archive changed in transfer')
            self.upload(record,archive)
            self.import_symlink(record)
            self.api('/sites/'+str(record['site'])+'/files/permissions',dict(file_path='.secret-note',mode='0640'),record['client'])
            self.api('/sites/'+str(record['site'])+'/files/permissions',dict(file_path='wp-config.php' if record['id']=='S01' else '.private-config.php',mode='0600'),record['client'])
            self.helper('import-sql',self.serializable(record))
            observed=self.helper('manifest',self.serializable(record));verify_manifest(source['manifest'],observed,record['uid'])
            self.state['cases'].append(dict(id=record['id'],domain=record['domain'],php=record['source_php'],customer=record['customer'],subscription=record['sub'],site=record['site'],source_files=len(source['manifest']),source_manifest_sha256=source['manifest_sha256'],archive_sha256=source['archive_sha256'],mapped_uid=record['uid'],import_verified=True))
        self.passed('R1: nonempty source files and logical MariaDB data imported with scoped clients; source manifests, modes, links and mapped owners preserved')
    def import_symlink(self, record):
        self.sftp(record,'ln -s files/content.txt content-link.txt\npwd\nls\n')
    def workloads(self):
        self.stage('R1-application-login-upload-permalinks-and-update')
        for record in self.records:
            runtime=json.loads(self.curl(record,'/rehearsal-runtime.php'))
            require(runtime['php'].startswith(record['source_php']+'.') and runtime['uid']==record['uid'],'FPM executed as the wrong runtime/account')
            cookie=self.private/(record['id']+'-app.cookies')
            if record['id']=='S01':
                self.curl(record,'/wp-login.php',cookie=cookie)
                self.curl(record,'/wp-login.php',dict(log='rehearsal',pwd=record['wp_password'],testcookie='1',redirect_to='https://'+record['domain']+'/wp-admin/'),cookie,ok=(302,))
                self.curl(record,'/wp-admin/',cookie=cookie)
                require('wordpress_logged_in_' in cookie.read_text(),'WordPress login did not establish a real session')
                require('Hello world' in self.curl(record,'/hello-world/'),'WordPress clean permalink failed')
                self.helper('wordpress-workflow',self.serializable(record))
                require('R1 verified update' in self.curl(record,'/hello-world/'),'WordPress controlled update did not publish')
            else:
                health=json.loads(self.curl(record,'/fixture-route'));require(health['case']==record['id'] and health['rows']==12,'application/database route failed')
                self.curl(record,'/?action=login',dict(password=record['app_password']),cookie)
                require(json.loads(self.curl(record,'/?action=session',cookie=cookie))['authenticated'] is True,'application session did not persist')
                self.helper('application-workflow',self.serializable(record))
                if record['id']=='S02':require(health['composer']=='locked-dependency','locked local Composer dependency was not loaded')
                self.api('/sites/'+str(record['site'])+'/files/save',dict(path='version.txt',content='updated\n',sha256=hashlib.sha256(b'baseline\n').hexdigest()),record['client'])
                require(json.loads(self.curl(record,'/fixture-route'))['version']=='updated','controlled application update failed')
            self.curl(record,'/.secret-note',ok=(403,404))
            self.sftp(record,'get /etc/shadow /dev/null\n',success=False)
            next(case for case in self.state['cases'] if case['id']==record['id']).update(application_workflow_verified=True,actual_fpm_version=runtime['php'])
        s02=self.records[1]
        self.create_cron(s02)
        self.task=int(self.db("SELECT id FROM scheduled_tasks WHERE subscription_id="+str(s02['sub'])+" AND name='R1 cron'"))
        self.run_cron()
        mail=self.records[2];mail['mail_password']=self.password()
        self.api('/sites/'+str(mail['site'])+'/subdomains',dict(label='news',issue_certificate='false'))
        child=int(self.db("SELECT id FROM sites WHERE domain='news."+mail['domain']+"'"));self.wait('SELECT status FROM sites WHERE id='+str(child),'active')
        self.api('/subscriptions/'+str(mail['sub'])+'/mail-domains',dict(site_id=child,enabled='true',dkim='true',dmarc_policy='none'))
        mid=int(self.db('SELECT id FROM mail_domains WHERE site_id='+str(child)))
        self.wait('SELECT convergence_status||\':\'||effective_enabled FROM mail_domains WHERE id='+str(mid),'in_sync:true')
        self.api('/subscriptions/'+str(mail['sub'])+'/mailboxes',dict(mail_domain_id=mid,local_part='preserve',password=mail['mail_password'],quota_mb=32,enabled='true'),mail['client'])
        self.api('/subscriptions/'+str(mail['sub'])+'/mail-aliases',dict(mail_domain_id=mid,local_part='alias',destinations='preserve@news.'+mail['domain']),mail['client'])
        self.wait('SELECT convergence_status||\':\'||effective_enabled FROM mail_domains WHERE id='+str(mid),'in_sync:true')
        self.helper('mail-canary',self.serializable(mail))
        self.passed('R1: real FPM identity, application/WordPress login and sessions, clean URLs, uploads, locked Composer dependency, controlled updates, Run Now cron and a local mail canary')
    def create_cron(self,record):
        self.api('/subscriptions/'+str(record['sub'])+'/scheduled-tasks',dict(site_id=record['site'],name='R1 cron',schedule='0 0 1 1 *',script='cron.php',working_directory='.',timeout_seconds=30,enabled='true',kind='php',timezone='UTC'))
    def run_cron(self):
        record=self.records[1];self.api('/subscriptions/'+str(record['sub'])+'/scheduled-tasks/'+str(self.task)+'/run',{})
        self.until(lambda:self.db('SELECT status FROM scheduled_task_runs WHERE task_id='+str(self.task)+' ORDER BY id DESC LIMIT 1'),lambda value:value in ('succeeded','failed','timed_out'),'scheduled task terminal result')
        run=json.loads(self.db("SELECT json_build_object('id',id,'status',status,'exit_code',exit_code,'output',left(output,2000)) FROM scheduled_task_runs WHERE task_id="+str(self.task)+' ORDER BY id DESC LIMIT 1'))
        run['output']=redact(run.get('output') or '',self.secret_values);self.state.setdefault('cron_runs',[]).append(run)
        require(run['status']=='succeeded','scheduled task failed: '+json.dumps(run))
        result=self.helper('cron-result',self.serializable(record));require(result['uid']==record['uid'] and result['php']==record['source_php'] and result['marker']=='R1-CRON' and result['runs']==len(self.state['cron_runs']),'scheduled task ran with the wrong account/runtime, marker or execution count')
    def preserve(self):
        self.stage('R1-tenant-boundaries-backups-and-reboot')
        for record in self.records:
            foreign=next(other for other in self.records if other['id']!=record['id'])
            self.api('/sites/'+str(foreign['site'])+'/files',client=record['client'],ok=(404,))
            self.helper('boundaries',dict(own=self.serializable(record),foreign=self.serializable(foreign)))
            self.api('/backups',dict(subscription_id=record['sub'],domain=record['domain']))
            self.until(lambda:self.db('SELECT count(*) FROM backups WHERE site_id='+str(record['site'])+" AND status='active' AND checksum_sha256<>''"),lambda value:value=='1','verified site backup')
            record['baseline']=self.helper('snapshot',self.serializable(record))
        self.shell('assert_current_vm_identity');self.cmd(['multipass','restart',self.vm],timeout=240)
        self.until(lambda:self.guest('bash','-c','systemctl is-active nakpanel nakpanel-agent nginx mariadb postgresql stalwart-mail || true').splitlines(),lambda values:len(values)==6 and all(value=='active' for value in values),'unassisted service boot')
        self.shell('assert_current_vm_identity');self.shell('assert_qualification_installed_release')
        self.containment(['root']+[record['username'] for record in self.records])
        self.verify_dns_denial()
        self.state['offline_php_startup_after_reboot']=self.helper('offline-dns-check')
        require(self.helper('runtimes')==self.state['runtime_inventory'],'runtime inventory changed across reboot')
        for record in self.records:
            current=self.helper('snapshot',self.serializable(record));require(current==record['baseline'],'file/database/mail/backup baseline changed after reboot for '+record['id'])
            runtime=json.loads(self.curl(record,'/rehearsal-runtime.php'));require(runtime['php'].startswith(record['source_php']+'.') and runtime['uid']==record['uid'],'FPM boot persistence failed')
            cookie=self.private/(record['id']+'-app.cookies')
            if record['id']=='S01':
                require('R1 verified update' in self.curl(record,'/hello-world/'),'WordPress/database failed after reboot')
                self.curl(record,'/wp-admin/',cookie=cookie)
            else:
                health=json.loads(self.curl(record,'/fixture-route'))
                require(health['rows']==12 and health['version']=='updated','application/database failed after reboot')
                require(json.loads(self.curl(record,'/?action=session',cookie=cookie))['authenticated'] is True,'application session lost after reboot')
        self.run_cron();self.passed('R1: cross-tenant file/API/SQL denials; three verified local backups; unassisted reboot retained files/data/mail/backups, all runtimes and containment; cron ran again')
    def run(self):
        self.bootstrap();self.provision();self.imports();self.workloads();self.preserve()
        self.state.update(status='PASS',completed_at=time.time(),R0='PASS',R1='PASS',excluded=['installed Plesk source extraction','R2','R3 mail import/catch-up','R4 public DNS/TLS transition','R5 restore/write-aware rollback','real customers','production qualification'])
        write(self.evidence/'result.json',self.state)


def cleanup():
    shared.hosted_guard();token='p2-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']
    base=Path(os.environ['RUNNER_TEMP']);private=base/'plesk-rehearsal-private';owners=private/'owners';status=0;count=0
    env=dict(os.environ,NAKPANEL_RUN_TOKEN=token,NAKPANEL_OWNERSHIP_DIR=str(owners),NAKPANEL_MULTIPASS_IMAGE='26.04',NAKPANEL_MULTIPASS_ARCH='amd64',NAKPANEL_QUALIFICATION_PHP_PROVIDER='sury')
    for record in (owners/token).glob('nakpanel-*'):
        if not record.is_file() or record.name.endswith('.image.json'):continue
        count+=1
        result=subprocess.run(['bash','-c','set -euo pipefail; source "$1"; destroy_owned_vm "$2" "$3"','_',str(SOURCE/'deploy/multipass/common.sh'),record.name,token],env=env,timeout=180)
        if result.returncode:status=1
    firewall=private/'firewall.json'
    if firewall.exists() and status==0:
        identity=json.loads(firewall.read_text());require(identity['token']==token and identity['table']==token.replace('-','_'),'cleanup ownership differs')
        result=subprocess.run(['sudo','nft','delete','table','inet',identity['table']],capture_output=True)
        if result.returncode:status=1
    evidence=base/'plesk-rehearsal-evidence';evidence.mkdir(mode=0o700,exist_ok=True)
    write(evidence/'cleanup.json',dict(owned_records=count,exit_code=status,firewall_removed=firewall.exists() and status==0))
    require(status==0,'owned rehearsal cleanup failed')


if __name__=='__main__':
    drill=None
    try:
        if sys.argv[1]=='prepare':prepare(sys.argv[2])
        elif sys.argv[1]=='run':drill=Drill();drill.run()
        elif sys.argv[1]=='cleanup':cleanup()
        else:raise ValueError('select prepare, run or cleanup')
    except Exception as error:
        if drill:
            signal.alarm(0);drill.capture_failure()
            drill.state.update(status='FAIL',error=redact(str(error),drill.secret_values));write(drill.evidence/'result.json',drill.state)
        print(redact(traceback.format_exc(),drill.secret_values if drill else []),file=sys.stderr);raise SystemExit(1)
    finally:signal.alarm(0)
