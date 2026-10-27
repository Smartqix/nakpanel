#!/usr/bin/env python3
"""Owned guest fixture operations. Input is private JSON on stdin; output is bounded metadata."""
import base64, hashlib, json, os, pwd, re, shutil, smtplib, ssl, stat, subprocess, sys, time, zipfile
from pathlib import Path
import imaplib


def require(value, message):
    if not value: raise ValueError(message)


def service_certificate_path(value):
    match=re.fullmatch(r'%\{file:([^}]+)\}%',value)
    require(match,'unexpected Stalwart certificate source')
    target=Path(match.group(1))
    require(target.is_absolute() and '..' not in target.parts and (target.is_relative_to('/etc/stalwart') or target.is_relative_to('/etc/nakpanel')),'unexpected service certificate path')
    return target


def sandbox_negative_zones(search):
    require(len(search)<=6,'too many private DNS search suffixes')
    for name in search:
        require(len(name)<=220 and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*',name),'unsafe private DNS search suffix')
    return ['telemetry.sury.org']+['telemetry.sury.org.'+name for name in dict.fromkeys(search)]


def verify_sql_export(expected, observed):
    require(bool(expected) and expected==observed,'logical SQL row contents differ from source')
    return hashlib.sha256(observed.encode()).hexdigest()


def logical_dump(database):
    return run(['mariadb-dump','--skip-comments','--skip-lock-tables','--skip-add-locks','--skip-extended-insert','--hex-blob','--order-by-primary',database])


def run(args, data=None, env=None):
    try:result=subprocess.run(args,input=data,text=True,capture_output=True,timeout=180,env=env)
    except subprocess.TimeoutExpired as error:
        def stream(value):return value.decode(errors='replace') if isinstance(value,bytes) else value or ''
        raise ValueError('fixture child timed out: '+Path(args[0]).name+': '+stream(error.stdout)[-1000:]+stream(error.stderr)[-1500:]) from error
    if result.returncode: raise ValueError('fixture command failed: '+Path(args[0]).name+': '+result.stderr[-1500:])
    return result.stdout


def file_manifest(root, owner=False):
    values={}
    for path in sorted(root.rglob('*')):
        info=path.lstat()
        if stat.S_ISLNK(info.st_mode): entry=dict(type='link',target=os.readlink(path),mode=stat.S_IMODE(info.st_mode))
        elif stat.S_ISREG(info.st_mode):entry=dict(type='file',sha256=hashlib.sha256(path.read_bytes()).hexdigest(),mode=stat.S_IMODE(info.st_mode))
        elif stat.S_ISDIR(info.st_mode):entry=dict(type='directory',mode=stat.S_IMODE(info.st_mode))
        else:raise ValueError('unexpected fixture file type')
        if owner:entry['uid']=info.st_uid
        values[str(path.relative_to(root))]=entry
    return values


def mysql(query, database=None, defaults=None):
    args=['mariadb']
    if defaults:args+=['--defaults-extra-file='+str(defaults)]
    args+=['--batch','--skip-column-names']
    if database:args+=[database]
    return run(args,data=query)


def config_php(record, db, user, password, wordpress=False):
    if not wordpress:
        value=dict(database=db,user=user,password=password,case=record['id'],application_password=record['app_password'])
        return '<?php return json_decode(base64_decode('+json.dumps(base64.b64encode(json.dumps(value).encode()).decode())+'),true);\n'
    values=dict(DB_NAME=db,DB_USER=user,DB_PASSWORD=password,DB_HOST='localhost',DB_CHARSET='utf8mb4',DB_COLLATE='',WP_HOME='https://'+record['domain'],WP_SITEURL='https://'+record['domain'])
    result='<?php\n'+''.join('define('+json.dumps(key)+','+json.dumps(value)+');\n' for key,value in values.items())
    result+="define('DISABLE_WP_CRON',true);define('AUTOMATIC_UPDATER_DISABLED',true);define('WP_HTTP_BLOCK_EXTERNAL',true);define('WP_DEBUG',false);\n"
    result+="$table_prefix='wp_';define('ABSPATH',__DIR__.'/');require_once ABSPATH.'wp-settings.php';\n"
    return result


MEDIA_PNG = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC')

APP = r'''<?php
session_start(['cookie_secure'=>true,'cookie_httponly'=>true]);
$c=require __DIR__.'/.private-config.php';
header('Content-Type: application/json');
$action=$_GET['action']??'health';
if($action==='login'){if(!hash_equals($c['application_password'],$_POST['password']??'')){http_response_code(403);exit;}$_SESSION['authenticated']=true;echo json_encode(['authenticated'=>true]);exit;}
if($action==='session'){echo json_encode(['authenticated'=>$_SESSION['authenticated']??false]);exit;}
if($action==='upload'){if(empty($_SESSION['authenticated'])){http_response_code(403);exit;}if(!is_dir(__DIR__.'/uploads'))mkdir(__DIR__.'/uploads',0755);$p=__DIR__.'/uploads/r1-upload.txt';if(!move_uploaded_file($_FILES['upload']['tmp_name'],$p)){http_response_code(500);exit;}echo json_encode(['sha256'=>hash_file('sha256',$p)]);exit;}
if(file_exists(__DIR__.'/vendor/autoload.php'))require __DIR__.'/vendor/autoload.php';
$m=new mysqli('localhost',$c['user'],$c['password'],$c['database']);$row=$m->query('SELECT count(*) n FROM records')->fetch_assoc();
echo json_encode(['case'=>$c['case'],'rows'=>(int)$row['n'],'version'=>trim(file_get_contents(__DIR__.'/version.txt')),'composer'=>class_exists('Synthetic\\Greeting')?Synthetic\Greeting::value():null]);
'''
RUNTIME = "<?php header('Content-Type: application/json');echo json_encode(['php'=>PHP_VERSION,'uid'=>posix_geteuid(),'extensions'=>get_loaded_extensions()]);\n"
CRON = "<?php $p=__DIR__.'/cron-result.json';$n=1;if(is_file($p)){$old=json_decode(file_get_contents($p),true,512,JSON_THROW_ON_ERROR);if(!is_int($old['runs']??null))throw new RuntimeException('Invalid canary counter');$n=$old['runs']+1;}file_put_contents($p,json_encode(['uid'=>posix_geteuid(),'php'=>PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION,'marker'=>'R1-CRON','runs'=>$n],JSON_THROW_ON_ERROR));\n"


class Fixture:
    def __init__(self, payload):
        self.token=payload['token'];require(re.fullmatch(r'p2-[0-9]+-[0-9]+',self.token),'invalid fixture ownership')
        self.base=Path('/var/lib/nakpanel-qualification')/self.token;require(self.base.is_dir(),'owned qualification root missing')
        self.private=self.base/'fixtures';self.private.mkdir(mode=0o700,exist_ok=True)
        self.record=payload.get('record',{})
    def progress(self,operation):
        (self.private/'progress.json').write_text(json.dumps(dict(case=self.record.get('id'),operation=operation,time=time.time())))
    def check_record(self, record=None):
        record=record or self.record
        require(record.get('id') in ('S01','S02','S03') and re.fullmatch(r'[a-z0-9-]+\.test',record['domain']),'unapproved case')
        require(record['source_php'] in ('8.3','8.4','8.5') and re.fullmatch(r'nps[0-9]+',record['username']),'unsupported runtime/account')
        root=Path(record['root']);require(root==Path('/home')/record['username']/'domains'/record['domain']/'public_html','target path differs from subscription identity')
        require(pwd.getpwnam(record['username']).pw_uid==record['uid'],'target UID differs')
        require(re.fullmatch(r'p2_s0[123]',record['db_name']) and record['db_user']==record['db_name'],'unsafe target database')
        return root
    def cert(self,name,sans,output,full_chain=True):
        ca=self.base/'fixture-ca';output.parent.mkdir(mode=0o750,parents=True,exist_ok=True)
        key=output.with_suffix('.key');csr=output.with_suffix('.csr');crt=output.with_suffix('.crt');ext=output.with_suffix('.ext')
        run(['openssl','ecparam','-genkey','-name','prime256v1','-out',str(key)])
        run(['openssl','req','-new','-key',str(key),'-subj','/CN='+name,'-out',str(csr)])
        ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName='+sans+'\n')
        run(['openssl','x509','-req','-in',str(csr),'-CA',str(ca/'root.crt'),'-CAkey',str(ca/'root.key'),'-CAcreateserial','-days','3','-sha256','-extfile',str(ext),'-out',str(crt)])
        if full_chain:crt.write_text(crt.read_text()+(ca/'root.crt').read_text())
        key.chmod(0o600)
        return crt,key
    def trust(self):
        import ipaddress,tomllib
        ip=str(ipaddress.ip_address(self.record['ip']));ca=self.base/'fixture-ca';ca.mkdir(mode=0o700)
        run(['openssl','ecparam','-genkey','-name','prime256v1','-out',str(ca/'root.key')]);(ca/'root.key').chmod(0o600)
        run(['openssl','req','-x509','-new','-key',str(ca/'root.key'),'-days','3','-sha256','-subj','/CN=Nakpanel R0 isolated fixture','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-out',str(ca/'root.crt')])
        shutil.copyfile(ca/'root.crt','/usr/local/share/ca-certificates/plesk-r0-fixture.crt');run(['update-ca-certificates'])
        crt,key=self.cert('rehearsal-panel.test','IP:'+ip+',IP:127.0.0.1',ca/'panel')
        account=pwd.getpwnam('nakpanel')
        for source,target,mode in ((crt,Path('/var/lib/nakpanel/tls/panel.crt'),0o644),(key,Path('/var/lib/nakpanel/tls/panel.key'),0o600)):
            shutil.copyfile(source,target);os.chown(target,account.pw_uid,account.pw_gid);target.chmod(mode)
        config=tomllib.loads(Path('/etc/stalwart/config.toml').read_text());crt,key=self.cert('mail.rehearsal.test','DNS:mail.rehearsal.test,IP:127.0.0.1',ca/'mail')
        for field,source,mode in (('cert',crt,0o644),('private-key',key,0o600)):
            target=service_certificate_path(config['certificate']['default'][field])
            shutil.copyfile(source,target);target.chmod(mode)
        run(['systemctl','restart','nakpanel','stalwart-mail']);return {'trusted_fixture_certificates':True}
    def runtimes(self):
        source=(self.base/'source/internal/agent/ops/php_capabilities.go').read_text()
        required=re.findall(r'"([^"]+)"',re.search(r'var requiredPHPExtensions = \[\]string\{(.*?)\}',source,re.S).group(1));result={}
        for minor in ('8.3','8.4','8.5'):
            data=json.loads(run(['/usr/bin/php'+minor,'-r','echo json_encode([PHP_VERSION,get_loaded_extensions()]);']))
            require(data[0].startswith(minor+'.') and set(name.lower() for name in required)<=set(name.lower() for name in data[1]),'CLI runtime extensions unavailable')
            fpm=run(['/usr/sbin/php-fpm'+minor,'-i']);require(all(re.search(r'^'+re.escape(name)+r'\s*$',fpm,re.I|re.M) for name in required),'FPM extension unavailable')
            result[minor]=dict(version=data[0],extensions=sorted(data[1]),fpm_extensions_verified=True)
        return result
    def offline_dns(self):
        search=[]
        for line in Path('/etc/resolv.conf').read_text().splitlines():
            fields=line.split()
            if fields and fields[0] in ('search','domain'):search.extend(name.lower().rstrip('.') for name in fields[1:] if name!='.')
        zones=sandbox_negative_zones(search)
        config=Path('/etc/bind')/('nakpanel-rehearsal-'+self.token+'.conf')
        require(not config.exists(),'private DNS configuration already exists')
        entries=[]
        for index,zone in enumerate(zones):
            file=Path('/etc/bind')/('db.rehearsal-'+self.token+'-'+str(index))
            file.write_text('$TTL 60\n@ IN SOA ns.'+zone+'. hostmaster.invalid. (1 60 60 60 60)\n@ IN NS ns.'+zone+'.\nns IN A 127.0.0.1\n');file.chmod(0o644)
            run(['named-checkzone',zone,str(file)])
            entries.append('zone "'+zone+'" { type master; file "'+str(file)+'"; };')
        config.write_text('\n'.join(entries)+'\n');config.chmod(0o644)
        main=Path('/etc/bind/named.conf');original=main.read_text();(self.private/'named.conf.original').write_text(original)
        main.write_text(original+'\n// Owned synthetic rehearsal '+self.token+'\ninclude "'+str(config)+'";\n')
        run(['named-checkconf']);run(['systemctl','reload','named'])
        directory=Path('/etc/systemd/resolved.conf.d');directory.mkdir(mode=0o755,exist_ok=True)
        file=directory/('99-nakpanel-rehearsal-'+self.token+'.conf')
        file.write_text('[Resolve]\nDNS=\nDNS=127.0.0.1\nFallbackDNS=\nDomains=\nDomains=~. '+ ' '.join('~'+name for name in search)+'\n');file.chmod(0o644)
        anchors=Path('/etc/dnssec-trust-anchors.d');anchors.mkdir(mode=0o755,exist_ok=True)
        anchor=anchors/('99-nakpanel-rehearsal-'+self.token+'.negative');anchor.write_text('\n'.join(zones+['test'])+'\n');anchor.chmod(0o644)
        run(['systemctl','restart','systemd-resolved'])
        data=json.loads((self.base/'source/docs/migration/fixtures/plesk-customers.synthetic.json').read_text())
        domains=[case['domain'] for case in data['cases'] if case['id'] in ('S01','S02','S03')]+['news.meadow-blog.test','mail.rehearsal.test']
        require(all(re.fullmatch(r'[a-z0-9.-]+\.test',name) for name in domains),'unsafe private hosts name')
        with Path('/etc/hosts').open('a') as stream:stream.write('\n# Owned synthetic rehearsal '+self.token+'\n127.0.0.1 '+' '.join(domains)+'\n')
        return dict(negative_zones=zones,private_hosts=domains)
    def offline_dns_check(self):
        import socket
        started=time.monotonic();denied=False
        try:socket.getaddrinfo('telemetry.sury.org',53,type=socket.SOCK_DGRAM)
        except socket.gaierror:denied=True
        elapsed=time.monotonic()-started
        require(denied and elapsed<2,'provider telemetry DNS did not fail locally and promptly')
        fpm={}
        for minor in ('8.3','8.4','8.5'):
            start=time.monotonic();run(['/usr/sbin/php-fpm'+minor,'-t']);fpm[minor]=round(time.monotonic()-start,3)
            require(fpm[minor]<2.5,'offline PHP-FPM initialization exceeded its normal readiness budget')
        return dict(telemetry_resolution_denied=True,dns_seconds=round(elapsed,3),fpm_config_seconds=fpm)
    def containment_dns(self):
        import socket,ipaddress
        route=json.loads(run(['ip','-j','route','get','1.1.1.1']))[0]
        gateway=str(ipaddress.ip_address(route['gateway']))
        name=self.token+'.test';question=b''.join(bytes([len(label)])+label.encode() for label in name.split('.'))+b'\x00'
        packet=b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+question+b'\x00\x01\x00\x01'
        started=time.monotonic();blocked=False;code=None;response=None;source=None
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            try:client.connect((gateway,53));client.send(packet);response=client.recv(512)
            except OSError as error:code=error.errno;blocked=code in (1,13,101,111,113)
            source=client.getsockname()
        return dict(blocked_immediately=blocked,errno=code,elapsed_seconds=round(time.monotonic()-started,3),gateway=gateway,source=source,response_bytes=len(response) if response is not None else None)
    def certificate(self):
        self.check_record();record=self.record
        output=Path('/run/plesk-rehearsal-certificates')/record['id'];crt,key=self.cert(record['domain'],'DNS:'+record['domain'],output,full_chain=False)
        account=pwd.getpwnam('nakpanel');os.chown(output.parent,0,account.pw_gid);output.parent.chmod(0o750);os.chown(key,account.pw_uid,account.pw_gid)
        return {'created':True}
    def wp(self,root,args,record=None,stdin=None,source=False):
        record=record or self.record
        self.progress('WordPress '+ ' '.join(args[:2]))
        command=['env','WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1','WP_CLI_CONFIG_PATH=/dev/null','/usr/bin/php'+record['source_php'],'/usr/local/lib/nakpanel/wp-cli.phar','--path='+str(root)]
        if source:command+=['--allow-root']
        else:command=['sudo','-u',record['username'],*command]
        return run(command+args,data=stdin)
    def source(self):
        self.progress('source database and files')
        target=self.check_record();record=self.record;work=self.private/record['id'];work.mkdir(mode=0o700);source=work/'source';source.mkdir(mode=0o700)
        db='p2_src_'+record['id'].lower();password=record['db_password']
        require(mysql("SELECT count(*) FROM information_schema.schemata WHERE schema_name='"+db+"'").strip()=='0','source schema already exists')
        mysql("CREATE DATABASE "+db+" CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER '"+db+"'@'localhost' IDENTIFIED BY '"+password+"'; GRANT ALL ON "+db+".* TO '"+db+"'@'localhost';")
        wordpress=record['id']=='S01'
        if wordpress:
            with zipfile.ZipFile('/tmp/'+self.token+'-wordpress.zip') as archive:
                for item in archive.infolist():
                    path=Path(item.filename);require(path.parts[0]=='wordpress' and '..' not in path.parts and not path.is_absolute(),'unsafe WordPress source path')
                    relative=Path(*path.parts[1:]);destination=source/relative
                    if item.is_dir():destination.mkdir(parents=True,exist_ok=True)
                    else:destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(archive.read(item))
            (source/'wp-config.php').write_text(config_php(record,db,db,password,True))
            plugins=source/'wp-content/mu-plugins';plugins.mkdir(exist_ok=True)
            (plugins/'r1-contained.php').write_text("<?php add_filter('pre_wp_mail','__return_false');add_filter('pre_http_request',function(){return new WP_Error('r1_contained','HTTP disabled in synthetic rehearsal');});add_action('r1_canary',function(){file_put_contents(ABSPATH.'wp-content/r1-cron.txt','R1-WP-CRON');});\n")
            self.wp(source,['core','install','--url=https://'+record['domain'],'--title=R1 Synthetic WordPress','--admin_user=rehearsal','--admin_email=owner@'+record['domain'],'--skip-email','--prompt=admin_password'],stdin=record['wp_password']+'\n',source=True)
            self.wp(source,['rewrite','structure','/%postname%/'],source=True)
        else:
            (source/'index.php').write_text(APP);(source/'.private-config.php').write_text(config_php(record,db,db,password));(source/'version.txt').write_text('baseline\n');(source/'cron.php').write_text(CRON)
            mysql("CREATE TABLE records(id int PRIMARY KEY,label varchar(64));"+''.join("INSERT INTO records VALUES ("+str(i)+",'"+record['id']+"-row-"+str(i)+"');" for i in range(1,13)),db)
            if record['id']=='S02':
                package=source/'packages/rehearsal-lib';package.mkdir(parents=True)
                (package/'composer.json').write_text(json.dumps({'name':'synthetic/rehearsal-lib','version':'1.0.0','autoload':{'psr-4':{'Synthetic\\':'src/'}}}))
                (package/'src').mkdir();(package/'src/Greeting.php').write_text("<?php namespace Synthetic; class Greeting {public static function value(){return 'locked-dependency';}}\n")
                (source/'composer.json').write_text(json.dumps({'name':'synthetic/r1-app','require':{'synthetic/rehearsal-lib':'1.0.0'},'repositories':[{'type':'path','url':'packages/rehearsal-lib','options':{'symlink':False}}]}))
                env=dict(os.environ,COMPOSER_DISABLE_NETWORK='1',COMPOSER_ALLOW_SUPERUSER='1',COMPOSER_HOME=str(work/'composer-home'))
                run(['/usr/bin/php8.4','/usr/local/lib/nakpanel/composer.phar','--working-dir='+str(source),'update','--no-scripts','--no-plugins','--no-interaction','--no-progress'],env=env)
        (source/'files').mkdir(exist_ok=True);(source/'files/content.txt').write_text('R1 nonempty file canary '+record['id']+'\n');(source/'.secret-note').write_text('R1 private fixture '+record['id']+'\n');(source/'rehearsal-runtime.php').write_text(RUNTIME)
        (source/'content-link.txt').symlink_to('files/content.txt')
        self.progress('source SQL export and archive')
        sql=work/'export.sql';sql.write_text(logical_dump(db));require(sql.stat().st_size>100,'source database export is empty')
        export=work/'export';shutil.copytree(source,export,symlinks=True)
        config=export/('wp-config.php' if wordpress else '.private-config.php');config.write_text(config_php(record,record['db_name'],record['db_user'],record['db_password'],wordpress))
        for path in export.rglob('*'):
            if not path.is_symlink():path.chmod(0o755 if path.is_dir() else 0o644)
        config.chmod(0o600);(export/'.secret-note').chmod(0o640)
        manifest=file_manifest(export)
        (work/'manifest.json').write_text(json.dumps(manifest,sort_keys=True));(work/'source-manifest.json').write_text(json.dumps(file_manifest(source),sort_keys=True))
        archive=Path('/tmp')/(self.token+'-'+record['id']+'.zip')
        with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as stream:
            for path in export.rglob('*'):
                if not path.is_symlink():stream.write(path,str(path.relative_to(export)))
        ubuntu=pwd.getpwnam('ubuntu');os.chown(archive,ubuntu.pw_uid,ubuntu.pw_gid);archive.chmod(0o600)
        return dict(archive=str(archive),archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),manifest=manifest,manifest_sha256=hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest(),sql_sha256=hashlib.sha256(sql.read_bytes()).hexdigest(),configuration_mapping=['database name','database user','database password'],source_kind='private synthetic logical export; not installed Plesk')
    def credentials(self,record=None):
        record=record or self.record;self.check_record(record)
        directory=Path('/run/plesk-rehearsal-clients');directory.mkdir(mode=0o755,exist_ok=True);file=directory/(record['id']+'.cnf')
        file.write_text('[client]\nuser='+record['db_user']+'\npassword='+record['db_password']+'\nprotocol=socket\n');file.chmod(0o600);account=pwd.getpwnam(record['username']);os.chown(file,account.pw_uid,account.pw_gid)
        return file
    def import_sql(self):
        self.check_record();record=self.record;defaults=self.credentials();sql=self.private/record['id']/'export.sql'
        run(['sudo','-u',record['username'],'mariadb','--defaults-extra-file='+str(defaults),record['db_name']],data=sql.read_text())
        source='p2_src_'+record['id'].lower()
        source_rows=mysql('SELECT table_name,table_rows FROM information_schema.tables WHERE table_schema=\''+source+'\' ORDER BY table_name').strip()
        target_rows=mysql('SELECT table_name,table_rows FROM information_schema.tables WHERE table_schema=\''+record['db_name']+'\' ORDER BY table_name').strip()
        require(source_rows.splitlines() and [line.split('\t')[0] for line in source_rows.splitlines()]==[line.split('\t')[0] for line in target_rows.splitlines()],'table inventory differs')
        for table in (line.split('\t')[0] for line in source_rows.splitlines()):
            require(re.fullmatch(r'[a-z0-9_]+',table),'unsafe fixture table')
            require(mysql('SELECT COUNT(*) FROM '+table,source)==mysql('SELECT COUNT(*) FROM '+table,record['db_name']),'row count differs')
        for schema in (source,record['db_name']):require(mysql("SELECT count(*) FROM information_schema.routines WHERE routine_schema='"+schema+"'").strip()=='0','unexpected fixture routine')
        digest=verify_sql_export(sql.read_text(),logical_dump(record['db_name']))
        return {'logical_import_verified':True,'routines':0,'source_and_target_sql_sha256':digest}
    def manifest(self):return file_manifest(self.check_record(),True)
    def application_workflow(self):
        root=self.check_record();record=self.record;work=self.private/record['id']
        if record['id']=='S02':
            env=dict(os.environ,COMPOSER_DISABLE_NETWORK='1',COMPOSER_HOME='/home/'+record['username']+'/.cache/composer/r1')
            run(['sudo','-u',record['username'],'env','COMPOSER_DISABLE_NETWORK=1','COMPOSER_HOME='+env['COMPOSER_HOME'],'/usr/bin/php8.4','/usr/local/lib/nakpanel/composer.phar','--working-dir='+str(root),'install','--no-scripts','--no-plugins','--no-interaction','--no-progress'])
        upload=Path('/tmp')/(self.token+'-'+record['id']+'-upload.txt');body='R1 upload '+record['id']+'\n';upload.write_text(body);upload.chmod(0o644)
        cookie=work/'app-cookies'
        args=['curl','--silent','--show-error','--fail','--max-time','30','--cacert','/usr/local/share/ca-certificates/plesk-r0-fixture.crt','--resolve',record['domain']+':443:127.0.0.1','-b',str(cookie),'-c',str(cookie)]
        run(args+['--data-binary','@-','https://'+record['domain']+'/?action=login'],data='password='+record['app_password'])
        result=json.loads(run(args+['-F','upload=@'+str(upload),'https://'+record['domain']+'/?action=upload']))
        require(result['sha256']==hashlib.sha256(body.encode()).hexdigest(),'upload bytes changed')
        return {'application_upload_verified':True}
    def wordpress_workflow(self):
        root=self.check_record();record=self.record
        require(self.wp(root,['core','version']).strip()=='7.1','WordPress source version differs')
        image=Path('/tmp')/(self.token+'-media.png');image.write_bytes(MEDIA_PNG);image.chmod(0o644)
        media=self.wp(root,['media','import',str(image),'--porcelain']).strip();require(media.isdecimal(),'WordPress media import failed')
        relative=self.wp(root,['post','meta','get',media,'_wp_attached_file']).strip();stored=(root/'wp-content/uploads'/relative).resolve()
        require(stored.is_relative_to((root/'wp-content/uploads').resolve()) and stored.is_file() and hashlib.sha256(stored.read_bytes()).digest()==hashlib.sha256(MEDIA_PNG).digest(),'WordPress imported media bytes differ')
        self.wp(root,['post','update','1','--post_title=R1 verified update'])
        self.wp(root,['cron','event','schedule','r1_canary','now']);self.wp(root,['cron','event','run','r1_canary'])
        require((root/'wp-content/r1-cron.txt').read_text()=='R1-WP-CRON','WordPress cron canary missing')
        return {'wordpress':'7.1','media_id':int(media),'controlled_update':True,'cron':True}
    def cron_result(self):return json.loads((self.check_record()/'cron-result.json').read_text())
    def mail_canary(self):
        self.check_record();record=self.record;address='preserve@news.'+record['domain'];alias='alias@news.'+record['domain'];body=('From: '+address+'\r\nTo: '+alias+'\r\nSubject: R1 local canary\r\nMessage-ID: <'+self.token+'@rehearsal.test>\r\n\r\nR1 LOCAL CANARY '+self.token+'\r\n').encode()
        with smtplib.SMTP_SSL('127.0.0.1',465,context=ssl.create_default_context(),timeout=20) as smtp:smtp.login(address,record['mail_password']);smtp.sendmail(address,[alias],body)
        state=self.private/'mail-canary.json';state.write_text(json.dumps(dict(address=address,password=record['mail_password'],message_id=self.token,body_sha256=None)));state.chmod(0o600)
        return self.mail_snapshot()
    def mail_snapshot(self):
        path=self.private/'mail-canary.json'
        if not path.exists():return None
        record=json.loads(path.read_text())
        with imaplib.IMAP4_SSL('127.0.0.1',993,ssl_context=ssl.create_default_context(),timeout=20) as imap:
            imap.login(record['address'],record['password']);end=time.monotonic()+30
            while True:
                imap.select('INBOX');status,ids=imap.uid('search',None,'ALL')
                if status=='OK' and len(ids[0].split())==1:break
                require(time.monotonic()<end,'local mail canary not uniquely present');time.sleep(1)
            uid=ids[0].split()[0];status,data=imap.uid('fetch',uid,'(BODY.PEEK[])');require(status=='OK','mail canary unreadable');body=next(part[1] for part in data if isinstance(part,tuple))
            if record['body_sha256'] is None:
                require(('R1 LOCAL CANARY '+self.token).encode() in body,'delivered canary content missing')
                record['body_sha256']=hashlib.sha256(body).hexdigest();path.write_text(json.dumps(record))
            require(hashlib.sha256(body).hexdigest()==record['body_sha256'],'mail canary bytes changed')
            return dict(uid=uid.decode(),sha256=record['body_sha256'])
    def boundaries(self):
        own=self.record['own'];foreign=self.record['foreign'];self.check_record(own);foreign_root=self.check_record(foreign)
        probe=run(['sudo','-u',own['username'],'python3','-c','import pathlib,sys\ntry:pathlib.Path(sys.argv[1]).read_bytes()\nexcept PermissionError:print("DENIED")\nelse:raise SystemExit("cross-tenant file read succeeded")',str(foreign_root/'.secret-note')]);require(probe.strip()=='DENIED','filesystem boundary failed')
        defaults=self.credentials(own);result=subprocess.run(['sudo','-u',own['username'],'mariadb','--defaults-extra-file='+str(defaults),'-e','SELECT COUNT(*) FROM '+foreign['db_name']+'.'+('wp_options' if foreign['id']=='S01' else 'records')],text=True,capture_output=True,timeout=20)
        require(result.returncode!=0 and 'denied' in result.stderr.lower(),'database grant boundary failed');return {'filesystem_and_database_denied':True}
    def snapshot(self):
        root=self.check_record();record=self.record
        sql=logical_dump(record['db_name'])
        row=run(['sudo','-u','postgres','psql','-XqAt','-d','nakpanel','-c',"SELECT archive_path||'|'||checksum_sha256 FROM backups WHERE site_id="+str(record['site'])+" AND status='active' ORDER BY id DESC LIMIT 1"]).strip();archive,digest=row.split('|');require(hashlib.sha256(Path(archive).read_bytes()).hexdigest()==digest,'backup archive changed')
        source=self.private/record['id']/'source';old=json.loads((self.private/record['id']/'source-manifest.json').read_text());require(file_manifest(source)==old,'source fixture changed')
        return dict(files_sha256=hashlib.sha256(json.dumps(file_manifest(root,True),sort_keys=True).encode()).hexdigest(),sql_sha256=hashlib.sha256(sql.encode()).hexdigest(),backup_sha256=digest,source_unchanged=True,mail=self.mail_snapshot() if record['id']=='S03' else None)


if __name__=='__main__':
    payload=json.loads(sys.stdin.read(2<<20));fixture=Fixture(payload)
    action=sys.argv[1].replace('-','_');require(action in ('trust','runtimes','offline_dns','offline_dns_check','containment_dns','certificate','source','import_sql','manifest','application_workflow','wordpress_workflow','cron_result','mail_canary','snapshot','boundaries'),'unapproved fixture action')
    print(json.dumps(getattr(fixture,action)(),sort_keys=True))
