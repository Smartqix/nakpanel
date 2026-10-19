#!/usr/bin/env python3
"""Prepare and verify a concrete, owned Nakpanel logical migration fixture.

Never runs on import. Private JSON is stdin to guest probes, never command-line
credentials. --template emits configuration only; --prepare is an explicit
mutation of an already-owned disposable source, never an ordinary server.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import tarfile
import stat
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
CAPABILITIES = ('fixture-v1', 'install-native-target', 'assert-source-readonly', 'assert-baseline',
    'assert-migration-data', 'assert-services', 'assert-trusted-tls', 'assert-reboot', 'assert-no-source-writes')


def run(args, data=None, env=None):
    result = subprocess.run([str(a) for a in args], input=data, text=True, capture_output=True,
                            env=env, timeout=3600)
    if result.returncode:
        # Child output may contain credentials or tenant records. Keep the stage
        # failure public and the private input bundle available for diagnosis.
        raise RuntimeError('fixture command failed: ' + str(args[0]))
    return result.stdout.strip()


def private_write(path, value):
    path = Path(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        stream.write(value)


def example_spec():
    return {'version': 1, 'source_vm': 'nakpanel-24-04-arm64-CHANGE-ME', 'architecture': 'arm64',
        'run_token': 'CHANGE-ME', 'target_profile': 'ubuntu-26.04-native',
        'remote_src': '', 'admin_email': 'admin@nakpanel.test',
        'admin_password': 'NakpanelAdmin!2026',
        'normalize_php85': False, 'remediate_stale_php82': False,
        'site_id': 0, 'worker_id': 0, 'oci_image_ref': '',
        'database_password': secrets.token_urlsafe(30), 'application_secret': secrets.token_urlsafe(30),
        'ftp_password': secrets.token_urlsafe(30), 'mailbox_password': secrets.token_urlsafe(30),
        'tls_hostname': 'forward-fixture.test'}


def validate_spec(c):
    if c.get('version') != 1 or c.get('architecture') not in ('amd64', 'arm64'):
        raise ValueError('fixture requires version=1 and explicit architecture')
    token = c.get('run_token', '')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{5,63}', token) or 'CHANGE' in token:
        raise ValueError('fixture requires a real ownership run token')
    name = c.get('source_vm', '')
    if not re.fullmatch(r'nakpanel-[A-Za-z0-9._-]+', name) or name in ('nakpanel-lab', 'nakpanel-soak') or 'CHANGE' in name:
        raise ValueError('fixture requires an owned disposable source VM')
    if c.get('target_profile') not in ('ubuntu-26.04-native', 'ubuntu-26.04-sury'):
        raise ValueError('unknown target profile')
    for flag in ('normalize_php85','remediate_stale_php82'):
        if type(c.get(flag,False)) is not bool:
            raise ValueError('fixture '+flag+' must be a boolean')
    if c.get('oci_image_ref') and not re.fullmatch(r'docker\.io/library/nginx@sha256:[a-f0-9]{64}',c['oci_image_ref']):
        raise ValueError('fixture requires an explicit immutable official nginx image or trusted active catalog')
    expected_source='/var/lib/nakpanel-qualification/'+token+'/source'
    if c.get('remote_src') and c['remote_src']!=expected_source:
        raise ValueError('fixture source must use its exact root-owned persistent qualification directory')
    c['remote_src']=expected_source
    for key in ('admin_email', 'admin_password', 'database_password', 'application_secret', 'ftp_password', 'mailbox_password'):
        if not isinstance(c.get(key), str) or not c[key] or '\x00' in c[key] or '\n' in c[key]:
            raise ValueError('missing private fixture field ' + key)
    if not re.fullmatch(r'[a-z0-9][a-z0-9.-]*', c.get('tls_hostname', '')):
        raise ValueError('fixture TLS hostname is required')
    return c


def load_spec(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise ValueError('fixture JSON must be a private regular file (mode 0600)')
    return validate_spec(json.loads(path.read_text()))



def validate_prepared(c):
    validate_spec(c)
    if not isinstance(c.get('baseline'), dict) or not c['baseline']:
        raise ValueError('fixture must be prepared before the source baseline')
    for field in ('intent','identities','files','mariadb','grants','roundcube'):
        if not c['baseline'].get(field):
            raise ValueError('prepared durable inventory is incomplete: ' + field)
    for field in ('site_id','worker_id','subscription_id','oci_id'):
        if not isinstance(c.get(field), int) or c[field] < 1:
            raise ValueError('prepared runtime identity is missing: ' + field)
    for field in ('username','domain','marker','database','database_user','image_ref','guest_ca','volume_file','tenant_file','ftp_username','mailbox','oci_digest','oci_image_id'):
        if not isinstance(c.get(field), str) or not c[field] or any(v in c[field] for v in ('\x00','\n','\r')):
            raise ValueError('prepared runtime inventory is incomplete: ' + field)
    if c.get('worker_php_version') not in ('8.3','8.4','8.5'):
        raise ValueError('prepared actual worker PHP identity is missing')
    if not re.fullmatch(r'[a-f0-9]{64}', c.get('worker_secret_sha256','')):
        raise ValueError('prepared worker secret evidence is missing')
    if not isinstance(c.get('images'),list) or not c['images']:
        raise ValueError('prepared complete OCI image inventory is missing')
    for image in c['images']:
        if not isinstance(image.get('subscription_id'),int) or image['subscription_id'] < 1 or not re.fullmatch(r'[a-z][a-z0-9_-]{2,31}',image.get('username','')) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}',image.get('image_ref','')):
            raise ValueError('prepared OCI image identity or immutable digest is invalid')
    if not re.fullmatch(r'[a-f0-9]{64}', c.get('archive_sha256', '')):
        raise ValueError('prepared fixture archive digest is missing')
    for key in ('archive_file', 'backup_key_file', 'ssh_identity_file', 'ca_file'):
        path = Path(c.get(key, ''))
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size == 0:
            raise ValueError('prepared fixture requires private regular input: ' + key)
    if hashlib.sha256(Path(c['archive_file']).read_bytes()).hexdigest() != c['archive_sha256']:
        raise ValueError('prepared fixture archive digest mismatch')
    for environment, key in [('NAKPANEL_MULTIPASS_SOURCE_VM','source_vm'), ('NAKPANEL_RUN_TOKEN','run_token'), ('NAKPANEL_MULTIPASS_ARCH','architecture')]:
        if os.environ.get(environment) and os.environ[environment] != c[key]:
            raise ValueError('prepared fixture differs from ' + environment)
    for environment, key in [('NAKPANEL_FORWARD_ARCHIVE','archive_file'), ('NAKPANEL_FORWARD_KEY','backup_key_file')]:
        if os.environ.get(environment) and Path(os.environ[environment]).resolve() != Path(c[key]).resolve():
            raise ValueError('prepared fixture differs from ' + environment)
    if c.get('backup_key_sha256') and hashlib.sha256(Path(c['backup_key_file']).read_bytes()).hexdigest() != c['backup_key_sha256']:
        raise ValueError('prepared fixture offline key changed')
    return c


def identity(c, vm, version):
    environment = dict(os.environ, NAKPANEL_RUN_TOKEN=c['run_token'], NAKPANEL_MULTIPASS_ARCH=c['architecture'])
    run(['bash', '-c', 'source "$1"; assert_vm_identity "$2" "$3" "$4" "$5"', '_',
         HERE / 'common.sh', vm, version, c['architecture'], c['run_token']], env=environment)


def probe(c, vm, action):
    program = (HERE / 'ubuntu-forward-migration-probe.py').read_text()
    output = run(['multipass', 'exec', vm, '--', 'sudo', 'python3', '-c', program],
                 json.dumps({'action': action, 'config': c}))
    return json.loads(output)


def guest(c, vm, program, payload=None):
    return run(['multipass', 'exec', vm, '--', 'sudo', 'python3', '-c', program], json.dumps(payload or c))


def compare_snapshots(source, target):
    if source.keys() != target.keys():
        raise ValueError('durable fixture inventory changed')
    for key in source:
        if key == 'grants':
            if not source[key] or not isinstance(target[key], list) or not set(source[key]).issubset(target[key]):
                raise ValueError('tenant grants were lost')
        elif source[key] != target[key]:
            raise ValueError('durable fixture mismatch: ' + key)


def source_unchanged(c):
    identity(c, c['source_vm'], '24.04')
    probe(c, c['source_vm'], 'frozen')
    compare_snapshots(c['baseline'], probe(c, c['source_vm'], 'snapshot'))


def assert_ssh(c, vm):
    # Pin the host key fetched over the separately authenticated, owned VM
    # channel; target-native SSH host keys must not be copied from the source.
    ip = run(['multipass', 'exec', vm, '--', 'hostname', '-I']).split()[0]
    public = run(['multipass', 'exec', vm, '--', 'sudo', 'cat', '/etc/ssh/ssh_host_ed25519_key.pub'])
    with tempfile.TemporaryDirectory(prefix='nakpanel-forward-ssh-') as directory:
        known = Path(directory) / 'known_hosts'
        private_write(known, ip + ' ' + public + '\n')
        args = ['sftp', '-q', '-oBatchMode=yes', '-oStrictHostKeyChecking=yes',
                '-oUserKnownHostsFile=' + str(known), '-oHostKeyAlgorithms=ssh-ed25519',
                '-oConnectTimeout=20', '-i', c['ssh_identity_file'], '-b', '-', c['username'] + '@' + ip]
        output = run(args, 'pwd\nls\n')
        if '/domains/' + c['domain'] + '/public_html' not in output:
            raise ValueError('restored SFTP did not enter its confined domain directory')
        result = subprocess.run(args, input='get /etc/shadow /dev/null\n', text=True, capture_output=True, timeout=30)
        if result.returncode == 0:
            raise ValueError('SFTP escaped the subscription chroot')


def certificates(c):
    program = r'''
import json,os,subprocess,sys,time
from pathlib import Path
c=json.load(sys.stdin);root=Path('/tmp/nakpanel-forward-certs-'+c['run_token']);root.mkdir(mode=0o700)
def x(*a): subprocess.run(a,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
x('openssl','ecparam','-genkey','-name','prime256v1','-out',str(root/'ca.key'))
x('openssl','req','-x509','-new','-key',str(root/'ca.key'),'-sha256','-days','30','-subj','/CN=Nakpanel Forward Fixture Root','-out',str(root/'ca.crt'),'-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
x('openssl','ecparam','-genkey','-name','prime256v1','-out',str(root/'site.key'))
x('openssl','req','-new','-key',str(root/'site.key'),'-subj','/CN='+c['tls_hostname'],'-out',str(root/'site.csr'))
domains=subprocess.check_output(['runuser','-u','postgres','--','psql','-Atqd','nakpanel','-c','SELECT domain FROM sites ORDER BY domain'],text=True).splitlines()
panel_env=Path('/etc/nakpanel/panel.env').read_text() if Path('/etc/nakpanel/panel.env').exists() else ''
domains += [line.split('=',1)[1].strip().strip('\"') for line in panel_env.splitlines() if line.startswith('NAKPANEL_PANEL_HOSTNAME=') and line.split('=',1)[1]]
(root/'site.ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName='+','.join('DNS:'+h for h in sorted(set(domains+[c['tls_hostname']])))+'\n')
x('openssl','x509','-req','-in',str(root/'site.csr'),'-CA',str(root/'ca.crt'),'-CAkey',str(root/'ca.key'),'-CAcreateserial','-days','14','-sha256','-extfile',str(root/'site.ext'),'-out',str(root/'site.crt'))
x('install','-m','0644',str(root/'ca.crt'),'/usr/local/share/ca-certificates/nakpanel-forward-fixture.crt')
x('update-ca-certificates')
x('install','-m','0644',str(root/'ca.crt'),c['guest_ca'])
# The lab's global TLS identity is explicit source fixture preparation. All
# destination services must subsequently retain and trust this archived leaf.
for name in ('panel.crt','server.crt'): x('install','-m','0644',str(root/'site.crt'),'/var/lib/nakpanel/tls/'+name)
for name in ('panel.key','server.key'): x('install','-m','0600',str(root/'site.key'),'/var/lib/nakpanel/tls/'+name)
Path('/var/lib/nakpanel/tls/panel.pem').write_bytes((root/'site.crt').read_bytes()+(root/'site.key').read_bytes());os.chmod('/var/lib/nakpanel/tls/panel.pem',0o600);x('chown','nakpanel:nakpanel','/var/lib/nakpanel/tls/panel.pem')
x('chown','nakpanel:nakpanel',str(root/'site.key'));os.chmod(root,0o755)
x('runuser','-u','nakpanel','--','env','NAKPANEL_DATABASE_URL=postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable','NAKPANEL_AGENT_SOCKET=/run/nakpanel/agent.sock','NAKPANEL_SECRET_KEY_FILE=/etc/nakpanel/secret-keys.json','panelctl','--actor','forward-fixture','ssl','set-custom',c['domain'],'--cert',str(root/'site.crt'),'--key',str(root/'site.key'),'--yes')
for _ in range(120):
 state=subprocess.check_output(['runuser','-u','postgres','--','psql','-Atqd','nakpanel','-c',"SELECT tls_issuer||':'||tls_status FROM sites WHERE id="+str(c['site_id'])],text=True).strip()
 if state=='custom:active': break
 time.sleep(1)
else: raise RuntimeError('custom fixture certificate did not converge')
x('/usr/local/libexec/nakpanel/sync-service-certificates',c['domain'])
x('systemctl','restart','nakpanel.service','stalwart-mail.service','nakpanel-proftpd.service','nginx.service')
print((root/'ca.crt').read_text())
'''
    return guest(c, c['source_vm'], program)


def archive_frozen(c, key):
    # The panel is stopped and databases are read-only. Only the agent remains
    # available, and the peer-gated public backup RPC needs no control-plane SQL
    # mutation or configured archive-key replacement.
    payload = {'id': 'forward-' + c['run_token'], 'op': 'create_server_backup', 'data': {
        'destination': {'kind': 'local', 'settings': {'dir': '/var/lib/nakpanel/server-backups'}},
        'archive_key': base64.b64encode(key).decode(), 'archive_name': 'forward-' + c['run_token'] + '.nkbk',
        'include_mail_data': True}}
    metadata = json.loads(guest(c, c['source_vm'], r'''
import json,subprocess,sys
c=json.load(sys.stdin)
def q(sql): return subprocess.check_output(['runuser','-u','postgres','--','psql','-Atqd','nakpanel','-c',sql],text=True).strip()
print(json.dumps({'databases':q("SELECT db_name FROM databases WHERE engine='mariadb' AND status='active' ORDER BY db_name").splitlines(),'users':q('SELECT username FROM subscription_system_accounts ORDER BY username').splitlines(),'schema':int(q('SELECT max(version_id) FROM goose_db_version')),'version':subprocess.check_output(['panelctl','version'],text=True).strip()}))
'''))
    payload['data'].update(tenant_databases=metadata['databases'], system_users=metadata['users'], goose_version=metadata['schema'], panel_version=metadata['version'])
    rpc_program = '''import json,socket,sys\nr=json.load(sys.stdin)\ns=socket.socket(socket.AF_UNIX);s.settimeout(3600);s.connect('/run/nakpanel/agent.sock');s.sendall((json.dumps(r)+'\\n').encode());f=s.makefile('rb');result=json.load(f);s.close();print(json.dumps(result))'''
    def rpc(request):
        response = json.loads(run(['multipass', 'exec', c['source_vm'], '--', 'sudo', 'runuser', '-u', 'nakpanel', '--', 'python3', '-c', rpc_program], json.dumps(request)))
        if not response.get('ok'): raise RuntimeError('frozen-source backup RPC failed')
        return response['data']
    created = rpc(payload)
    verified = rpc({'id': 'verify-forward-' + c['run_token'], 'op': 'verify_server_backup', 'data': {
        'destination': payload['data']['destination'], 'archive_key': payload['data']['archive_key'],
        'archive_name': created['archive_name'], 'expected_sha256': created['sha256']}})
    if not verified.get('pg_restore_list_ok'): raise ValueError('backup did not verify its actual PostgreSQL archive')
    return created


def seed_roundcube(c):
    environment=dict(os.environ,NAKPANEL_MULTIPASS_VM=c['source_vm'],
        NAKPANEL_MULTIPASS_SOURCE_VM=c['source_vm'],NAKPANEL_MULTIPASS_IMAGE='24.04',
        NAKPANEL_MULTIPASS_ARCH=c['architecture'],NAKPANEL_RUN_TOKEN=c['run_token'],
        NAKPANEL_REMOTE_SRC=c['remote_src'])
    # The root-owned source stays private. The common helper validates it and
    # exposes only the exact canary script to www-data in a recreated /run leaf.
    run(['bash','-c','source "$1"; run_qualification_roundcube_canary "$2" seed "$3"',
         '_',HERE/'common.sh',c['source_vm'],c['mailbox']],env=environment)


def prepare(spec_path, output):
    c = load_spec(spec_path)
    identity(c, c['source_vm'], '24.04')
    # Read-only storage qualification precedes fixture files, PHP normalization,
    # seed mutations and freezing. Never convert an existing webmail backend.
    c.update(probe(c, c['source_vm'], 'source-preflight'))
    output = Path(output).resolve()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(output, 0o700)
    receipt={key:c[key] for key in ('source_vm','run_token','architecture','target_profile')}
    receipt.update(version=1,normalize_php85=c.get('normalize_php85',False),
        remediate_stale_php82=c.get('remediate_stale_php82',False),before_php_inventory=c['prior_php_inventory'])
    def checkpoint(stage,status='running',error_type=None):
        receipt.update(stage=stage,status=status)
        if error_type:receipt['error_type']=error_type
        temporary=output/'.preparation-receipt.next'
        private_write(temporary,json.dumps(receipt,indent=2)+'\n')
        with temporary.open('rb') as stream:os.fsync(stream.fileno())
        os.replace(temporary,output/'preparation-receipt.json')
    checkpoint('read-only-preflight','passed')
    try:
        return prepare_source_fixture(c,output,checkpoint)
    except Exception as error:
        checkpoint(receipt['stage'],'failed',type(error).__name__)
        raise


def prepare_source_fixture(c,output,checkpoint):
    checkpoint('local-input-generation')
    key_path = output / 'sftp-key'
    run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', key_path])
    c['ssh_identity_file'] = str(key_path)
    c['ssh_public_key'] = Path(str(key_path) + '.pub').read_text().strip()
    c['marker'] = 'forward-canary-' + c['run_token']
    c['guest_ca'] = '/etc/nakpanel/forward-fixture-ca.crt'
    checkpoint('source-php-preparation-and-seed')
    c = probe(c, c['source_vm'], 'seed')
    checkpoint('roundcube-canary-seed')
    seed_roundcube(c)
    checkpoint('fixture-certificates')
    private_write(output / 'fixture-ca.crt', certificates(c))
    c['ca_file'] = str(output / 'fixture-ca.crt')
    checkpoint('source-live-checks')
    probe(c, c['source_vm'], 'live')
    probe(c, c['source_vm'], 'tls')
    assert_ssh(c, c['source_vm'])
    checkpoint('freeze-for-backup')
    probe(c, c['source_vm'], 'freeze-for-backup')
    before = probe(c, c['source_vm'], 'snapshot')
    key = secrets.token_bytes(32)
    private_write(output / 'archive.key', 'nkbk1-' + base64.b32encode(key).decode().rstrip('=') + '\n')
    checkpoint('encrypted-backup')
    created = archive_frozen(c, key)
    run(['multipass', 'exec', c['source_vm'], '--', 'sudo', 'systemctl', 'stop', 'nakpanel-agent.service'])
    probe(c, c['source_vm'], 'frozen')
    c['baseline'] = probe(c, c['source_vm'], 'snapshot')
    compare_snapshots(before, c['baseline'])
    checkpoint('offline-export')
    archive_path = output / 'source.nkbk'
    with archive_path.open('wb') as destination:
        os.chmod(archive_path, 0o600)
        result = subprocess.run(['multipass', 'exec', c['source_vm'], '--', 'sudo', 'cat', '/var/lib/nakpanel/server-backups/' + created['archive_name']], stdout=destination, stderr=subprocess.PIPE, timeout=3600)
        if result.returncode: raise RuntimeError('offline archive export failed')
    c['archive_sha256'] = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    if c['archive_sha256'] != created['sha256']: raise ValueError('offline archive digest mismatch')
    c['archive_file'], c['backup_key_file'] = str(archive_path), str(output / 'archive.key')
    c['backup_key_sha256'] = hashlib.sha256((output / 'archive.key').read_bytes()).hexdigest()
    c['valkey_image'] = guest(c, c['source_vm'], "import json,sys;from pathlib import Path;c=json.load(sys.stdin);print(next((s.split('=',1)[1] for s in Path('/etc/nakpanel/agent.env').read_text().splitlines() if s.startswith('NAKPANEL_VALKEY_IMAGE=')),''))")
    private_write(output / 'fixture.json', json.dumps(c, indent=2) + '\n')
    checkpoint('complete','passed')
    print('Prepared frozen-source fixture: ' + str(output / 'fixture.json'))



def stage_target_bundle(bundle, public_key, version, architecture, allow_development='0'):
    """Seal and authenticate exact local inputs before any Multipass action."""
    if architecture not in ('amd64','arm64') or not version or allow_development not in ('0','1'):
        raise ValueError('signed target requires exact version, architecture and explicit 0/1 development opt-in')
    key=Path(public_key)
    if not stat.S_ISREG(key.lstat().st_mode) or not key.stat().st_size:
        raise ValueError('target public key must be a nonempty regular out-of-band file')
    root=Path(tempfile.mkdtemp(prefix='nakpanel-forward-target-'))
    staged=None
    try:
        os.chmod(root,0o700)
        private_write(root/'public.pem',key.read_text())
        staged=Path(run([sys.executable,HERE.parent/'install/stage_bundle.py',bundle]))
        shutil.move(str(staged),str(root/'bundle'));staged=None
        args=[sys.executable,HERE.parent/'release/verify.py','--bundle',root/'bundle','--public-key',root/'public.pem','--version',version,'--architecture',architecture]
        if allow_development=='1':args+=['--allow-development']
        try:run(args)
        except RuntimeError as error:raise ValueError('signed target bundle verification failed') from error
        private_write(root/'verified-inputs.json',json.dumps({'version':version,'architecture':architecture,'allow_development':allow_development=='1'}))
        return str(root)
    except BaseException:
        shutil.rmtree(root)
        if staged is not None:shutil.rmtree(staged)
        raise


def discard_target_bundle(path):
    root=Path(path)
    info=root.lstat()
    if not root.name.startswith('nakpanel-forward-target-') or not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or not (root/'verified-inputs.json').is_file():
        raise ValueError('refusing to remove an unrecognized target staging directory')
    shutil.rmtree(root)


def target_install_program():
    return r'''
import hashlib,io,json,os,shutil,stat,subprocess,sys,tarfile,tempfile
from pathlib import Path,PurePosixPath
payload=json.load(sys.stdin);c=payload['config']
fd=os.open(payload['archive'],os.O_RDONLY|os.O_NOFOLLOW)
with os.fdopen(fd,'rb') as archive_file:
 if not stat.S_ISREG(os.fstat(archive_file.fileno()).st_mode):raise ValueError('bundle archive must be regular')
 archive=archive_file.read()
if hashlib.sha256(archive).hexdigest()!=payload['archive_sha256']:raise ValueError('signed target archive digest mismatch')
with tempfile.TemporaryDirectory(prefix='nakpanel-forward-install-') as directory:
 root=Path(directory);os.chmod(root,0o700);bundle=root/'bundle';bundle.mkdir(mode=0o700)
 with tarfile.open(fileobj=io.BytesIO(archive),mode='r:') as stream:
  seen=set()
  for entry in stream:
   name=entry.name.removeprefix('./') if hasattr(entry.name,'removeprefix') else entry.name[2:] if entry.name.startswith('./') else entry.name
   if name in ('','.'):continue
   path=PurePosixPath(name)
   if path.is_absolute() or '..' in path.parts or str(path)!=name or name in seen or not (entry.isdir() or entry.isfile()):raise ValueError('unsafe signed target archive member')
   seen.add(name);destination=bundle/name
   if entry.isdir():destination.mkdir(mode=0o755,parents=True,exist_ok=True)
   else:
    destination.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
    with destination.open('xb') as output,stream.extractfile(entry) as source:shutil.copyfileobj(source,output)
    destination.chmod(0o755 if entry.mode&0o111 else 0o644)
 key=root/'public.pem';key.write_text(payload['public_key']);key.chmod(0o600)
 verifier=root/'verify.py';verifier.write_text(payload['verifier_program']);verifier.chmod(0o600)
 verify=[sys.executable,str(verifier),'--bundle',str(bundle),'--public-key',str(key),'--version',payload['version'],'--architecture',c['architecture']]
 if payload['allow_development']:verify+=['--allow-development']
 subprocess.run(verify,check=True)
 descriptor,password_path=tempfile.mkstemp(prefix='admin-',dir=root)
 try:
  os.fchmod(descriptor,0o600)
  with os.fdopen(descriptor,'w') as password_file:password_file.write(c['admin_password'])
  args=['bash',str(bundle/'deploy/install/install.sh'),'--fresh','--bundle',str(bundle),'--release-public-key',str(key),'--yes','--admin-email',c['admin_email'],'--admin-password-file',password_path]
  if payload['allow_development']:args+=['--allow-development-bundle']
  if c['target_profile']=='ubuntu-26.04-sury':args+=['--php-provider','sury']
  # sudo sanitizes the caller environment. Carry the verified explicit policy
  # to the real installer, and clear any inherited override for production.
  installer_env=dict(os.environ,NAKPANEL_RELEASE_ALLOW_DEVELOPMENT='1' if payload['allow_development'] else '0')
  subprocess.run(args,check=True,env=installer_env)
 finally:
  os.unlink(password_path)
'''


def install_target(c, target, bundle, evidence):
    bundle=Path(bundle).resolve()
    key=Path(os.environ['NAKPANEL_FORWARD_TARGET_PUBLIC_KEY'])
    version=os.environ['NAKPANEL_FORWARD_TARGET_VERSION']
    allow=os.environ.get('NAKPANEL_FORWARD_ALLOW_DEVELOPMENT','0')
    if allow not in ('0','1'):raise ValueError('development opt-in must be 0 or 1')
    verifier=HERE.parent/'release/verify.py'
    args=[sys.executable,verifier,'--bundle',bundle,'--public-key',key,'--version',version,'--architecture',c['architecture']]
    if allow=='1':args+=['--allow-development']
    run(args)
    remote='/tmp/nakpanel-forward-target-'+c['run_token']
    run(['multipass','exec',target,'--','mkdir','-m','700',remote])
    with tempfile.TemporaryDirectory(prefix='nakpanel-forward-transfer-') as temporary:
        archive=Path(temporary)/'bundle.tar'
        with tarfile.open(archive,'w',format=tarfile.PAX_FORMAT) as stream:
            for path in sorted(bundle.rglob('*')):
                if path.is_file():stream.add(path,arcname=path.relative_to(bundle).as_posix(),recursive=False)
        digest=hashlib.sha256(archive.read_bytes()).hexdigest()
        run(['multipass','transfer',archive,target+':'+remote+'/bundle.tar'])
    guest(c,target,target_install_program(),{'config':c,'archive':remote+'/bundle.tar',
        'archive_sha256':digest,'public_key':key.read_text(),'verifier_program':verifier.read_text(),
        'version':version,'allow_development':allow=='1'})
    run(['multipass', 'transfer', c['ca_file'], target + ':' + remote + '/ca.crt'])
    run(['multipass', 'exec', target, '--', 'sudo', 'install', '-m', '0644', remote + '/ca.crt', '/usr/local/share/ca-certificates/nakpanel-forward-fixture.crt'])
    run(['multipass', 'exec', target, '--', 'sudo', 'update-ca-certificates'])
    # Create exact collision-checked identities before filling allowed stores.
    probe(c,target,'cache-target-images')
    boot = run(['multipass', 'exec', target, '--', 'cat', '/proc/sys/kernel/random/boot_id'])
    private_write(Path(evidence) / 'initial-target-boot-id', boot + '\n')


def driver(stage, target, source, token, bundle, evidence):
    c = validate_prepared(load_spec(os.environ.get('NAKPANEL_FORWARD_FIXTURE_JSON', '')))
    if source != c['source_vm'] or token != c['run_token']: raise ValueError('fixture identity differs from orchestration')
    if target == source: raise ValueError('migration target equals source')
    identity(c, source, '24.04')
    if stage != 'assert-source-readonly': identity(c, target, '26.04')
    if stage in ('assert-source-readonly', 'assert-baseline', 'assert-no-source-writes'):
        source_unchanged(c)
        archive = os.environ.get('NAKPANEL_FORWARD_ARCHIVE', c['archive_file'])
        if hashlib.sha256(Path(archive).read_bytes()).hexdigest() != c['archive_sha256']: raise ValueError('fixture does not describe this offline archive')
    elif stage == 'install-native-target': install_target(c, target, bundle, evidence)
    elif stage == 'assert-migration-data':
        observed = probe(c, target, 'snapshot')
        compare_snapshots(c['baseline'], observed)
        state = probe(c, target, 'live')
        private_write(Path(evidence) / ('target-data-' + state['boot_id'] + '.json'),json.dumps(observed,sort_keys=True,indent=2)+'\n')
    elif stage == 'assert-services':
        state = probe(c, target, 'live')
        assert_ssh(c, target)
        print(json.dumps(state,sort_keys=True))
    elif stage == 'assert-trusted-tls': print(json.dumps(probe(c, target, 'tls'),sort_keys=True))
    elif stage == 'assert-reboot':
        before = (Path(evidence) / 'initial-target-boot-id').read_text().strip()
        after = probe(c, target, 'live')['boot_id']
        if before == after: raise ValueError('target did not actually reboot')
        assert_ssh(c, target)
        print(json.dumps({'before_boot_id': before,'after_boot_id': after},sort_keys=True))
    else: raise ValueError('unknown fixture stage')
    print('Verified actual fixture stage: ' + stage)


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['--capabilities']: print('\n'.join(CAPABILITIES))
        elif sys.argv[1:] == ['--template']: print(json.dumps(example_spec(), indent=2))
        elif len(sys.argv) == 7 and sys.argv[1] == '--stage-target-bundle': print(stage_target_bundle(*sys.argv[2:]))
        elif len(sys.argv) == 3 and sys.argv[1] == '--discard-target-bundle': discard_target_bundle(sys.argv[2])
        elif len(sys.argv) == 3 and sys.argv[1] == '--validate': validate_prepared(load_spec(sys.argv[2]))
        elif len(sys.argv) == 4 and sys.argv[1] == '--prepare': prepare(sys.argv[2], sys.argv[3])
        elif len(sys.argv) == 7 and sys.argv[1] in CAPABILITIES[1:]: driver(*sys.argv[1:])
        else: raise ValueError('usage: --template | --prepare PRIVATE_SPEC NEW_OUTPUT_DIR | STAGE TARGET SOURCE TOKEN VERIFIED_BUNDLE EVIDENCE')
    except Exception as error:
        print('forward fixture failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
