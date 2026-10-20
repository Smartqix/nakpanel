"""Pending single Surý26 diagnostic bootstrap. No action without reviewed activation.

The binding cannot authenticate itself. Root must review/pin the concrete W tree
and authorize its exact push separately; this private PENDING rendering is inert.
"""
import hashlib,io,json,os,re,stat,subprocess,sys,tarfile,time,zipfile
from pathlib import Path,PurePosixPath
from urllib.request import Request,urlopen,build_opener,HTTPRedirectHandler
from urllib.error import HTTPError
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from contract import SOURCE,HELPER,Rejected,need,context,parse,digest,canonical,exclusive_output,exclusive_bytes,read_private,root_identity,stable
from prepare_custody import validate_canonical,run_prepare
import custody_base as base
PINS=parse((HERE/'bootstrap-pins.json').read_bytes())
BRANCH='ricky/sury-source26-maintenance-diagnostic-v3'
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None
def urlopen_no_redirect(request,timeout):return build_opener(NoRedirect()).open(request,timeout=timeout)
def bounded_response(response,limit):
    data=bytearray()
    while len(data)<=limit:
        block=response.read(min(2**20,limit+1-len(data)))
        if not block:break
        data.extend(block)
    need(len(data)<=limit);return bytes(data)
def api_json(path,token,*,evidence=None):
    need(path.startswith('/repos/Smartqix/nakpanel/actions/'))
    request=Request('https://api.github.com'+path,headers={'Accept':'application/vnd.github+json','Authorization':'Bearer '+token,'X-GitHub-Api-Version':'2022-11-28'})
    with urlopen_no_redirect(request,timeout=60) as response:raw=bounded_response(response,2**20)
    if evidence is not None:
        fd=exclusive_bytes(evidence,raw);os.close(fd)
    return parse(raw)
def api_archive(url,token,limit):
    need(url=='https://api.github.com/repos/Smartqix/nakpanel/actions/artifacts/12231269532/zip')
    request=Request(url,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json'})
    try:
        with urlopen_no_redirect(request,timeout=60) as response:return bounded_response(response,limit)
    except HTTPError as error:
        need(error.code==302);location=error.headers.get('Location','')
        from urllib.parse import urlparse
        parsed=urlparse(location)
        need(parsed.scheme=='https' and parsed.username is None and parsed.password is None and parsed.port in (None,443) and parsed.hostname and (parsed.hostname.endswith('.blob.core.windows.net') or parsed.hostname.endswith('.githubusercontent.com')))
        # Deliberately construct a new request WITHOUT Authorization for storage.
        with urlopen_no_redirect(Request(location),timeout=300) as response:return bounded_response(response,limit)
def command(argv,*,cwd,env,timeout=300):
    need(type(argv) is list and all(type(x) is str and '\0' not in x for x in argv))
    result=subprocess.run(argv,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
    need(result.returncode==0);return result.stdout

def clean_child_environment(env):
    return {k:v for k,v in env.items() if not k.startswith(('PYTHON','NAKPANEL_','GIT_CONFIG')) and k not in ('__PYVENV_LAUNCHER__','BASH_ENV','ENV','CDPATH','GH_TOKEN','GITHUB_TOKEN')}

def admit(binding,env):
    need(type(binding) is dict and binding.get('schema')=='source26-diagnostic-binding-v1' and binding.get('admission_state')=='APPROVED')
    need(binding.get('repository')=='Smartqix/nakpanel' and type(binding.get('repository_id')) is int and binding['repository_id']==1292416194)
    need(binding.get('source_commit')==SOURCE and binding.get('branch')==BRANCH and binding.get('event')=='push')
    need(type(binding.get('archive_id')) is int and binding['archive_id']==12231269532 and binding.get('archive_sha256')==PINS['artifact']['digest'].split(':')[1])
    # Root approval is external to W's self-referential commit; never derive it from this file.
    need(binding.get('actual_root_approval') is None)
    wanted={'GITHUB_REPOSITORY':'Smartqix/nakpanel','GITHUB_REPOSITORY_ID':'1292416194','GITHUB_EVENT_NAME':'push','GITHUB_REF':'refs/heads/'+BRANCH,'GITHUB_RUN_ATTEMPT':'1','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux','RUNNER_ARCH':'X64','GITHUB_ACTIONS':'true'}
    need(all(env.get(k)==v for k,v in wanted.items()))
    run=env.get('GITHUB_RUN_ID','');need(type(run) is str and re.fullmatch('[1-9][0-9]{0,13}',run))
    wrapper=env.get('GITHUB_SHA','');need(type(wrapper) is str and re.fullmatch('[a-f0-9]{40}',wrapper))
    token='hosted-'+run+'-1-26-04'
    return context(dict(schema='source26-diagnostic-context-v1',run_id=int(run),run_attempt=1,wrapper_commit=wrapper,source_vm='nakpanel-26-04-amd64-'+token,run_token=token,runtime_commit=SOURCE,qualifier_commit=SOURCE,maintenance_helper_sha256=HELPER))

def source_checks(application,operator,bound,env):
    for tree in (application,operator):need(tree.is_absolute() and tree.resolve()==tree and tree!=application.parent and tree.exists())
    need(application!=operator and application.parent==operator.parent)
    need(command(['git','rev-parse','HEAD'],cwd=str(operator),env=env).decode().strip()==bound['wrapper_commit'])
    need(command(['git','rev-list','--parents','-n','1','HEAD'],cwd=str(operator),env=env).decode().strip().split()==[bound['wrapper_commit'],SOURCE])
    need(command(['git','status','--porcelain','--untracked-files=all'],cwd=str(operator),env=env)==b'')
    need(command(['git','rev-parse','HEAD'],cwd=str(application),env=env).decode().strip()==SOURCE)
    need(command(['git','status','--porcelain','--untracked-files=all'],cwd=str(application),env=env)==b'')
    for name,expected in PINS['source26_inputs'].items():need(digest((application/name).read_bytes())==expected['sha256'])

def check_archive_metadata(run,jobs,artifact):
    need(type(run) is dict and run.get('id')==39347496239 and type(run.get('id')) is int and run.get('run_attempt')==1 and type(run.get('run_attempt')) is int)
    need(run.get('event')=='workflow_dispatch' and run.get('head_sha')==SOURCE and run.get('head_branch')=='ricky/ubuntu-26-sury-candidate26' and run.get('path')=='.github/workflows/ubuntu-hosted-qualification.yml')
    repository=run.get('repository',{});need(repository.get('id')==1292416194 and type(repository.get('id')) is int and repository.get('full_name')=='Smartqix/nakpanel' and repository.get('private') is False)
    need(type(jobs) is dict and type(jobs.get('jobs')) is list)
    chosen=[j for j in jobs['jobs'] if type(j) is dict and j.get('id')==118383538478]
    need(len(chosen)==1 and chosen[0].get('name')=='signed-bundles' and chosen[0].get('conclusion')=='success')
    need(type(artifact) is dict and type(artifact.get('id')) is int and artifact['id']==12231269532 and artifact.get('name')==PINS['artifact']['name'] and artifact.get('expired') is False)
    need(type(artifact.get('size_in_bytes')) is int and artifact['size_in_bytes']==73997080 and artifact.get('digest')==PINS['artifact']['digest'])
    origin=artifact.get('workflow_run',{});need(origin.get('id')==39347496239 and type(origin.get('id')) is int and origin.get('head_sha')==SOURCE)

def safe_member(name):
    path=PurePosixPath(name);need(name and not path.is_absolute() and '..' not in path.parts and '\\' not in name and '\0' not in name)
    return path
ZIP_NAMES={'bundles.json','images.json','test-public.pem','candidate/nakpanel-29.0.0-linux-amd64.tar.gz','prior/nakpanel-29.0.0-linux-amd64.tar.gz','images/noble/SHA256SUMS','images/noble/SHA256SUMS.gpg','images/resolute/SHA256SUMS','images/resolute/SHA256SUMS.gpg'}
def extract_zip(raw,destination):
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        entries=z.infolist();names=[x.filename for x in entries]
        need(len(names)==len(set(names)) and set(names)==ZIP_NAMES)
        need(sum(x.file_size for x in entries)<=80*2**20)
        for x in entries:
            safe_member(x.filename);kind=(x.external_attr>>16)&0o170000;need(not x.is_dir() and kind in (0,stat.S_IFREG) and x.file_size<=40*2**20)
        destination=Path(destination);destination.mkdir(mode=0o700)
        for x in entries:
            path=destination/x.filename;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            with path.open('xb') as out:out.write(z.read(x))
            path.chmod(0o600)
def extract_tar(raw,destination):
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as t:
        entries=t.getmembers();names=[x.name for x in entries]
        need(len(entries)<=300 and len(names)==len(set(names)) and sum(x.size for x in entries)<=200*2**20)
        for x in entries:safe_member(x.name);need((x.isdir() or x.isfile()) and not (x.issym() or x.islnk() or x.isdev()))
        destination=Path(destination);destination.mkdir(mode=0o700)
        # All entries validated first; no archive link may redirect a later path.
        for x in entries:
            path=destination/x.name
            if x.isdir():path.mkdir(mode=0o700,parents=True,exist_ok=True)
            else:
                path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                with path.open('xb') as out:out.write(t.extractfile(x).read())
                path.chmod(0o700 if x.mode&0o111 else 0o600)

def prepare_bundles(raw,destination,app,env):
    need(len(raw)==73997080 and digest(raw)==PINS['artifact']['digest'].split(':')[1]);extract_zip(raw,destination)
    need(parse((destination/'bundles.json').read_bytes())==PINS['bundles_metadata'] and parse((destination/'images.json').read_bytes())==PINS['images'])
    need(digest((destination/'test-public.pem').read_bytes())==PINS['public_key_sha256'])
    exports={}
    for tree,prefix in (('candidate','NAKPANEL_RELEASE_'),('prior','NAKPANEL_PRIOR_RELEASE_')):
        item=PINS['runtime_sources'][tree];archive=destination/item['archive'];data=archive.read_bytes()
        need(len(data)==item['archive_bytes'] and digest(data)==item['archive_sha256'])
        unpack=destination/(tree+'-unpacked');extract_tar(data,unpack)
        bundle=unpack/PINS['bundles_metadata'][tree]['directory'].split('/',1)[1]
        need(digest((bundle/'manifest.json').read_bytes())==item['manifest_sha256'])
        command([sys.executable,'-I','-B',str(app/'deploy/release/verify.py'),'--bundle',str(bundle),'--public-key',str(destination/'test-public.pem'),'--version','29.0.0','--architecture','amd64','--allow-development'],cwd=str(app),env=env)
        exports[prefix+'BUNDLE']=str(bundle);exports[prefix+'PUBLIC_KEY']=str(destination/'test-public.pem');exports[prefix+'VERSION']='29.0.0'
    return exports

def cleanup_allowed(canonical_record,prepare_record,bound=None):
    try:
        bound=context(bound)
        selected={k:bound[k] for k in ('source_vm','run_token')};selected.update(release='26.04',architecture='amd64',profile='ubuntu-26.04-sury',php_provider='sury')
        need(type(canonical_record) is dict and canonical_record.get('schema')=='nakpanel-canonical-execution-v1' and canonical_record.get('runtime_commit')==SOURCE and canonical_record.get('source_binding')==selected and canonical_record.get('status') in ('PASS','FAIL') and type(canonical_record.get('exit_code')) is int)
        need(type(canonical_record) is dict and canonical_record.get('process_exited') is True and type(canonical_record.get('pid')) is int and canonical_record['pid']>1 and canonical_record.get('process_group')==canonical_record['pid'])
        need(base.group_state(canonical_record['pid'])=='empty')
        if prepare_record is not None:
            need(prepare_record.get('schema')=='source26-prepare-custody-v1' and prepare_record.get('source_binding')==bound)
            need(prepare_record.get('finished') is True and prepare_record.get('process_exited') is True and type(prepare_record.get('pid')) is int and prepare_record['pid']>1 and prepare_record.get('process_group')==prepare_record['pid'] and prepare_record.get('group_observation')=='empty')
            need(base.group_state(prepare_record['pid'])=='empty')
        return True
    except Exception:return False

PUBLIC_FILES={
 'cell/report.json':'canonical-report.json','canonical-execution.json':'canonical-execution.json',
 'cell/release-manifest.json':'release-manifest.json','cell/roundcube-send-read.json':'roundcube-send-read.json',
 'cell/roundcube-send-read.execution.json':'roundcube-send-read.execution.json','cell/sury-maintenance-request.json':'sury-maintenance-request.json'}
for _name in ('preparation.json','capacity.json','roundcube_execution_receipt.json','retention_receipt.json','native_gpgv_receipt.json','package-baseline.json','package-layout.json','result.json','recovery.json','reboot-1.json','reboot-2.json','roundcube-recovered.execution.json','roundcube-reboot-1.execution.json','roundcube-reboot-2.execution.json'):
    PUBLIC_FILES['cell/sury-maintenance/'+_name]='maintenance-'+_name

def public_shape(value):
    if type(value) is dict:
        need(not set(value)&{'diagnostic','password','password_hash','password_ciphertext','private_key','recovery_key','database_dsn','secret'})
        for v in value.values():public_shape(v)
    elif type(value) is list:
        for v in value:public_shape(v)
    elif type(value) is str:need('nkbk1' not in value.lower())
    else:need(value is None or type(value) in (bool,int,float))

def copy_public_receipts(root,destination):
    seals=[]
    for relative,name in PUBLIC_FILES.items():
        if not (root/relative).exists() and not (root/relative).is_symlink():continue
        raw,extra=read_private(root,relative,2**20);public_shape(parse(raw));seals.extend(extra)
        fd=exclusive_bytes(destination/name,raw);os.close(fd)
    need(stable(seals))

def inventory_empty(value,bound):
    try:
        bound=context(bound);need(type(value) is dict and type(value.get('list')) is list and value.get('errors',[])==[])
        need(all(type(x) is dict and type(x.get('name')) is str for x in value['list']))
        return not any(bound['run_token'] in row['name'] for row in value['list'])
    except Exception:return False

def save(path,value):
    fd=exclusive_output(path,value);os.close(fd)
def load_state(root):
    p=root/'state.json';need(p.is_file() and not p.is_symlink() and p.stat().st_mode&0o777==0o600 and p.stat().st_uid==os.getuid() and p.stat().st_nlink==1)
    return parse(p.read_bytes())
def initialize(app,root,bound,env):
    env=dict(env);env.update(NAKPANEL_RUN_TOKEN=bound['run_token'],NAKPANEL_CELL_REPORT_DIR=str(root/'cell'),NAKPANEL_MULTIPASS_ARCH='amd64',NAKPANEL_MULTIPASS_IMAGE='26.04',NAKPANEL_QUALIFICATION_PHP_PROVIDER='sury',NAKPANEL_RELEASE_ALLOW_DEVELOPMENT='1',NAKPANEL_PRIOR_RELEASE_ALLOW_DEVELOPMENT='1',NAKPANEL_QUALIFICATION_VM_CPUS='2',NAKPANEL_QUALIFICATION_VM_MEMORY='5G',NAKPANEL_QUALIFICATION_VM_DISK='32G',NAKPANEL_QUALIFICATION_DR_CPUS='2',NAKPANEL_QUALIFICATION_DR_MEMORY='3G',NAKPANEL_QUALIFICATION_DR_DISK='16G',NAKPANEL_QUALIFICATION_RECLAIM_PRIOR='1',NAKPANEL_VERIFY_DATABASE_MANAGER='1',NAKPANEL_VERIFY_SURY_MAINTENANCE='1')
    command(['bash',str(app/'deploy/multipass/prepare-hosted-runner.sh')],cwd=str(app),env=env,timeout=1200)
    # That unchanged helper writes a fresh visible private TMPDIR to GITHUB_ENV.
    lines=Path(env['GITHUB_ENV']).read_text().splitlines();temps=[x[7:] for x in lines if x.startswith('TMPDIR=')]
    need(bool(temps));tmp=Path(temps[-1]);root_identity(tmp);env['TMPDIR']=str(tmp)
    images=root/'images';images.mkdir(mode=0o700)
    for release,image in PINS['images'].items():
        suite=image['suite'];sums=root/'bundles/images'/suite/'SHA256SUMS';signature=sums.with_name('SHA256SUMS.gpg')
        command(['gpgv','--keyring','/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg',str(signature),str(sums)],cwd=str(app),env=env)
        filename='ubuntu-'+release+'-server-cloudimg-amd64.img'
        need(any(line.split()==[image['sha256'],'*'+filename] or line.split()==[image['sha256'],filename] for line in sums.read_text().splitlines()))
        target=images/filename
        command(['curl','--fail','--location','--retry','3','--proto','=https','--proto-redir','=https',image['url'],'--output',str(target)],cwd=str(app),env=env,timeout=900)
        h=hashlib.sha256()
        with target.open('rb') as stream:
            for block in iter(lambda:stream.read(2**20),b''):h.update(block)
        need(h.hexdigest()==image['sha256'])
        prefix='NAKPANEL_MULTIPASS_' if release=='26.04' else 'NAKPANEL_PRIOR_MULTIPASS_'
        env[prefix+'IMAGE_SOURCE']=str(target);env[prefix+'IMAGE_SHA256']=image['sha256']
    command([sys.executable,'-I','-B',str(app/'deploy/multipass/hosted-runner-preflight.py'),'--output',str(root/'host-preflight.json')],cwd=str(app),env=env)
    shell='set -euo pipefail; source "$1"; init_qualification_run; python3 -I -B -c \'import json,os;print(json.dumps({k:v for k,v in os.environ.items() if k.startswith("NAKPANEL_")}))\''
    selected=parse(command(['bash','-c',shell,'_',str(app/'deploy/multipass/common.sh')],cwd=str(app),env=env));need(type(selected) is dict and selected.get('NAKPANEL_MULTIPASS_VM')==bound['source_vm'])
    env.update(selected)
    command(['npm','install','--prefix',str(root/'browser'),'--no-audit','--no-fund','playwright@1.64.1'],cwd=str(app),env=env,timeout=300)
    env['PLAYWRIGHT_MODULE']=str(root/'browser/node_modules/playwright');env['NAKPANEL_CI_OWNERSHIP_READY']='1'
    return env

def main(operation):
    original=dict(os.environ);binding=parse((HERE/'runtime-binding.json').read_bytes());bound=admit(binding,original)
    workspace=Path(original['GITHUB_WORKSPACE']);app=workspace/'application';operator=workspace/'operator';runner=Path(original['RUNNER_TEMP']);need(runner.resolve()==runner and runner.stat().st_uid==os.getuid())
    env=clean_child_environment(original)
    import platform
    need(platform.system()=='Linux' and platform.machine() in ('x86_64','amd64'))
    source_checks(app,operator,bound,env)
    root=runner/'source26-diagnostic-private';public=runner/'source26-diagnostic-public'
    if operation=='stage':
        root.mkdir(mode=0o700);public.mkdir(mode=0o700)
        event=parse(Path(env['GITHUB_EVENT_PATH']).read_bytes());need(event.get('repository',{}).get('private') is False and event.get('repository',{}).get('id')==1292416194)
        token=original.get('GH_TOKEN','');need(token)
        run=api_json('/repos/Smartqix/nakpanel/actions/runs/39347496239',token,evidence=root/'api-original-run.json');jobs=api_json('/repos/Smartqix/nakpanel/actions/runs/39347496239/jobs?per_page=100',token,evidence=root/'api-original-jobs.json');artifact=api_json('/repos/Smartqix/nakpanel/actions/artifacts/12231269532',token,evidence=root/'api-original-artifact.json')
        check_archive_metadata(run,jobs,artifact)
        raw=api_archive('https://api.github.com/repos/Smartqix/nakpanel/actions/artifacts/12231269532/zip',token,73997080)
        env.update(prepare_bundles(raw,root/'bundles',app,env))
        archive_path=root/'artifact12231269532.zip'
        with archive_path.open('xb') as stream:stream.write(raw)
        archive_path.chmod(0o600)
        save(public/'bootstrap.json',dict(schema='source26-diagnostic-bootstrap-v1',context=bound,original_run_id=39347496239,original_attempt=1,signed_build_job=118383538478,artifact_id=12231269532,artifact_bytes=len(raw),artifact_sha256=digest(raw),public_key_sha256=PINS['public_key_sha256'],candidate_manifest_sha256=PINS['runtime_sources']['candidate']['manifest_sha256'],prior_manifest_sha256=PINS['runtime_sources']['prior']['manifest_sha256'],both_RSA_verifier_exits_zero=True,claims_M_success=False))
        env=initialize(app,root,bound,env)
        (root/'custody').mkdir(mode=0o700)
        save(root/'state.json',dict(context=bound,env={k:v for k,v in env.items() if k.startswith('NAKPANEL_') or k in ('PLAYWRIGHT_MODULE','TMPDIR')},source='UNCHANGED26',wrapper_commit=bound['wrapper_commit']))
        with open(env['GITHUB_ENV'],'a') as stream:
            for k,v in sorted(env.items()):
                if k.startswith('NAKPANEL_') or k in ('PLAYWRIGHT_MODULE','TMPDIR'):
                    need('\n' not in k+v and '\r' not in k+v);stream.write(k+'='+v+'\n')
        return 0
    root_identity(root);root_identity(public)
    if operation=='project' and not (root/'state.json').exists():
        save(public/'diagnostic.json',dict(schema='source26-maintenance-diagnostic-v1',diagnostic_only=True,claims_M_success=False,input_binding='INVALID',observation='UNKNOWN',expected_context=bound,observed_identity=None,phase='UNKNOWN',predicate='UNKNOWN',guest_exit_code=None,prepare_exit_code=None,M_status=None,invocation_drain='UNKNOWN'));return 1
    state=load_state(root);need(state.get('context')==bound);env.update(state['env'])
    canonical_path=root/'canonical-execution.json';report_path=root/'cell/report.json';prepare_root=root/'prepare';custody=root/'custody/prepare/receipt.json'
    canonical_record=None;prepare_record=None
    if canonical_path.exists():canonical_record=parse(read_private(root,'canonical-execution.json')[0])
    if custody.exists():
        need(custody.resolve()==custody and custody.stat().st_uid==os.getuid() and custody.stat().st_mode&0o777==0o600 and custody.stat().st_nlink==1);prepare_record=parse(custody.read_bytes())
    if (root/'custody/prepare').exists() and not custody.exists():prepare_record={}
    if operation=='prepare':
        need(canonical_record is not None);validate_canonical(canonical_record,read_private(root/'cell','report.json')[0],bound)
        need(cleanup_allowed(canonical_record,None,bound))
        command([sys.executable,'-I','-B',str(app/'deploy/multipass/sury-maintenance-prepare.py'),'request'],cwd=str(app),env=env)
        run_prepare(app,prepare_root,canonical_path,root/'custody',bound,env);return 0
    if operation=='project':
        if not cleanup_allowed(canonical_record,prepare_record,bound):
            save(public/'diagnostic.json',dict(schema='source26-maintenance-diagnostic-v1',diagnostic_only=True,claims_M_success=False,input_binding='INVALID',observation='UNKNOWN',expected_context=bound,observed_identity=None,phase='UNKNOWN',predicate='UNKNOWN',guest_exit_code=None,prepare_exit_code=None,M_status=None,invocation_drain='UNKNOWN'));return 1
        from projector import project
        observed=project(bound,prepare_record,prepare_root,public/'diagnostic.json')
        copy_public_receipts(root,public)
        return 0 if observed['input_binding']=='MATCHED' else 1
    if operation=='cleanup':
        need(cleanup_allowed(canonical_record,prepare_record,bound))
        shell='set -euo pipefail; source "$1"; expected="$2"; [[ "${NAKPANEL_CI_OWNERSHIP_READY:-}" == 1 && "$NAKPANEL_RUN_TOKEN" == "$expected" ]]; status=0; for record in "$NAKPANEL_OWNERSHIP_DIR/$expected"/nakpanel-*; do [[ -f "$record" && "$record" != *.image.json ]] || continue; destroy_owned_vm "$(basename "$record")" "$expected" || status=1; done; exit "$status"'
        command(['bash','-c',shell,'_',str(app/'deploy/multipass/common.sh'),bound['run_token']],cwd=str(app),env=env,timeout=300)
        inventory=parse(command(['multipass','list','--format','json'],cwd=str(app),env=env,timeout=60));need(inventory_empty(inventory,bound))
        save(public/'cleanup.json',dict(schema='source26-diagnostic-cleanup-v1',context=bound,status='PASS',owned_cleanup_returned=True,owned_remaining_count=0));return 0
    raise Rejected()
if __name__=='__main__':
    try:
        need(len(sys.argv)==2 and sys.argv[1] in ('stage','prepare','project','cleanup'))
        raise SystemExit(main(sys.argv[1]))
    except SystemExit:raise
    except KeyboardInterrupt:
        print('source26 diagnostic unavailable',file=sys.stderr);raise SystemExit(130)
    except BaseException:
        print('source26 diagnostic unavailable',file=sys.stderr);raise SystemExit(1)
