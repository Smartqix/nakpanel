"""PENDING single fresh-install inventory probe; external W approval required."""
import hashlib,os,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from contract import *
from artifact_support import command,clean_child_environment,api_json,api_archive,check_archive_metadata,prepare_bundles
from custody import run_owned,LIMITS
from projector import project,command_binding

def admit(binding,env):
    keys={'schema','scope','admission_state','actual_root_approval','repository','repository_id','event','branch','source_commit','archive_id','archive_sha256'}
    need(type(binding) is dict and set(binding)==keys and binding['schema']=='source26-inventory-binding-v1' and binding['scope']==SCOPE and binding['admission_state']=='APPROVED')
    need(binding['actual_root_approval'] is None and binding['repository']=='Smartqix/nakpanel' and type(binding['repository_id']) is int and binding['repository_id']==1292416194 and binding['event']=='push' and binding['branch']==BRANCH and binding['source_commit']==SOURCE)
    need(type(binding['archive_id']) is int and binding['archive_id']==12231269532 and binding['archive_sha256']==PINS['artifact']['digest'].split(':')[1])
    wanted={'GITHUB_REPOSITORY':'Smartqix/nakpanel','GITHUB_REPOSITORY_ID':'1292416194','GITHUB_EVENT_NAME':'push','GITHUB_REF':'refs/heads/'+BRANCH,'GITHUB_RUN_ATTEMPT':'1','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux','RUNNER_ARCH':'X64','GITHUB_ACTIONS':'true'}
    need(all(env.get(k)==v for k,v in wanted.items()))
    run=env.get('GITHUB_RUN_ID','');need(type(run) is str and re.fullmatch('[1-9][0-9]{0,13}',run))
    return make_context(int(run),env.get('GITHUB_SHA'))

def source_checks(application,operator,bound,env):
    for tree in (application,operator):need(tree.is_absolute() and tree.resolve()==tree and tree!=application.parent and tree.exists())
    need(application!=operator and application.parent==operator.parent)
    need(command(['git','rev-parse','HEAD'],cwd=str(operator),env=env).decode().strip()==bound['wrapper_commit'])
    need(command(['git','rev-list','--parents','-n','1','HEAD'],cwd=str(operator),env=env).decode().strip().split()==[bound['wrapper_commit'],SOURCE])
    need(command(['git','status','--porcelain','--untracked-files=all'],cwd=str(operator),env=env)==b'')
    need(command(['git','rev-parse','HEAD'],cwd=str(application),env=env).decode().strip()==SOURCE)
    need(command(['git','status','--porcelain','--untracked-files=all'],cwd=str(application),env=env)==b'')
    for name,expected in PINS['source26_inputs'].items():pinned_source(application/name,expected['sha256'])
    validate_runtime_files()

def inventory_empty(value,bound):
    try:
        bound=context(bound);need(type(value) is dict and type(value.get('list')) is list and value.get('errors',[])==[])
        need(all(type(row) is dict and type(row.get('name')) is str for row in value['list']))
        return not any(bound['run_token'] in row['name'] for row in value['list'])
    except Exception:return False

def initialize(app,root,bound,env):
    env=dict(env);env.update(NAKPANEL_RUN_TOKEN=bound['run_token'],NAKPANEL_CELL_REPORT_DIR=str(root/'unused-cell'),NAKPANEL_MULTIPASS_ARCH='amd64',NAKPANEL_MULTIPASS_IMAGE='26.04',NAKPANEL_QUALIFICATION_PHP_PROVIDER='sury',NAKPANEL_RELEASE_ALLOW_DEVELOPMENT='1',NAKPANEL_INSTALL_ONLY='1',NAKPANEL_QUALIFICATION_VM_CPUS='2',NAKPANEL_QUALIFICATION_VM_MEMORY='5G',NAKPANEL_QUALIFICATION_VM_DISK='32G')
    command(['bash',str(app/'deploy/multipass/prepare-hosted-runner.sh')],cwd=str(app),env=env,timeout=1200)
    temps=[line[7:] for line in Path(env['GITHUB_ENV']).read_text().splitlines() if line.startswith('TMPDIR=')]
    need(bool(temps));tmp=Path(temps[-1]);root_identity(tmp);env['TMPDIR']=str(tmp)
    images=root/'images';images.mkdir(mode=0o700)
    image=PINS['images']['26.04'];sums=root/'bundles/images'/image['suite']/'SHA256SUMS';signature=sums.with_name('SHA256SUMS.gpg')
    command(['gpgv','--keyring','/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg',str(signature),str(sums)],cwd=str(app),env=env)
    filename='ubuntu-26.04-server-cloudimg-amd64.img'
    need(any(line.split() in ([image['sha256'],'*'+filename],[image['sha256'],filename]) for line in sums.read_text().splitlines()))
    target=images/filename
    command(['curl','--fail','--location','--retry','3','--proto','=https','--proto-redir','=https',image['url'],'--output',str(target)],cwd=str(app),env=env,timeout=900)
    h=hashlib.sha256()
    with target.open('rb') as stream:
        for block in iter(lambda:stream.read(2**20),b''):h.update(block)
    need(h.hexdigest()==image['sha256']);env.update(NAKPANEL_MULTIPASS_IMAGE_SOURCE=str(target),NAKPANEL_MULTIPASS_IMAGE_SHA256=image['sha256'])
    command([sys.executable,'-I','-B',str(app/'deploy/multipass/hosted-runner-preflight.py'),'--output',str(root/'host-preflight.json')],cwd=str(app),env=env)
    shell='set -euo pipefail; source "$1"; init_qualification_run; python3 -I -B -c \'import json,os;print(json.dumps({k:v for k,v in os.environ.items() if k.startswith("NAKPANEL_")}))\''
    selected=parse(command(['bash','-c',shell,'_',str(app/'deploy/multipass/common.sh')],cwd=str(app),env=env))
    need(type(selected) is dict and selected.get('NAKPANEL_MULTIPASS_VM')==bound['source_vm']);env.update(selected);env['NAKPANEL_CI_OWNERSHIP_READY']='1'
    need(inventory_empty(parse(command(['multipass','list','--format','json'],cwd=str(app),env=env,timeout=60)),bound))
    # The original initializer selects names only; a fresh token has no host record directory.
    ownership=Path(env['NAKPANEL_OWNERSHIP_DIR'])/bound['run_token'];need(not ownership.exists() and not ownership.is_symlink())
    return env

def read_receipt(root,phase):
    path=root/'custody'/phase
    if not path.exists():return None
    return parse(read_private(path,'receipt.json')[0])

def require_drained(root,bound,app):
    for phase in ('install','inventory'):
        record=read_receipt(root,phase)
        if record is not None:command_binding(record,phase,bound,app,root/phase)

def phase_public(root,public,phase,bound,app):
    try:record=read_receipt(root,phase)
    except Exception:record=None
    value=dict(schema='source26-inventory-phase-v1',scope=SCOPE,context=bound,phase=phase,status='UNKNOWN',input_binding='INVALID',exit_code=None,leader_reaped=None,owned_group='UNKNOWN',failure_code=None,claims_full17=False,claims_M_success=False)
    try:
        command_binding(record,phase,bound,app,root/phase)
        need(record.get('failure_code') in (None,'cancelled','output-budget','timeout','exit','group-unconfirmed','background-child','launch','internal','cleanup','private-log'))
        value.update(status=record['status'],input_binding='MATCHED',exit_code=record['exit_code'],leader_reaped=True,owned_group='EMPTY',failure_code=record['failure_code'])
    except Exception:pass
    safe_save(public/(phase+'.json'),value);return value

def cleanup_public(root,public,bound,app,remaining=None):
    value=dict(schema='source26-inventory-cleanup-v1',scope=SCOPE,context=bound,status='UNKNOWN',exit_code=None,leader_reaped=None,owned_group='UNKNOWN',owned_remaining_count=None,claims_full17=False,claims_M_success=False)
    try:
        record=read_receipt(root,'cleanup');command_binding(record,'cleanup',bound,app,root/'cleanup')
        value.update(status='FAIL',exit_code=record['exit_code'],leader_reaped=True,owned_group='EMPTY')
        if record['status']=='PASS' and record['exit_code']==0 and remaining==0:value.update(status='PASS',owned_remaining_count=0)
    except Exception:pass
    safe_save(public/'cleanup.json',value);return value

def main(operation):
    original=dict(os.environ);bound=admit(parse((HERE/'runtime-binding.json').read_bytes()),original)
    import platform
    need(platform.system()=='Linux' and platform.machine() in ('x86_64','amd64'))
    workspace=Path(original['GITHUB_WORKSPACE']);app=workspace/'application';operator=workspace/'operator';runner=Path(original['RUNNER_TEMP']);need(runner.resolve()==runner and runner.stat().st_uid==os.getuid())
    env=clean_child_environment(original);source_checks(app,operator,bound,env)
    root=runner/'source26-inventory-private';public=runner/'source26-inventory-public'
    if operation=='stage':
        root.mkdir(mode=0o700);public.mkdir(mode=0o700);safe_save(root/'context.json',bound)
        event=parse(Path(env['GITHUB_EVENT_PATH']).read_bytes());need(event.get('repository',{}).get('private') is False and event.get('repository',{}).get('id')==1292416194)
        token=original.get('GH_TOKEN','');need(token)
        run=api_json('/repos/Smartqix/nakpanel/actions/runs/39347496239',token,evidence=root/'api-original-run.json');jobs=api_json('/repos/Smartqix/nakpanel/actions/runs/39347496239/jobs?per_page=100',token,evidence=root/'api-original-jobs.json');artifact=api_json('/repos/Smartqix/nakpanel/actions/artifacts/12231269532',token,evidence=root/'api-original-artifact.json')
        check_archive_metadata(run,jobs,artifact)
        raw=api_archive('https://api.github.com/repos/Smartqix/nakpanel/actions/artifacts/12231269532/zip',token,73997080)
        env.update(prepare_bundles(raw,root/'bundles',app,env))
        safe_save(public/'bootstrap.json',dict(schema='source26-inventory-bootstrap-v1',scope=SCOPE,context=bound,status='AUTHENTICATED',artifact_id=12231269532,artifact_sha256=digest(raw),public_key_sha256=PINS['public_key_sha256'],manifest_sha256=bound['manifest_sha256'],installed_binary_sha256=bound['installed_binary_sha256'],RSA_verifier_exit_zero=True,claims_full17=False,claims_M_success=False))
        env=initialize(app,root,bound,env);(root/'custody').mkdir(mode=0o700)
        safe_save(root/'state.json',dict(context=bound,env={k:v for k,v in env.items() if k.startswith('NAKPANEL_') or k=='TMPDIR'}))
        return 0
    root_identity(root);root_identity(public)
    if operation=='project':
        phase_public(root,public,'install',bound,app)
        try:record=read_receipt(root,'inventory')
        except Exception:record=None
        value=project(bound,record,root/'inventory',app,public/'inventory.json')
        return 0 if value['input_binding']=='MATCHED' else 1
    if operation=='cleanup' and not (root/'state.json').exists():
        need(not any((root/'custody'/phase).exists() for phase in LIMITS))
        safe_save(public/'cleanup.json',dict(schema='source26-inventory-cleanup-v1',scope=SCOPE,context=bound,status='NOT_STARTED',exit_code=None,leader_reaped=None,owned_group='NOT_STARTED',owned_remaining_count=None,claims_full17=False,claims_M_success=False));return 0
    state=parse(read_private(root,'state.json')[0]);need(state.get('context')==bound);env.update(state['env'])
    if operation=='install':
        need(inventory_empty(parse(command(['multipass','list','--format','json'],cwd=str(app),env=env,timeout=60)),bound))
        ownership=Path(env['NAKPANEL_OWNERSHIP_DIR'])/bound['run_token'];need(not ownership.exists() and not ownership.is_symlink())
        run_owned('install',app,root/'install',root/'custody',bound,env);return 0
    if operation=='inventory':
        record=read_receipt(root,'install');command_binding(record,'install',bound,app,root/'install');need(record['status']=='PASS' and record['exit_code']==0)
        run_owned('inventory',app,root/'inventory',root/'custody',bound,env);return 0
    if operation=='cleanup':
        try:
            require_drained(root,bound,app);run_owned('cleanup',app,root/'cleanup',root/'custody',bound,env)
            record=read_receipt(root,'cleanup');command_binding(record,'cleanup',bound,app,root/'cleanup');need(record['status']=='PASS' and record['exit_code']==0)
            need(inventory_empty(parse(command(['multipass','list','--format','json'],cwd=str(app),env=env,timeout=60)),bound))
        except BaseException:
            cleanup_public(root,public,bound,app);raise
        cleanup_public(root,public,bound,app,remaining=0);return 0
    raise Rejected()

if __name__=='__main__':
    try:
        need(len(sys.argv)==2 and sys.argv[1] in ('stage','install','inventory','project','cleanup'));raise SystemExit(main(sys.argv[1]))
    except SystemExit:raise
    except KeyboardInterrupt:print('inventory-only diagnostic unavailable',file=sys.stderr);raise SystemExit(130)
    except BaseException:print('inventory-only diagnostic unavailable',file=sys.stderr);raise SystemExit(1)
