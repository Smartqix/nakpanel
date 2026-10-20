#!/usr/bin/env python3
"""Fixed candidate26 hosted fixture. Inert until separately root-bound admission.

No import-time actions. The trusted workflow revision and out-of-band admission
SHA are the entry trust roots; this is not protection from replacement of them.
"""
import sys
sys.dont_write_bytecode=True
import argparse, hashlib, json, math, os, platform, re, signal, stat, subprocess, tarfile, tempfile, time, zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

COMMIT='1627bba3c681a884255eb91452dbba74a43ebbdc'
TREE='fc003d27bc7e0fc13d095a4ebc464b17471dc26f'
ROOT_BASELINES={'native24':'dcefa079e44d23d1f6fc9514b32f1be399d3bc7c89190e1f8028dd5cf17c8a18','native26':'f230cba666f3edbdc2fdca18a43e070d13d5b53fbe9fdd10c6aae2e4cabf4a3d','required_ci':'d020396446bb2368b90a7c146e3ff26749eb1aa27eb6b580b97757b58837918b','payload':'3dff375db5cb83a6afa2c54a07d76301a10087d8adaa319bebb108e93c91faf4'}
ACCEPTED_PAYLOAD={'manifest_sha256':'50a0cc9802629bcdecb50f26a64f0ec8e49a434856f3f3aabb8e36650e8a60cc','public_key_sha256':'043971dd64ac6b9868e3d9f6cf29c852548e8f32276822187c66c2d40656ba61','binaries':{'panel':'535185eb683942313793bcf833f6e71d481a0cf12149103711d1f0e68a0d9c5f','agent':'9dea11b8ddb98e0f21863747d50c5778ab6629b1406a2cb0971b876ccf12fd4c','panelctl':'44319f18d64575dc46afc48d24115634a81e63925a567d9420634cdaf212fc60'}}
CAPS={k:v*60 for k,v in {'artifact':15,'host':20,'images':20,'admit':1,'current':45,'phase28':15,'phase30':20,'negative_backup':15,'prepare':30,'negative_install':40,'negative_check':5,'positive':90,'cleanup':15}.items()}
TOTAL_SECONDS=342*60
SHA=re.compile(r'[a-f0-9]{64}')
BINARY_PATHS={'panel':'/usr/local/bin/nakpanel-panel','agent':'/usr/local/bin/nakpanel-agent','panelctl':'/usr/local/bin/panelctl'}
IMAGES={'24.04':('noble','20261017','04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94'),'26.04':('resolute','20260927','8800651811af9a85465ad1d552add729947bb16488dddb4a9b5305a3d97332b2')}
class Refusal(ValueError):pass
class Deadline(Refusal):pass
PREDICATES={'positive_preflight','positive_snapshot','positive_mail_data','positive_php_inventory','positive_restore_result','positive_restore_manifest','positive_database_import','positive_services','positive_stage_evidence','positive_target_reboot','terminal_outcomes'}
BOUNDARIES=set(CAPS)|{'setup','source','negative_target','positive_driver','positive_evidence','positive_preflight','positive_restore','positive_budget','positive_identity','positive_reboot','source_unchanged','publication','completed'}
PROOF_CONTEXTS={'current','phase28','phase30','negative_backup','prepare','positive_source','negative_target','positive_target'}
SERVICE_ALIASES={'panel':'nakpanel.service','agent':'nakpanel-agent.service','nginx':'nginx.service','postgresql':'postgresql.service','mariadb':'mariadb.service','named':'named.service','stalwart':'stalwart-mail.service','proftpd':'nakpanel-proftpd.service'}
CORE_SEVEN=tuple(v for k,v in SERVICE_ALIASES.items() if k!='proftpd')
CHECK_KEYS={'binary_inventory_matches','panel_matches','agent_matches','panelctl_matches','architecture_matches','profile_matches','version_matches','database_fingerprint_valid','boot_id_valid','units_predicate'}|set(SERVICE_ALIASES)
PREDICATES.update({'source_binary_inventory','source_architecture','source_profile','source_version','source_database_fingerprint','source_boot_id','source_units','trusted_file_metadata','host_owner_binding','input_pin_mismatch'}|{prefix+'_'+part for prefix in ('vm_list','cleanup_initial','cleanup_final') for part in ('object','errors','rows','absence')})
BOUNDARIES.update({'source_current_run','source_phase28_run','source_phase30_run','source_budget','proof_owner','proof_pins','proof_command','proof_json','proof_binaries','proof_architecture','proof_profile','proof_version','proof_database','proof_boot','proof_units','cleanup_group','cleanup_destroy'}|{prefix+'_'+part for prefix in ('vm_list','cleanup_initial','cleanup_final') for part in ('command','json','object','errors','rows','absence')})

def closed(value,allowed):return value if type(value) is str and value in allowed else 'UNKNOWN'
def proof_projection(value):
    if type(value) is not dict:return None
    n=value.get('invocation')
    if type(n) is not int or not 0<n<=65535:return None
    r={'invocation':n,'context':closed(value.get('context'),PROOF_CONTEXTS),'active':value.get('active') is True,'json_decoded':value.get('json_decoded') is True,'checks':{}}
    checks=value.get('checks')
    if type(checks) is dict:r['checks']={k:checks[k] for k in CHECK_KEYS if type(checks.get(k)) is bool}
    return r

def failure_projection(value):
    value=value if type(value) is dict else {}
    count=value.get('command_count');r={'boundary':closed(value.get('boundary'),BOUNDARIES),'predicate':closed(value.get('predicate'),PREDICATES),'kind':closed(value.get('kind'),{'semantic','command','cancelled','deadline'}),'command_count':count if type(count) is int and 0<=count<=100000 else 0}
    observation=proof_projection(value.get('proof_observation'))
    if observation is not None:r['proof_observation']=observation
    return r

def outcomes_projection(state):
    primary=state.get('primary_outcome');primary=primary if type(primary) is dict else {}
    work=dict(status=primary.get('status') if primary.get('status') in ('not_run','passed','failed') else 'not_run',**failure_projection(primary))
    cleanup=state.get('cleanup_outcome');cleanup=cleanup if type(cleanup) is dict else {}
    result={'status':cleanup.get('status') if cleanup.get('status') in ('not_run','passed','failed') else 'not_run','failures':[]}
    rows=cleanup.get('failures')
    if type(rows) is list:
        for row in rows[:4]:
            if type(row) is dict:result['failures'].append(dict(role=closed(row.get('role'),{'source','negative','positive','private_staging'}),**failure_projection(row)))
    return work,result

class PredicateRefusal(Refusal):
    def __init__(self,predicate):
        self.predicate=predicate if predicate in PREDICATES else 'UNKNOWN'
        super().__init__('fixed forward predicate failed')
def predicate_require(ok,predicate):
    if not ok:raise PredicateRefusal(predicate)

def require(ok,message):
    if not ok:raise Refusal(message)
def utc():return datetime.now(timezone.utc).isoformat()
def instant(value):
    require(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)',value),'invalid UTC time')
    parsed=value.replace('Z','+00:00');fraction=re.search(r'\.(\d{1,6})(?=\+00:00$)',parsed)
    if fraction:parsed=parsed[:fraction.start(1)]+fraction.group(1).ljust(6,'0')+parsed[fraction.end(1):]
    try:return datetime.fromisoformat(parsed)
    except ValueError:raise Refusal('invalid UTC time')
def digest(data):return hashlib.sha256(data).hexdigest()
def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode('ascii')
def duplicate_pairs(pairs):
    result={}
    for k,v in pairs:
        require(k not in result,'duplicate JSON field');result[k]=v
    return result
def decoded(data):
    try:return json.loads(data,object_pairs_hook=duplicate_pairs)
    except (ValueError,UnicodeError):raise Refusal('invalid JSON data')
def regular(path,private=False):
    p=Path(path);s=p.lstat();predicate_require(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid(),'trusted_file_metadata')
    predicate_require(not s.st_mode&0o022,'trusted_file_metadata')
    if private:predicate_require(not s.st_mode&0o077,'trusted_file_metadata')
    return p

def publish(path,value):
    path=Path(path);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.'+path.name+'.',dir=path.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb') as f:f.write(canonical(value));f.flush();os.fsync(f.fileno())
        os.replace(name,path)
        d=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(d)
        finally:os.close(d)
    finally:
        try:os.unlink(name)
        except FileNotFoundError:pass

def read_admission(path,expected_sha,now=None):
    p=regular(path,True);require(p.stat().st_size<=262144,'admission exceeds data-only bound');require(SHA.fullmatch(expected_sha or '') and sha(p)==expected_sha,'out-of-band admission SHA differs')
    a=decoded(p.read_bytes());require(type(a) is dict and a.get('state')=='AUTHORIZED','hosted admission is PENDING')
    keys={'schema','state','source_commit','source_tree','controller_commit','valid_from','expires_at','nonce','repository','baseline_reviews','artifact','payload','oci_image_ref','authority','controller_files','app_helpers'}
    require(set(a)==keys and a['schema']=='nakpanel-hosted-forward-admission-v1','admission schema/fields differ')
    require(a['source_commit']==COMMIT and a['source_tree']==TREE and re.fullmatch('[a-f0-9]{40}',a['controller_commit'] or ''),'source/controller commit differs')
    now=now or datetime.now(timezone.utc);start,end=instant(a['valid_from']),instant(a['expires_at'])
    require(start<=now<end and 0<(end-start).total_seconds()<=24*3600,'admission expired or not yet valid')
    require(re.fullmatch('[a-f0-9]{32}',a['nonce'] or '') and a['repository']=='Smartqix/nakpanel','unsafe run/repository identity')
    require(a['baseline_reviews']==ROOT_BASELINES,'accepted application baseline bindings differ')
    require(type(a['authority']) is dict and type(a['authority'].get('maximum_guests')) is int and type(a['authority'].get('cpus')) is int and a['authority'].get('production') is False and a['authority']=={'scope':'fresh-synthetic-native-forward-only','maximum_guests':2,'cpus':2,'memory':'5G','disk':'32G','production':False},'unsupported authority scope/resources')
    require(re.fullmatch('docker.io/library/nginx@sha256:[a-f0-9]{64}',a['oci_image_ref'] or ''),'immutable official OCI reference missing')
    ar=a['artifact'];require(type(ar) is dict and set(ar)=={'id','run_id','name','size','sha256','expires_at'},'artifact schema differs')
    require(all(type(ar[k]) is int and 0<ar[k]<=2**40 for k in ('id','run_id','size')) and ar['size']<=2**30 and SHA.fullmatch(ar['sha256'] or '') and type(ar['name']) is str and re.fullmatch('[A-Za-z0-9_.-]{1,150}',ar['name']),'artifact binding invalid')
    require(now<instant(ar['expires_at']),'selected artifact expired')
    pld=a['payload'];require(type(pld) is dict and set(pld)=={'archive','archive_size','archive_sha256','manifest_sha256','public_key_sha256','binaries'},'payload schema differs')
    require(pld['archive']=='candidate/nakpanel-29.0.0-linux-amd64.tar.gz' and type(pld['archive_size']) is int and 0<pld['archive_size']<=2**30,'payload archive differs')
    require(all(type(pld[k]) is str and SHA.fullmatch(pld[k]) for k in ('archive_sha256','manifest_sha256','public_key_sha256')),'payload digests missing')
    require(type(pld['binaries']) is dict and set(pld['binaries'])==set(BINARY_PATHS) and all(type(v) is str and SHA.fullmatch(v) for v in pld['binaries'].values()),'binary inventory differs')
    require(all(pld[k]==v for k,v in ACCEPTED_PAYLOAD.items()),'selected payload differs from accepted native application bytes')
    for key in ('controller_files','app_helpers'):
        require(type(a[key]) is dict and a[key] and all(safe_name(n) and type(h) is str and SHA.fullmatch(h) for n,h in a[key].items()),'helper inventory missing/unsafe')
    require('forward_hosted.py' in a['controller_files'] and 'deploy/multipass/common.sh' in a['app_helpers'],'required coordinator/helpers missing')
    return a

def safe_name(name):
    return type(name) is str and bool(name) and not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts and str(PurePosixPath(name))==name and '\\' not in name and not any(c in name for c in '\r\n\0')
def check_artifact(row,a,now=None):
    ar=a['artifact'];now=now or datetime.now(timezone.utc)
    require(type(row) is dict and type(row.get('id')) is int and row['id']==ar['id'] and row.get('name')==ar['name'],'artifact API identity differs')
    require(type(row.get('size_in_bytes')) is int and row['size_in_bytes']==ar['size'] and row.get('digest')=='sha256:'+ar['sha256'],'artifact API size/digest differs')
    require(row.get('expired') is False and row.get('expires_at')==ar['expires_at'] and now<instant(row['expires_at']),'artifact expired')
    w=row.get('workflow_run');require(type(w) is dict and type(w.get('id')) is int and w['id']==ar['run_id'] and w.get('head_sha')==COMMIT,'artifact original workflow/source differs')
def check_capacity(row):
    require(type(row) is dict and row.get('status')=='PASS' and row.get('architecture') in ('x86_64','amd64'),'host preflight failed')
    for key,minimum in [('cpu_count',4),('total_memory',14*2**30),('available_memory',11*2**30),('free_disk',80*2**30)]:require(type(row.get(key)) is int and row[key]>=minimum,'host capacity insufficient: '+key)
    require(row.get('kvm_api')==12 and type(row['kvm_api']) is int,'KVM creation not proven')
def check_owner(path,release,token):predicate_require(regular(path,True).read_text()==release+'\tamd64\t'+token+'\n','host_owner_binding')
def check_negative(code,text,required):
    require(type(code) is int and code!=0,'negative check unexpectedly succeeded')
    expected={f'panelctl: target lacks required hosted PHP {v}; tenant intent cannot be rewritten' for v in required if v!='8.5' and re.fullmatch(r'8\.[234]',v)}
    clean=text.strip()
    require(clean in expected,'negative failed for an unrelated reason')
    return next(v for v in required if clean==f'panelctl: target lacks required hosted PHP {v}; tenant intent cannot be rewritten')
def check_pins(pins):
    for name,h in pins.items():predicate_require(sha(regular(name))==h,'input_pin_mismatch')

def extract_zip(path,target):
    require(not Path(target).exists(),'ZIP target already exists');entries=[];seen=set();total=0
    with zipfile.ZipFile(path) as z:
        for i in z.infolist():
            name=i.filename.rstrip('/') if i.is_dir() else i.filename
            require(safe_name(name) and name not in seen,'unsafe/duplicate ZIP member');seen.add(name)
            kind=(i.external_attr>>16)&0o170000
            require(kind in (0,stat.S_IFREG,stat.S_IFDIR) and not i.flag_bits&1,'nonregular/encrypted ZIP member')
            total+=i.file_size;require(total<=2**31 and len(seen)<=2000,'ZIP expansion exceeds bound');entries.append(i)
        Path(target).mkdir(mode=0o700)
        for i in entries:
            p=Path(target)/i.filename
            if i.is_dir():p.mkdir(mode=0o700,parents=True,exist_ok=True)
            else:
                p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                with z.open(i) as src,p.open('xb') as dst:
                    while True:
                        b=src.read(2**20)
                        if not b:break
                        dst.write(b)
                p.chmod(0o600)

def extract_tar(path,target):
    require(not Path(target).exists(),'tar target already exists');seen=set();total=0
    Path(target).mkdir(mode=0o700)
    # Stream bounded members; never collect an unbounded getmembers() list.
    with tarfile.open(path,'r|gz') as t:
        for i in t:
            name=i.name.rstrip('/') if i.isdir() else i.name
            require(safe_name(name) and name not in seen and (i.isdir() or i.isfile()),'unsafe/duplicate/nonregular tar member');seen.add(name);total+=i.size
            require(total<=2**31 and len(seen)<=2000,'tar expansion exceeds bound')
            p=Path(target)/i.name
            if i.isdir():p.mkdir(mode=0o700,parents=True,exist_ok=True)
            else:
                p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                with t.extractfile(i) as src,p.open('xb') as dst:
                    while True:
                        block=src.read(2**20)
                        if not block:break
                        dst.write(block)
                p.chmod(0o700 if i.mode&0o111 else 0o600)

def check_paths(app,controller,private,public,runner_temp):
    app,controller,private,public,runner_temp=map(Path,(app,controller,private,public,runner_temp))
    require(app.is_absolute() and controller.is_absolute() and app.resolve()==app and controller.resolve()==controller,'source checkout path is not canonical')
    require(app!=controller and app not in controller.parents and controller not in app.parents,'application/controller checkouts overlap')
    require(private.is_absolute() and public.is_absolute() and private!=public and private.parent.resolve()==runner_temp.resolve() and public.parent.resolve()==runner_temp.resolve(),'private/public roots must be distinct direct children of runner temp')
    require(private not in app.parents and public not in app.parents and app not in private.parents and app not in public.parents and controller not in private.parents and controller not in public.parents,'outputs overlap trusted sources')

def check_positive(pre,result):
    predicate_require(type(pre) is dict and pre.get('compatible') is True and pre.get('mode')=='forward-migration' and pre.get('migration_qualified') is False,'positive_preflight')
    manifest=pre.get('manifest');predicate_require(type(manifest) is dict and manifest.get('format_version')==2 and manifest.get('roundcube_sqlite_path') in ('/var/lib/roundcube/roundcube.sqlite','/var/lib/roundcube/db/roundcube','/var/lib/dbconfig-common/sqlite3/roundcube/roundcube'),'positive_snapshot')
    predicate_require(manifest.get('include_mail_data') is True,'positive_mail_data')
    p=manifest.get('platform');predicate_require(type(p) is dict and p.get('profile')=='ubuntu-24.04' and p.get('version_id')=='24.04' and p.get('architecture')=='amd64' and p.get('internal_php_version')=='8.3' and p.get('php_inventory_complete') is True and p.get('required_php_versions')==['8.5'],'positive_php_inventory')
    predicate_require(type(result) is dict and result.get('schema_mismatch') is False,'positive_restore_result')
    r=result.get('summary');predicate_require(type(r) is dict and r.get('manifest')==manifest and r.get('schema_mismatch') is False and type(r.get('extracted_entries')) is int and r['extracted_entries']>0,'positive_restore_manifest')
    predicate_require(type(r.get('mariadb_restored')) is list and 'np_forward_fixture' in r['mariadb_restored'],'positive_database_import')
    predicate_require(type(r.get('services_started')) is list and r['services_started'] and result.get('services_started')==r['services_started'],'positive_services')

class Budget:
    def __init__(self,start=None,clock=time.monotonic):self.clock=clock;self.start=clock() if start is None else start;self.ends={}
    def allowance(self,stage):
        require(stage in CAPS,'unknown bounded stage');now=self.clock();reserve=0 if stage=='cleanup' else CAPS['cleanup']
        self.ends.setdefault(stage,now+CAPS[stage]);remaining=min(self.ends[stage]-now,self.start+TOTAL_SECONDS-now-reserve)
        if remaining<6:raise Deadline('insufficient stage/cleanup deadline headroom')
        return remaining-4
    def check(self,stage):
        now=self.clock();reserve=0 if stage=='cleanup' else CAPS['cleanup']
        if now>=self.start+TOTAL_SECONDS-reserve:raise Deadline('overall/cleanup deadline expired')
        if stage in self.ends and now>=self.ends[stage]:raise Deadline('cumulative stage deadline expired')


def group_exists(group):
    try:os.killpg(group,0);return True
    except ProcessLookupError:return False
    except PermissionError:return True

# Reviewed v6 group primitive; only the accepted fixed stage-name set is adapted.
class ControlledTermination(KeyboardInterrupt):
 def __init__(self,message,signum=None):
  super().__init__(message);self.signum=signum
def _terminate(signum,frame):raise ControlledTermination('controlled SIGTERM',signum)

def owned_group_wait(group,child,grace):
 deadline=time.monotonic()+grace
 while True:
  child.poll()  # Reap our direct leader before deciding whether its group remains.
  if not group_exists(group):return True
  if time.monotonic()>=deadline:return False
  time.sleep(.01)

def owned_action(B,root,state,command,environment,*,stdout=None,stderr=None,timeout=10800,term_grace=1,kill_grace=2):
 require(state['operation'] in CAPS,'unsupported owned action')
 require(all(type(v) in (int,float) and v>0 for v in (timeout,term_grace,kill_grace)),'owned action needs bounded positive deadlines')
 root=Path(root);folder=root/'actions';folder.mkdir(mode=0o700,exist_ok=True)
 path=folder/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')+'-'+state['operation']+'.json')
 child=None;phase='starting';received=None;failure=None;timed_out=False;unexpected=False;drained=False;cleanup_error=None;started=utc();previous={};outcome=None
 state['action_tree']={'started':False,'owned_group_empty':False,'leader_reaped':False}
 def terminate(signum,frame):
  nonlocal received
  if received is None:received=signum
  # Acquire the actual newly created PID before unwinding startup. Repeated
  # cancellation while cleaning cannot interrupt custody or receipt publication.
  if phase=='waiting':raise ControlledTermination('controlled owned-action cancellation',signum)
 def publish_terminal_cancellation(error):
  nonlocal outcome
  if outcome is None:return
  # Block real cancellation during durable FAIL publication and restoration.
  # On unmask, an already pending signal may raise through the restored outer
  # handler; the original cancellation is still propagated after FAIL exists.
  blocked=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
  try:
   outcome.update(status='failed',interrupted=True,termination_signal=received if received is not None else getattr(error,'signum',None),error_type=type(error).__name__,finished_at=utc())
   state['action_tree']=outcome;publish(path,outcome);state['action_receipt']=file_ref(path)
  finally:
   try:
    for signum,handler in previous.items():signal.signal(signum,handler)
   finally:
    try:signal.pthread_sigmask(signal.SIG_SETMASK,blocked)
    except KeyboardInterrupt:pass
 try:
  try:
   for signum in (signal.SIGINT,signal.SIGTERM):previous[signum]=signal.signal(signum,terminate)
   try:
    child=subprocess.Popen(command,env=environment,stdout=stdout,stderr=stderr,start_new_session=True)
    state['action_tree']['started']=True;phase='waiting'
    if received is not None:raise ControlledTermination('controlled startup cancellation',received)
    child.wait(timeout=timeout)
   except subprocess.TimeoutExpired as error:timed_out=True;failure=error
   except BaseException as error:failure=error
   finally:
    phase='cleanup'
    if child is None:drained=True
    else:
     try:
      if child.returncode==0 and failure is None and received is None:unexpected=not owned_group_wait(child.pid,child,.3)
      if group_exists(child.pid):
       try:os.killpg(child.pid,signal.SIGTERM)
       except ProcessLookupError:pass
       drained=owned_group_wait(child.pid,child,term_grace)
       if not drained:
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        drained=owned_group_wait(child.pid,child,kill_grace)
      else:drained=True
      child.poll()
     except Exception as error:cleanup_error=type(error).__name__;drained=False
    reaped=child is None or child.returncode is not None
    passed=child is not None and child.returncode==0 and failure is None and received is None and not timed_out and not unexpected and drained and reaped
    outcome={'schema':'nakpanel-forward-owned-action-v1','source_vm':B['source_vm'],'run_token':B['run_token'],'runtime_commit':B['source_payload']['commit'],'operation':state['operation'],'status':'passed' if passed else 'failed','action_pid':child.pid if child else None,'action_pgid':child.pid if child else None,'started':child is not None,'exit_code':child.returncode if child else None,'timed_out':timed_out,'interrupted':received is not None or isinstance(failure,KeyboardInterrupt),'termination_signal':received,'unexpected_descendants':unexpected,'owned_group_empty':drained,'leader_reaped':reaped,'started_at':started,'finished_at':utc()}
    if failure is not None:outcome['error_type']=type(failure).__name__
    if cleanup_error is not None:outcome['cleanup_error_type']=cleanup_error
    state['action_tree']=outcome;publish(path,outcome);state['action_receipt']=file_ref(path)
  finally:
   for signum,handler in previous.items():signal.signal(signum,handler)
  require(drained and reaped,'owned action group drain is unconfirmed; no source stop or handoff authorized')
  if received is not None:raise ControlledTermination('cancellation before action handoff',received)
  if failure is not None:raise failure
  require(passed,'owned action failed or left unexpected descendants; inspect private outcome')
  result=subprocess.CompletedProcess(command,child.returncode)
  if received is not None:raise ControlledTermination('cancellation at action return',received)
  return result
 except BaseException as error:
  if received is not None or isinstance(error,KeyboardInterrupt):publish_terminal_cancellation(error)
  raise


def file_ref(path):return {'path':str(path),'sha256':sha(path)}

def public_result(state):
    # New fixed projection only. Never copy arbitrary child output/JSON values.
    r={'schema':'nakpanel-hosted-forward-result-v1','status':'PASS' if state.get('status')=='PASS' else 'FAIL','scope':'fresh-synthetic-native-forward','source_commit':COMMIT,'source_tree':TREE,'production_qualified':False,'fresh_source_full17_claim':False,'post_job_source_retained':False,'target_reboots':1 if state.get('target_reboot_verified') is True else 0,'planned_target_reboots':1,'dynamic_zero_writes_instrumentation':False,'resources':{'maximum_simultaneous_guests':2,'source':{'cpus':2,'memory':'5G','disk':'32G'},'target':{'cpus':2,'memory':'5G','disk':'32G'}},'stages':[]}
    for row in state.get('stages',[]):
        if type(row) is dict and row.get('stage') in CAPS and (type(row.get('exit_code')) is int or row.get('exit_code') is None):r['stages'].append(dict(stage=row['stage'],exit_code=row['exit_code'],**{k:row.get(k) is True for k in ('owned_group_empty','leader_reaped','timed_out','interrupted')}))
    for key in ('negative_missing_php','negative_archive_sha256','positive_archive_sha256','manifest_sha256','public_key_sha256','source_boot_id','target_boot_id'):
        value=state.get(key)
        if type(value) is str and (SHA.fullmatch(value) or (key=='negative_missing_php' and re.fullmatch(r'8\.[234]',value)) or (key.endswith('boot_id') and re.fullmatch('[a-f0-9-]{36}',value))):r[key]=value
    for key in ('source_vm','negative_vm','positive_vm'):
        value=state.get(key)
        if type(value) is str and re.fullmatch('nakpanel-[A-Za-z0-9-]{1,120}',value):r[key]=value
    value=state.get('run_token')
    if type(value) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9-]{5,63}',value):r['run_token']=value
    for key in ('workflow_run_id','workflow_run_attempt'):
        if type(state.get(key)) is str and re.fullmatch('[0-9]{1,20}',state[key]):r[key]=state[key]
    r['actual_guest_allocations']=[]
    for row in state.get('actual_guest_allocations',[]):
        if type(row) is dict and row.get('role') in ('source','negative','positive') and type(row.get('vm')) is str and re.fullmatch('nakpanel-[A-Za-z0-9-]{1,120}',row['vm']) and all(type(row.get(k)) is int and 0<row[k]<=64*2**30 for k in ('cpu_count','memory_bytes','root_disk_bytes')):
            r['actual_guest_allocations'].append({k:row[k] for k in ('role','vm','cpu_count','memory_bytes','root_disk_bytes')})
    host=state.get('host_admission')
    if type(host) is dict and all(type(host.get(k)) is int and 0<host[k]<2**60 for k in ('cpu_count','total_memory','available_memory','free_disk','kvm_api')):r['host_admission']={k:host[k] for k in ('cpu_count','total_memory','available_memory','free_disk','kvm_api')}
    r['cleanup_completed']=state.get('cleanup_completed') is True
    for key in ('ordered_negative_check_only','positive_restore_verified','source_unchanged','target_reboot_verified'):r[key]=state.get(key) is True
    for key in ('controller_commit','workflow_commit'):
        if re.fullmatch('[a-f0-9]{40}',state.get(key,'')):r[key]=state[key]
    for key in ('admission_sha256','command_sources_inventory_sha256'):
        if SHA.fullmatch(state.get(key,'')):r[key]=state[key]
    for key in ('current_boundary','last_completed_boundary','failure_boundary'):
        r[key]=state.get(key) if type(state.get(key)) is str and state.get(key) in BOUNDARIES else 'UNKNOWN'
    r['failure_predicate']=state.get('failure_predicate') if type(state.get('failure_predicate')) is str and state.get('failure_predicate') in PREDICATES else 'UNKNOWN'
    r['failure_kind']=state.get('failure_kind') if type(state.get('failure_kind')) is str and state.get('failure_kind') in {'semantic','command','cancelled','deadline'} else 'UNKNOWN'
    r['failure_code']=state.get('failure_code') if state.get('failure_code') in {'admission_refused','stage_failed','cancelled','cleanup_failed','deadline','input_drift'} else (None if r['status']=='PASS' else 'stage_failed')
    r['primary_outcome'],r['cleanup_outcome']=outcomes_projection(state)
    return r

class Runner:
    def __init__(self,root,env,binding,budget=None):self.root=Path(root);self.env=env;self.binding=binding;self.budget=budget or Budget();self.rows=[];self.counter=0;self.last_tree_empty=True;self.before=lambda stage:None
    def call(self,stage,args,*,data=None,env=None,accepted=(0,)):
        self.before(stage);self.counter+=1;folder=self.root/'logs';folder.mkdir(mode=0o700,exist_ok=True);prefix=folder/(str(self.counter)+'-'+stage)
        inp=None
        if data is not None:
            inp=Path(str(prefix)+'.stdin');inp.write_bytes(data if isinstance(data,bytes) else data.encode());inp.chmod(0o600)
        stdout=Path(str(prefix)+'.stdout');stderr=Path(str(prefix)+'.stderr');state={'operation':stage}
        # Existing owned_action takes file descriptors, and Popen inherits stdin
        # via an explicit duplicate-free pre-opened fd, never command-line secrets.
        read=None
        command=list(map(str,args))
        if inp is not None:
            # A fixed tiny shim sets fd0 then execs the intended argv in the SAME
            # session/group; no shell quoting or new process/session is introduced.
            command=[sys.executable,'-I','-B','-c','import os,sys;f=os.open(sys.argv[1],os.O_RDONLY);os.dup2(f,0);os.close(f);os.execvpe(sys.argv[2],sys.argv[2:],os.environ)',str(inp),*command]
        try:
            with stdout.open('xb') as out,stderr.open('xb') as err:
                os.chmod(stdout,0o600);os.chmod(stderr,0o600)
                try:owned_action(self.binding,self.root,state,command,env or self.env,stdout=out,stderr=err,timeout=self.budget.allowance(stage))
                except Refusal:
                    tree=state.get('action_tree',{})
                    if type(tree.get('exit_code')) is not int or tree['exit_code'] not in accepted or not tree.get('owned_group_empty') or tree.get('unexpected_descendants') or tree.get('interrupted') or tree.get('timed_out'):raise
        finally:
            if read:read.close()
            tree=state.get('action_tree',{});self.last_tree_empty=tree.get('owned_group_empty') is True and tree.get('leader_reaped') is True
            self.rows.append(dict(stage=stage,**{k:tree.get(k) for k in ('exit_code','owned_group_empty','leader_reaped','timed_out','interrupted')}))
        self.budget.check(stage);self.before(stage)
        code=state['action_tree']['exit_code'];require(code in accepted,'command returned an unexpected exit')
        return code,stdout,stderr
    def output(self,stage,args,**kw):
        code,out,err=self.call(stage,args,**kw);return out.read_text()

# Read-only witness only: root-owned platform state, three actual executables,
# individual unit observations, physical SQL and a stable logical DB fingerprint.
PROOF=r'''import hashlib,json,os,pathlib,stat,subprocess
paths={'panel':'/usr/local/bin/nakpanel-panel','agent':'/usr/local/bin/nakpanel-agent','panelctl':'/usr/local/bin/panelctl'}
r={'binaries':{},'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
for k,p in paths.items():
 s=os.lstat(p)
 if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise SystemExit('untrusted installed executable')
 r['binaries'][k]=hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
r['platform']=json.loads(pathlib.Path('/etc/nakpanel/platform.json').read_text())
r['architecture']=subprocess.check_output(['dpkg','--print-architecture'],text=True).strip()
r['units']={}
for u in ['nakpanel.service','nakpanel-agent.service','nginx.service','postgresql.service','mariadb.service','named.service','stalwart-mail.service','nakpanel-proftpd.service']:
 p=subprocess.run(['systemctl','is-active',u],capture_output=True,text=True,timeout=10);r['units'][u]=p.stdout.strip()
q="SELECT json_build_object('sites',(SELECT COALESCE(json_agg(json_build_array(id,domain,php_version,desired_php_version,desired_status) ORDER BY id),'[]'::json) FROM sites),'plans',(SELECT COALESCE(json_agg(json_build_array(id,revision) ORDER BY id),'[]'::json) FROM plans),'schema',(SELECT max(version_id) FROM goose_db_version))::text"
sql=subprocess.check_output(['runuser','-u','postgres','--','psql','-XAtq','-d','nakpanel','-c',q],text=True,timeout=20)
r['database_fingerprint']=hashlib.sha256(sql.encode()).hexdigest()
print(json.dumps(r,sort_keys=True))'''

class Coordinator:
    def __init__(self,a,app,controller,private,public,env=None):
        self.a=a;self.app=Path(app);self.controller=Path(controller);self.root=Path(private);self.public=Path(public);self.host=dict(os.environ if env is None else env);self.state={'status':'STARTED','stages':[]};self.pins={};self.known={};self.staged=None;self.private_created=False;self.public_created=False
        self.bash='/usr/bin/bash';self.python=sys.executable;self.token=None;self.bundle=None;self.key=None
        self._work_operation='UNKNOWN';self._proof_count=0;self._proof_failure=None;self._proof_observation=None
        self.state.update(primary_outcome={'status':'not_run'},cleanup_outcome={'status':'not_run','failures':[]})
    def boundary(self,name):
        require(name in BOUNDARIES,'unknown fixed boundary');self.state['current_boundary']=name
    def remember_failure(self,error):
        if 'failure_boundary' in self.state:return
        self.state['failure_boundary']=self.state.get('current_boundary','UNKNOWN')
        self.state['failure_predicate']=error.predicate if isinstance(error,PredicateRefusal) else 'UNKNOWN'
        rows=self.run.rows if hasattr(self,'run') else []
        nonzero=bool(rows and type(rows[-1].get('exit_code')) is int and rows[-1]['exit_code']!=0)
        self.state['failure_kind']='semantic' if isinstance(error,PredicateRefusal) else 'deadline' if isinstance(error,Deadline) else 'cancelled' if isinstance(error,KeyboardInterrupt) else 'command' if nonzero else 'UNKNOWN'
    def failure_details(self,error):
        rows=self.run.rows if hasattr(self,'run') else []
        nonzero=bool(rows and type(rows[-1].get('exit_code')) is int and rows[-1]['exit_code']!=0)
        result={'boundary':self.state.get('current_boundary','UNKNOWN'),'predicate':error.predicate if isinstance(error,PredicateRefusal) else 'UNKNOWN','kind':'semantic' if isinstance(error,PredicateRefusal) else 'deadline' if isinstance(error,Deadline) else 'cancelled' if isinstance(error,KeyboardInterrupt) else 'command' if nonzero else 'UNKNOWN','command_count':len(rows)}
        pending=self._proof_failure
        if pending is not None and pending[0] is error:result['proof_observation']=pending[1]
        return failure_projection(result)
    def capture_primary(self,error=None):
        if self.state.get('primary_outcome',{}).get('status')!='not_run':return
        value=self.failure_details(error) if error is not None else failure_projection({'boundary':self.state.get('current_boundary'),'command_count':len(self.run.rows) if hasattr(self,'run') else 0})
        self.state['primary_outcome']=dict(status='failed' if error is not None else 'passed',**value)
    def cleanup_failure(self,role,error):
        outcome=self.state['cleanup_outcome'];outcome['status']='failed'
        if len(outcome['failures'])<4:outcome['failures'].append(dict(role=closed(role,{'source','negative','positive','private_staging'}),**self.failure_details(error)))
    def proof_note(self,key,value):
        # Observation-only: malformed/unavailable diagnostics never become a gate.
        try:
            if self._proof_observation is not None and key in CHECK_KEYS and type(value) is bool:self._proof_observation['checks'][key]=value
        except Exception:pass
    def proof_context(self,name,stage):
        if type(stage) is not str:return 'UNKNOWN'
        if name==getattr(self,'source',None):return stage if stage in {'current','phase28','phase30','negative_backup','prepare'} else 'positive_source' if stage=='positive' else 'UNKNOWN'
        if name==getattr(self,'negative',None) and stage=='negative_check':return 'negative_target'
        if name==getattr(self,'positive_vm',None) and stage=='positive':return 'positive_target'
        return 'UNKNOWN'
    def list_names(self,row,prefix):
        self.boundary(prefix+'_object');predicate_require(type(row) is dict,prefix+'_object')
        self.boundary(prefix+'_errors');predicate_require('errors' not in row or (type(row['errors']) is list and row['errors']==[]),prefix+'_errors')
        self.boundary(prefix+'_rows');predicate_require(type(row.get('list')) is list,prefix+'_rows')
        names=[]
        for item in row['list']:
            predicate_require(type(item) is dict and type(item.get('name')) is str and re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,127}',item['name']),prefix+'_rows');names.append(item['name'])
        predicate_require(len(names)==len(set(names)),prefix+'_rows');return names
    def environment(self):
        allowed=('PATH','HOME','LANG','LC_ALL','TMPDIR','RUNNER_TEMP','GITHUB_ENV','GITHUB_ACTIONS','RUNNER_ENVIRONMENT','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_REPOSITORY','GITHUB_SHA','CONTROLLER_SHA')
        e={k:self.host[k] for k in allowed if k in self.host};e.update(PYTHONDONTWRITEBYTECODE='1',GOTOOLCHAIN='go1.26.9',NAKPANEL_QUALIFICATION_PHP_PROVIDER='native',NAKPANEL_MULTIPASS_ARCH='amd64',NAKPANEL_MULTIPASS_IMAGE='24.04',NAKPANEL_RELEASE_ALLOW_DEVELOPMENT='1',NAKPANEL_FORWARD_ALLOW_DEVELOPMENT='1')
        return e
    def git(self,root,*args):return self.run.output('artifact',['git','-C',root,*args]).strip()
    def checkout(self,root,commit,tree,expected):
        require(self.git(root,'rev-parse','HEAD')==commit,'checkout commit differs')
        if tree:require(self.git(root,'rev-parse','HEAD^{tree}')==tree,'checkout tree differs')
        require(not self.git(root,'status','--porcelain','--untracked-files=all'),'checkout dirty')
        names=self.git(root,'ls-files','-z','deploy/multipass').split('\0') if root==self.app else list(expected)
        names={n for n in names if n};names.update(['deploy/release/verify.py','deploy/install/platform.sh','deploy/install/platform_state.py'] if root==self.app else [])
        require(set(expected)==names,'complete helper inventory differs')
        for name,h in expected.items():
            p=regular(root/name)
            # Git command output is text; avoid newline/encoding normalization by
            # hashing the retained byte stdout, not the convenience text result.
            code,out,err=self.run.call('artifact',['git','-C',root,'show',commit+':'+name]);require(sha(p)==sha(out)==h,'helper differs from committed blob');self.pins[str(p)]=h
        require(not any(root.rglob('__pycache__')),'foreign source bytecode cache')
    def shell(self,stage,body,*args,env=None,data=None,accepted=(0,)):
        return self.run.call(stage,[self.bash,'-ceu','set -euo pipefail; source "$APP_SOURCE/deploy/multipass/common.sh"; '+body,'--',*args],env=env,data=data,accepted=accepted)
    def jshell(self,stage,body,*args,env=None):return decoded(self.shell(stage,body,*args,env=env)[1].read_bytes())
    def require_live_host(self):
        require(platform.system()=='Linux' and platform.machine() in ('x86_64','amd64') and self.host.get('GITHUB_ACTIONS')=='true' and self.host.get('RUNNER_ENVIRONMENT')=='github-hosted','disposable hosted Linux AMD64 required')
        require(self.host.get('GITHUB_REPOSITORY')==self.a['repository'] and self.host.get('CONTROLLER_SHA')==self.a['controller_commit'],'workflow controller/repository differs')
        require(all(re.fullmatch('[0-9]+',self.host.get(k,'')) for k in ('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT')),'actual workflow identity missing')
    def setup(self):
        self.require_live_host();check_paths(self.app,self.controller,self.root,self.public,Path(self.host['RUNNER_TEMP']));os.umask(0o077);require(not self.root.exists() and not self.public.exists(),'new private/public outputs must not exist')
        self.root.mkdir(mode=0o700);self.private_created=True;self.public.mkdir(mode=0o700);self.public_created=True
        self.token='hosted-forward-'+self.host['GITHUB_RUN_ID']+'-'+self.host['GITHUB_RUN_ATTEMPT']+'-'+self.a['nonce'][:8]
        require(len(self.token)<=64,'ownership token too long')
        self.source='nakpanel-24-04-amd64-'+self.token;self.negative='nakpanel-negative-'+self.token;self.positive_vm='nakpanel-positive-'+self.token
        self.state.update(source_vm=self.source,negative_vm=self.negative,positive_vm=self.positive_vm,run_token=self.token,workflow_run_id=self.host['GITHUB_RUN_ID'],workflow_run_attempt=self.host['GITHUB_RUN_ATTEMPT'])
        env=self.environment();env.update(APP_SOURCE=str(self.app),NAKPANEL_RUN_TOKEN=self.token,NAKPANEL_MULTIPASS_VM=self.source,NAKPANEL_MULTIPASS_SOURCE_VM=self.source,NAKPANEL_MULTIPASS_DR_VM=self.negative,NAKPANEL_OWNERSHIP_DIR=str(self.root/'owners'),NAKPANEL_QUALIFICATION_VM_CPUS='2',NAKPANEL_QUALIFICATION_VM_MEMORY='5G',NAKPANEL_QUALIFICATION_VM_DISK='32G',NAKPANEL_QUALIFICATION_DR_CPUS='2',NAKPANEL_QUALIFICATION_DR_MEMORY='5G',NAKPANEL_QUALIFICATION_DR_DISK='32G')
        self.state.update(controller_commit=self.a['controller_commit'],workflow_commit=self.host.get('GITHUB_SHA',''),command_sources_inventory_sha256=digest(canonical(self.a['app_helpers'])))
        self.run=Runner(self.root,env,{'source_vm':self.source,'run_token':self.token,'source_payload':{'commit':COMMIT}})
        child_bash=self.run.output('artifact',[self.bash,'-c','((BASH_VERSINFO[0]>=5)) && command -v bash']).strip();require(os.path.samefile(child_bash,self.bash),'nested Bash interpreter differs')
        self.checkout(self.controller,self.a['controller_commit'],None,self.a['controller_files']);self.checkout(self.app,COMMIT,TREE,self.a['app_helpers']);self.run.before=self.guard
    def guard(self,stage):
        check_pins(self.pins)
        if stage!='cleanup':require(datetime.now(timezone.utc)<instant(self.a['expires_at']),'launch admission expired before transition')
    def acquire(self):
        a=self.a;repo=a['repository'];ar=a['artifact'];ghenv=dict(self.run.env);require(type(self.host.get('GH_TOKEN')) is str and bool(self.host['GH_TOKEN']),'read-only artifact token missing');ghenv['GH_TOKEN']=self.host['GH_TOKEN']
        row=decoded(self.run.output('artifact',['gh','api','--hostname','github.com',f'/repos/{repo}/actions/artifacts/{ar["id"]}'],env=ghenv));check_artifact(row,a)
        code,z,_=self.run.call('artifact',['gh','api','--hostname','github.com',f'/repos/{repo}/actions/artifacts/{ar["id"]}/zip'],env=ghenv)
        require(z.stat().st_size==ar['size'] and sha(z)==ar['sha256'],'actual original ZIP digest/size differs');self.pins[str(z)]=sha(z)
        dst=self.root/'download';extract_zip(z,dst);archive=regular(dst/a['payload']['archive']);require(archive.stat().st_size==a['payload']['archive_size'] and sha(archive)==a['payload']['archive_sha256'],'inner current archive differs')
        self.pins[str(archive)]=sha(archive);extract_tar(archive,self.root/'release');self.bundle=self.root/'release'/'nakpanel-29.0.0-linux-amd64';self.key=regular(dst/'test-public.pem')
        require(sha(self.bundle/'manifest.json')==a['payload']['manifest_sha256'] and sha(self.key)==a['payload']['public_key_sha256'],'manifest/public trust key differs')
        manifest=decoded((self.bundle/'manifest.json').read_bytes());require(manifest.get('commit')==COMMIT and manifest.get('development') is True and manifest.get('go_toolchain')=='go1.26.9','manifest source/toolchain/development differs')
        self.run.call('artifact',[self.python,'-I','-B',self.app/'deploy/release/verify.py','--bundle',self.bundle,'--public-key',self.key,'--version','29.0.0','--architecture','amd64','--allow-development'])
        require(type(manifest.get('files')) is dict and len(manifest['files'])==173,'signed release inventory differs')
        for name,h in manifest['files'].items():
            if name.startswith('bin/'):
                require(name in {'bin/'+n+s for n in BINARY_PATHS for s in ('','.buildinfo')},'unexpected binary artifact')
                if not name.endswith('.buildinfo'):require(h==a['payload']['binaries'][name[4:]],'signed selected binary differs')
            else:require(sha(self.app/name)==h,'release asset differs from current source')
            self.pins[str(self.bundle/name)]=h
        for n in BINARY_PATHS:
            code,p,_=self.run.call('artifact',['go','version','-m',self.bundle/'bin'/n]);actual=p.read_text().splitlines();signed=(self.bundle/'bin'/(n+'.buildinfo')).read_text().splitlines();require(actual[1:]==signed[1:] and actual[0].endswith(': go1.26.9'),'signed binary buildinfo differs')
        for p in (self.bundle/'manifest.json',self.bundle/'manifest.sig',self.key):self.pins[str(p)]=sha(p)
        self.state.update(manifest_sha256=sha(self.bundle/'manifest.json'),public_key_sha256=sha(self.key))
        self.run.env.update(NAKPANEL_RELEASE_BUNDLE=str(self.bundle),NAKPANEL_RELEASE_PUBLIC_KEY=str(self.key),NAKPANEL_RELEASE_VERSION='29.0.0')
    def host_prepare(self):
        self.run.call('host',[self.bash,self.app/'deploy/multipass/prepare-hosted-runner.sh'])
        # Read ONLY TMPDIR from the new helper-produced GITHUB_ENV protocol.
        lines=Path(self.host['GITHUB_ENV']).read_text().splitlines();paths=[s[7:] for s in lines if s.startswith('TMPDIR=')]
        require(paths,'private snap-visible TMPDIR missing');p=Path(paths[-1]);s=p.lstat();base=Path(self.host['RUNNER_TEMP']).resolve()
        require(p.is_absolute() and p.resolve()==p and base in p.parents and stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700,'untrusted hosted TMPDIR')
        self.run.env['TMPDIR']=str(p)
    def images(self):
        dst=self.root/'download'
        for release,(suite,serial,h) in IMAGES.items():
            metadata=dst/'images'/suite
            self.run.call('images',['gpgv','--keyring','/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg',metadata/'SHA256SUMS.gpg',metadata/'SHA256SUMS'])
            filename='ubuntu-'+release+'-server-cloudimg-amd64.img';rows=[line.split()[0] for line in (metadata/'SHA256SUMS').read_text().splitlines() if len(line.split())==2 and line.split()[1].lstrip('*')==filename];require(rows==[h],'image pin differs from signed manifest')
            url=f'https://cloud-images.ubuntu.com/releases/{suite}/release-{serial}/{filename}';target=self.root/filename
            self.run.call('images',['curl','--fail','--location','--proto','=https','--proto-redir','=https','--max-time','600',url,'--output',target]);require(sha(target)==h,'image bytes differ');self.pins[str(target)]=h
            prefix='NAKPANEL_MULTIPASS_IMAGE_' if release=='24.04' else 'NAKPANEL_FORWARD_TARGET_IMAGE_';self.run.env.update({prefix+'SOURCE':str(target),prefix+'SHA256':h})
        path=self.root/'host-preflight.json';self.run.call('admit',[self.python,'-I','-B',self.app/'deploy/multipass/hosted-runner-preflight.py','--output',path]);row=decoded(path.read_bytes());check_capacity(row);self.state['host_admission']={k:row[k] for k in ('cpu_count','total_memory','available_memory','free_disk','kvm_api')};row['requested_forward_budget']={'maximum_guests':2,'source':{'cpus':2,'memory':'5G','disk':'32G'},'target':{'cpus':2,'memory':'5G','disk':'32G'}};publish(self.root/'forward-capacity.json',row)
    def check_new_vm(self,name,stage):
        caller=self.state.get('current_boundary');self.boundary('vm_list_command');text=self.run.output(stage,['multipass','list','--format','json']);self.boundary('vm_list_json');row=decoded(text)
        names=self.list_names(row,'vm_list');require(name not in names and set(names)<=set(self.known),'unexpected/preexisting VM; refuse allocation/adoption')
        if caller is None:self.state.pop('current_boundary',None)
        else:self.state['current_boundary']=caller
    def owner(self,name,release):check_owner(self.root/'owners'/self.token/name,release,self.token)
    def proof(self,name,release,stage,frozen=False):
        caller=self.state.get('current_boundary');self._proof_count+=1
        self._proof_failure=None;self._proof_observation={'invocation':self._proof_count,'context':self.proof_context(name,stage),'active':True,'json_decoded':False,'checks':{}}
        self.state['proof_observation']=proof_projection(self._proof_observation);passed=False
        try:
            self.boundary('proof_owner');self.owner(name,release)
            self.boundary('proof_pins');check_pins(self.pins)
            self.boundary('proof_command');code,out,_=self.shell(stage,'assert_vm_identity "$1" "$2" amd64 "$NAKPANEL_RUN_TOKEN"; multipass exec "$1" -- sudo python3 -c "$3"',name,release,PROOF)
            self.boundary('proof_json');row=decoded(out.read_bytes());self._proof_observation['json_decoded']=True
            p=row.get('platform',{});expected='ubuntu-24.04' if release=='24.04' else 'ubuntu-26.04-native'
            self.boundary('proof_binaries');ok=row.get('binaries')==self.a['payload']['binaries'];self.proof_note('binary_inventory_matches',ok)
            if type(row.get('binaries')) is dict:
                for k in ('panel','agent','panelctl'):self.proof_note(k+'_matches',row['binaries'].get(k)==self.a['payload']['binaries'].get(k))
            predicate_require(ok,'source_binary_inventory')
            self.boundary('proof_architecture');ok=row.get('architecture')=='amd64';self.proof_note('architecture_matches',ok);predicate_require(ok,'source_architecture')
            self.boundary('proof_profile');ok=p.get('profile')==expected;self.proof_note('profile_matches',ok);predicate_require(ok,'source_profile')
            self.boundary('proof_version');ok=p.get('version_id')==release;self.proof_note('version_matches',ok);predicate_require(ok,'source_version')
            self.boundary('proof_database');ok=type(row.get('database_fingerprint')) is str and SHA.fullmatch(row['database_fingerprint']);self.proof_note('database_fingerprint_valid',bool(ok));predicate_require(ok,'source_database_fingerprint')
            self.boundary('proof_boot');ok=re.fullmatch('[a-f0-9-]{36}',row.get('boot_id',''));self.proof_note('boot_id_valid',bool(ok));predicate_require(ok,'source_boot_id')
            if not frozen:
                self.boundary('proof_units');units=row.get('units')
                # The original conjunction evaluates first. In particular an
                # unhashable malformed value still raises before any override.
                ok=type(units) is dict and len(units)==8 and set(units.values())=={'active'}
                eligible=type(stage) is str and ((name==getattr(self,'source',None) and ((self._work_operation=='source_phases' and stage in {'current','phase28','phase30'}) or (self._work_operation=='negative_backup' and stage=='negative_backup'))) or (name==getattr(self,'negative',None) and self._work_operation=='negative_target' and stage=='negative_check'))
                if not ok and eligible:ok=type(units) is dict and len(units)==8 and all(type(v) is str for v in units.values()) and all(units.get(u)=='active' for u in CORE_SEVEN)
                self.proof_note('units_predicate',ok)
                if type(units) is dict:
                    for alias,unit in SERVICE_ALIASES.items():self.proof_note(alias,units.get(unit)=='active')
                predicate_require(ok,'source_units')
            publish(self.root/(stage+'-'+name+'-proof.json'),row);passed=True;return row
        except BaseException as error:
            self._proof_failure=(error,proof_projection(self._proof_observation));raise
        finally:
            self._proof_observation['active']=False;self.state['proof_observation']=proof_projection(self._proof_observation);self._proof_observation=None
            if passed:
                if caller is None:self.state.pop('current_boundary',None)
                else:self.state['current_boundary']=caller
    def observed_budget(self,name,stage):
        row=decoded(self.run.output(stage,['multipass','info',name,'--format','json']));require(row.get('errors')==[] and set(row.get('info',{}))=={name},'actual VM budget record differs');i=row['info'][name]
        def number(x):require(type(x) is int or (type(x) is str and x.isdigit()),'invalid actual allocation');return int(x)
        cpu=number(i.get('cpu_count'));mem=number(i.get('memory',{}).get('total'));disks=i.get('disks');require(type(disks) is dict and disks,'actual disk observation missing');size=max(number(v.get('total')) for v in disks.values())
        require(cpu==2 and 4_800_000_000<=mem<=5.5*2**30 and 28_000_000_000<=size<=34.5*2**30,'observed guest allocation differs from requested2/5G/32G')
        self.state.setdefault('actual_guest_allocations',[]).append({'role':{self.source:'source',self.negative:'negative',self.positive_vm:'positive'}[name],'vm':name,'cpu_count':cpu,'memory_bytes':mem,'root_disk_bytes':size})
        publish(self.root/(name+'-allocation.json'),{'requested':{'cpus':2,'memory':'5G','disk':'32G'},'observed':{'cpu_count':cpu,'memory_bytes':mem,'root_disk_bytes':size}})
    def source_phases(self):
        self.check_new_vm(self.source,'current');self.known[self.source]='24.04'
        self.boundary('source_current_run');self.shell('current','init_qualification_run; exec "$BASH" "$APP_SOURCE/deploy/multipass/current-install-verify.sh"')
        self.boundary('source_budget');self.observed_budget(self.source,'current');self.proof(self.source,'24.04','current')
        for stage in ('phase28','phase30'):
            self.boundary('source_'+stage+'_run');check_pins(self.pins);self.shell(stage,'export NAKPANEL_SKIP_PRIOR_PHASES=1; exec "$BASH" "$APP_SOURCE/deploy/multipass/'+stage+'-verify.sh"');self.proof(self.source,'24.04',stage)
    def operator(self,*args):
        return ['multipass','exec',self.source,'--','sudo','runuser','-u','nakpanel','--','env','NAKPANEL_DATABASE_URL=postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable','NAKPANEL_AGENT_SOCKET=/run/nakpanel/agent.sock','NAKPANEL_SECRET_KEY_FILE=/etc/nakpanel/secret-keys.json','panelctl','--actor','task10-forward',*args]
    def negative_backup(self):
        self.proof(self.source,'24.04','negative_backup');dest='forward-negative-'+self.a['nonce'][:12]
        count=self.run.output('negative_backup',['multipass','exec',self.source,'--','sudo','-u','postgres','psql','-XAtq','-d','nakpanel','-c',"SELECT count(*) FROM server_backup_destinations WHERE name='"+dest+"'"]).strip();require(count=='0','negative backup destination already exists')
        text=self.run.output('negative_backup',self.operator('backup-server','key','init'));lines=[s for s in text.splitlines() if re.fullmatch('nkbk1-[A-Z2-7]{52}',s)];require(len(lines)==1,'one-time backup key output invalid');self.negkey=self.root/'negative.key';self.negkey.write_text(lines[0]+'\n');self.negkey.chmod(0o600)
        self.run.call('negative_backup',self.operator('backup-server','destination','add','--name',dest,'--kind','local','--disabled','--settings','{"dir":"/var/lib/nakpanel/server-backups"}','--retention-count','1','--retention-days','0'))
        self.run.call('negative_backup',self.operator('backup-server','run','--destination',dest,'--wait','--timeout','12m'))
        sql="SELECT json_build_object('archive',b.archive_name,'size',b.size_bytes,'sha256',b.checksum_sha256,'verified',b.verified_at IS NOT NULL,'status',b.status,'detail',b.verify_detail) FROM server_backups b JOIN server_backup_destinations d ON d.id=b.destination_id WHERE d.name='"+dest+"' ORDER BY b.id"
        row=decoded(self.run.output('negative_backup',['multipass','exec',self.source,'--','sudo','-u','postgres','psql','-XAtq','-d','nakpanel','-c',sql]));require(row.get('status')=='active' and row.get('verified') is True and row.get('detail',{}).get('pg_restore_list_ok') is True and re.fullmatch(r'[A-Za-z0-9_.-]+\.nkbk',row.get('archive','')),'negative backup not verified')
        self.negarchive=self.root/'negative.nkbk';_,p,_=self.run.call('negative_backup',['multipass','exec',self.source,'--','sudo','cat','/var/lib/nakpanel/server-backups/'+row['archive']]);require(type(row.get('size')) is int and p.stat().st_size==row['size'] and sha(p)==row.get('sha256'),'negative archive physical digest/size differs');p.replace(self.negarchive)
        keyguest='/tmp/task10-negative-'+self.token+'.key';self.run.call('negative_backup',['multipass','transfer',self.negkey,self.source+':'+keyguest]);self.run.call('negative_backup',['multipass','exec',self.source,'--','sudo','chown','root:root',keyguest]);self.run.call('negative_backup',['multipass','exec',self.source,'--','sudo','chmod','600',keyguest])
        result=decoded(self.run.output('negative_backup',['multipass','exec',self.source,'--','sudo','panelctl','restore-server','--mode','same-platform','--check-only','--archive','/var/lib/nakpanel/server-backups/'+row['archive'],'--backup-key-file',keyguest]));require(result.get('compatible') is True and result.get('migration_qualified') is False,'negative archive authenticated inspection failed')
        self.missing=result.get('manifest',{}).get('platform',{}).get('required_php_versions');require(type(self.missing) is list and any(v in ('8.2','8.3','8.4') for v in self.missing),'archive lacks actual old PHP requirement')
        self.run.call('negative_backup',['multipass','exec',self.source,'--','sudo','rm','-f',keyguest]);self.state['negative_archive_sha256']=sha(self.negarchive)
        self.pins.update({str(self.negkey):sha(self.negkey),str(self.negarchive):sha(self.negarchive)})
    def prepare(self):
        check_pins(self.pins);spec=decoded(self.run.output('prepare',[self.python,'-I','-B',self.app/'deploy/multipass/ubuntu-forward-migration-fixture.py','--template']));spec.update(source_vm=self.source,run_token=self.token,architecture='amd64',target_profile='ubuntu-26.04-native',oci_image_ref=self.a['oci_image_ref'],normalize_php85=True,remediate_stale_php82=True)
        path=self.root/'spec.json';publish(path,spec);self.prepared=self.root/'prepared';self.run.call('prepare',[self.python,'-I','-B',self.app/'deploy/multipass/ubuntu-forward-migration-fixture.py','--prepare',path,self.prepared]);self.fixture=self.prepared/'fixture.json'
        self.run.env.update(NAKPANEL_FORWARD_FIXTURE_JSON=str(self.fixture),NAKPANEL_FORWARD_ARCHIVE=str(self.prepared/'source.nkbk'),NAKPANEL_FORWARD_KEY=str(self.prepared/'archive.key'),NAKPANEL_FORWARD_TARGET_BUNDLE=str(self.bundle),NAKPANEL_FORWARD_TARGET_PUBLIC_KEY=str(self.key),NAKPANEL_FORWARD_TARGET_VERSION='29.0.0')
        self.run.call('prepare',[self.python,'-I','-B',self.app/'deploy/multipass/ubuntu-forward-migration-fixture.py','--validate',self.fixture]);c=decoded(self.fixture.read_bytes());require(c.get('baseline') and c.get('archive_sha256')==sha(self.prepared/'source.nkbk'),'positive baseline/archive absent')
        for p in self.prepared.iterdir():
            if p.is_file():regular(p,True);self.pins[str(p)]=sha(p)
        self.state['positive_archive_sha256']=c['archive_sha256'];self.state['source_boot_id']=self.proof(self.source,'24.04','prepare',True)['boot_id']
    def target_env(self,name):
        e=dict(self.run.env);e.update(NAKPANEL_MULTIPASS_VM=name,NAKPANEL_MULTIPASS_DR_VM=name,NAKPANEL_MULTIPASS_IMAGE='26.04',NAKPANEL_MULTIPASS_IMAGE_SOURCE=e['NAKPANEL_FORWARD_TARGET_IMAGE_SOURCE'],NAKPANEL_MULTIPASS_IMAGE_SHA256=e['NAKPANEL_FORWARD_TARGET_IMAGE_SHA256']);return e
    def stage(self,stage,name,target,env=None):
        folder=self.root/(target+'-evidence');folder.mkdir(mode=0o700,exist_ok=True)
        return self.run.call(stage,[self.python,'-I','-B',self.app/'deploy/multipass/ubuntu-forward-migration-fixture.py',name,target,self.source,self.token,self.staged+'/bundle' if self.staged else self.bundle,folder],env=env)
    def headroom(self,stage):
        # Same runner measurement, without resetting initial KVM/capacity receipt.
        raw=self.run.output(stage,[self.python,'-I','-B','-c','import json,shutil;from pathlib import Path;m={s.split(":")[0]:int(s.split()[1])*1024 for s in Path("/proc/meminfo").read_text().splitlines()};print(json.dumps({"memory":m["MemAvailable"],"disk":shutil.disk_usage("/var/snap/multipass/common").free}))']);r=decoded(raw)
        require(type(r.get('memory')) is int and r['memory']>=6*2**30 and type(r.get('disk')) is int and r['disk']>=40*2**30,'insufficient remaining target memory/disk headroom')
    def negative_target(self):
        check_pins(self.pins);self.headroom('negative_install');self.check_new_vm(self.negative,'negative_install')
        self.staged=self.run.output('negative_install',[self.python,'-I','-B',self.app/'deploy/multipass/ubuntu-forward-migration-fixture.py','--stage-target-bundle',self.bundle,self.key,'29.0.0','amd64','1']).strip();require(Path(self.staged).is_dir(),'staged bundle missing');env=self.target_env(self.negative);env['NAKPANEL_FORWARD_TARGET_PUBLIC_KEY']=self.staged+'/public.pem'
        self.known[self.negative]='26.04';self.shell('negative_install','ensure_vm 4 8G 40G',env=env);self.observed_budget(self.negative,'negative_install');self.stage('negative_install','install-native-target',self.negative,env)
        self.run.call('negative_check',['multipass','exec',self.negative,'--','sudo','python3','-I','-B','-'],data=(self.app/'deploy/multipass/qualification_maintenance_ready.py').read_bytes())
        before=self.proof(self.negative,'26.04','negative_check');leaf='/tmp/task10-negative-'+self.token
        self.run.call('negative_check',['multipass','exec',self.negative,'--','sudo','install','-d','-m','0700',leaf])
        for p,n in ((self.negarchive,'archive.nkbk'),(self.negkey,'archive.key')):
            self.run.call('negative_check',['multipass','transfer',p,self.negative+':/home/ubuntu/task10-negative-'+self.token+'-'+n]);self.run.call('negative_check',['multipass','exec',self.negative,'--','sudo','install','-m','0600','/home/ubuntu/task10-negative-'+self.token+'-'+n,leaf+'/'+n]);self.run.call('negative_check',['multipass','exec',self.negative,'--','rm','-f','/home/ubuntu/task10-negative-'+self.token+'-'+n])
        actual=self.run.output('negative_check',['multipass','exec',self.negative,'--','sudo','sha256sum',leaf+'/archive.nkbk',leaf+'/archive.key']).splitlines();require(actual==[sha(self.negarchive)+'  '+leaf+'/archive.nkbk',sha(self.negkey)+'  '+leaf+'/archive.key'],'negative guest archive/key transfer differs')
        code,out,err=self.run.call('negative_check',['multipass','exec',self.negative,'--','sudo','panelctl','restore-server','--mode','forward-migration','--check-only','--archive',leaf+'/archive.nkbk','--backup-key-file',leaf+'/archive.key'],accepted=tuple(range(1,126)))
        self.state['negative_missing_php']=check_negative(code,err.read_text(),self.missing);self.state['ordered_negative_check_only']=True;after=self.proof(self.negative,'26.04','negative_check');require(before==after,'negative check changed observed logical DB/service/binary/boot state')
        self.run.call('negative_check',['multipass','exec',self.negative,'--','sudo','rm','-f',leaf+'/archive.key']);self.stage('negative_check','assert-no-source-writes',self.negative,env)
        self.delete(self.negative,'negative_check');self.run.call('negative_check',[self.python,'-I','-B',self.app/'deploy/multipass/ubuntu-forward-migration-fixture.py','--discard-target-bundle',self.staged]);self.staged=None
    def positive(self):
        self.boundary('positive_driver');check_pins(self.pins);self.headroom('positive');self.check_new_vm(self.positive_vm,'positive');self.known[self.positive_vm]='26.04';env=dict(self.run.env,NAKPANEL_MULTIPASS_DR_VM=self.positive_vm,NAKPANEL_FORWARD_KEEP_TARGET='1',NAKPANEL_FORWARD_EVIDENCE_DIR=str(self.root/'positive-evidence'))
        self.run.call('positive',[self.bash,self.app/'deploy/multipass/ubuntu-forward-migration-verify.sh'],env=env)
        self.boundary('positive_evidence');evidence=self.root/'positive-evidence';expected=['assert-source-readonly','install-native-target','assert-baseline','assert-migration-data','assert-services','assert-trusted-tls','assert-reboot','assert-migration-data','assert-trusted-tls','assert-no-source-writes']
        for n,name in enumerate(expected,1):predicate_require((evidence/(str(n)+'-'+name+'.log')).is_file(),'positive_stage_evidence')
        self.boundary('positive_preflight');restore=decoded((evidence/'restore.json').read_bytes());pre=decoded((evidence/'preflight.json').read_bytes());check_positive(pre,restore)
        self.boundary('positive_budget');self.observed_budget(self.positive_vm,'positive')
        self.boundary('positive_identity');proof=self.proof(self.positive_vm,'26.04','positive')
        self.boundary('positive_reboot');initial=(evidence/'initial-target-boot-id').read_text().strip();predicate_require(initial!=proof['boot_id'],'positive_target_reboot');self.state['target_boot_id']=proof['boot_id']
        self.boundary('source_unchanged');self.proof(self.source,'24.04','positive',True);self.state.update(positive_restore_verified=True,source_unchanged=True,target_reboot_verified=True)
    def delete(self,name,stage):
        self.boundary('cleanup_group');require(self.run.last_tree_empty,'action descendants remain; cleanup refused')
        self.boundary('cleanup_initial_command');text=self.run.output(stage,['multipass','list','--format','json']);self.boundary('cleanup_initial_json');listing=decoded(text);names=self.list_names(listing,'cleanup_initial')
        if name not in names:self.known.pop(name);return
        release=self.known[name];self.boundary('proof_owner');self.owner(name,release)
        env=dict(self.run.env,NAKPANEL_MULTIPASS_DR_VM=name if name!=self.source else self.positive_vm)
        self.boundary('cleanup_destroy');self.shell(stage,'destroy_owned_vm "$1" "$NAKPANEL_RUN_TOKEN"',name,env=env)
        self.boundary('cleanup_final_command');text=self.run.output(stage,['multipass','list','--format','json']);self.boundary('cleanup_final_json');row=decoded(text);names=self.list_names(row,'cleanup_final')
        self.boundary('cleanup_final_absence');predicate_require(name not in names,'cleanup_final_absence');self.known.pop(name)
    def cleanup(self):
        self.boundary('cleanup_group');require(self.run.last_tree_empty,'cannot clean guests before owned group drain')
        errors=[]
        for name in list(self.known)[::-1]:
            # Never adopt or delete a launch whose ownership cannot be proven.
            try:self.delete(name,'cleanup')
            except Exception as error:
                errors.append(name);role='source' if name==getattr(self,'source',None) else 'negative' if name==getattr(self,'negative',None) else 'positive' if name==getattr(self,'positive_vm',None) else 'UNKNOWN';self.cleanup_failure(role,error)
        if self.staged:
            try:self.run.call('cleanup',[self.python,'-I','-B',self.app/'deploy/multipass/ubuntu-forward-migration-fixture.py','--discard-target-bundle',self.staged])
            except Exception as error:errors.append('private-staging');self.cleanup_failure('private_staging',error)
        require(not errors,'owned cleanup failed');self.state['cleanup_completed']=True;self.state['cleanup_outcome']['status']='passed'
    def execute(self):
        previous={};error=None;received=None;phase='work';self.state['started_at']=utc()
        def terminate(signum,frame):
            nonlocal received
            if received is None:received=signum
            if phase in ('work','returning'):raise ControlledTermination('coordinator cancelled',signum)
        def write_result():
            if self.private_created:publish(self.root/'private-result.json',self.state)
            if self.public_created:publish(self.public/'result.json',public_result(self.state))
        def cancelled_result():
            nonlocal error
            if received is not None:
                error=ControlledTermination('coordinator cancellation before return',received)
                self.remember_failure(error)
                self.state.update(status='FAIL',failure_code='cancelled',termination_signal=received)
                return True
            return False
        try:
            for signum in (signal.SIGINT,signal.SIGTERM):previous[signum]=signal.signal(signum,terminate)
            try:
                for boundary,action in [('setup',self.setup),('artifact',self.acquire),('host',self.host_prepare),('images',self.images),('source',self.source_phases),('negative_backup',self.negative_backup),('prepare',self.prepare),('negative_target',self.negative_target),('positive',self.positive)]:
                    self._work_operation={'source':'source_phases','negative_backup':'negative_backup','negative_target':'negative_target'}.get(boundary,'UNKNOWN')
                    self.boundary(boundary);action();self.state['last_completed_boundary']=boundary
                predicate_require(all(self.state.get(k) is True for k in ('ordered_negative_check_only','positive_restore_verified','source_unchanged','target_reboot_verified')),'terminal_outcomes');self.state['status']='PASS';self.capture_primary()
            except BaseException as e:
                error=e;self.remember_failure(e);self.capture_primary(e);self.state.update(status='FAIL',failure_code='cancelled' if isinstance(e,KeyboardInterrupt) else 'stage_failed')
                if isinstance(e,KeyboardInterrupt) and received is None:received=getattr(e,'signum',signal.SIGINT)
            self._work_operation='UNKNOWN';phase='cleanup';self.boundary('cleanup')
            if hasattr(self,'run'):
                try:self.cleanup();self.state['cleanup_outcome']['status']='passed';self.state['last_completed_boundary']='cleanup'
                except BaseException as e:
                    if not self.state['cleanup_outcome']['failures']:self.cleanup_failure('UNKNOWN',e)
                    self.remember_failure(e);self.state.update(status='FAIL',failure_code='cleanup_failed');error=error or e
                    if isinstance(e,KeyboardInterrupt) and received is None:received=getattr(e,'signum',signal.SIGINT)
                self.state['stages']=self.run.rows
            if hasattr(self,'run'):self.run.budget.check('cleanup')
            self.state['finished_at']=utc();self.boundary('publication');cancelled_result();write_result()
            if hasattr(self,'run'):self.run.budget.check('cleanup')
            # Deferred first or repeated cancellation during cleanup/publication
            # becomes FAIL after custody is finished, including actual child0.
            if cancelled_result():
                blocked=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
                try:write_result()
                finally:signal.pthread_sigmask(signal.SIG_SETMASK,blocked)
            if error is not None:raise error
            require(self.state.get('cleanup_completed') is True,'cleanup not complete')
            phase='returning';result=public_result(self.state)
            if cancelled_result():write_result();raise error
            return result
        except BaseException as e:
            self.remember_failure(e);self.state.update(status='FAIL',failure_code='deadline' if isinstance(e,Deadline) else self.state.get('failure_code','stage_failed'))
            if not isinstance(e,KeyboardInterrupt):write_result()
            if isinstance(e,KeyboardInterrupt):
                if received is None:received=getattr(e,'signum',signal.SIGINT)
                cancelled_result()
                blocked=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
                try:write_result()
                finally:signal.pthread_sigmask(signal.SIG_SETMASK,blocked)
            raise
        finally:
            try:
                for signum,handler in previous.items():signal.signal(signum,handler)
            except KeyboardInterrupt as late:
                received=getattr(late,'signum',signal.SIGINT);cancelled_result();blocked=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
                try:
                    write_result()
                    for signum,handler in previous.items():signal.signal(signum,handler)
                finally:signal.pthread_sigmask(signal.SIG_SETMASK,blocked)
                raise

def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('action',choices=['validate','run']);p.add_argument('--admission',required=True);p.add_argument('--sha256',required=True);p.add_argument('--app-source');p.add_argument('--controller-source');p.add_argument('--private-root');p.add_argument('--public-root');args=p.parse_args(argv)
    try:
        a=read_admission(args.admission,args.sha256)
        if args.action=='validate':print('explicit hosted admission is valid; no action executed');return 0
        require(all((args.app_source,args.controller_source,args.private_root,args.public_root)),'explicit isolated source/output paths required')
        c=Coordinator(a,args.app_source,args.controller_source,args.private_root,args.public_root);c.state['admission_sha256']=args.sha256;c.pins[str(Path(args.admission).resolve())]=args.sha256;c.execute();return 0
    except (Exception,KeyboardInterrupt):
        # No arbitrary exception or child output crosses the public boundary.
        print('hosted forward refused or failed; inspect private evidence in the active ephemeral runner',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
