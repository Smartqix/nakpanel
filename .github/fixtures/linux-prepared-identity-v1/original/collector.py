"""Private day0 fixed readonly identity collector; inert import, no CLI.

A caller's expected binding is NOT authenticated here. No runtime/day0 authority
is granted, and injected fixtures are permanently marked synthetic.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import types

CANONICAL_DSN = 'postgres:///nakpanel?host=/var/run/postgresql&sslmode=disable'
HERE = Path(__file__).parent
CUSTODY = HERE.parent / 'day0-hosted-command-custody-v1' / 'custody.py'
# Exact independently reviewed lifecycle helpers; no initializer/sweep namespace use.
CUSTODY_SHA = 'bbe68b69d270aae3a253c2848dee8e4145eb546454d767e00ab2d8392e11b8b3'
PROPERTIES = ('Id','LoadState','ActiveState','SubState','FragmentPath','DropInPaths',
    'NeedDaemonReload','User','Group','ExecStart','MainPID','InvocationID','ControlGroup',
    'RootDirectory','RootImage')
ROLES = ('panel','agent')
HEX = re.compile('[0-9a-f]{64}\\Z')
MAX_EXE = 256*1024*1024

class Rejected(ValueError):
    def __init__(self): super().__init__('day0 process identity rejected')

def need(value):
    if not value: raise Rejected()

def bounded(deadline): need(time.monotonic() < deadline)

def digest(data): return hashlib.sha256(data).hexdigest()

def strict_json(raw):
    def pairs(xs):
        d={}
        for k,v in xs: need(k not in d);d[k]=v
        return d
    try: return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False))
    except Exception: raise Rejected() from None

def custody():
    raw=CUSTODY.read_bytes();need(digest(raw)==CUSTODY_SHA)
    m=types.ModuleType('reviewed_custody');exec(compile(raw,str(CUSTODY),'exec'),m.__dict__)
    return m

def fixed_read(kind, role, deadline, *, projector_fd=None):
    """No public arbitrary argv/env surface; reused frozen cancellation helpers."""
    need(kind in ('systemctl','projector') and role in ROLES)
    argv=(['/usr/bin/systemctl','show',unit_name(role)]+['--property='+x for x in PROPERTIES]
          if kind=='systemctl' else ['/proc/self/fd/'+str(projector_fd)])
    need((kind=='systemctl' and projector_fd is None) or (kind=='projector' and type(projector_fd) is int and projector_fd>=0))
    env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TZ':'UTC','PGPASSFILE':'/dev/null'}
    life=custody();proc=None;chunks=[];total=0;sel=selectors.DefaultSelector()
    try:
        with life.cancellation_custody() as pending:
            try:
                bounded(deadline);need(not pending)
                proc=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,env=env,start_new_session=True,
                    pass_fds=() if projector_fd is None else (projector_fd,))
                child_end=min(deadline,time.monotonic()+3)
                for stream in (proc.stdout,proc.stderr):
                    os.set_blocking(stream.fileno(),False);sel.register(stream,selectors.EVENT_READ)
                while sel.get_map():
                    bounded(child_end);need(not pending)
                    for key,_ in sel.select(min(.03,max(0,child_end-time.monotonic()))):
                        b=os.read(key.fileobj.fileno(),32769)
                        if not b:sel.unregister(key.fileobj);continue
                        total+=len(b);need(total<=32768)
                        if key.fileobj is proc.stdout:chunks.append(b)
                proc.wait(timeout=max(.001,child_end-time.monotonic()))
                need(not pending and proc.returncode==0 and life.group_state(proc.pid)=='empty')
                bounded(child_end)
            finally:
                if proc is not None and (proc.poll() is None or life.group_state(proc.pid)!='empty'):
                    need(life.stop_owned(proc))
        return b''.join(chunks)
    except BaseException: raise Rejected() from None
    finally:
        sel.close()
        if proc is not None:
            for stream in (proc.stdout,proc.stderr):
                if stream is not None:stream.close()

def unit_name(role): return ('nakpanel' if role=='panel' else 'nakpanel-agent')+'.service'
def executable(role): return '/usr/local/bin/nakpanel-'+role

def validated_expected(e):
    need(type(e) is dict and set(e)=={'binding','authority_sha256','unit_sha256','dropin_sha256',
         'panel_uid','panel_gid','projector_sha256','collector_sha256'})
    b=custody().binding_copy(e['binding'])
    for k in ('authority_sha256','projector_sha256','collector_sha256'):need(type(e[k]) is str and HEX.fullmatch(e[k]))
    need(e['dropin_sha256'] is None or (type(e['dropin_sha256']) is str and HEX.fullmatch(e['dropin_sha256'])))
    for k in ('panel_uid','panel_gid'):need(type(e[k]) is int and 0<e[k]<2**32-1)
    need(type(e['unit_sha256']) is dict and set(e['unit_sha256'])==set(ROLES))
    need(all(type(x) is str and HEX.fullmatch(x) for x in e['unit_sha256'].values()))
    return dict(e,binding=b,unit_sha256=dict(e['unit_sha256']))

def parsed_properties(raw,role,dropin_hash):
    need(type(raw) is bytes and len(raw)<=32768 and raw.endswith(b'\n'))
    try: lines=raw.decode('ascii').splitlines()
    except Exception:raise Rejected() from None
    d={}
    for line in lines:
        need('=' in line);k,v=line.split('=',1);need(k in PROPERTIES and k not in d);d[k]=v
    need(set(d)==set(PROPERTIES))
    fixed={'Id':unit_name(role),'LoadState':'loaded','ActiveState':'active','SubState':'running',
        'FragmentPath':'/etc/systemd/system/'+unit_name(role),'NeedDaemonReload':'no',
        'User':'nakpanel' if role=='panel' else 'root','Group':'nakpanel' if role=='panel' else 'root',
        'DropInPaths':'/etc/systemd/system/nakpanel.service.d/database-manager.conf' if role=='panel' and dropin_hash is not None else '',
        'ControlGroup':'/system.slice/'+unit_name(role),'RootDirectory':'','RootImage':''}
    need(all(d[k]==v for k,v in fixed.items()))
    need(re.fullmatch('[1-9][0-9]{0,9}',d['MainPID']) and int(d['MainPID'])<2**31)
    need(re.fullmatch('[a-f0-9]{32}',d['InvocationID']) and d['InvocationID']!='0'*32)
    # systemctl show's known escaped structured property. Never echo unknown data.
    x=d['ExecStart'];need(x.startswith('{ ') and x.endswith(' }'))
    fields={}
    for segment in x[2:-2].split(' ; '):
        need('=' in segment);k,v=segment.split('=',1);need(k not in fields);fields[k]=v
    need(set(fields)=={'path','argv[]','ignore_errors','start_time','stop_time','pid','code','status'})
    need(fields['path']==executable(role) and fields['argv[]']==executable(role) and fields['ignore_errors']=='no')
    need(all(len(v)<=256 and '\n' not in v and '\r' not in v for v in fields.values()))
    # Dates/code/status are not stable identity and are never published.
    return dict(unit=unit_name(role),fragment_path=fixed['FragmentPath'],
        dropin_path=fixed['DropInPaths'],user=fixed['User'],group=fixed['Group'],
        exec_start=executable(role),main_pid=int(d['MainPID']),invocation_id=d['InvocationID'],
        control_group=d['ControlGroup'])

def validate_proof(p,expected_hash=None,executable_file=False):
    keys={'sha256','device','inode','size','mode','uid','gid','nlink','mtime_ns','ctime_ns'}
    need(type(p) is dict and set(p)==keys)
    need(type(p['sha256']) is str and HEX.fullmatch(p['sha256']))
    need(all(type(p[k]) is int and p[k]>=0 for k in keys-{'sha256'}))
    need(p['inode']>0 and 0<p['size']<=MAX_EXE and p['uid']==0 and p['nlink']==1)
    need(stat.S_ISREG(p['mode']) and not p['mode']&0o022)
    if executable_file:need(p['mode']&0o111)
    if expected_hash is not None:need(p['sha256']==expected_hash)
    return dict(p)

def account_check(raw,e):
    need(type(raw) is bytes and len(raw)<=1024*1024)
    try:lines=raw.decode('utf-8').splitlines()
    except Exception:raise Rejected() from None
    matches={}
    for line in lines:
        fields=line.split(':')
        need(len(fields)==7)
        if fields[0] in ('root','nakpanel'):
            need(fields[0] not in matches and fields[2].isdigit() and fields[3].isdigit())
            matches[fields[0]]=(int(fields[2]),int(fields[3]))
    need(matches=={'root':(0,0),'nakpanel':(e['panel_uid'],e['panel_gid'])})
    # No alias account may share the expected service identities.
    for line in lines:
        f=line.split(':')
        need(f[2].isdigit() and f[3].isdigit())
        if int(f[2]) in (0,e['panel_uid']):need(f[0] in ('root','nakpanel'))

def env_projection(raw):
    need(type(raw) is bytes and 0<len(raw)<=256*1024 and raw.endswith(b'\0'))
    values={}
    for row in raw[:-1].split(b'\0'):
        need(b'=' in row);key,value=row.split(b'=',1)
        need(re.fullmatch(b'[A-Za-z_][A-Za-z0-9_]*',key) and key not in values)
        # Other values are never decoded or retained.
        values[key]=value if key in (b'TZ',b'NAKPANEL_DATABASE_URL') else None
        need(not key.startswith(b'PG') and key!=b'ZONEINFO')
    need(values.get(b'NAKPANEL_DATABASE_URL')==CANONICAL_DSN.encode())
    need(b'TZ' not in values or values[b'TZ'] in (b'UTC',b''))
    return dict(timezone=dict(input_kind='system_default_utc' if b'TZ' not in values else 'explicit_utc' if values[b'TZ']==b'UTC' else 'explicit_empty',effective_zone='UTC',semantics='source_derived_go_initLocal'),
        query=dict(contract='owned-unit-unix-default-v1',pgx_version='5.7.2',mode='cache_statement',parser_mode='cache statement',network_or_sql_executed=False))

from datetime import datetime, timezone
GO_INIT_LOCAL_SHA = "d2001a2351a080f1a47ebb3999be74f99caceb4a8f1ea6369a3c843fa0442f08"
DIR_PATHS=('/', '/etc', '/usr', '/usr/share', '/usr/share/zoneinfo', '/usr/share/zoneinfo/Etc')

def utc_ns(value):
    seconds,ns=divmod(value,1000000000)
    return datetime.fromtimestamp(seconds,timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')+'.'+str(ns).zfill(9)+'Z'

def birth_projection(x):
    v=x['birth_evidence'];keys={'boot_time_unix_seconds','clock_ticks_per_second','realtime_before_ns','boottime_ns','realtime_after_ns'}
    need(type(v) is dict and set(v)==keys and all(type(z) is int and z>0 for z in v.values()))
    b=v['boot_time_unix_seconds'];hz=v['clock_ticks_per_second'];ticks=x['start_ticks']
    need(hz<=1000000 and type(ticks) is int and ticks>0 and b<4102444800)
    a=v['realtime_before_ns'];z=v['realtime_after_ns'];boot=v['boottime_ns']
    need(a<=z and z-a<=100000000 and boot>=ticks*1000000000//hz)
    # Bracketing clock samples must intersect the kernel btime one-second interval.
    need(a-boot<(b+1)*1000000000 and z-boot>=b*1000000000)
    lower=b*1000000000+ticks*1000000000//hz
    upper=(b+1)*1000000000+((ticks+1)*1000000000+hz-1)//hz
    need(upper<a and lower<upper)
    ns=x['time_namespace'];need(type(ns) is str and re.fullmatch(r'time:\[[1-9][0-9]{0,19}\]',ns))
    need(x['collector_time_namespace']==ns)
    return dict(boot_time_unix_seconds=b,clock_ticks_per_second=hz,lower_unix_ns=lower,upper_unix_ns=upper,
                lower_utc=utc_ns(lower),upper_utc=utc_ns(upper)),dict(v)

def validate_localtime(q,birth,require_old):
    need(type(q) is dict and set(q)=={'file','canonical_file','link','directories'})
    a=validate_proof(q['file']);b=validate_proof(q['canonical_file'])
    if require_old:need(a['sha256']==b['sha256'] and a['size']==b['size'])
    link=q['link']
    if link is not None:
        keys={'device','inode','mode','uid','gid','nlink','size','mtime_ns','ctime_ns','target'}
        need(type(link) is dict and set(link)==keys and link['target']=='/usr/share/zoneinfo/Etc/UTC')
        need(all(type(link[k]) is int and link[k]>=0 for k in keys-{'target'}))
        need(stat.S_ISLNK(link['mode']) and link['uid']==0 and link['inode']>0 and link['nlink']==1 and a==b)
    dirs=q['directories'];need(type(dirs) is list and len(dirs)==len(DIR_PATHS))
    need([d.get('path') for d in dirs]==list(DIR_PATHS))
    for d in dirs:
        need(type(d) is dict and set(d)=={'path','device','inode','mode','uid','gid','nlink','mtime_ns','ctime_ns'})
        need(all(type(d[k]) is int and d[k]>=0 for k in set(d)-{'path'}))
        need(d['uid']==0 and d['inode']>0 and stat.S_ISDIR(d['mode']) and not d['mode']&0o022)
    if require_old:
        for item in (a,b) if link is None else (a,b,link):
            need(item['mtime_ns']<birth['lower_unix_ns'] and item['ctime_ns']<birth['lower_unix_ns'])
    return dict(file=a,canonical_file=b,link=None if link is None else dict(link),directories=[dict(d) for d in dirs])

def dir_proof(path,s):
    need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022)
    return dict(path=path,device=s.st_dev,inode=s.st_ino,mode=s.st_mode,uid=s.st_uid,gid=s.st_gid,
                nlink=s.st_nlink,mtime_ns=s.st_mtime_ns,ctime_ns=s.st_ctime_ns)

def rooted_localtime(root,deadline):
    # Hold all directory FDs; verify their original names and metadata at end.
    fds={'/':os.dup(root)};parents={};start={};leaf=None;canonical=None
    try:
        start['/']=dir_proof('/',os.fstat(fds['/']))
        for path in DIR_PATHS[1:]:
            parent=path.rsplit('/',1)[0] or '/';name=path.rsplit('/',1)[1]
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fds[parent]);fds[path]=fd;parents[path]=(parent,name)
            start[path]=dir_proof(path,os.fstat(fd))
        first=os.stat('localtime',dir_fd=fds['/etc'],follow_symlinks=False)
        link=None
        if stat.S_ISLNK(first.st_mode):
            target=os.readlink('localtime',dir_fd=fds['/etc']);need(target=='/usr/share/zoneinfo/Etc/UTC' and first.st_uid==0)
            link=dict(device=first.st_dev,inode=first.st_ino,mode=first.st_mode,uid=first.st_uid,gid=first.st_gid,
                nlink=first.st_nlink,size=first.st_size,mtime_ns=first.st_mtime_ns,ctime_ns=first.st_ctime_ns,target=target)
        canonical=os.open('UTC',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fds['/usr/share/zoneinfo/Etc'])
        cp=file_proof(canonical,deadline,1024*1024)
        if link is None:
            leaf=os.open('localtime',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fds['/etc']);lp=file_proof(leaf,deadline,1024*1024)
            need(metadata(os.fstat(leaf))==metadata(first))
        else:lp=dict(cp)
        need(metadata(os.stat('localtime',dir_fd=fds['/etc'],follow_symlinks=False))==metadata(first))
        need(metadata(os.stat('UTC',dir_fd=fds['/usr/share/zoneinfo/Etc'],follow_symlinks=False))==metadata(os.fstat(canonical)))
        need(file_proof(canonical,deadline,1024*1024)==cp)
        if leaf is not None:need(file_proof(leaf,deadline,1024*1024)==lp)
        for path in DIR_PATHS:
            need(dir_proof(path,os.fstat(fds[path]))==start[path])
            if path!='/':
                parent,name=parents[path];need(dir_proof(path,os.stat(name,dir_fd=fds[parent],follow_symlinks=False))==start[path])
        return dict(file=lp,canonical_file=cp,link=link,directories=[start[d] for d in DIR_PATHS])
    finally:
        for fd in (leaf,canonical):
            if fd is not None:os.close(fd)
        for fd in reversed(list(fds.values())):os.close(fd)

def process_record(x,role,unit,e):
    keys={'boot_id','pid','start_ticks','state','uids','gids','cmdline','cgroup','exe_path','exe','installed','environ','localtime','birth_evidence','time_namespace','collector_time_namespace'}
    need(type(x) is dict and set(x)==keys)
    need(type(x['boot_id']) is str and re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}',x['boot_id']))
    need(type(x['pid']) is int and x['pid']==unit['main_pid'] and type(x['start_ticks']) is int and x['start_ticks']>0)
    need(x['state'] in ('R','S','D','I'))
    uid=e['panel_uid'] if role=='panel' else 0;gid=e['panel_gid'] if role=='panel' else 0
    need(type(x['uids']) is list and all(type(v) is int for v in x['uids']) and x['uids']==[uid]*4)
    need(type(x['gids']) is list and all(type(v) is int for v in x['gids']) and x['gids']==[gid]*4)
    need(x['cmdline']==executable(role).encode()+b'\0' and x['exe_path']==executable(role))
    need(x['cgroup']==('0::'+unit['control_group']+'\n').encode())
    a=validate_proof(x['exe'],e['binding']['installed_binary_sha256'][role],True)
    z=validate_proof(x['installed'],e['binding']['installed_binary_sha256'][role],True)
    need(a==z)
    config=env_projection(x['environ']) if role=='panel' else None
    birth,_=birth_projection(x)
    localtime=validate_localtime(x['localtime'],birth,config['timezone']['input_kind']=='system_default_utc') if role=='panel' else None
    need(role=='panel' or (x['environ'] is None and x['localtime'] is None))
    return dict(boot_id=x['boot_id'],pid=x['pid'],start_ticks=x['start_ticks'],uid=uid,gid=gid,
                exe=a,localtime=localtime,birth_interval=birth,time_namespace=x['time_namespace']),config

def collect(expected,*,fixture=None):
    sessions=[]
    try:
        if fixture is None:
            need(sys.platform=='linux' and os.geteuid()==0);reader=LinuxReader();synthetic=False
        else:
            need(getattr(fixture,'synthetic',None) is True);reader=fixture;synthetic=True
        e=validated_expected(expected)
        if fixture is None:reader.dropin_hash=e['dropin_sha256']
        start=time.monotonic();deadline=start+15
        started=time.time();need(digest(Path(__file__).read_bytes())==e['collector_sha256']);account_check(reader.accounts(deadline),e)
        before={};configuration=None;clocks={}
        for role in ROLES:
            bounded(deadline);u=parsed_properties(reader.show(role,deadline),role,e['dropin_sha256'])
            files=reader.unit_files(role,deadline)
            need(type(files) is dict and set(files)=={'unit','dropins'})
            unit_file=validate_proof(files['unit'],e['unit_sha256'][role])
            need(type(files['dropins']) is list and len(files['dropins'])==(1 if role=='panel' and e['dropin_sha256'] is not None else 0))
            dropins=[validate_proof(p,e['dropin_sha256']) for p in files['dropins']]
            session=reader.open_process(role,u['main_pid'],deadline);sessions.append(session)
            raw=session.snapshot(deadline);proc,cfg=process_record(raw,role,u,e)
            clocks.setdefault(role,[]).append({k:raw['birth_evidence'][k] for k in ('realtime_before_ns','boottime_ns','realtime_after_ns')})
            before[role]=dict(unit=u,unit_file=unit_file,dropins=dropins,process=proc)
            if cfg is not None:configuration=cfg
        need(before['panel']['process']['boot_id']==before['agent']['process']['boot_id'])
        need(before['panel']['process']['time_namespace']==before['agent']['process']['time_namespace'])
        for field in ('boot_time_unix_seconds','clock_ticks_per_second'):
            need(before['panel']['process']['birth_interval'][field]==before['agent']['process']['birth_interval'][field])
        projected=strict_json(reader.project(e['projector_sha256'],deadline))
        need(type(projected) is dict and set(projected)=={'pgx_version','mode','parser_mode','network_or_sql_executed'})
        need(projected['pgx_version']=='5.7.2' and projected['mode']=='cache_statement' and projected['parser_mode']=='cache statement' and projected['network_or_sql_executed'] is False)
        for role,session in zip(ROLES,sessions):
            bounded(deadline);u=parsed_properties(reader.show(role,deadline),role,e['dropin_sha256'])
            files=reader.unit_files(role,deadline)
            need(u==before[role]['unit'] and files==dict(unit=before[role]['unit_file'],dropins=before[role]['dropins']))
            raw=session.snapshot(deadline);proc,cfg=process_record(raw,role,u,e)
            clocks.setdefault(role,[]).append({k:raw['birth_evidence'][k] for k in ('realtime_before_ns','boottime_ns','realtime_after_ns')})
            need(proc==before[role]['process'] and (cfg is None or cfg==configuration))
        account_check(reader.accounts(deadline),e);bounded(deadline)
        need(digest(Path(__file__).read_bytes())==e['collector_sha256'])
        finished=time.time();duration=time.monotonic()-start
        need(finished>=started and abs((finished-started)-duration)<=2 and duration<15)
        return dict(schema='nakpanel-day0-process-identity-v2',success=True,synthetic_fixture=synthetic,
            platform='synthetic-linux' if synthetic else 'linux',source_binding=e['binding'],authority_sha256=e['authority_sha256'],
            observed_started_unix=started,observed_finished_unix=finished,duration_monotonic_seconds=duration,
            services=before,panel_configuration=configuration,process_clock_observations=clocks,
            go_initLocal_source_sha256=GO_INIT_LOCAL_SHA,projector_sha256=e['projector_sha256'],
            collector_sha256=e['collector_sha256'],custody_sha256=CUSTODY_SHA,
            claims_runtime_or_day0_acceptance=False)
    except BaseException: raise Rejected() from None
    finally:
        cleanup_failed=False
        for session in sessions:
            try:session.close()
            except BaseException:cleanup_failed=True
        if cleanup_failed:raise Rejected() from None

# Actual Linux adapter below. Tests inject clearly synthetic sessions; they never
# access host /proc environment or claim the Linux adapter ran on macOS.
def metadata(s):
    return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)

def file_proof(fd,deadline,limit=MAX_EXE):
    first=os.fstat(fd);need(stat.S_ISREG(first.st_mode) and 0<first.st_size<=limit)
    os.lseek(fd,0,os.SEEK_SET);h=hashlib.sha256();total=0
    while True:
        bounded(deadline);b=os.read(fd,min(1024*1024,limit-total+1))
        if not b:break
        total+=len(b);need(total<=limit);h.update(b)
    need(metadata(os.fstat(fd))==metadata(first) and total==first.st_size)
    return dict(sha256=h.hexdigest(),device=first.st_dev,inode=first.st_ino,size=total,mode=first.st_mode,
        uid=first.st_uid,gid=first.st_gid,nlink=first.st_nlink,mtime_ns=first.st_mtime_ns,ctime_ns=first.st_ctime_ns)

# Keep the initial anchor explicit, including a supplied process-root FD.
@contextmanager
def anchored(path,*,rootfd=None):
    need(type(path) is str and path.startswith('/') and all(x not in ('','.','..') for x in path.split('/')[1:]))
    anchor=os.dup(rootfd) if rootfd is not None else os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    opened=[];parent=anchor
    try:
        s=os.fstat(parent);need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022)
        for part in path.split('/')[1:-1]:
            fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);opened.append(fd);parent=fd
            s=os.fstat(fd);need(s.st_uid==0 and not s.st_mode&0o022)
        fd=os.open(path.rsplit('/',1)[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            info=os.fstat(fd);need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022)
            yield fd
            need(metadata(os.stat(path.rsplit('/',1)[1],dir_fd=parent,follow_symlinks=False))==metadata(os.fstat(fd)))
        finally:os.close(fd)
    finally:
        for fd in reversed(opened):os.close(fd)
        os.close(anchor)

def read_fd(fd,limit,deadline):
    out=[];n=0
    while True:
        bounded(deadline);b=os.read(fd,min(65536,limit-n+1))
        if not b:return b''.join(out)
        n+=len(b);need(n<=limit);out.append(b)

def parse_proc_stat(raw,pid):
    need(type(raw) is bytes and len(raw)<=8192 and raw.startswith(str(pid).encode()+b' ('))
    i=raw.rfind(b') ');need(i>0);parts=raw[i+2:].split();need(len(parts)>=50)
    need(parts[19].isdigit() and len(parts[0])==1)
    return parts[0].decode('ascii'),int(parts[19])

class LinuxSession:
    def __init__(self,role,pid,deadline):
        self.role=role;self.pid=pid;self.fd=None;self.pidfd=None
        try:
            self.pidfd=os.pidfd_open(pid,0)
            self.fd=os.open('/proc/'+str(pid),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            self.initial=self._identity(deadline)
        except BaseException:self.close();raise
    def read(self,name,limit,deadline):
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self.fd)
        try:return read_fd(fd,limit,deadline)
        finally:os.close(fd)
    def _identity(self,deadline):return parse_proc_stat(self.read('stat',8192,deadline),self.pid)
    def snapshot(self,deadline):
        sel=selectors.DefaultSelector()
        try:sel.register(self.pidfd,selectors.EVENT_READ);need(not sel.select(0))
        finally:sel.close()
        state,ticks=self._identity(deadline);need(ticks==self.initial[1])
        status=self.read('status',32768,deadline);ids={}
        for line in status.splitlines():
            if line.startswith((b'Uid:',b'Gid:')):
                k,v=line.split(b':',1);need(k not in ids);ids[k]=[int(x) for x in v.split()]
        with open('/proc/sys/kernel/random/boot_id','rb') as stream:boot=stream.read(100).strip().decode('ascii')
        path=os.readlink('exe',dir_fd=self.fd)
        fd=os.open('exe',os.O_RDONLY,dir_fd=self.fd) # intended kernel magic link, then same-FD proof
        try:exe=file_proof(fd,deadline)
        finally:os.close(fd)
        with anchored(executable(self.role)) as installedfd:installed=file_proof(installedfd,deadline)
        env=self.read('environ',256*1024,deadline) if self.role=='panel' else None
        localtime=None
        if self.role=='panel':
            root=os.open('root',os.O_RDONLY|os.O_DIRECTORY,dir_fd=self.fd)
            try:localtime=rooted_localtime(root,deadline)
            finally:os.close(root)
        with anchored('/proc/stat') as fd:bootstat=read_fd(fd,1024*1024,deadline)
        rows=[r.split() for r in bootstat.splitlines() if r.startswith(b'btime ')]
        need(len(rows)==1 and len(rows[0])==2 and rows[0][1].isdigit())
        realtime_before=time.time_ns();boottime=time.clock_gettime_ns(time.CLOCK_BOOTTIME);realtime_after=time.time_ns()
        result=dict(boot_id=boot,pid=self.pid,start_ticks=ticks,state=state,uids=ids.get(b'Uid'),gids=ids.get(b'Gid'),
            cmdline=self.read('cmdline',4096,deadline),cgroup=self.read('cgroup',8192,deadline),exe_path=path,
            exe=exe,installed=installed,environ=env,localtime=localtime,
            birth_evidence=dict(boot_time_unix_seconds=int(rows[0][1]),clock_ticks_per_second=os.sysconf('SC_CLK_TCK'),
                realtime_before_ns=realtime_before,boottime_ns=boottime,realtime_after_ns=realtime_after),
            time_namespace=os.readlink('ns/time',dir_fd=self.fd),collector_time_namespace=os.readlink('/proc/self/ns/time'))
        end_state,end_ticks=self._identity(deadline)
        need(end_ticks==ticks and end_state in ('R','S','D','I'))
        # Detect same-PID exec during this snapshot as well as across boundaries.
        fd=os.open('exe',os.O_RDONLY,dir_fd=self.fd)
        try:need(file_proof(fd,deadline)==exe and os.readlink('exe',dir_fd=self.fd)==path)
        finally:os.close(fd)
        return result
    def close(self):
        for name in ('fd','pidfd'):
            fd=getattr(self,name,None)
            if fd is not None:os.close(fd);setattr(self,name,None)

class LinuxReader:
    dropin_hash=None
    def show(self,role,deadline):return fixed_read('systemctl',role,deadline)
    def unit_files(self,role,deadline):
        with anchored('/etc/systemd/system/'+unit_name(role)) as fd:u=file_proof(fd,deadline,32768)
        ds=[]
        if role=='panel' and self.dropin_hash is not None:
            with anchored('/etc/systemd/system/nakpanel.service.d/database-manager.conf') as fd:ds.append(file_proof(fd,deadline,32768))
        return dict(unit=u,dropins=ds)
    def accounts(self,deadline):
        with anchored('/etc/passwd') as fd:return read_fd(fd,1024*1024,deadline)
    def open_process(self,role,pid,deadline):return LinuxSession(role,pid,deadline)
    def project(self,expected_hash,deadline):
        with anchored(str(HERE/'query-projector'/'projector')) as fd:
            initial=validate_proof(file_proof(fd,deadline),expected_hash,True)
            # Execute exactly this attested FD, never reopen a pathname at exec.
            result=fixed_read('projector','panel',deadline,projector_fd=fd)
            need(file_proof(fd,deadline)==initial)
        return result

def publish(private_root,name,receipt):
    """Exclusive publication with original FD held through final namespace proof."""
    directory=None;output=None;temporary=None;baseline=None;complete=False
    def own_unlink(entry):
        if directory is None or output is None or entry is None:return
        try:
            named=os.stat(entry,dir_fd=directory,follow_symlinks=False)
            actual=os.fstat(output)
            if stat.S_ISREG(named.st_mode) and (named.st_dev,named.st_ino)==(actual.st_dev,actual.st_ino):
                os.unlink(entry,dir_fd=directory)
        except FileNotFoundError:pass
    try:
        need(type(name) is str and re.fullmatch('[a-z][a-z0-9-]{0,60}\\.json',name))
        root=Path(private_root);info=root.lstat()
        need(root.is_absolute() and root.resolve()==root and stat.S_ISDIR(info.st_mode) and
             info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700)
        need(type(receipt) is dict and receipt.get('schema')=='nakpanel-day0-process-identity-v2' and receipt.get('success') is True)
        data=(json.dumps(receipt,sort_keys=True,separators=(',',':'))+'\n').encode();need(len(data)<=256*1024)
        directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        need(metadata(os.fstat(directory))==metadata(info))
        temporary='.identity-'+os.urandom(16).hex()+'.tmp'
        output=os.open(temporary,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=directory)
        first=os.fstat(output)
        need(stat.S_ISREG(first.st_mode) and stat.S_IMODE(first.st_mode)==0o600 and first.st_uid==os.getuid() and first.st_nlink==1)
        original=(first.st_dev,first.st_ino,first.st_mode,first.st_uid,first.st_gid)
        position=0
        while position<len(data):
            count=os.write(output,data[position:]);need(count>0);position+=count
        os.fsync(output)
        def content_and_identity():
            x=os.fstat(output)
            need((x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid)==original and x.st_nlink==1 and x.st_size==len(data))
            os.lseek(output,0,os.SEEK_SET);raw=read_fd(output,len(data),time.monotonic()+2)
            need(raw==data and metadata(os.fstat(output))==metadata(x))
            return metadata(x)
        written=content_and_identity()
        need(metadata(os.stat(temporary,dir_fd=directory,follow_symlinks=False))==written)
        current=root.lstat();need((current.st_dev,current.st_ino,current.st_uid,stat.S_IMODE(current.st_mode))==(info.st_dev,info.st_ino,os.getuid(),0o700))
        os.link(temporary,name,src_dir_fd=directory,dst_dir_fd=directory,follow_symlinks=False)
        own_unlink(temporary);temporary=None
        # Link/unlink legitimately change ctime/nlink. Validate original immutable
        # invariants and exact bytes before sealing the final complete metadata.
        baseline=content_and_identity()
        need(metadata(os.stat(name,dir_fd=directory,follow_symlinks=False))==baseline)
        dir_seal=metadata(os.fstat(directory))
        os.fsync(directory)
        # All success facts are revalidated AFTER that last directory fsync.
        need(content_and_identity()==baseline)
        need(metadata(os.stat(name,dir_fd=directory,follow_symlinks=False))==baseline)
        named_root=root.lstat();need(metadata(named_root)==dir_seal and metadata(os.fstat(directory))==dir_seal)
        need(stat.S_ISDIR(named_root.st_mode) and named_root.st_uid==os.getuid() and stat.S_IMODE(named_root.st_mode)==0o700)
        complete=True
    except BaseException:raise Rejected() from None
    finally:
        cleanup_failed=False
        if not complete:
            for entry in (name,temporary):
                try:own_unlink(entry)
                except BaseException:cleanup_failed=True
        for fd in (output,directory):
            if fd is not None:
                try:os.close(fd)
                except BaseException:cleanup_failed=True
        if cleanup_failed:raise Rejected() from None
