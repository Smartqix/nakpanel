"""INERT prepared hosted fixture. No import effects; no real Nakpanel executable."""
import argparse
from datetime import datetime,timezone
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import pwd
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
SOURCE='1627bba3c681a884255eb91452dbba74a43ebbdc'
INPUTS_SHA='2590fdcf0a622c665da8b67209e692f18e70b6746c81cb411540dcf35968cea5'
FIXED_ENV={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'}
UNITS={'panel':'nakpanel.service','agent':'nakpanel-agent.service'}
COMMAND_DEADLINE=None
SHA=lambda b:hashlib.sha256(b).hexdigest()
NOW=lambda:datetime.now(timezone.utc).isoformat()

class Refused(Exception):pass
class Interrupted(BaseException):pass

def need(value):
    if not value:raise Refused('identity adapter fixture refused')

def command(argv,limit=8):
    if COMMAND_DEADLINE is not None:limit=min(limit,COMMAND_DEADLINE-time.monotonic())
    need(limit>0)
    r=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,env=FIXED_ENV,timeout=limit)
    need(r.returncode==0 and len(r.stdout)+len(r.stderr)<=32768)
    return r.stdout

def properties(unit):
    raw=command(['/usr/bin/systemctl','show',unit,'--property=LoadState','--property=ActiveState','--property=SubState','--property=MainPID','--property=InvocationID','--property=FragmentPath'])
    pairs=[line.split('=',1) for line in raw.decode('ascii').splitlines()]
    need(all(len(x)==2 for x in pairs));d=dict(pairs);need(len(d)==len(pairs)==6)
    return d

def marker(path):
    s=os.lstat(path)
    return (s.st_dev,s.st_ino,stat.S_IFMT(s.st_mode),stat.S_IMODE(s.st_mode),s.st_uid,s.st_gid)

def read_regular(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<s.st_size<=limit and not s.st_mode&0o022)
        raw=b''
        while len(raw)<=limit:
            b=os.read(fd,min(65536,limit-len(raw)+1))
            if not b:break
            raw+=b
        end=os.fstat(fd);need((s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(end.st_dev,end.st_ino,end.st_size,end.st_mtime_ns,end.st_ctime_ns) and len(raw)==s.st_size)
        need(os.lstat(path).st_ino==s.st_ino);return raw
    finally:os.close(fd)

def fixed_outer():
    return dict(schema='nakpanel-linux-identity-adapter-fixture-v1',fixture=True,
        uses_fixture_executables=True,server_qualification=False,appsource_runtime=False,
        real_nakpanel_application_executed=False,day0_baseline=False,VM_or_KVM_actions=False,
        application_source_commit=SOURCE,started_at=NOW(),finished_at=None,
        source_hashes={},fixture_executable_sha256=None,projector_sha256=None,
        cases={'unset_UTC_no_dropin':None,'explicit_UTC':None,'old_pidfd_restart_refused':None,
               'real_FIFO_publication_refused':None,'unsafe_root_mode_refused':None,'private_publication':None},
        postgres_state_unchanged=False,cleanup={'attempted':False,'success':False,'remaining_owned_objects':None},
        fixture_completed=False,failure_class=None)

class Fixture:
    def __init__(self,a,out):
        self.a=a;self.out=out;self.records=[];self.account=None;self.unit_ids={};self.pidfds={};self.root=None;self.journal=None
        self.original_pg=None;self.deadline=time.monotonic()+125;self.mutation_started=False;self.start_intent=False
    def bounded(self):need(time.monotonic()<self.deadline)
    def record(self,path,kind):
        q=Path(path);entry={'path':str(q),'kind':kind,'identity':marker(q)}
        if kind=='file':entry['sha256']=SHA(read_regular(q,64*1024*1024))
        self.records.append(entry);self.save()
    def save(self):
        if self.journal is None:return
        raw=(json.dumps({'fixture':True,'source':SOURCE,'run_id':self.a.run_id,'attempt':self.a.attempt,
            'driver_pid':os.getpid(),'mutation_started':self.mutation_started,'start_intent':self.start_intent,'created':self.records,'account':self.account,'units':self.unit_ids},sort_keys=True)+'\n').encode()
        os.lseek(self.journal,0,os.SEEK_SET);os.ftruncate(self.journal,0)
        position=0
        while position<len(raw):
            count=os.write(self.journal,raw[position:]);need(count>0);position+=count
        os.fsync(self.journal)
    def owns(self,entry):
        q=Path(entry['path'])
        need(marker(q)==tuple(entry['identity']))
        if entry['kind']=='file':need(SHA(read_regular(q,64*1024*1024))==entry['sha256'])
    def make_dir(self,path,mode=0o700,uid=0,gid=0):
        os.mkdir(path,mode);os.chown(path,uid,gid);os.chmod(path,mode);self.record(path,'directory')
    def write(self,path,raw,mode=0o600):
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
        try:
            os.fchmod(fd,mode);position=0
            while position<len(raw):
                count=os.write(fd,raw[position:]);need(count>0);position+=count
            os.fsync(fd)
        finally:os.close(fd)
        self.record(path,'file')
    def preflight(self):
        need(sys.platform=='linux' and platform.machine()=='x86_64' and os.geteuid()==0)
        need(Path('/proc/1/comm').read_bytes()==b'systemd\n')
        release=Path('/etc/os-release').read_text();need('\nID=ubuntu\n' in '\n'+release and '\nVERSION_ID="24.04"\n' in '\n'+release)
        need(re.fullmatch('[a-f0-9]{64}',self.a.admission_sha) and self.a.admission_sha!='0'*64)
        need(re.fullmatch('[a-f0-9]{40}',self.a.workflow_commit) and re.fullmatch('[1-9][0-9]{0,19}',self.a.run_id))
        need(re.fullmatch('[1-9][0-9]{0,3}',self.a.attempt))
        raw=read_regular(HERE/'inputs.json',32768);need(SHA(raw)==INPUTS_SHA);inputs=json.loads(raw)
        need(inputs['application_source_commit']==SOURCE and inputs['uses_fixture_executables']is True and inputs['server_qualification']is False)
        self.input_bytes={}
        for name,h in inputs['files'].items():
            need(not Path(name).is_absolute() and '..' not in Path(name).parts)
            b=read_regular(HERE/name,1024*1024);need(SHA(b)==h);self.input_bytes[name]=b
        self.out['source_hashes']=dict(inputs['files'])
        self.dummy=read_regular(Path(self.a.build_root)/'fixture-sleeper',32*1024*1024)
        self.projector=read_regular(Path(self.a.build_root)/'projector',32*1024*1024)
        for b in (self.dummy,self.projector):need(b[:6]==b'\x7fELF\x02\x01' and b[18:20]==b'\x3e\x00')
        self.out.update(fixture_executable_sha256=SHA(self.dummy),projector_sha256=SHA(self.projector))
        for parent in ('/etc','/etc/systemd','/etc/systemd/system','/usr','/usr/local','/usr/local/bin','/var','/var/lib','/run'):
            st=os.lstat(parent);need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022)
        for base in ('/etc/systemd/system','/run/systemd/system','/usr/lib/systemd/system','/lib/systemd/system','/usr/local/lib/systemd/system','/etc/systemd/system.control','/run/systemd/system.control','/run/systemd/transient','/run/systemd/generator','/run/systemd/generator.early','/run/systemd/generator.late'):
            for unit in UNITS.values():
                need(not os.path.lexists(base+'/'+unit) and not os.path.lexists(base+'/'+unit+'.d'))
        for path in ('/usr/local/bin/nakpanel-panel','/usr/local/bin/nakpanel-agent','/usr/local/bin/nakpanel-panelctl',
                     '/etc/nakpanel','/var/lib/nakpanel','/run/nakpanel','/var/mail/nakpanel','/var/spool/mail/nakpanel','/home/nakpanel'):
            need(not os.path.lexists(path))
        for role,unit in UNITS.items():need(properties(unit)['LoadState']=='not-found')
        for fn in (pwd.getpwnam,grp.getgrnam):
            try:fn('nakpanel')
            except KeyError:pass
            else:need(False)
        # Do not change global manager/process timezone. Unset positive must be real.
        manager=command(['/usr/bin/systemctl','show-environment'])
        need(not any(line.startswith((b'TZ=',b'ZONEINFO=',b'PG')) for line in manager.splitlines()))
        local=os.lstat('/etc/localtime');need(local.st_uid==0)
        if stat.S_ISLNK(local.st_mode):need(os.readlink('/etc/localtime')=='/usr/share/zoneinfo/Etc/UTC')
        else:need(stat.S_ISREG(local.st_mode) and not local.st_mode&0o022)
        # Actual rooted UTC checks/metadata/Go clock provenance remain collector-owned.
        self.original_pg=properties('postgresql.service')
        self.root=Path('/var/lib/nakpanel-identity-fixture-'+self.a.run_id+'-'+self.a.attempt)
        need(not os.path.lexists(self.root))
    def setup(self):
        # First root mutation occurs only after ALL canonical target/account absence checks.
        self.mutation_started=True
        self.make_dir(self.root)
        self.journal=os.open(self.root/'created.json',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);self.save()
        command(['/usr/sbin/groupadd','--system','nakpanel'])
        gid=grp.getgrnam('nakpanel').gr_gid;self.account={'group':gid,'user':None};self.save()
        command(['/usr/sbin/useradd','--system','--no-create-home','--no-log-init','--gid','nakpanel','--home-dir','/nonexistent','--shell','/usr/sbin/nologin','nakpanel'])
        account=pwd.getpwnam('nakpanel');need(account.pw_gid==gid and account.pw_uid>0)
        self.account['user']=account.pw_uid;self.save()
        for path,mode,uid,g in [('/etc/nakpanel',0o700,0,0),('/var/lib/nakpanel',0o755,account.pw_uid,gid),('/run/nakpanel',0o750,0,0)]:self.make_dir(path,mode,uid,g)
        for role in UNITS:
            self.write('/usr/local/bin/nakpanel-'+role,self.dummy,0o755)
            self.write('/etc/systemd/system/'+UNITS[role],self.input_bytes['units/'+UNITS[role]],0o644)
        for d in ('day0-hosted-command-custody-v1','day0-hosted-process-identity-v2'):self.make_dir(self.root/d)
        identity=self.root/'day0-hosted-process-identity-v2';self.make_dir(identity/'query-projector')
        self.write(self.root/'day0-hosted-command-custody-v1/custody.py',self.input_bytes['custody.py'])
        self.write(identity/'collector.py',self.input_bytes['collector.py'])
        self.write(identity/'query-projector/projector',self.projector,0o700)
        command(['/usr/bin/systemctl','daemon-reload'])
        self.start_intent=True;self.save()
        command(['/usr/bin/systemctl','--job-mode=ignore-dependencies','start','nakpanel-agent.service','nakpanel.service'])
        for role in UNITS:self.remember_unit(role)
        spec=importlib.util.spec_from_file_location('fixture_linux_collector',identity/'collector.py');self.collector=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.collector)
        fixture_manifest=SHA(json.dumps({'fixture':True,'dummy':SHA(self.dummy),'source':SOURCE},sort_keys=True).encode())
        self.expected={'binding':{'source_commit':SOURCE,'manifest_sha256':fixture_manifest,'source_vm':'nakpanel-hosted-identity-fixture-'+self.a.run_id,
            'run_token':'fixture-'+self.a.run_id+'-'+self.a.attempt,'profile':'ubuntu-24.04','php_provider':'native','architecture':'amd64',
            'installed_binary_sha256':dict.fromkeys(('panel','agent','panelctl'),SHA(self.dummy))},
            'authority_sha256':self.a.admission_sha,'unit_sha256':{r:SHA(self.input_bytes['units/'+UNITS[r]]) for r in UNITS},
            'dropin_sha256':None,'panel_uid':account.pw_uid,'panel_gid':gid,'projector_sha256':SHA(self.projector),'collector_sha256':SHA(self.input_bytes['collector.py'])}
    def remember_unit(self,role):
        d=properties(UNITS[role]);need(d['LoadState']=='loaded' and d['ActiveState']=='active' and d['SubState']=='running')
        need(d['FragmentPath']=='/etc/systemd/system/'+UNITS[role] and re.fullmatch('[a-f0-9]{32}',d['InvocationID']))
        need(d['MainPID'].isdigit() and int(d['MainPID'])>1)
        if role in self.pidfds:os.close(self.pidfds.pop(role))
        pid=int(d['MainPID']);fd=os.pidfd_open(pid,0)
        try:
            need(Path('/proc/'+str(pid)+'/cmdline').read_bytes()==('/usr/local/bin/nakpanel-'+role).encode()+b'\0')
            need(os.readlink('/proc/'+str(pid)+'/exe')=='/usr/local/bin/nakpanel-'+role)
            need(SHA(read_regular('/proc/'+str(pid)+'/root/usr/local/bin/nakpanel-'+role,32*1024*1024))==SHA(self.dummy))
        except BaseException:os.close(fd);raise
        self.pidfds[role]=fd;self.unit_ids[role]=d;self.save()
    def same_unit(self,role):need(properties(UNITS[role])==self.unit_ids[role])
    def mature(self,roles):
        need(type(roles)is tuple and roles and all(role in UNITS for role in roles))
        self.bounded()
        for role in roles:self.same_unit(role)
        started=time.monotonic();need(self.deadline-started>=2.0)
        # One pre-sampling age barrier, never a retry of a failed collection.
        time.sleep(2.0);need(time.monotonic()-started>=2.0)
        for role in roles:self.same_unit(role)
        self.bounded()
    def runtime_before_stop(self):
        matches=[e for e in self.records if e['path']=='/run/nakpanel']
        need(len(matches)==1 and matches[0]['kind']=='directory');entry=matches[0]
        self.owns(entry)
        fd=os.open('/run/nakpanel',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            def full(x):
                # atime may legitimately change when this guard enumerates.
                return (x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
            x=os.fstat(fd)
            need((x.st_dev,x.st_ino,stat.S_IFMT(x.st_mode),stat.S_IMODE(x.st_mode),x.st_uid,x.st_gid)==tuple(entry['identity']))
            seal=full(x);need(full(os.lstat('/run/nakpanel'))==seal)
            with os.scandir(fd) as entries:need(next(entries,None)is None)
            self.owns(entry)
            need(full(os.fstat(fd))==seal)
            need(full(os.lstat('/run/nakpanel'))==seal)
        finally:os.close(fd)
    def receipt(self):
        self.bounded();r=self.collector.collect(self.expected)
        need(r['success']is True and r['synthetic_fixture']is False and r['platform']=='linux' and r['claims_runtime_or_day0_acceptance']is False)
        return r
    def cases(self):
        self.mature(('panel','agent'))
        first=self.receipt();need(first['panel_configuration']['timezone']['input_kind']=='system_default_utc')
        self.out['cases']['unset_UTC_no_dropin']=True
        self.make_dir(self.root/'publication')
        self.collector.publish(self.root/'publication','positive.json',first);self.record(self.root/'publication/positive.json','file')
        self.out['cases']['private_publication']=True
        fifo=self.root/'publication/fifo.json';os.mkfifo(fifo,0o600);self.record(fifo,'fifo')
        try:
            with self.collector.anchored(str(fifo)):need(False)
        except self.collector.Rejected:pass
        else:need(False)
        try:self.collector.publish(self.root/'publication','fifo.json',first)
        except self.collector.Rejected:self.out['cases']['real_FIFO_publication_refused']=True
        else:need(False)
        pub=self.root/'publication';owned=next(e for e in self.records if e['path']==str(pub));self.owns(owned)
        os.chmod(pub,0o755)
        try:
            try:self.collector.publish(pub,'mode.json',first)
            except self.collector.Rejected:self.out['cases']['unsafe_root_mode_refused']=True
            else:need(False)
        finally:
            need(os.lstat(pub).st_ino==owned['identity'][1]);os.chmod(pub,0o700)
        self.same_unit('panel');self.same_unit('agent')
        old=self.collector.LinuxSession('panel',int(self.unit_ids['panel']['MainPID']),time.monotonic()+5)
        try:
            self.write('/etc/nakpanel/panel.env',b'TZ=UTC\n')
            command(['/usr/bin/systemctl','--job-mode=ignore-dependencies','restart','nakpanel.service'])
            previous=self.unit_ids['panel'];self.remember_unit('panel');need(previous['MainPID']!=self.unit_ids['panel']['MainPID'] and previous['InvocationID']!=self.unit_ids['panel']['InvocationID'])
            try:old.snapshot(time.monotonic()+5)
            except self.collector.Rejected:self.out['cases']['old_pidfd_restart_refused']=True
            else:need(False)
        finally:old.close()
        self.mature(('panel',))
        second=self.receipt();need(second['panel_configuration']['timezone']['input_kind']=='explicit_utc')
        need(first['services']['agent']==second['services']['agent'] and first['services']['panel']!=second['services']['panel'])
        self.out['cases']['explicit_UTC']=True
        self.out['postgres_state_unchanged']=properties('postgresql.service')==self.original_pg
        need(self.out['postgres_state_unchanged'])
    def cleanup(self):
        global COMMAND_DEADLINE
        COMMAND_DEADLINE=time.monotonic()+25
        self.out['cleanup']['attempted']=self.mutation_started
        if not self.mutation_started:self.out['cleanup'].update(success=True,remaining_owned_objects=0);return
        if not self.records:
            self.out['cleanup'].update(success=False,remaining_owned_objects=None);return
        failures=0
        for role in ('panel','agent'):
            try:
                if self.start_intent and role not in self.unit_ids:
                    current=properties(UNITS[role])
                    if current['MainPID']!='0':self.remember_unit(role)
                    else:need(current['ActiveState']in ('inactive','failed'))
                if role in self.unit_ids:
                    self.same_unit(role)
                    for e in self.records:
                        if e['path'] in ('/usr/local/bin/nakpanel-'+role,'/etc/systemd/system/'+UNITS[role]):self.owns(e)
                    if role=='agent':self.runtime_before_stop()
                    command(['/usr/bin/systemctl','--job-mode=ignore-dependencies','stop',UNITS[role]],10)
                    d=properties(UNITS[role]);need(d['MainPID']=='0' and d['ActiveState']=='inactive')
                    with selectors.DefaultSelector() as sel:
                        sel.register(self.pidfds[role],selectors.EVENT_READ);need(bool(sel.select(1)))
            except BaseException:failures+=1
        for fd in self.pidfds.values():
            try:os.close(fd)
            except OSError:failures+=1
        # Any uncertain service ownership prevents deleting accounts/binaries/resources.
        if failures:self.out['cleanup'].update(success=False,remaining_owned_objects=len(self.records));return
        for e in reversed(self.records[1:]):
            try:
                q=Path(e['path'])
                if e['path']=='/run/nakpanel' and not os.path.lexists(q):continue # unit-owned RuntimeDirectory removed by stop
                self.owns(e)
                if e['kind']=='directory':q.rmdir()
                else:q.unlink()
            except BaseException:failures+=1
        try:
            command(['/usr/bin/systemctl','daemon-reload'])
            need(properties('postgresql.service')==self.original_pg)
            if self.account:
                if self.account['user'] is not None:
                    need(not any(os.path.lexists(x) for x in ('/var/mail/nakpanel','/var/spool/mail/nakpanel','/home/nakpanel')))
                    u=pwd.getpwnam('nakpanel');need(u.pw_uid==self.account['user'] and u.pw_gid==self.account['group'])
                    command(['/usr/sbin/userdel','nakpanel'])
                g=grp.getgrnam('nakpanel');need(g.gr_gid==self.account['group'] and not g.gr_mem)
                command(['/usr/sbin/groupdel','nakpanel'])
        except BaseException:failures+=1
        if failures:
            self.out['cleanup'].update(success=False,remaining_owned_objects=sum(os.path.lexists(e['path']) for e in self.records));return
        try:
            if self.journal is not None:
                self.save();need(os.fstat(self.journal).st_ino==os.lstat(self.root/'created.json').st_ino)
                os.close(self.journal);self.journal=None;os.unlink(self.root/'created.json')
            self.owns(self.records[0]);self.root.rmdir()
        except BaseException:failures+=1
        remaining=sum(os.path.lexists(e['path']) for e in self.records)
        for path in ('/etc/nakpanel','/var/lib/nakpanel','/run/nakpanel','/usr/local/bin/nakpanel-panel','/usr/local/bin/nakpanel-agent','/etc/systemd/system/nakpanel.service','/etc/systemd/system/nakpanel-agent.service'):
            if os.path.lexists(path):remaining+=1
        for lookup in (pwd.getpwnam,grp.getgrnam):
            try:lookup('nakpanel');remaining+=1
            except KeyError:pass
        self.out['cleanup'].update(success=failures==0 and remaining==0,remaining_owned_objects=remaining)

def main():
    global COMMAND_DEADLINE
    COMMAND_DEADLINE=time.monotonic()+125
    p=argparse.ArgumentParser();p.add_argument('--build-root',required=True);p.add_argument('--run-id',required=True);p.add_argument('--attempt',required=True)
    p.add_argument('--workflow-commit',required=True);p.add_argument('--admission-sha',required=True);a=p.parse_args()
    os.umask(0o077);out=fixed_outer();f=Fixture(a,out)
    def interrupt(number,frame):raise Interrupted()
    for number in (signal.SIGTERM,signal.SIGINT):signal.signal(number,interrupt)
    try:f.preflight();f.setup();f.cases()
    except BaseException:out['failure_class']='fixture-refused'
    finally:
        try:f.cleanup()
        except BaseException:out['cleanup'].update(attempted=True,success=False);out['failure_class']='cleanup-refused'
        out['fixture_completed']=out['failure_class']is None and all(v is True for v in out['cases'].values()) and out['cleanup']['success']is True
        out['finished_at']=NOW();print(json.dumps(out,sort_keys=True,separators=(',',':')))
    return 0 if out['fixture_completed']else 1

if __name__=='__main__':sys.exit(main())
