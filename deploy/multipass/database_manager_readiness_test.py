"""Execute the actual guest block and maintenance probe against private fixtures."""
import sys
sys.dont_write_bytecode = True
import contextlib
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SECRET = 'private-fixture-key-' + 'e' * 48
POISON = 'PRIVATE_RESPONSE_BODY_NEVER_LOG'

# The fixture maps only fixed guest filesystem/network boundaries. The production
# Python stdin remains unchanged, including its deadlines and authentication.
BOOTSTRAP = r'''
import builtins,http.client,json,os,pathlib,socket,stat,subprocess,sys,time,types
fixture=pathlib.Path(os.environ['FIXTURE_DIR']);original_open=os.open;original_lstat=os.lstat;original_fstat=os.fstat
def mapped(path):
    return str(fixture/'key') if str(path)=='/etc/nakpanel/database-manager.key' else str(fixture/'bridge') if str(path)=='/run/nakpanel-db-manager/bridge.sock' else path
def opened(path,*args,**kwargs):return original_open(mapped(path),*args,**kwargs)
def inspected(path,*args,**kwargs):return original_lstat(mapped(path),*args,**kwargs)
def file_stat(fd):
    value=original_fstat(fd)
    return types.SimpleNamespace(**dict({name:getattr(value,name) for name in dir(value) if name.startswith('st_')},st_uid=0))
os.open=opened;os.lstat=inspected;os.fstat=file_stat
connect=socket.create_connection
def connection(address,*args,**kwargs):
    with open(fixture/'connections','a') as out:out.write(json.dumps(address)+'\n')
    count=len((fixture/'connections').read_text().splitlines())
    if address==('127.0.0.1',9082):
        refused=os.environ.get('FIXTURE_MODE')=='refused' or os.environ.get('FIXTURE_MODE')=='delayed-listener' and count<3
        address=('127.0.0.1',int(os.environ['FIXTURE_CLOSED_PORT'] if refused else os.environ['FIXTURE_PORT']))
    return connect(address,*args,**kwargs)
socket.create_connection=connection
clock=[0.0]
# Only the production stdin receives synthetic time. subprocess/threading keep
# the real stdlib module for timed waits and process reaping.
probe_time=types.SimpleNamespace(monotonic=lambda:clock[0],sleep=lambda delay:clock.__setitem__(0,clock[0]+max(delay,20)))
run=subprocess.run
def bounded(args,*a,**kwargs):
    assert 0<kwargs['timeout']<=120
    with open(fixture/'timeouts','a') as out:out.write(json.dumps({'args':args,'timeout':kwargs['timeout']})+'\n')
    unavailable=os.environ.get('FIXTURE_MODE')=='restart-unavailable' and args[1]=='restart' or os.environ.get('FIXTURE_MODE')=='inspection-unavailable' and args[1]=='show'
    if unavailable:raise OSError((fixture/'key').read_text())
    result=run(args,*a,**kwargs)
    if os.environ.get('FIXTURE_MODE')=='restart-overrun' and args[1]=='restart':clock[0]+=1000
    if os.environ.get('FIXTURE_MODE')=='inspection-overrun' and args[1]=='show':clock[0]+=1000
    return result
subprocess.run=bounded
response=http.client.HTTPConnection.getresponse
def received(self):
    value=response(self)
    if os.environ.get('FIXTURE_MODE')=='overrun':clock[0]+=1000
    return value
http.client.HTTPConnection.getresponse=received
original_import=builtins.__import__
def isolated_import(name,globals=None,locals=None,fromlist=(),level=0):
    if name=='time' and level==0:return probe_time
    return original_import(name,globals,locals,fromlist,level)
probe_builtins=dict(vars(builtins),__import__=isolated_import)
exec(compile(sys.stdin.read(),'actual-readiness-stdin','exec'),{'__name__':'__main__','__builtins__':probe_builtins})
'''

@contextlib.contextmanager
def fixture(mode='delayed'):
    with tempfile.TemporaryDirectory() as td:
        root=Path(td);root.chmod(0o700);(root/'key').write_text(SECRET+'\n');(root/'key').chmod(0o640)
        bridge=socket.socket(socket.AF_UNIX);bridge.bind(str(root/'bridge'));(root/'bridge').chmod(0o660)
        unready=socket.socket();unready.bind(('127.0.0.1',0))
        state={'requests':[], 'active':0}
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                authorized=self.headers.get('X-Nakpanel-Manager-Key')==SECRET
                activated=(root/'restarted').exists()
                state['requests'].append({'authorized':authorized,'activated':activated,'path':self.path})
                status=403 if not authorized else 503 if not activated else 204
                if mode=='delayed' and len(state['requests'])<3 and status==204:status=503
                if mode=='unavailable':status=503
                if mode=='unauthorized':status=403
                if mode=='redirect':status=302
                self.send_response(status);self.send_header('Location','http://example.invalid/never-follow');self.end_headers()
                if status!=204:self.wfile.write(POISON.encode())
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        closed_port=unready.getsockname()[1]
        # A bound-but-not-listening socket times out on macOS; closing the
        # reserved port produces the actual refusal boundary used by this case.
        unready.close()
        scripts={
            'timeout':'#!/bin/bash\nshift;exec "$@"\n',
            'node':'#!/bin/bash\nprintf "browser\\n" >> "$CALL_LOG"\n',
            'python3':'#!'+sys.executable+'\n'+BOOTSTRAP,
            'systemctl':'#!'+sys.executable+'''\nimport json,os,pathlib,sys
p=pathlib.Path(os.environ['FIXTURE_DIR'])
with open(os.environ['CALL_LOG'],'a') as f:f.write(json.dumps(sys.argv[1:])+'\\n')
if sys.argv[1]=='restart':
    assert sys.argv[2:]==['nakpanel.service'];(p/'restarted').write_text('active');sys.exit(0)
if sys.argv[1]=='is-active':sys.exit(0)
unit=sys.argv[-1]
state='inactive' if os.environ.get('FIXTURE_MODE')=='http-inactive' and unit=='nakpanel-database-manager-http.service' else 'active'
if '--value' in sys.argv:print(state)
else:print('ActiveState='+state+'\\nSubState=running\\nResult=success\\nExecMainStatus=0\\nPRIVATE_ENV='+((p/'key').read_text().strip() if (p/'key').is_file() else 'private'))
''',
            'curl':'#!'+sys.executable+'''\nimport http.client,os
c=http.client.HTTPConnection('127.0.0.1',int(os.environ['FIXTURE_PORT']),timeout=2)
c.request('GET','/__nakpanel_health');r=c.getresponse();print(r.status,end='');r.close();c.close()
''',
        }
        for name,body in scripts.items():(root/name).write_text(body);(root/name).chmod(0o700)
        installer=root/'assets/deploy/install/database-manager-install.sh';installer.parent.mkdir(parents=True)
        installer.write_text('#!/bin/bash\nprintf "install\\n" >> "$CALL_LOG"\n');installer.chmod(0o700)
        env=dict(os.environ,PATH=str(root)+':'+os.environ['PATH'],FIXTURE_DIR=str(root),FIXTURE_PORT=str(server.server_port),FIXTURE_CLOSED_PORT=str(closed_port),FIXTURE_MODE=mode,CALL_LOG=str(root/'calls'),HTTP_PROXY='http://example.invalid:9',ALL_PROXY='http://example.invalid:9')
        try:yield root,env,state
        finally:server.shutdown();server.server_close();thread.join();bridge.close();unready.close()

def canonical_block():
    text=(HERE/'internal-tools-verify.sh').read_text()
    return text[text.index('if [[ "${NAKPANEL_VERIFY_DATABASE_MANAGER:-0}" == 1 ]]'):]

def execute_block(root,env):
    script='''set -euo pipefail
NAKPANEL_VERIFY_DATABASE_MANAGER=1;VM_NAME=owned;base=https://fixture;site_id=1;tmpdir="$FIXTURE_DIR";SCRIPT_DIR="$FIXTURE_DIR"
NAKPANEL_REMOTE_SRC="$FIXTURE_DIR/assets";NAKPANEL_GUEST_RELEASE_DIR="$FIXTURE_DIR/assets"
assert_current_vm_identity(){ :; }
multipass(){ while [[ "$1" != bash ]];do shift;done;shift;bash "$@"; }
'''+canonical_block()
    return subprocess.run(['bash','-c',script],env=env,capture_output=True,text=True,timeout=15)

class DatabaseManagerReadiness(unittest.TestCase):
    def test_canonical_activates_once_before_authenticated_delayed_real_health_and_browser(self):
        # Missing restart, missing header, or accepting first503 must fail.
        with fixture() as (root,env,state):
            result=execute_block(root,env)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            calls=(root/'calls').read_text().splitlines()
            self.assertEqual(calls[0],'install');self.assertEqual(calls.count('["restart", "nakpanel.service"]'),1)
            self.assertEqual(calls[-1],'browser');self.assertGreaterEqual(len(state['requests']),3)
            self.assertTrue(all(x['authorized'] and x['activated'] for x in state['requests']))
            self.assertNotIn(SECRET,result.stdout+result.stderr+'\n'.join(calls));self.assertNotIn(POISON,result.stdout+result.stderr)
            self.assertNotIn('roundcube-flow',result.stdout)
            bounded=[json.loads(line) for line in (root/'timeouts').read_text().splitlines()]
            self.assertEqual(bounded[0]['args'],['systemctl','restart','nakpanel.service'])
            self.assertLessEqual(bounded[0]['timeout'],30)

    def test_canonical_real_delayed_child_exit_keeps_subprocess_clock_real(self):
        # POSIX subprocess timeout polling sleeps after pipe EOF until reaping.
        # This valid50ms child exit must not spend the synthetic120s deadline.
        with fixture('ready') as (root,env,state):
            command=root/'systemctl'
            source=command.read_text().replace('import json,os,pathlib,sys',"import atexit,json,os,pathlib,sys,time\ndef delayed_exit():\n    sys.stdout.flush();sys.stderr.flush();sys.stdout.close();sys.stderr.close();os.close(1);os.close(2);time.sleep(0.05)\natexit.register(delayed_exit)")
            command.write_text(source)
            control=subprocess.run([str(command),'show','--value','nakpanel-database-manager.service'],env=env,capture_output=True,text=True,timeout=2)
            self.assertEqual(control.returncode,0,control.stderr)
            (root/'calls').unlink()
            result=execute_block(root,env)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            calls=(root/'calls').read_text().splitlines()
            self.assertEqual(calls.count('["restart", "nakpanel.service"]'),1)
            self.assertEqual(calls[-1],'browser')
            self.assertTrue(state['requests'])
            self.assertTrue(all(row['authorized'] and row['activated'] for row in state['requests']))

    def test_canonical_waits_through_actual_initial_tcp_refusals(self):
        with fixture('delayed-listener') as (root,env,state):
            result=execute_block(root,env)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            attempts=[json.loads(line) for line in (root/'connections').read_text().splitlines()]
            self.assertGreaterEqual(len(attempts),3)
            self.assertTrue(all(x==['127.0.0.1',9082] for x in attempts))
            self.assertTrue(all(x['authorized'] and x['activated'] for x in state['requests']))
            self.assertEqual((root/'calls').read_text().splitlines()[-1],'browser')

    def test_canonical_rejects_non204_redirect_and_overdue_success_without_browser(self):
        for mode in ['unavailable','unauthorized','redirect','refused','overrun','http-inactive','restart-overrun','inspection-overrun','restart-unavailable','inspection-unavailable']:
            with self.subTest(mode=mode),fixture(mode) as (root,env,state):
                result=execute_block(root,env)
                self.assertNotEqual(result.returncode,0)
                calls=(root/'calls').read_text();self.assertNotIn('browser',calls)
                self.assertNotIn(SECRET,result.stdout+result.stderr+calls);self.assertNotIn(POISON,result.stdout+result.stderr)
                messages=[json.loads(line) for line in result.stderr.splitlines() if line.startswith('{')]
                self.assertEqual(len(messages),1,result.stderr)
                self.assertIs(messages[0]['success'],False)
                self.assertLess(len(result.stderr),4000)
                if mode in ['restart-overrun','inspection-overrun']:self.assertEqual(state['requests'],[])
                if (root/'connections').exists():self.assertTrue(all(json.loads(x)==['127.0.0.1',9082] for x in (root/'connections').read_text().splitlines()))
                if mode=='refused':self.assertIs(messages[0]['listener_reachable'],False)
                if mode in ['restart-unavailable','inspection-unavailable']:self.assertEqual(messages[0]['error_code'],'probe-unavailable')

    def test_canonical_requires_actual_socket_and_bounded_regular_key(self):
        for change in ['socket-file','key-symlink','key-oversize','key-fifo','key-world-readable']:
            with self.subTest(change=change),fixture('ready') as (root,env,state):
                if change=='socket-file':(root/'bridge').unlink();(root/'bridge').write_text('not a socket')
                elif change=='key-world-readable':(root/'key').chmod(0o644)
                else:
                    (root/'key').unlink()
                    if change=='key-symlink':(root/'other').write_text(SECRET);(root/'key').symlink_to(root/'other')
                    elif change=='key-fifo':os.mkfifo(root/'key')
                    else:(root/'key').write_bytes(b'k'*5000)
                result=execute_block(root,env)
                self.assertNotEqual(result.returncode,0);self.assertNotIn('browser',(root/'calls').read_text())

    def maintenance(self):
        spec=importlib.util.spec_from_file_location('dbmanager_maintenance',HERE/'sury-maintenance-drill.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

    def test_maintenance_authenticates_existing_full_health_without_restart_or_repair(self):
        for mode in ['ready','delayed-listener','refused','unauthorized','unavailable','redirect','http-inactive','overrun','inspection-overrun']:
          with self.subTest(mode=mode),fixture(mode) as (root,env,state):
            (root/'restarted').write_text('preexisting');module=self.maintenance();calls=[]
            original_connection=socket.create_connection;clock=[0.0]
            def command(args,**kwargs):
                calls.append(args);self.assertNotIn(args[1],['start','stop','restart','enable','daemon-reload'])
                self.assertGreater(kwargs.get('timeout',0),0);self.assertLessEqual(kwargs['timeout'],120)
                if args[0]=='curl':
                    c=http.client.HTTPConnection('127.0.0.1',int(env['FIXTURE_PORT']));c.request('GET','/__nakpanel_health');r=c.getresponse();status=r.status;r.close();c.close();return subprocess.CompletedProcess(args,0,str(status),'')
                if mode=='inspection-overrun':clock[0]+=1000
                inactive=mode=='http-inactive' and args[-1]=='nakpanel-database-manager-http.service'
                return subprocess.CompletedProcess(args,0,'inactive\n' if inactive else 'active\n','')
            connections=[]
            def connect(address,*args,**kwargs):
                connections.append(address);self.assertEqual(address,('127.0.0.1',9082))
                refused=mode=='refused' or mode=='delayed-listener' and len(connections)<3
                return original_connection(('127.0.0.1',int(env['FIXTURE_CLOSED_PORT'] if refused else env['FIXTURE_PORT'])),*args,**kwargs)
            original_open=os.open;original_lstat=os.lstat;original_fstat=os.fstat
            def mapped(path):return str(root/'key') if str(path)=='/etc/nakpanel/database-manager.key' else str(root/'bridge') if str(path)=='/run/nakpanel-db-manager/bridge.sock' else path
            def fstat(fd):
                import types
                value=original_fstat(fd);return types.SimpleNamespace(**dict({name:getattr(value,name) for name in dir(value) if name.startswith('st_')},st_uid=0))
            response=http.client.HTTPConnection.getresponse
            def received(connection):
                value=response(connection)
                if mode=='overrun':clock[0]+=1000
                return value
            with patch.object(module,'command',side_effect=command),patch('socket.create_connection',side_effect=connect),patch('os.open',side_effect=lambda path,*a,**kw:original_open(mapped(path),*a,**kw)),patch('os.lstat',side_effect=lambda path,*a,**kw:original_lstat(mapped(path),*a,**kw)),patch('os.fstat',side_effect=fstat),patch.object(module,'time',types.SimpleNamespace(monotonic=lambda:clock[0],sleep=lambda delay:clock.__setitem__(0,clock[0]+30))),patch.object(http.client.HTTPConnection,'getresponse',received):
                if mode in ['ready','delayed-listener']:module.service_wait({'nakpanel.service':'active','nakpanel-agent.service':'active'},True)
                else:
                    with self.assertRaisesRegex(ValueError,'readiness timed out'):
                        module.service_wait({'nakpanel.service':'active','nakpanel-agent.service':'active'},True)
            if mode not in ('http-inactive','inspection-overrun','refused'):
                self.assertTrue(state['requests']);self.assertTrue(all(x['authorized'] for x in state['requests']))
            if mode!='inspection-overrun':self.assertTrue(any('nakpanel-database-manager-http.service' in args for args in calls))

    def test_maintenance_transport_cleanup_failure_has_fixed_private_error(self):
        module=self.maintenance();closed=[]
        class Response:
            status=204
            def close(self):raise OSError(SECRET)
        class Connection:
            sock=None
            def __init__(self,*args,**kwargs):pass
            def request(self,*args,**kwargs):pass
            def getresponse(self):return Response()
            def close(self):closed.append(True)
        with patch.object(module,'manager_key',return_value=SECRET),patch.object(http.client,'HTTPConnection',Connection):
            with self.assertRaisesRegex(ValueError,'database-manager connection cleanup failed'):
                module.manager_http(module.time.monotonic()+2)
        self.assertEqual(closed,[True])

    def test_maintenance_unit_failure_uses_fixed_class_not_exception_text(self):
        module=self.maintenance()
        for error in [OSError(SECRET),subprocess.TimeoutExpired(['systemctl',SECRET],1)]:
            with self.subTest(error=type(error).__name__),patch.object(module,'command',side_effect=error):
                with self.assertRaisesRegex(ValueError,'post-maintenance service inspection unavailable'):
                    module.service_wait({'nakpanel.service':'active'},True)

    def test_maintenance_keeps_postboot_observation_before_any_wait_or_repair(self):
        module=self.maintenance()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);before={'nakpanel.service':'active','nakpanel-agent.service':'active'}
            baseline={'mutation_services':before,'database_manager':True,'package_inventory':{},'settings':{},'package_files':{},'intent':{},'managed_services':{}}
            for name,value in [('baseline.json',baseline),('packages.json',[])]:
                (root/name).write_text(json.dumps(value));(root/name).chmod(0o600)
            calls=[]
            def command(args,**kwargs):
                calls.append(args)
                self.assertNotIn(args[1],['start','stop','restart','enable','daemon-reload'])
                return subprocess.CompletedProcess(args,0,'','')
            read=module.root_regular
            with patch.object(module,'root_regular',side_effect=lambda path: b'boot-after\n' if str(path)=='/proc/sys/kernel/random/boot_id' else read(path)),patch.object(module,'command',side_effect=command),patch.object(module,'service_state',side_effect=lambda unit:'inactive' if unit=='nakpanel.service' else 'active'),patch.object(module,'package_inventory',return_value={}),patch.object(module,'guarded_settings',return_value={}),patch.object(module,'package_files',return_value={}),patch.object(module,'intent_state',return_value={}),patch.object(module,'managed_state',return_value={}),patch.object(module,'time',types.SimpleNamespace(monotonic=iter([0,121]).__next__)):
                with self.assertRaisesRegex(ValueError,'readiness timed out'):
                    module.guest_health(root,{},'reboot-1',reboot=True)
            observation=json.loads((root/'observed-reboot-1.json').read_text())
            self.assertEqual(observation['mutation_services']['nakpanel.service'],'inactive')
            details=next(args for args in calls if args[:2]==['systemctl','show'])
            self.assertIn('nakpanel-database-manager.service',details)
            self.assertIn('nakpanel-database-manager-http.service',details)

    def test_maintenance_private_key_errors_do_not_escape_with_raw_exception_messages(self):
        for change in ['nonascii','symlink']:
            with self.subTest(change=change),fixture('ready') as (root,env,state):
                if change=='nonascii':(root/'key').write_bytes(b'\xff'+SECRET.encode())
                else:(root/'key').unlink();(root/'key').symlink_to(root/'absent-private-target')
                module=self.maintenance();original_open=os.open;original_fstat=os.fstat
                def fstat(fd):
                    import types
                    value=original_fstat(fd);return types.SimpleNamespace(**dict({name:getattr(value,name) for name in dir(value) if name.startswith('st_')},st_uid=0))
                with patch('os.open',side_effect=lambda path,*a,**kw:original_open(root/'key' if str(path)=='/etc/nakpanel/database-manager.key' else path,*a,**kw)),patch('os.fstat',side_effect=fstat):
                    with self.assertRaisesRegex(ValueError,'database-manager private key unavailable'):
                        module.manager_key(module.time.monotonic()+2)

if __name__=='__main__':unittest.main()
