package multipass

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestHostedQualificationRequiresActualNativeGatesAndPinnedBaseline(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/ubuntu-hosted-qualification.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow qualificationWorkflow
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	if _, ok := workflow.On["workflow_dispatch"]; !ok {
		t.Fatal("hosted qualification must be manually dispatched")
	}
	if _, ok := workflow.On["pull_request"]; ok {
		t.Fatal("hosted qualification must not run implicitly for pull requests")
	}
	push, ok := workflow.On["push"].(map[string]any)
	if !ok {
		t.Fatal("dedicated review branch push trigger missing")
	}
	branches, ok := push["branches"].([]any)
	if !ok || len(branches) != 1 || branches[0] != "codex/ubuntu-26-support" {
		t.Fatal("push trigger must be limited to isolated review branch")
	}
	job, ok := workflow.Jobs["qualify-amd64"]
	if !ok {
		t.Fatal("native AMD64 qualification job missing")
	}
	if job.RunsOn != "ubuntu-24.04" {
		t.Fatal("hosted native AMD64 runner must be explicit")
	}
	releases := map[string]bool{}
	for _, cell := range job.Strategy.Matrix.Include {
		releases[cell.Release] = true
	}
	if len(releases) != 1 || !releases["26.04"] {
		t.Fatal("only the Ubuntu 26.04 guest cell is required")
	}
	gate, preflight, cleanup, evidence := false, false, false, false
	for _, step := range job.Steps {
		gate = gate || strings.Contains(step.Run, "ubuntu-platform-verify.sh")
		preflight = preflight || strings.Contains(step.Run, "hosted-runner-preflight.py")
		cleanup = cleanup || (step.If == "always()" && strings.Contains(step.Run, "destroy_owned_vm"))
		evidence = evidence || (step.If == "always()" && strings.HasPrefix(step.Uses, "actions/upload-artifact@"))
		if strings.Contains(step.Run, "multipass delete") {
			t.Fatal("owned deletion helper bypassed")
		}
	}
	if !gate || !preflight || !cleanup || !evidence {
		t.Fatalf("missing strict hosted lifecycle: gates%v preflight%v cleanup%v evidence%v", gate, preflight, cleanup, evidence)
	}
}

func TestHostedCapacityPreflightRejectsMissingKVMAndInsufficientDisk(t *testing.T) {
	helper, err := filepath.Abs("hosted-runner-preflight.py")
	if err != nil {
		t.Fatal(err)
	}
	script := `import importlib.util,sys
spec=importlib.util.spec_from_file_location('preflight',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
good=dict(architecture='x86_64',cpu_count=4,total_memory=16*2**30,available_memory=12*2**30,free_disk=56*2**30,kvm_api=12)
assert m.capacity_errors(**good)==[]
for key,value,needle in [('kvm_api',None,'KVM'),('free_disk',14*2**30,'disk'),('available_memory',8*2**30,'memory'),('architecture','aarch64','AMD64')]:
 case=dict(good);case[key]=value;assert any(needle in e for e in m.capacity_errors(**case)),(key,m.capacity_errors(**case))
`
	out, err := exec.Command("python3", "-c", script, helper).CombinedOutput()
	if err != nil {
		t.Fatalf("hosted preflight: %s %v", out, err)
	}
}

func TestHostedKVMPreflightRecordsDeviceEvidenceBeforeActualIOCTLChecks(t *testing.T) {
	helper, err := filepath.Abs("hosted-runner-preflight.py")
	if err != nil {
		t.Fatal(err)
	}
	script := `import errno,importlib.util,json,os,pathlib,stat,sys,types
spec=importlib.util.spec_from_file_location('preflight',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
root=pathlib.Path(sys.argv[2]);real_os=m.os
class FixturePath(type(pathlib.Path())):
 def read_text(self,*args,**kwargs):
  if str(self)=='/proc/meminfo':return 'MemTotal: 16777216 kB\nMemAvailable: 12582912 kB\n'
  return super().read_text(*args,**kwargs)
m.Path=FixturePath
m.platform.machine=lambda:'x86_64'
m.shutil.disk_usage=lambda _:types.SimpleNamespace(free=56*2**30)
for mode in ['ready','open-denied','wrong-api','create-denied']:
 calls=[]
 def node_stat(path,**kwargs):
  assert path=='/dev/kvm' and kwargs=={'follow_symlinks':False}
  calls.append('metadata')
  return types.SimpleNamespace(st_uid=0,st_gid=108,st_mode=stat.S_IFCHR|0o660,st_rdev=os.makedev(10,232))
 def command(args,**kwargs):
  assert args==['getfacl','-n','-p','/dev/kvm'],args
  assert 0<kwargs['timeout']<=10
  calls.append('acl')
  return types.SimpleNamespace(returncode=0,stdout='# owner: 0\nuser:1001:rw-\nother::---\n')
 def open_kvm(path,flags):
  assert path=='/dev/kvm' and flags==os.O_RDWR|os.O_CLOEXEC
  calls.append('open')
  if mode=='open-denied':raise PermissionError(errno.EACCES,'Permission denied',path)
  return 10
 def ioctl(fd,request,arg):
  assert fd==10 and arg==0
  if request==0xAE00:
   calls.append('api');return 11 if mode=='wrong-api' else 12
  assert request==0xAE01,request
  calls.append('create')
  if mode=='create-denied':raise PermissionError(errno.EPERM,'VM creation denied')
  return 20
 m.os=types.SimpleNamespace(**real_os.__dict__)
 m.os.stat=node_stat;m.os.open=open_kvm;m.os.close=lambda fd:calls.append('close:'+str(fd))
 m.os.cpu_count=lambda:4;m.os.getuid=lambda:1001;m.os.getgroups=lambda:[1001]
 m.subprocess=types.SimpleNamespace(run=command,PIPE=-1,STDOUT=-2)
 m.fcntl.ioctl=ioctl
 output=root/(mode+'.json');sys.argv=['preflight','--output',str(output)]
 result=m.main();report=json.loads(output.read_text())
 assert (result==0)==(mode=='ready'),(mode,report)
 assert calls[:3]==['metadata','acl','open'],(mode,calls)
 assert report.get('kvm_device')==dict(uid=0,gid=108,mode='0660',major=10,minor=232,character_device=True,runner_uid=1001,runner_groups=[1001]),report
 assert report.get('kvm_acl',{}).get('exit_code')==0 and 'user:1001:rw-' in report['kvm_acl']['output'],report
 assert report['qualification_passed'] is False and report['promotion_eligible'] is False,report
 if mode=='open-denied':assert calls==['metadata','acl','open'] and 'Permission denied' in report['kvm_error'],report
 else:
  assert calls[3:5]==['api','create'] and calls[-1]=='close:10',calls
  if mode!='create-denied':assert 'close:20' in calls,calls
 if mode!='ready':assert any('KVM' in error for error in report['errors']),report
`
	out, err := exec.Command("python3", "-c", script, helper, t.TempDir()).CombinedOutput()
	if err != nil {
		t.Fatalf("hosted KVM evidence and actual acceleration checks: %s %v", out, err)
	}
}
