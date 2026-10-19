package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestStalwartArtifactRejectsTamperingAndUnsafePayloads(t *testing.T) {
	program := `
import hashlib, importlib.util, io, pathlib, struct, tarfile, tempfile
spec=importlib.util.spec_from_file_location('stalwart_artifact','stalwart_artifact.py')
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
with tempfile.TemporaryDirectory() as directory:
 root=pathlib.Path(directory); path=root/'archive.tar.gz'
 elf=bytearray(64); elf[:7]=b'\x7fELF\x02\x01\x01'; struct.pack_into('<H',elf,18,62)
 def archive(kind='regular',name='stalwart-mail',extra=False,payload=elf):
  with tarfile.open(path,'w:gz') as t:
   member=tarfile.TarInfo(name); member.size=len(payload)
   if kind=='link':member.type=tarfile.SYMTYPE; member.linkname='/etc/passwd'; member.size=0
   if kind=='device':member.type=tarfile.CHRTYPE; member.size=0
   t.addfile(member,io.BytesIO(payload) if member.isfile() else None)
   if extra:t.addfile(tarfile.TarInfo('extra'))
  data=path.read_bytes(); m.ASSETS['amd64']['sha256']=hashlib.sha256(data).hexdigest(); m.ASSETS['amd64']['size']=len(data)
 def denied():
  try:m.validate(path,'amd64')
  except (ValueError,OSError):return
  raise AssertionError('unsafe archive accepted')
 archive(); assert m.validate(path,'amd64')==bytes(elf)
 destination=root/'binary'; m.extract(path,'amd64',destination)
 assert destination.read_bytes()==bytes(elf) and destination.stat().st_mode&0o777==0o755
 try:m.extract(path,'amd64',destination)
 except FileExistsError:pass
 else:raise AssertionError('existing binary overwritten nonatomically')
 path.write_bytes(path.read_bytes()+b'tamper'); denied()
 for kwargs in [{'kind':'link'},{'kind':'device'},{'name':'../stalwart-mail'},{'extra':True},{'payload':b'not ELF'}]:
  archive(**kwargs); denied()
 arm=bytearray(elf); struct.pack_into('<H',arm,18,183); archive(payload=arm); denied()
 archive(); m.ASSETS['amd64']['size']+=1; denied()
 archive(); link=root/'link'; link.symlink_to(path)
 try:m.validate(link,'amd64')
 except (ValueError,OSError):pass
 else:raise AssertionError('symlink archive accepted')
`
	output, err := exec.Command("python3", "-c", program).CombinedOutput()
	if err != nil {
		t.Fatalf("artifact policy: %s %v", output, err)
	}
}

func TestStalwartSourceIsInertAndExistingStageMustVerify(t *testing.T) {
	output, err := exec.Command("bash", "-c", "source ./stalwart.sh").CombinedOutput()
	if err != nil || len(output) != 0 {
		t.Fatalf("source has effects: %s %v", output, err)
	}
	stage := t.TempDir()
	if err := os.Chmod(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "stalwart-mail.tar.gz"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", "-c", "source ./stalwart.sh; nakpanel_prepare_stalwart_artifact")
	command.Env = append(os.Environ(), "NAKPANEL_STALWART_STAGE="+stage)
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("untrusted environment stage accepted: %s", output)
	}
}
