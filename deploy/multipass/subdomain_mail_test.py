import importlib.util,os,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('submail',Path(__file__).with_name('subdomain-mail-verify.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Guards(unittest.TestCase):
 def test_hosted_guard_rejects_local_even_with_github_flag(self):
  with patch.dict(os.environ,{'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'self-hosted'},clear=True):
   with self.assertRaises(ValueError):m.hosted_guard()
 def test_archive_rejects_links_and_parent_escape_before_extract(self):
  for name,kind in [('../escape',tarfile.REGTYPE),('bundle/link',tarfile.SYMTYPE)]:
   with self.subTest(name=name),tempfile.TemporaryDirectory() as temp:
    root=Path(temp); archive=root/'bundle.tar'
    with tarfile.open(archive,'w') as stream:
     item=tarfile.TarInfo(name);item.type=kind;item.linkname='/tmp/foreign';stream.addfile(item)
    with self.assertRaises(ValueError):m.extract_release(archive,root/'out')
    self.assertFalse((root/'out').exists())
 def test_identity_rejects_wrong_commit_and_architecture(self):
  valid={'commit':'a'*40,'architecture':'amd64','development':True}
  with self.assertRaises(ValueError):m.check_identity(valid,'b'*40)
  with self.assertRaises(ValueError):m.check_identity(dict(valid,architecture='arm64'),'a'*40)
if __name__=='__main__':unittest.main()
