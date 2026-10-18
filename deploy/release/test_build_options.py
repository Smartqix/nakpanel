import os
from pathlib import Path
import subprocess
import unittest

SCRIPT=Path(__file__).with_name('build.sh')

class ReleaseArchitectureSelection(unittest.TestCase):
 def run_builder(self, architectures):
  env=os.environ.copy()
  env.pop('NAKPANEL_RELEASE_SIGNING_KEY',None)
  if architectures is None:env.pop('NAKPANEL_RELEASE_ARCHITECTURES',None)
  else:env['NAKPANEL_RELEASE_ARCHITECTURES']=architectures
  return subprocess.run(['bash',str(SCRIPT)],env=env,capture_output=True,text=True)
 def test_rejects_empty_unknown_duplicate_and_malformed_lists_before_build(self):
  for value in ('','amd64 amd64','arm64 arm64','amd64 riscv64','amd64,arm64','amd64\nunknown'):
   with self.subTest(value=value):
    result=self.run_builder(value)
    self.assertNotEqual(result.returncode,0)
    self.assertIn('invalid release architectures',result.stderr)
    self.assertNotIn('NAKPANEL_RELEASE_SIGNING_KEY',result.stderr)
 def test_valid_selection_advances_to_required_signing_key_gate(self):
  for value in (None,'amd64','arm64','amd64 arm64','arm64 amd64'):
   with self.subTest(value=value):
    result=self.run_builder(value)
    self.assertNotEqual(result.returncode,0)
    self.assertIn('NAKPANEL_RELEASE_SIGNING_KEY',result.stderr)
    self.assertNotIn('invalid release architectures',result.stderr)
if __name__=='__main__':unittest.main()
