import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('php_fetch',Path(__file__).with_name('php')/'fetch.py')
fetch=importlib.util.module_from_spec(spec);spec.loader.exec_module(fetch)

class PHPSignerPolicy(unittest.TestCase):
 def test_accepts_only_branch_pinned_primary_signer(self):
  accepted='0616E93D95AF471243E26761770426E17EBBB3DD'
  valid='[GNUPG:] VALIDSIG '+accepted+' 2026-09-24 1790256000 0 4 0 1 10 00 '+accepted+'\n'
  self.assertTrue(fetch.has_allowed_signer(valid,[accepted]))
  self.assertFalse(fetch.has_allowed_signer(valid,['C28D937575603EB4ABB725861C0779DC5C0A9DE4']))
  self.assertFalse(fetch.has_allowed_signer('[GNUPG:] GOODSIG 770426E17EBBB3DD signer',[accepted]))
 def test_subkey_requires_pinned_primary(self):
  primary='AFD8691FDAEDF03BDF6E460563F15A9B715376CA'
  subkey='A'*40
  status='[GNUPG:] VALIDSIG '+subkey+' 2026-09-24 1790256000 0 4 0 1 10 00 '+primary+'\n'
  self.assertTrue(fetch.has_allowed_signer(status,[primary]))
  self.assertFalse(fetch.has_allowed_signer(status,[subkey]))
if __name__=='__main__':unittest.main()
