import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('native_admin',Path(__file__).with_name('native_admin.py'))
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class NativeAdministratorIntent(unittest.TestCase):
    def test_retry_retains_required_identity_until_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            module.record(root,' Admin@Example.com ')
            self.assertEqual(module.resolve(root,'',owner=os.getuid()),'admin@example.com')
            self.assertEqual(module.resolve(root,'ADMIN@example.com',owner=os.getuid()),'admin@example.com')
            with self.assertRaises(ValueError):module.resolve(root,'other@example.com',owner=os.getuid())
            self.assertTrue((root/module.RELATIVE_PATH).exists())
            module.clear(root,owner=os.getuid())
            self.assertEqual(module.resolve(root,'',owner=os.getuid()),'')
    def test_untrusted_or_linked_intent_rejects(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);module.record(root,'admin@example.com')
            path=root/module.RELATIVE_PATH
            path.chmod(0o666)
            with self.assertRaises(ValueError):module.resolve(root,'',owner=os.getuid())
            path.unlink();path.symlink_to(root/'missing')
            with self.assertRaises(ValueError):module.resolve(root,'',owner=os.getuid())
    def test_lab_install_does_not_invent_admin_requirement(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);module.record(root,'')
            self.assertEqual(module.resolve(root,'',owner=os.getuid()),'')
            self.assertFalse((root/module.RELATIVE_PATH).exists())

if __name__=='__main__':unittest.main()
