import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('platform_state', Path(__file__).with_name('platform_state.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class BootstrapGateTests(unittest.TestCase):
    def test_effective_pending_survives_false_commit_before_marker_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module.write_state(root, dict(bootstrap_pending=True))
            original = module.atomic_write
            def interrupt_after_commit(path, contents, mode):
                original(path, contents, mode)
                if path.name == 'platform.json' and json.loads(contents).get('bootstrap_pending') is False:
                    raise OSError('interrupted before marker cleanup')
            module.atomic_write = interrupt_after_commit
            try:
                with self.assertRaises(OSError): module.write_state(root, dict(bootstrap_pending=False))
            finally:
                module.atomic_write = original
            state = root/'etc/nakpanel/platform.json'
            self.assertFalse(json.loads(state.read_text())['bootstrap_pending'])
            self.assertTrue(module.is_pending(state, owner=os.geteuid()))
            module.write_state(root, dict(bootstrap_pending=False))
            self.assertFalse(module.is_pending(state, owner=os.geteuid()))

    def test_untrusted_marker_cannot_authorize_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module.write_state(root, dict(bootstrap_pending=True))
            state = root/'etc/nakpanel/platform.json'
            marker = state.with_name('platform-bootstrap-pending')
            marker.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'marker'):
                module.is_pending(state, owner=os.geteuid())
            marker.unlink()
            marker.symlink_to(state)
            with self.assertRaisesRegex(ValueError, 'marker'):
                module.is_pending(state, owner=os.geteuid())

    def test_pending_gate_survives_failed_state_write_and_clear_commits_first(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = dict(bootstrap_pending=True)
            original = module.atomic_write
            def fail_state(path, contents, mode):
                if path.name == 'platform.json':
                    raise OSError('interrupted state commit')
                original(path, contents, mode)
            module.atomic_write = fail_state
            try:
                with self.assertRaises(OSError): module.write_state(root, state)
            finally:
                module.atomic_write = original
            marker = root/'etc/nakpanel/platform-bootstrap-pending'
            self.assertTrue(marker.is_file())
            dropin = root/'etc/systemd/system/nakpanel.service.d/platform-bootstrap.conf'
            self.assertIn('ConditionPathExists=!/etc/nakpanel/platform-bootstrap-pending', dropin.read_text())
            module.write_state(root, state)
            self.assertTrue(json.loads((root/'etc/nakpanel/platform.json').read_text())['bootstrap_pending'])
            state['bootstrap_pending'] = False
            def assert_marker_during_commit(path, contents, mode):
                if path.name == 'platform.json': self.assertTrue(marker.exists())
                original(path, contents, mode)
            module.atomic_write = assert_marker_during_commit
            try: module.write_state(root, state)
            finally: module.atomic_write = original
            self.assertFalse(marker.exists())
            self.assertFalse(json.loads((root/'etc/nakpanel/platform.json').read_text())['bootstrap_pending'])
            self.assertTrue(dropin.is_file())

if __name__ == '__main__': unittest.main()
