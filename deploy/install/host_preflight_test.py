import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('host_preflight', Path(__file__).with_name('host_preflight.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class HostPreflightTests(unittest.TestCase):
    def setUp(self):
        self.host = dict(init='systemd', cgroup_controllers=['cpu', 'memory', 'pids', 'io'],
                         home_filesystem=dict(fstype='ext4', target='/', source='/dev/test'),
                         storage=[dict(path=path, available_bytes=123456789, available_inodes=12000,
                                       read_only=False) for path in ('/', '/home', '/var/lib', '/tmp')])

    def test_actual_requirements_accept_all_profiles_without_an_invented_capacity_floor(self):
        for profile in ('ubuntu-24.04', 'ubuntu-26.04-native', 'ubuntu-26.04-sury'):
            self.host['storage'][0]['available_bytes'] = 1
            report = module.validate(copy.deepcopy(self.host), profile)
            self.assertEqual(report['profile'], profile)
            self.assertFalse(report['warnings'])

    def test_impossible_installation_targets_reject(self):
        for key, value in (('read_only', True), ('available_bytes', 0), ('available_inodes', 0)):
            with self.subTest(key=key):
                host = copy.deepcopy(self.host)
                host['storage'][1][key] = value
                with self.assertRaisesRegex(ValueError, '/home'):
                    module.validate(host, 'ubuntu-24.04')
        self.host['init'] = 'bash'
        with self.assertRaisesRegex(ValueError, 'systemd'):
            module.validate(self.host, 'ubuntu-26.04-native')

    def test_new_resolute_requires_qualified_kernel_and_filesystem(self):
        for controller in ('cpu', 'memory', 'pids'):
            host = copy.deepcopy(self.host)
            host['cgroup_controllers'].remove(controller)
            with self.assertRaisesRegex(ValueError, 'cgroup'):
                module.validate(host, 'ubuntu-26.04-native')
        self.host['home_filesystem']['fstype'] = 'overlay'
        with self.assertRaisesRegex(ValueError, 'ext4'):
            module.validate(self.host, 'ubuntu-26.04-sury')

    def test_existing_noble_filesystem_and_controller_semantics_remain_eligible(self):
        self.host['home_filesystem']['fstype'] = 'xfs'
        self.host['cgroup_controllers'] = []
        report = module.validate(self.host, 'ubuntu-24.04')
        self.assertEqual(len(report['warnings']), 2)
        with self.assertRaisesRegex(ValueError, 'profile'):
            module.validate(self.host, 'unknown')


if __name__ == '__main__':
    unittest.main()
