"""Read-only first-boot readiness behavior; no guest or package actions."""
import importlib.util
import subprocess
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
APT = ('apt-daily.service', 'apt-daily-upgrade.service')
CORE = ('nakpanel.service', 'nakpanel-agent.service', 'nginx.service',
        'postgresql.service', 'mariadb.service', 'named.service', 'stalwart-mail.service')


def show(units, changes=None):
    changes = changes or {}
    blocks = []
    for unit in units:
        value = dict(Id=unit, LoadState='loaded', ActiveState='inactive' if unit in APT else 'active',
                     SubState='dead' if unit in APT else 'exited' if unit == 'postgresql.service' else 'running',
                     Result='success', Job='')
        value.update(changes.get(unit, {}))
        blocks.append('\n'.join(key + '=' + value[key] for key in value))
    return '\n\n'.join(blocks) + '\n'


class Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class Boundary:
    def __init__(self, clock, apt=None, core=None, sql=None):
        self.clock = clock
        self.apt = apt or (lambda n, now: show(APT))
        self.core = core or (lambda n, now: show(CORE))
        self.sql = sql or (lambda n, now: (0, '1\n'))
        self.calls = []
        self.count = dict(apt=0, core=0, sql=0)

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), dict(kwargs), self.clock.now))
        self_test = args[:2] == ['systemctl', 'show']
        if self_test:
            units = tuple(arg for arg in args[2:] if not arg.startswith('--'))
            kind = 'apt' if units == APT else 'core'
            if units not in (APT, CORE):
                raise AssertionError('unexpected/mutating unit command: ' + repr(args))
            self.count[kind] += 1
            result = getattr(self, kind)(self.count[kind], self.clock.now)
            return subprocess.CompletedProcess(args, 0, result, '')
        if args != ['sudo', '-u', 'postgres', 'psql', '-X', '-A', '-t', '-q', '-d', 'nakpanel', '-c', 'SELECT 1']:
            raise AssertionError('unexpected/mutating command: ' + repr(args))
        self.count['sql'] += 1
        code, output = self.sql(self.count['sql'], self.clock.now)
        return subprocess.CompletedProcess(args, code, output, 'private diagnostic deliberately not printed' if code else '')


class MaintenanceReady(unittest.TestCase):
    def module(self):
        path = HERE / 'qualification_maintenance_ready.py'
        self.assertTrue(path.is_file(), 'post-installer read-only maintenance readiness helper is missing')
        spec = importlib.util.spec_from_file_location('maintenance_ready', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def wait(self, module, boundary, clock, **options):
        return module.wait_ready(run=boundary, monotonic=clock, sleep=clock.sleep, **options)

    def test_three_supported_profiles_require_all_units_sql_and_four_quiet_seconds(self):
        for profile in ('ubuntu-24.04', 'ubuntu-26.04-native', 'ubuntu-26.04-sury'):
            with self.subTest(profile=profile):
                m = self.module(); clock = Clock(); boundary = Boundary(clock)
                value = self.wait(m, boundary, clock)
                self.assertEqual(value['status'], 'PASS')
                self.assertGreaterEqual(clock.now, 4)
                self.assertGreaterEqual(boundary.count['sql'], 2)
                self.assertEqual(boundary.count['apt'], boundary.count['sql'] * 2)
                self.assertTrue(all(seconds > 0 for seconds in clock.sleeps))

    def test_active_update_and_two_postgres_restarts_must_finish_before_quiet_window(self):
        m = self.module(); clock = Clock()
        def apt(n, now):
            return show(APT, {APT[1]: dict(ActiveState='active', SubState='running')}) if 1 <= now < 8 else show(APT)
        def sql(n, now):
            return (2, '') if now < 1 or 8 <= now < 10 else (0, '1\n')
        boundary = Boundary(clock, apt=apt, sql=sql)
        self.wait(m, boundary, clock)
        self.assertGreaterEqual(clock.now, 14)
        self.assertTrue(any(8 <= when < 10 for args, options, when in boundary.calls if args[0] == 'sudo'))

    def test_queued_activation_and_bracket_change_reset_quiet_stability(self):
        for changes in (dict(Job='451'), dict(ActiveState='activating', SubState='start'),
                        dict(ActiveState='reloading', SubState='reload'), dict(ActiveState='deactivating', SubState='stop')):
            with self.subTest(changes=changes):
                m = self.module(); clock = Clock()
                boundary = Boundary(clock, apt=lambda n, now: show(APT, {APT[0]: changes}) if n == 2 else show(APT))
                self.wait(m, boundary, clock)
                self.assertGreaterEqual(clock.now, 5)
                self.assertGreaterEqual(boundary.count['apt'], 4)

    def test_all_seven_core_units_are_required_even_when_systemctl_exit_is_zero(self):
        m = self.module(); clock = Clock()
        boundary = Boundary(clock, core=lambda n, now: show(CORE, {CORE[-1]: dict(ActiveState='inactive', SubState='dead')}))
        with self.assertRaises(m.ReadinessError):
            self.wait(m, boundary, clock, timeout=6)
        self.assertEqual(clock.now, 6)
        self.assertEqual(boundary.count['sql'], 0)

    def test_sql_connection_failure_is_bounded_wait_but_wrong_success_stdout_is_not_ready(self):
        m = self.module(); clock = Clock(); boundary = Boundary(clock, sql=lambda n, now: (2, '') if n < 3 else (0, '1\n'))
        self.wait(m, boundary, clock)
        self.assertGreaterEqual(clock.now, 6)
        for output in ('', '1\n1\n', '2\n', '1', 'notice\n1\n'):
            with self.subTest(output=output):
                clock = Clock(); boundary = Boundary(clock, sql=lambda n, now: (0, output))
                with self.assertRaises(m.ReadinessError):
                    self.wait(m, boundary, clock)

    def test_failed_unknown_missing_duplicate_or_malformed_unit_data_fails(self):
        m = self.module()
        values = [show(APT, {APT[0]: dict(ActiveState='failed', SubState='failed', Result='exit-code')}),
                  show(APT, {APT[0]: dict(LoadState='not-found')}), show(APT, {APT[0]: dict(ActiveState='mystery')}),
                  show(APT, {APT[0]: dict(SubState='mystery')}), show(APT, {APT[0]: dict(Result='timeout')}),
                  show(APT, {APT[0]: dict(Job='unknown')}), show(APT[:1]), show(APT) + show(APT[:1]),
                  show(APT).replace('LoadState=loaded\n', '', 1), show(APT).replace('Result=success', 'Result=success\nResult=success', 1)]
        for value in values:
            with self.subTest(value=value):
                clock = Clock(); boundary = Boundary(clock, apt=lambda n, now: value)
                with self.assertRaises(m.ReadinessError):
                    self.wait(m, boundary, clock)
                self.assertEqual(clock.sleeps, [])
                self.assertEqual(boundary.count['sql'], 0)

    def test_actual_empty_job_and_explicit_zero_both_mean_no_queued_job(self):
        m = self.module()
        for job in ('', '0'):
            clock = Clock(); boundary = Boundary(clock, apt=lambda n, now: show(APT, {unit: dict(Job=job) for unit in APT}))
            self.assertEqual(self.wait(m, boundary, clock)['status'], 'PASS')

    def test_captured_native26_show_protocol_with_empty_job_is_accepted(self):
        m = self.module(); clock = Clock()
        # Read-only protocol observation after the retained failed16 case.
        raw = ('Id=apt-daily.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nJob=\nResult=success\n\n'
               'Id=apt-daily-upgrade.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nJob=\nResult=success\n')
        boundary = Boundary(clock, apt=lambda n, now: raw)
        self.assertEqual(self.wait(m, boundary, clock)['status'], 'PASS')

    def test_deadline_is_checked_after_commands_and_final_success_with_remaining_timeouts(self):
        m = self.module()
        for late_command in (1, 2, 3, 4, 7):
            with self.subTest(late_command=late_command):
                clock = Clock(); boundary = Boundary(clock); calls = []
                def slow(args, **kwargs):
                    result = boundary(args, **kwargs); calls.append(args)
                    if len(calls) == late_command:
                        clock.now = 6
                    return result
                with self.assertRaises(m.ReadinessError):
                    self.wait(m, slow, clock, timeout=6)
                self.assertEqual(len(calls), late_command)
                for args, options, when in boundary.calls:
                    self.assertGreater(options['timeout'], 0)
                    self.assertLessEqual(options['timeout'], 6 - when)
        clock = Clock(); boundary = Boundary(clock)
        with self.assertRaises(m.ReadinessError):
            self.wait(m, boundary, clock, timeout=4)
        self.assertEqual(clock.now, 4)

    def test_deadline_crossing_at_the_final_success_barrier_cannot_return_pass(self):
        m = self.module(); clock = Clock(); boundary = Boundary(clock); armed = []
        def observed(args, **kwargs):
            result = boundary(args, **kwargs)
            if args[:2] == ['systemctl', 'show'] and boundary.count['apt'] == 10:
                armed.append(0)
            return result
        def monotonic():
            if armed:
                armed[0] += 1
                if armed[0] == 4:
                    clock.now = 6
            return clock.now
        with self.assertRaises(m.ReadinessError):
            m.wait_ready(run=observed, monotonic=monotonic, sleep=clock.sleep, timeout=6)
        self.assertEqual(clock.now, 6)

    def test_only_read_commands_execute_and_command_failure_or_timeout_cannot_pass(self):
        m = self.module(); clock = Clock(); boundary = Boundary(clock)
        self.wait(m, boundary, clock)
        self.assertTrue(all(args[:2] == ['systemctl', 'show'] or args[-2:] == ['-c', 'SELECT 1'] for args, options, when in boundary.calls))
        for failure in ('exit', 'timeout'):
            clock = Clock()
            def broken(args, **kwargs):
                if failure == 'timeout':
                    raise subprocess.TimeoutExpired(args, kwargs['timeout'])
                return subprocess.CompletedProcess(args, 1, '', 'private error')
            with self.assertRaises(m.ReadinessError) as caught:
                self.wait(m, broken, clock, timeout=5)
            self.assertNotIn('private error', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
