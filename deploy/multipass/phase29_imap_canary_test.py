import importlib.util
import contextlib
import imaplib
import io
import os
from pathlib import Path
import ssl
import subprocess
import unittest
from unittest.mock import patch


module_path = Path(os.environ.get('NAKPANEL_TEST_IMAP_MODULE', Path(__file__).with_name('phase29-imap-canary.py')))
spec = importlib.util.spec_from_file_location('phase29_imap', module_path)
canary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canary)


class Clock:
    def __init__(self):
        self.now = 0
        self.delays = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.delays.append(seconds)
        self.now += seconds


class Client:
    def __init__(self, login_error=None, append_error=None, body=b'phase29-restored-message-content'):
        self.login_error = login_error
        self.append_error = append_error
        self.body = body
        self.logins = []
        self.appends = []
        self.closed = 0
        self.sock = self
        self.timeouts = []

    def settimeout(self, seconds):
        self.timeouts.append(seconds)

    def login(self, mailbox, password):
        self.logins.append((mailbox, password))
        if self.login_error:
            raise self.login_error
        return 'OK', []

    def append(self, *args):
        self.appends.append(args)
        if self.append_error:
            raise self.append_error
        return 'OK', []

    def select(self, mailbox):
        return 'OK', []

    def search(self, *args):
        return 'OK', [b'7']

    def fetch(self, *args):
        return 'OK', [(b'7 (RFC822)', self.body)]

    def logout(self):
        self.closed += 1
        return 'BYE', []

    def shutdown(self):
        self.closed += 1


class Factory:
    def __init__(self, outcomes):
        self.outcomes = outcomes
        self.calls = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        outcome = self.outcomes[min(len(self.calls) - 1, len(self.outcomes) - 1)]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class IMAPCanaryTests(unittest.TestCase):
    def run_canary(self, mode, factory, clock=None, deadline=5):
        clock = clock or Clock()
        canary.run_canary(mode, 'phase29@example.test', 'fixture-password',
                          factory=factory, monotonic=clock.monotonic,
                          sleep=clock.sleep, timeout=deadline, interval=1)
        return clock

    def test_transient_connection_and_auth_readiness_then_append_once(self):
        not_ready = Client(login_error=imaplib.IMAP4.error('not ready'))
        ready = Client()
        factory = Factory([ConnectionRefusedError(), not_ready, ready])
        clock = self.run_canary('seed', factory)
        self.assertEqual(len(factory.calls), 3)
        self.assertEqual(clock.delays, [1, 1])
        self.assertEqual(not_ready.closed, 1)
        self.assertEqual(ready.closed, 1)
        self.assertEqual(ready.logins, [('phase29@example.test', 'fixture-password')])
        self.assertEqual(len(ready.appends), 1)
        self.assertIn(b'phase29-restored-message-content', ready.appends[0][3])
        for args, kwargs in factory.calls:
            self.assertEqual(args, ('127.0.0.1', 993))
            self.assertEqual(kwargs['ssl_context'].verify_mode, ssl.CERT_NONE)
            self.assertLessEqual(kwargs['timeout'], 5)

    def test_persistent_connection_failure_stops_at_deadline_without_append(self):
        clock = Clock()
        factory = Factory([ConnectionRefusedError()])
        with self.assertRaisesRegex(TimeoutError, 'readiness'):
            self.run_canary('seed', factory, clock, deadline=3)
        self.assertEqual(clock.now, 3)
        self.assertEqual(len(factory.calls), 3)

    def test_persistent_authentication_failure_is_not_readiness_success(self):
        clients = [Client(login_error=imaplib.IMAP4.error('fixture-password')) for _ in range(3)]
        factory = Factory(clients)
        with self.assertRaisesRegex(TimeoutError, 'readiness'):
            self.run_canary('seed', factory, deadline=3)
        self.assertTrue(all(not c.appends and c.closed == 1 for c in clients))

    def test_connection_consuming_deadline_never_authenticates_or_appends(self):
        clock = Clock()
        ready = Client()

        def slow_factory(*args, **kwargs):
            clock.now = 6
            return ready

        with self.assertRaisesRegex(TimeoutError, 'readiness'):
            self.run_canary('seed', slow_factory, clock)
        self.assertEqual(ready.logins, [])
        self.assertEqual(ready.appends, [])
        self.assertEqual(ready.closed, 1)

    def test_uncertain_append_failure_is_never_retried(self):
        ready = Client(append_error=imaplib.IMAP4.abort('connection lost after APPEND'))
        factory = Factory([ready])
        with self.assertRaisesRegex(RuntimeError, 'append'):
            self.run_canary('seed', factory)
        self.assertEqual(len(factory.calls), 1)
        self.assertEqual(len(ready.appends), 1)
        self.assertEqual(ready.closed, 1)

    def test_append_rejection_is_not_retried(self):
        ready = Client()
        ready.append = lambda *args: ('NO', [])
        factory = Factory([ready])
        with self.assertRaisesRegex(RuntimeError, 'append'):
            self.run_canary('seed', factory)
        self.assertEqual(len(factory.calls), 1)

    def test_restore_assertion_waits_for_authentication_and_checks_content(self):
        ready = Client()
        factory = Factory([ConnectionRefusedError(), ready])
        self.run_canary('assert', factory)
        self.assertEqual(len(factory.calls), 2)
        self.assertEqual(ready.appends, [])
        self.assertEqual(ready.closed, 1)

    def test_missing_or_wrong_restored_content_fails_without_reconnect(self):
        for stage in ['select', 'search', 'fetch', 'body']:
            with self.subTest(stage=stage):
                ready = Client(body=b'different content')
                if stage == 'select':
                    ready.select = lambda *args: ('NO', [])
                if stage == 'search':
                    ready.search = lambda *args: ('OK', [b''])
                if stage == 'fetch':
                    ready.fetch = lambda *args: ('NO', [])
                factory = Factory([ready])
                with self.assertRaisesRegex(RuntimeError, 'restored'):
                    self.run_canary('assert', factory)
                self.assertEqual(len(factory.calls), 1)
                self.assertEqual(ready.closed, 1)

    def test_remote_transport_timeout_is_single_attempt_with_exact_stdin(self):
        with patch.object(canary.subprocess, 'run', side_effect=subprocess.TimeoutExpired('multipass', 180)) as run:
            with self.assertRaisesRegex(RuntimeError, 'transport'):
                canary.run_remote('nakpanel-owned-run123', 'seed', 'phase29@example.test', 'fixture-password')
        run.assert_called_once()
        args, kwargs = run.call_args
        self.assertEqual(args[0], ['multipass', 'exec', 'nakpanel-owned-run123', '--', 'python3', '-',
                                   'seed', 'phase29@example.test', 'fixture-password'])
        self.assertEqual(kwargs['input'], module_path.read_bytes())
        self.assertEqual(kwargs['timeout'], 180)

    def test_remote_zero_exit_requires_exact_mode_bound_completion_receipt(self):
        expected = b'nakpanel-phase29-imap-v1\tseed\tverified\n'
        for output in [b'', b'nakpanel-phase29-imap-v1\tseed',
                       b'nakpanel-phase29-imap-v1\tassert\tverified\n', expected + b'extra\n']:
            with self.subTest(output=output), patch.object(canary.subprocess, 'run',
                    return_value=subprocess.CompletedProcess([], 0, stdout=output, stderr=b'')) as run:
                with self.assertRaisesRegex(RuntimeError, 'receipt'):
                    canary.run_remote('nakpanel-owned-run123', 'seed', 'phase29@example.test', 'fixture-password')
                run.assert_called_once()
        with patch.object(canary.subprocess, 'run', return_value=subprocess.CompletedProcess(
                [], 0, stdout=expected, stderr=b'')) as run:
            canary.run_remote('nakpanel-owned-run123', 'seed', 'phase29@example.test', 'fixture-password')
            self.assertTrue(run.call_args.kwargs['capture_output'])

    def test_guest_receipt_is_emitted_only_after_completed_check(self):
        for mode in ['seed', 'assert']:
            stdout = io.StringIO()
            with self.subTest(mode=mode), patch.object(canary, 'run_canary') as check, contextlib.redirect_stdout(stdout):
                self.assertEqual(canary.main([mode, 'phase29@example.test', 'fixture-password']), 0)
            check.assert_called_once_with(mode, 'phase29@example.test', 'fixture-password')
            self.assertEqual(stdout.getvalue(), f'nakpanel-phase29-imap-v1\t{mode}\tverified\n')

    def test_cli_does_not_log_credentials_or_untrusted_exception_text(self):
        stderr = io.StringIO()
        with patch.object(canary, 'run_canary', side_effect=RuntimeError('fixture-password')), contextlib.redirect_stderr(stderr):
            result = canary.main(['seed', 'phase29@example.test', 'fixture-password'])
        self.assertEqual(result, 1)
        self.assertNotIn('fixture-password', stderr.getvalue())
        self.assertNotIn('phase29@example.test', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
