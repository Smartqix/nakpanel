#!/usr/bin/env python3
"""Wait for authenticated mail readiness, then seed or assert one DR canary."""

import imaplib
from pathlib import Path
import ssl
import subprocess
import sys
import time


MESSAGE = b'Subject: Nakpanel phase29 durable mail canary\r\n\r\nphase29-restored-message-content\r\n'

# Only controller-owned messages may cross the guest boundary. Stderr can also
# contain transport diagnostics or server responses with private values.
SAFE_FAILURES = frozenset({
    'invalid IMAP canary request',
    'IMAP authenticated readiness deadline expired',
    'IMAP canary append rejected',
    'IMAP canary append failed; result uncertain, not retried',
    'restored mailbox could not be selected',
    'restored mailbox canary missing',
    'restored mailbox canary content missing',
    'restored mailbox canary could not be read',
    'IMAP canary session close failed',
    'IMAP canary failed',
})


class CanaryError(RuntimeError):
    pass


def success_receipt(mode):
    return f'nakpanel-phase29-imap-v1\t{mode}\tverified\n'.encode('ascii')


def shutdown(client):
    try:
        client.shutdown()
    except Exception:
        pass


def run_canary(mode, mailbox, password, *, factory=imaplib.IMAP4_SSL,
               monotonic=time.monotonic, sleep=time.sleep, timeout=120, interval=2):
    if mode not in {'seed', 'assert'} or timeout <= 0 or interval <= 0:
        raise CanaryError('invalid IMAP canary request')
    deadline = monotonic() + timeout
    client = None
    # Domain/mailbox writes queue configure_mail, which restarts Stalwart.
    # Retry only connection and authentication, never an uncertain APPEND.
    while monotonic() < deadline:
        try:
            client = factory('127.0.0.1', 993, ssl_context=ssl._create_unverified_context(),
                             timeout=min(20, deadline - monotonic()))
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError()
            client.sock.settimeout(min(20, remaining))
            status, _ = client.login(mailbox, password)
            if status != 'OK' or monotonic() >= deadline:
                raise imaplib.IMAP4.error('authentication not ready')
            break
        except (OSError, imaplib.IMAP4.error):
            if client is not None:
                shutdown(client)
                client = None
            remaining = deadline - monotonic()
            if remaining > 0:
                sleep(min(interval, remaining))
        except Exception:
            if client is not None:
                shutdown(client)
            raise
    if client is None:
        raise TimeoutError('IMAP authenticated readiness deadline expired')

    succeeded = False
    try:
        client.sock.settimeout(20)
        if mode == 'seed':
            try:
                status, _ = client.append('INBOX', None, None, MESSAGE)
                if status != 'OK':
                    raise CanaryError('IMAP canary append rejected')
            except (OSError, imaplib.IMAP4.error):
                raise CanaryError('IMAP canary append failed; result uncertain, not retried') from None
        else:
            try:
                if client.select('INBOX')[0] != 'OK':
                    raise CanaryError('restored mailbox could not be selected')
                status, messages = client.search(None, 'SUBJECT', 'durable')
                if status != 'OK' or not messages or not messages[0]:
                    raise CanaryError('restored mailbox canary missing')
                status, payload = client.fetch(messages[0].split()[-1], '(RFC822)')
                if status != 'OK' or not any(isinstance(p, tuple) and isinstance(p[1], bytes)
                                             and b'phase29-restored-message-content' in p[1] for p in payload):
                    raise CanaryError('restored mailbox canary content missing')
            except (OSError, imaplib.IMAP4.error):
                raise CanaryError('restored mailbox canary could not be read') from None
        succeeded = True
    finally:
        try:
            client.logout()
        except Exception:
            shutdown(client)
            if succeeded:
                raise CanaryError('IMAP canary session close failed') from None


def run_remote(vm, mode, mailbox, password):
    # The short-command watchdog retries commands. It must never replay a
    # successful or uncertain APPEND. Bound this one transport without retry.
    try:
        result = subprocess.run(['multipass', 'exec', vm, '--', 'python3', '-', mode, mailbox, password],
                                input=Path(__file__).read_bytes(), timeout=180, check=True,
                                capture_output=True)
    except subprocess.TimeoutExpired:
        raise CanaryError('IMAP transport deadline expired; not retried') from None
    except subprocess.CalledProcessError as error:
        stderr = error.stderr if isinstance(error.stderr, bytes) else b''
        # Bound parsing and require the entire message to match. Never forward
        # arbitrary stderr or a trusted-looking substring of an untrusted line.
        reason = stderr.decode('utf-8', errors='replace').strip() if len(stderr) <= 4096 else ''
        detail = f': {reason}' if reason in SAFE_FAILURES else ''
        raise CanaryError(f'IMAP remote canary failed (exit {error.returncode}){detail}; not retried') from None
    if result.stdout != success_receipt(mode):
        raise CanaryError('IMAP remote completion receipt missing or invalid; not retried')


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    remote = bool(args and args[0] == 'remote')
    if len(args) != (5 if remote else 3) or args[2 if remote else 0] not in {'seed', 'assert'}:
        print('usage: phase29-imap-canary.py [remote VM] seed|assert MAILBOX PASSWORD', file=sys.stderr)
        return 2
    try:
        if remote:
            run_remote(*args[1:])
        else:
            run_canary(*args)
    except CanaryError as error:
        print(str(error), file=sys.stderr)
        return 1
    except TimeoutError:
        print('IMAP authenticated readiness deadline expired', file=sys.stderr)
        return 1
    except Exception:
        # Never expose a password or untrusted server response in evidence.
        print('IMAP canary failed', file=sys.stderr)
        return 1
    sys.stdout.write(success_receipt(args[2 if remote else 0]).decode('ascii'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
