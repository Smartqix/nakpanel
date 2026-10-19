#!/usr/bin/env python3
"""Wait for a real Multipass daemon response, with bounded attempts and evidence."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time


def wait_for_daemon(output, budget, attempt_timeout, retry_interval):
    output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    deadline = started + budget
    attempts = 0
    ready = False
    last_error = 'no daemon response'
    with (output / 'multipass-readiness.log').open('w') as log:
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            attempts += 1
            try:
                result = subprocess.run(['multipass', 'list', '--format', 'json'],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                    timeout=min(attempt_timeout, remaining))
                log.write(f'Attempt {attempts}, exit {result.returncode}:\n{result.stdout}\n')
                if result.returncode == 0:
                    try:
                        data = json.loads(result.stdout)
                        if not isinstance(data, dict) or not isinstance(data.get('list'), list) or data.get('errors'):
                            raise ValueError('invalid Multipass list response')
                    except (ValueError, TypeError):
                        last_error = 'daemon returned no valid JSON instance list'
                    else:
                        (output / 'multipass-list.json').write_text(result.stdout)
                        ready = True
                        break
                else:
                    last_error = f'Multipass list exited {result.returncode}'
            except subprocess.TimeoutExpired as error:
                last_error = 'Multipass list timed out'
                log.write(f'Attempt {attempts}: {last_error}\n')
                if error.stdout:
                    log.write(error.stdout.decode(errors='replace') if isinstance(error.stdout, bytes) else error.stdout)
            except OSError as error:
                last_error = str(error)
                log.write(f'Attempt {attempts}: {last_error}\n')
            log.flush()
            time.sleep(max(0, min(retry_interval, deadline - time.monotonic())))
    report = dict(ready=ready, attempts=attempts, elapsed_seconds=time.monotonic() - started)
    if not ready:
        report['error'] = last_error
        try:
            journal = subprocess.run(['sudo', 'journalctl', '-u', 'snap.multipass.multipassd.service',
                '--no-pager', '-n', '100'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=10).stdout
        except (OSError, subprocess.TimeoutExpired) as error:
            journal = 'Unable to collect Multipass daemon journal: ' + str(error)
        (output / 'multipass-journal.log').write_text(journal)
        print(f'Multipass daemon did not become ready: {last_error}; see {output}', file=sys.stderr)
    (output / 'multipass-readiness.json').write_text(json.dumps(report, indent=2) + '\n')
    return 0 if ready else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--timeout', type=float, default=120)
    parser.add_argument('--attempt-timeout', type=float, default=10)
    parser.add_argument('--retry-interval', type=float, default=2)
    args = parser.parse_args()
    if not (0 < args.timeout <= 300 and 0 < args.attempt_timeout <= 30 and 0 < args.retry_interval <= 10):
        parser.error('readiness timeout/attempt/interval must be positive and bounded')
    sys.exit(wait_for_daemon(args.output_dir, args.timeout, args.attempt_timeout, args.retry_interval))
