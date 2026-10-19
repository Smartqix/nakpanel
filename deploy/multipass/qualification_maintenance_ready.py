#!/usr/bin/env python3
"""Wait read-only for first-boot package maintenance before qualification fixtures."""
import json
import math
import re
import subprocess
import sys
import time

APT_UNITS = ('apt-daily.service', 'apt-daily-upgrade.service')
CORE_UNITS = ('nakpanel.service', 'nakpanel-agent.service', 'nginx.service',
              'postgresql.service', 'mariadb.service', 'named.service', 'stalwart-mail.service')
PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'Result', 'Job')
SQL_COMMAND = ['sudo', '-u', 'postgres', 'psql', '-X', '-A', '-t', '-q', '-d', 'nakpanel', '-c', 'SELECT 1']
ACTIVE_STATES = {'inactive', 'active', 'activating', 'deactivating', 'reloading'}
SERVICE_SUBSTATES = {'dead', 'running', 'exited', 'condition', 'start-pre', 'start', 'start-post',
                     'reload', 'reload-signal', 'reload-notify', 'stop', 'stop-watchdog',
                     'stop-sigterm', 'stop-sigkill', 'stop-post', 'final-watchdog',
                     'final-sigterm', 'final-sigkill', 'auto-restart', 'auto-restart-queued', 'cleaning'}


class ReadinessError(RuntimeError):
    pass


def parse_units(raw, expected):
    if type(raw) is not str or not raw.strip():
        raise ReadinessError('systemctl returned no structured unit state')
    units = {}
    for block in raw.strip().split('\n\n'):
        values = {}
        for line in block.splitlines():
            key, separator, value = line.partition('=')
            if not separator or key not in PROPERTIES or key in values:
                raise ReadinessError('systemctl unit fields are missing, duplicate or malformed')
            values[key] = value
        if set(values) != set(PROPERTIES) or values['Id'] not in expected or values['Id'] in units:
            raise ReadinessError('systemctl did not return each exact requested unit once')
        if values['LoadState'] != 'loaded' or values['Result'] != 'success':
            raise ReadinessError('requested unit is unavailable or has a failed result: ' + values['Id'])
        if values['ActiveState'] not in ACTIVE_STATES or values['SubState'] not in SERVICE_SUBSTATES:
            raise ReadinessError('requested unit has a failed or unknown state: ' + values['Id'])
        if values['Job'] not in ('', '0') and re.fullmatch(r'[1-9][0-9]*', values['Job']) is None:
            raise ReadinessError('requested unit has an unrecognized job state: ' + values['Id'])
        units[values['Id']] = values
    if set(units) != set(expected):
        raise ReadinessError('systemctl omitted a requested unit')
    return units


def apt_idle(units):
    return all(unit['ActiveState'] == 'inactive' and unit['SubState'] == 'dead'
               and unit['Job'] in ('', '0') for unit in units.values())


def core_active(units):
    # The PostgreSQL aggregate is active/exited; the SQL probe proves its cluster.
    # A multi-unit `is-active --quiet` only proves that at least one unit is active.
    return all(unit['ActiveState'] == 'active' and unit['SubState'] in ('running', 'exited')
               and unit['Job'] in ('', '0') for unit in units.values())


def wait_ready(*, timeout=600, run=subprocess.run, monotonic=time.monotonic, sleep=time.sleep):
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 600:
        raise ReadinessError('readiness timeout must be positive and at most 600 seconds')
    started = monotonic()
    deadline = started + timeout
    stable_since = None
    stable_polls = 0
    polls = 0
    last = {}

    def remaining():
        value = deadline - monotonic()
        if value <= 0:
            raise ReadinessError('first-boot maintenance readiness deadline exceeded; last=' + json.dumps(last, sort_keys=True))
        return value

    def command(args, sql=False):
        allowance = min(10, remaining())
        try:
            result = run(args, capture_output=True, text=True, timeout=allowance, check=False)
        except subprocess.TimeoutExpired:
            remaining()
            if sql:
                return None
            raise ReadinessError('read-only systemctl observation timed out') from None
        except OSError:
            raise ReadinessError('read-only readiness command could not execute') from None
        remaining()
        if type(result.returncode) is not int:
            raise ReadinessError('read-only command returned a malformed exit status')
        if not sql and result.returncode != 0:
            raise ReadinessError('read-only systemctl observation failed')
        return result

    def observe(units):
        result = command(['systemctl', 'show', *units, '--property=' + ','.join(PROPERTIES), '--no-pager'])
        return parse_units(result.stdout, units)

    while True:
        remaining()
        polls += 1
        before = observe(APT_UNITS)
        last = {'apt_before': before}
        ready = False
        if apt_idle(before):
            core = observe(CORE_UNITS)
            last['core'] = core
            sql_ok = False
            if core_active(core):
                sql = command(SQL_COMMAND, sql=True)
                last['sql_exit'] = None if sql is None else sql.returncode
                if sql is not None and sql.returncode == 0:
                    if sql.stdout != '1\n':
                        raise ReadinessError('physical PostgreSQL SELECT 1 returned unexpected output')
                    sql_ok = True
            after = observe(APT_UNITS)
            last['apt_after'] = after
            ready = core_active(core) and sql_ok and apt_idle(after)
        now = monotonic()
        remaining()
        if ready:
            if stable_since is None:
                stable_since = now
            stable_polls += 1
            if stable_polls >= 2 and now - stable_since >= 4:
                result = {'schema': 'nakpanel-qualification-maintenance-readiness-v1', 'status': 'PASS',
                          'polls': polls, 'quiet_seconds': now - stable_since, 'elapsed_seconds': now - started,
                          'apt_units': list(APT_UNITS), 'core_units': list(CORE_UNITS), 'physical_sql_verified': True}
                remaining()
                return result
        else:
            stable_since = None
            stable_polls = 0
        sleep(min(1, remaining()))
        remaining()


def main():
    if len(sys.argv) != 1:
        raise ReadinessError('this qualification helper accepts no command or mutation arguments')
    print(json.dumps(wait_ready(), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ReadinessError, UnicodeError) as error:
        print('qualification first-boot maintenance readiness failed: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
