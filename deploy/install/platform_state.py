#!/usr/bin/env python3
"""Persist trusted installation state and the durable panel bootstrap gate."""
import json
import os
from pathlib import Path
import sys
import tempfile


def atomic_write(path, contents, mode):
    path.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(contents)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def write_state(root, data):
    (root / 'etc/nakpanel').mkdir(parents=True, mode=0o750, exist_ok=True)
    marker = root / 'etc/nakpanel/platform-bootstrap-pending'
    dropin = root / 'etc/systemd/system/nakpanel.service.d/platform-bootstrap.conf'
    atomic_write(dropin, '[Unit]\nConditionPathExists=!/etc/nakpanel/platform-bootstrap-pending\n', 0o644)
    if data['bootstrap_pending']:
        atomic_write(marker, 'Fresh plan initialization must complete before starting the panel.\n', 0o600)
    atomic_write(root / 'etc/nakpanel/platform.json', json.dumps(data, sort_keys=True) + '\n', 0o644)
    if not data['bootstrap_pending']:
        try: marker.unlink()
        except FileNotFoundError: pass


if __name__ == '__main__':
    if os.geteuid() != 0:
        sys.exit('platform state must be written by root')
    pending, osid, version, codename, arch, profile, php, *hosting = sys.argv[1:]
    if pending not in ('true', 'false'):
        sys.exit('invalid bootstrap marker')
    write_state(Path('/'), dict(os_id=osid, version_id=version, codename=codename,
        architecture=arch, profile=profile, internal_php_version=php,
        hosting_php_versions=hosting, bootstrap_pending=pending == 'true'))
