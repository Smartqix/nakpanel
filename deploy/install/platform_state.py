#!/usr/bin/env python3
"""Persist trusted installation state and the durable panel bootstrap gate."""
import json
import os
from pathlib import Path
import stat
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
        descriptor = os.open(marker.parent, os.O_RDONLY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)


def is_pending(state, owner=0):
    """The effective startup condition includes an interrupted marker removal."""
    marker = state.with_name('platform-bootstrap-pending')
    try:
        info = marker.lstat()
    except FileNotFoundError:
        marked = False
    else:
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError('bootstrap marker must be a private root-owned regular file')
        marked = True
    try:
        info = state.lstat()
    except FileNotFoundError:
        return marked
    if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
        raise ValueError('platform state must be a root-owned regular file without group/world writes')
    data = json.loads(state.read_text())
    if not isinstance(data, dict) or type(data.get('bootstrap_pending', False)) is not bool:
        raise ValueError('invalid platform bootstrap state')
    return marked or data.get('bootstrap_pending', False)


if __name__ == '__main__':
    if os.geteuid() != 0:
        sys.exit('platform state must be written by root')
    if sys.argv[1:2] == ['pending']:
        try: print('true' if is_pending(Path(sys.argv[2])) else 'false')
        except (OSError, ValueError, IndexError) as error: sys.exit('platform: ' + str(error))
        sys.exit(0)
    pending, osid, version, codename, arch, profile, php, *hosting = sys.argv[1:]
    if pending not in ('true', 'false'):
        sys.exit('invalid bootstrap marker')
    write_state(Path('/'), dict(os_id=osid, version_id=version, codename=codename,
        architecture=arch, profile=profile, internal_php_version=php,
        hosting_php_versions=hosting, bootstrap_pending=pending == 'true'))
