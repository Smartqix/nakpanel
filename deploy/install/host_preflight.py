#!/usr/bin/env python3
"""Read-only host requirements and storage report before installer mutation."""
import json
import os
from pathlib import Path
import subprocess
import sys

PROFILES = ('ubuntu-26.04-native', 'ubuntu-26.04-sury')


def collect():
    controllers = Path('/sys/fs/cgroup/cgroup.controllers')
    mount = json.loads(subprocess.check_output([
        'findmnt', '--json', '--target', '/home', '--output', 'TARGET,SOURCE,FSTYPE,OPTIONS'
    ], text=True))['filesystems']
    if len(mount) != 1:
        raise ValueError('cannot identify the /home backing filesystem')
    storage = []
    for name in ('/', '/home', '/var/lib', '/tmp'):
        ancestor = Path(name)
        while not ancestor.exists():
            ancestor = ancestor.parent
        info = os.statvfs(ancestor)
        storage.append(dict(path=name, measured_path=str(ancestor),
                            available_bytes=info.f_bavail * (info.f_frsize or info.f_bsize),
                            available_inodes=info.f_favail,
                            read_only=bool(info.f_flag & os.ST_RDONLY)))
    return dict(init=Path('/proc/1/comm').read_text().strip(),
                cgroup_controllers=controllers.read_text().split() if controllers.exists() else [],
                home_filesystem=mount[0], storage=storage)


def validate(host, profile):
    if profile not in PROFILES:
        raise ValueError('unknown platform profile')
    if host['init'] != 'systemd':
        raise ValueError('installation requires a booted systemd server')
    for item in host['storage']:
        if item['read_only'] or item['available_bytes'] <= 0 or item['available_inodes'] == 0:
            raise ValueError('installation path is read-only or has no available space/inodes: ' + item['path'])
    warnings = []
    missing = sorted({'cpu', 'memory', 'pids'} - set(host['cgroup_controllers']))
    if missing:
        message = 'cgroup v2 controllers missing: ' + ','.join(missing)
        raise ValueError(message)
    if host['home_filesystem']['fstype'] != 'ext4':
        raise ValueError('the experimental Resolute profile requires an ext4 filesystem backing /home')
    return dict(host, profile=profile, warnings=warnings)


if __name__ == '__main__':
    try:
        report = validate(collect(), sys.argv[1])
        print('platform: host preflight ' + json.dumps(report, sort_keys=True))
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError) as error:
        sys.exit('platform: host preflight failed: ' + str(error))
