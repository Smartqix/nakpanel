#!/usr/bin/env python3
"""Fail-closed capacity/KVM evidence for the disposable hosted AMD64 workflow."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess


def capacity_errors(architecture, cpu_count, total_memory, available_memory, free_disk, kvm_api):
    errors = []
    if architecture not in ('x86_64', 'amd64'):
        errors.append('native AMD64 host is required')
    if cpu_count < 4:
        errors.append('four host vCPUs are required for two 2-vCPU guests')
    if total_memory < 14 * 2**30 or available_memory < 11 * 2**30:
        errors.append('insufficient memory for two 5-GiB guests and host overhead')
    if free_disk < 48 * 2**30:
        errors.append('insufficient disk: at least 48 GiB measured free space is required after staging')
    if kvm_api != 12:
        errors.append('usable hardware KVM API 12 and VM creation are required; emulation cannot qualify')
    return errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    parser.add_argument('--storage-path', default='/var/snap/multipass/common')
    args = parser.parse_args()
    report = dict(qualification_passed=False, promotion_eligible=False, status='FAIL')
    try:
        memory = {}
        for line in Path('/proc/meminfo').read_text().splitlines():
            key, value = line.split(':', 1)
            memory[key] = int(value.split()[0]) * 1024
        report.update(architecture=platform.machine(), cpu_count=os.cpu_count() or 0,
                      total_memory=memory['MemTotal'], available_memory=memory['MemAvailable'],
                      free_disk=shutil.disk_usage(args.storage_path).free, kvm_api=None,
                      runner_image=os.environ.get('ImageVersion'), runner_os_image=os.environ.get('ImageOS'),
                      guest_budget=dict(max_simultaneous_guests=2,source_cpus=2,source_memory_gib=5,source_disk_gib=32,dr_cpus=2,dr_memory_gib=3,dr_disk_gib=16))
        # Capture the device state as the same actor, immediately before the
        # real open/ioctl checks. A diagnostic snapshot never substitutes for
        # API-version and VM-creation success below.
        try:
            device = os.stat('/dev/kvm', follow_symlinks=False)
            report['kvm_device'] = dict(uid=device.st_uid, gid=device.st_gid,
                mode=format(stat.S_IMODE(device.st_mode), '04o'),
                major=os.major(device.st_rdev), minor=os.minor(device.st_rdev),
                character_device=stat.S_ISCHR(device.st_mode),
                runner_uid=os.getuid(), runner_groups=os.getgroups())
        except OSError as error:
            report['kvm_device_error'] = str(error)
        try:
            acl = subprocess.run(['getfacl', '-n', '-p', '/dev/kvm'],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=5)
            report['kvm_acl'] = dict(exit_code=acl.returncode, output=acl.stdout)
        except (OSError, subprocess.TimeoutExpired) as error:
            report['kvm_acl_error'] = str(error)
        try:
            fd = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
            try:
                api = fcntl.ioctl(fd, 0xAE00, 0)  # KVM_GET_API_VERSION
                vm = fcntl.ioctl(fd, 0xAE01, 0)  # KVM_CREATE_VM: prove actual acceleration
                os.close(vm)
                report['kvm_api'] = api
            finally:
                os.close(fd)
        except OSError as error:
            report['kvm_error'] = str(error)
        errors = capacity_errors(**{key: report[key] for key in ('architecture','cpu_count','total_memory','available_memory','free_disk','kvm_api')})
        report.update(errors=errors, status='PASS' if not errors else 'FAIL')
    except Exception as error:
        report['errors'] = [str(error)]
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n')
    for error in report.get('errors', []):
        print(error)
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
