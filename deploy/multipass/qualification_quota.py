#!/usr/bin/env python3
"""Strict read-only user-quota assertion for the qualification filesystem."""

import json
import os
import posixpath
import subprocess
import sys

# quota-tools4.09 caches all mounts before selecting the requested filesystem.
# Its cache skips pseudo-device stat failures with this diagnostic. Do not
# generalize this exception to real devices or other errors.
# https://kernel.googlesource.com/pub/scm/utils/quota/quota-tools/+/refs/tags/v4.09/quotasys.c
TMPFS_SCAN_WARNING = b"quotaon: Cannot stat() mounted device tmpfs: No such file or directory\n"
MAX_OUTPUT = 8192


def read_command(args):
    env = dict(os.environ, LC_ALL="C")
    result = subprocess.run(args, env=env, capture_output=True, timeout=10, check=False)
    if len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT:
        raise ValueError("quota command output exceeds the diagnostic limit")
    return result


def absolute_path(value):
    return (
        isinstance(value, str)
        and value.startswith("/")
        and posixpath.normpath(value) == value
        and all(32 < ord(char) < 127 and char not in "()" for char in value)
    )


def assert_user_quota_on(path):
    if not absolute_path(path):
        raise ValueError("invalid quota filesystem path")
    mount = read_command(["findmnt", "--json", "--output", "TARGET,SOURCE", "--target", path])
    if mount.returncode != 0 or mount.stderr:
        raise ValueError("cannot resolve quota filesystem")
    data = json.loads(mount.stdout)
    if not isinstance(data, dict) or set(data) != {"filesystems"}:
        raise ValueError("invalid quota filesystem response")
    filesystems = data["filesystems"]
    if not isinstance(filesystems, list) or len(filesystems) != 1:
        raise ValueError("quota filesystem must resolve to exactly one mount")
    filesystem = filesystems[0]
    if not isinstance(filesystem, dict) or set(filesystem) != {"target", "source"}:
        raise ValueError("invalid quota filesystem identity")
    target, source = filesystem["target"], filesystem["source"]
    if not absolute_path(target) or not absolute_path(source) or not source.startswith("/dev/"):
        raise ValueError("invalid quota filesystem identity")

    state = read_command(["quotaon", "-p", "-u", target])
    expected = f"user quota on {target} ({source}) is on\n".encode("ascii")
    # In print-state mode the exit status is the number of enabled classes,
    # not conventional command success: selecting only user quotas requires1.
    # https://kernel.googlesource.com/pub/scm/utils/quota/quota-tools/+/refs/tags/v4.09/quotaon.c
    if state.returncode != 1 or state.stdout != expected:
        raise ValueError("user quota state is not unambiguously enabled")
    if any(line != TMPFS_SCAN_WARNING for line in state.stderr.splitlines(keepends=True)):
        raise ValueError("unexpected quota state diagnostic")


def main():
    if len(sys.argv) != 2:
        raise ValueError("expected the hosting filesystem path")
    assert_user_quota_on(sys.argv[1])


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        sys.exit("qualification: cannot verify enabled user quotas")
