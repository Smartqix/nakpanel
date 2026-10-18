#!/usr/bin/env python3
"""Validate the signed Roundcube archive, including its internal public links."""
from pathlib import PurePosixPath
import posixpath
import sys
import tarfile


def validate(archive, expected_root):
    with tarfile.open(archive) as stream:
        members = stream.getmembers()
    by_name = {}
    links = set()
    for member in members:
        name = member.name.rstrip("/")
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or str(path) != name or not (name == expected_root or name.startswith(expected_root + "/")):
            raise ValueError("unsafe Roundcube archive member")
        if name in by_name or not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
            raise ValueError("duplicate or unsupported Roundcube archive member")
        by_name[name] = member
        if member.issym() or member.islnk():
            links.add(name)
    for name, member in by_name.items():
        if any(str(parent) in links for parent in PurePosixPath(name).parents):
            raise ValueError("Roundcube archive writes through a link")
        if name not in links:
            continue
        link = PurePosixPath(member.linkname)
        if link.is_absolute():
            raise ValueError("absolute Roundcube archive link")
        target = posixpath.normpath(posixpath.join(posixpath.dirname(name), str(link)) if member.issym() else str(link))
        if not target.startswith(expected_root + "/") or target not in by_name:
            raise ValueError("Roundcube archive link escapes or has no target")
        if target in links or any(str(parent) in links for parent in PurePosixPath(target).parents):
            raise ValueError("Roundcube archive link chain is forbidden")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            raise ValueError("usage: archive_policy.py ARCHIVE EXPECTED_ROOT")
        validate(sys.argv[1], sys.argv[2])
    except (OSError, ValueError, tarfile.TarError) as error:
        sys.exit(str(error))
