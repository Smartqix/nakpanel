#!/usr/bin/env python3
"""Copy unverified files to private staging; verify the sealed copy before use."""
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile


def stage_bundle(source):
    source = Path(source)
    if source.is_symlink() or not source.is_dir():
        raise ValueError("bundle source must be a real directory")
    destination = Path(tempfile.mkdtemp(prefix="nakpanel-bundle-"))
    os.chmod(destination, 0o700)
    try:
        for directory, subdirs, names in os.walk(source, followlinks=False):
            root = Path(directory)
            target = destination / root.relative_to(source)
            for name in subdirs:
                path = root / name
                if not stat.S_ISDIR(path.lstat().st_mode):
                    raise ValueError("bundle directory links are forbidden")
                (target / name).mkdir(mode=0o755)
            for name in names:
                path = root / name
                if not stat.S_ISREG(path.lstat().st_mode):
                    raise ValueError("bundle members must be regular files")
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as original:
                    info = os.fstat(original.fileno())
                    if not stat.S_ISREG(info.st_mode):
                        raise ValueError("bundle member changed during staging")
                    with open(target / name, "xb") as copied:
                        shutil.copyfileobj(original, copied, 1024 * 1024)
                    os.chmod(target / name, 0o755 if info.st_mode & 0o111 else 0o644)
        return destination
    except BaseException:
        shutil.rmtree(destination)
        raise


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("usage: stage_bundle.py SOURCE")
        print(stage_bundle(sys.argv[1]))
    except (OSError, ValueError) as error:
        sys.exit("bundle staging: " + str(error))
