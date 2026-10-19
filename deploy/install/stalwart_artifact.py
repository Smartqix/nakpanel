#!/usr/bin/env python3
"""Pinned v0.11.8 GNU Stalwart archive validation; no downloaded code executes."""
import argparse
import hashlib
import io
import os
from pathlib import Path
import stat
import struct
import sys
import tarfile

ASSETS = {
    'amd64': {'target': 'x86_64', 'size': 28160752, 'machine': 62,
              'sha256': '17ace571b012ff0228b276e09c83f28114824596279f86234f7a55e3773ad7df'},
    'arm64': {'target': 'aarch64', 'size': 26412751, 'machine': 183,
              'sha256': '1e85521e44f1347336ad90235fa18c701616798bd2837d2dfdd6e9f082fcde3d'},
}


def private_stage(path):
    info = Path(path).lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('Stalwart staging directory must be private and owned by current user')


def validate(path, architecture):
    asset = ASSETS[architecture]
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size != asset['size']:
            raise ValueError('Stalwart archive type/size differs from pinned release')
        data = stream.read(asset['size'] + 1)
    if len(data) != asset['size'] or hashlib.sha256(data).hexdigest() != asset['sha256']:
        raise ValueError('Stalwart archive SHA256 differs from pinned release')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        members = archive.getmembers()
        if (len(members) != 1 or members[0].name != 'stalwart-mail'
                or members[0].type not in (tarfile.REGTYPE, tarfile.AREGTYPE)):
            raise ValueError('Stalwart archive must contain only the regular stalwart-mail binary')
        if not 64 <= members[0].size <= 150000000:
            raise ValueError('Stalwart binary size is invalid')
        binary = archive.extractfile(members[0]).read()
    if (binary[:7] != b'\x7fELF\x02\x01\x01' or binary[7] not in (0, 3)
            or struct.unpack_from('<H', binary, 18)[0] != asset['machine']):
        raise ValueError('Stalwart ELF architecture differs from host')
    return binary


def extract(path, architecture, destination):
    binary = validate(path, architecture)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(binary)
        stream.flush()
        os.fchmod(stream.fileno(), 0o755)
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('stage', 'url', 'verify', 'extract'))
    parser.add_argument('path')
    parser.add_argument('architecture', choices=ASSETS, nargs='?')
    parser.add_argument('destination', nargs='?')
    args = parser.parse_args()
    if args.command == 'stage':
        private_stage(args.path)
    elif args.command == 'url':
        if args.path not in ASSETS:
            raise ValueError('unsupported Stalwart architecture')
        print('https://github.com/stalwartlabs/stalwart/releases/download/v0.11.8/'
              'stalwart-mail-' + ASSETS[args.path]['target'] + '-unknown-linux-gnu.tar.gz')
    elif args.command == 'verify':
        validate(args.path, args.architecture)
    elif args.command == 'extract':
        if not args.destination:
            raise ValueError('extract requires destination')
        extract(args.path, args.architecture, args.destination)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, tarfile.TarError, struct.error) as error:
        sys.exit('Stalwart verification failed: ' + str(error))
