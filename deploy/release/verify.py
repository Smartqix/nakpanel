#!/usr/bin/env python3
"""Fail-closed local release-bundle verification. Requires Python 3 and OpenSSL.

The public key is an out-of-band trust anchor: never use a key from the bundle.
The caller must retain ownership of the verified, non-writable staging directory
until installation completes (verification alone cannot prevent a later write).
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys

BINARIES = ('bin/panel', 'bin/agent', 'bin/panelctl')
REQUIRED = (*BINARIES, 'VERSION', 'go.mod', 'go.sum', 'Makefile', 'deploy/install/install.sh')


def inspect_elf(path, architecture):
    data = Path(path).read_bytes()
    if len(data) < 64 or data[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError(f'{path}: requires little-endian ELF64')
    fields = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    _, kind, machine, version, _, offset, _, _, size, entry_size, count, _, _, _ = fields
    if kind not in (2, 3) or machine != {'amd64': 62, 'arm64': 183}[architecture] or version != 1 or size != 64:
        raise ValueError(f'{path}: incompatible executable ELF architecture/header')
    if not count or count == 65535 or entry_size != 56 or offset < 64 or offset + count * entry_size > len(data):
        raise ValueError(f'{path}: invalid ELF program headers')
    for index in range(count):
        segment = struct.unpack_from('<IIQQQQQQ', data, offset + index * entry_size)
        if segment[0] in (2, 3):  # PT_DYNAMIC / PT_INTERP
            raise ValueError(f'{path}: dynamic segment/loader forbidden in static release')
        if segment[2] + segment[5] > len(data):
            raise ValueError(f'{path}: truncated ELF segment')
    return {'architecture': architecture, 'interpreter': None, 'dynamic_dependencies': []}


def _regular(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError(f'{path}: must be a regular file, never a symlink')


def _json_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON key: {key}')
        result[key] = value
    return result


def verify_bundle(root, public_key, version, architecture, allow_development=False):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('bundle must be a real staging directory')
    for name in ('manifest.json', 'manifest.sig'):
        _regular(root / name)
    subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(public_key), '-signature', str(root / 'manifest.sig'), str(root / 'manifest.json')], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    manifest = json.loads((root / 'manifest.json').read_text(), object_pairs_hook=_json_no_duplicates)
    if manifest.get('schema_version') != 1 or manifest.get('version') != version:
        raise ValueError('manifest schema/application version mismatch')
    if manifest.get('development', False) is not False and not allow_development:
        raise ValueError('development bundle is not a production release')
    baseline = {'amd64': 'v1', 'arm64': 'v8.0'}[architecture]
    if manifest.get('architecture') != architecture or manifest.get('cpu_baseline') != baseline or manifest.get('os') != 'linux' or manifest.get('cgo_enabled') is not False:
        raise ValueError('manifest OS/architecture/CPU/static policy mismatch')
    if not re.fullmatch(r'[0-9a-f]{40,64}', manifest.get('commit', '')) or not re.fullmatch(r'go1\.\d+\.\d+', manifest.get('go_toolchain', '')):
        raise ValueError('manifest commit/toolchain missing or malformed')
    files = manifest.get('files')
    if not isinstance(files, dict) or not all(name in files for name in REQUIRED) or not any(name.startswith('migrations/') and name.endswith('.sql') for name in files):
        raise ValueError('manifest missing binaries/install/build/migration assets')
    for name, digest in files.items():
        path = PurePosixPath(name)
        if not name or path.is_absolute() or '..' in path.parts or str(path) != name or '\\' in name or name in ('manifest.json', 'manifest.sig'):
            raise ValueError('unsafe manifest path')
        if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError(f'{name}: invalid SHA256 digest')
    observed = set()
    for directory, subdirs, names in os.walk(root, followlinks=False):
        for name in subdirs:
            if (Path(directory) / name).is_symlink():
                raise ValueError('bundle contains directory symlink')
        for name in names:
            path = Path(directory) / name
            _regular(path)
            relative = path.relative_to(root).as_posix()
            if relative in ('manifest.json', 'manifest.sig'):
                continue
            observed.add(relative)
            if relative not in files or hashlib.sha256(path.read_bytes()).hexdigest() != files[relative]:
                raise ValueError(f'{relative}: unlisted or SHA256 mismatch')
    if observed != set(files):
        raise ValueError('manifest file set does not match staged files')
    if (root / 'VERSION').read_text().strip() != version:
        raise ValueError('VERSION asset does not match manifest')
    for binary in BINARIES:
        inspect_elf(root / binary, architecture)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--public-key', type=Path)
    parser.add_argument('--version')
    parser.add_argument('--architecture', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--allow-development', action='store_true', help='test-only opt-in for a dirty build; never use in production')
    parser.add_argument('--elf', type=Path, help='inspect one ELF; does not verify a bundle')
    args = parser.parse_args()
    try:
        if args.elf:
            print(json.dumps(inspect_elf(args.elf, args.architecture), sort_keys=True))
        else:
            if not args.bundle or not args.public_key or not args.version:
                parser.error('--bundle, --public-key and --version are required')
            result = verify_bundle(args.bundle, args.public_key, args.version, args.architecture, args.allow_development)
            print(f"verified {result['version']} linux/{result['architecture']} {result['commit']}")
    except (OSError, ValueError, KeyError, TypeError, struct.error, subprocess.CalledProcessError) as error:
        print(f'release verification failed: {error}', file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
