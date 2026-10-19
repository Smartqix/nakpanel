#!/usr/bin/env python3
"""Private, reboot-persistent artifacts for disposable qualification guests."""
import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import uuid

ROOT = Path('/var/lib/nakpanel-qualification')


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024*1024), b''):
            value.update(block)
    return value.hexdigest()


def run_root(token, root=ROOT):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{5,63}', token):
        raise ValueError('unsafe qualification token')
    return Path(root)/token


def owned_directory(path, owner_uid, create=False):
    path = Path(path)
    if create and not path.exists() and not path.is_symlink():
        path.mkdir(mode=0o700, parents=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError(f'{path}: requires an owned private directory without symlinks')


def owned_file(path, owner_uid):
    info = Path(path).lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or info.st_mode & 0o022:
        raise ValueError(f'{path}: requires an owned regular file without writable sharing')


def seal_input(source, destination, expected_sha, expected_size=None, limit=4*1024**3):
    if not re.fullmatch(r'[a-f0-9]{64}',expected_sha):
        raise ValueError('host SHA256 is required before reading a transferred input')
    fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size>limit:
            raise ValueError('transferred input must be a bounded regular file')
        size=info.st_size if expected_size is None else expected_size
        if size<0 or size>limit or info.st_size!=size:
            raise ValueError('transferred input size differs from frozen host input')
        sha=hashlib.sha256()
        with os.fdopen(fd,'rb') as input_file:
            fd=None
            with Path(destination).open('xb') as output:
                os.chmod(destination,0o600)
                remaining=size
                while remaining:
                    block=input_file.read(min(1024*1024,remaining))
                    if not block:raise ValueError('transferred input was truncated during sealing')
                    sha.update(block);output.write(block);remaining-=len(block)
                if input_file.read(1):raise ValueError('transferred input grew during sealing')
        if sha.hexdigest()!=expected_sha:
            raise ValueError('transferred input differs from frozen host SHA256')
        return Path(destination)
    finally:
        if fd is not None:os.close(fd)


def extract_regular_archive(archive, destination):
    with tarfile.open(archive) as payload:
        seen = set()
        for member in payload:
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):
                raise ValueError('qualification archive contains an unsafe entry')
            name = path.as_posix()
            if name in ('', '.'):
                continue
            if name in seen:
                raise ValueError('qualification archive contains a duplicate entry')
            seen.add(name)
            target = destination/name
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with payload.extractfile(member) as source, target.open('xb') as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)


def stage_source(token, archive, archive_sha, archive_size, root=ROOT, owner_uid=0):
    parent = run_root(token, root)
    owned_directory(root, owner_uid, create=True)
    owned_directory(parent, owner_uid, create=True)
    staging = Path(tempfile.mkdtemp(prefix='.source-', dir=parent))
    try:
        sealed=seal_input(archive,staging/'source.tar',archive_sha,archive_size)
        extracted=staging/'source';extracted.mkdir(mode=0o700)
        extract_regular_archive(sealed, extracted)
        source = parent/'source'
        if source.exists() or source.is_symlink():
            owned_directory(source, owner_uid)
            source.rename(parent/('source.previous-'+uuid.uuid4().hex))
        extracted.rename(source)
        return source
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def stage_public_probe(token, name, expected_sha, root=ROOT,
                       public_root=Path('/run/nakpanel-qualification-probes'), owner_uid=0):
    parent = run_root(token, root)
    if name not in ('roundcube-dr-canary.php', 'webhook_sink.py'):
        raise ValueError('only the reviewed public qualification probes may be exposed')
    for private in (root,parent,parent/'source'):
        owned_directory(private,owner_uid)
    source = parent/'source/deploy/multipass'/name
    owned_file(source,owner_uid)
    data=source.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_sha:
        raise ValueError('guest probe differs from the exact frozen host source')
    for directory in (Path(public_root),Path(public_root)/token):
        if not directory.exists() and not directory.is_symlink():
            directory.mkdir(mode=0o755,parents=True)
        info=directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != 0o755:
            raise ValueError('public probe directory must be owned and read-only to other users')
    target=Path(public_root)/token/name
    if target.exists() or target.is_symlink():owned_file(target,owner_uid)
    fd,temporary=tempfile.mkstemp(prefix='.probe-',dir=target.parent)
    try:
        with os.fdopen(fd,'wb') as output:output.write(data)
        os.chmod(temporary,0o644)
        os.replace(temporary,target)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)
    return target


def verify(release, key, verifier, version, architecture, allow_development):
    args = ['python3', str(verifier), '--bundle', str(release), '--public-key', str(key), '--version', version, '--architecture', architecture]
    if allow_development:
        args.append('--allow-development')
    subprocess.run(args, check=True)


def assert_staged(token, verifier, version, architecture, manifest_sha, key_sha,
                  allow_development=False, root=ROOT, owner_uid=0):
    parent = run_root(token, root)
    owned_directory(root, owner_uid)
    owned_directory(parent, owner_uid)
    release, key = parent/'release', parent/'public.pem'
    owned_directory(release, owner_uid)
    owned_file(key, owner_uid)
    owned_file(release/'manifest.json', owner_uid)
    if digest(key) != key_sha or digest(release/'manifest.json') != manifest_sha:
        raise ValueError('guest release does not match the exact selected manifest and trust anchor')
    verify(release, key, verifier, version, architecture, allow_development)
    return release


def assert_installed(installed_prefix=Path('/usr/local/bin'), **options):
    release=assert_staged(**options)
    result={}
    for artifact,name in [('panel','nakpanel-panel'),('agent','nakpanel-agent'),('panelctl','panelctl')]:
        installed=Path(installed_prefix)/name
        owned_file(installed,options.get('owner_uid',0))
        expected=digest(release/'bin'/artifact)
        if digest(installed)!=expected:
            raise ValueError('installed artifact differs from the exact selected signed release: '+name)
        result[str(installed)]=expected
    return result


def stage(token, archive, archive_sha, archive_size, public_key, verifier, version, architecture, manifest_sha,
          key_sha, allow_development=False, root=ROOT, owner_uid=0):
    parent = run_root(token, root)  # Validate before any filesystem mutation.
    owned_directory(root, owner_uid, create=True)
    owned_directory(parent, owner_uid, create=True)
    staging = Path(tempfile.mkdtemp(prefix='.release-', dir=parent))
    try:
        release, key = staging/'release', staging/'public.pem'
        release.mkdir(mode=0o700)
        seal_input(public_key,key,key_sha,limit=65536)
        sealed=seal_input(archive,staging/'release.tar',archive_sha,archive_size)
        extract_regular_archive(sealed, release)
        if digest(release/'manifest.json') != manifest_sha:
            raise ValueError('staged manifest differs from exact selected host release')
        verify(release, key, verifier, version, architecture, allow_development)
        previous = parent/'release'
        if previous.exists() or previous.is_symlink():
            owned_directory(previous, owner_uid)
            previous.rename(parent/('release.previous-'+uuid.uuid4().hex))
        os.replace(key, parent/'public.pem')
        os.replace(release, previous)
        return assert_staged(token, verifier, version, architecture, manifest_sha, key_sha,
                             allow_development, root, owner_uid)
    finally:
        shutil.rmtree(staging)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=('source', 'probe', 'stage', 'check', 'installed'))
    parser.add_argument('--token', required=True)
    parser.add_argument('--version')
    parser.add_argument('--architecture', choices=('amd64','arm64'))
    parser.add_argument('--manifest-sha')
    parser.add_argument('--key-sha')
    parser.add_argument('--allow-development', action='store_true')
    parser.add_argument('--archive')
    parser.add_argument('--archive-sha')
    parser.add_argument('--archive-size',type=int)
    parser.add_argument('--public-key')
    parser.add_argument('--name')
    parser.add_argument('--sha')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('guest artifact operations require root')
    if args.operation == 'source':
        if not args.archive or not args.archive_sha or args.archive_size is None:parser.error('source staging requires exact host archive identity')
        stage_source(args.token,args.archive,args.archive_sha,args.archive_size)
        return
    if args.operation == 'probe':
        if not args.name or not re.fullmatch(r'[a-f0-9]{64}',args.sha or ''):parser.error('probe requires an exact name and SHA256')
        print(stage_public_probe(args.token,args.name,args.sha))
        return
    if not args.version or not args.architecture or not all(re.fullmatch(r'[a-f0-9]{64}', item or '') for item in (args.manifest_sha,args.key_sha)):
        parser.error('exact SHA256 values are required')
    source = run_root(args.token)/'source'
    owned_directory(ROOT, 0)
    owned_directory(source.parent, 0)
    owned_directory(source, 0)
    verifier = source/'deploy/release/verify.py'
    owned_file(verifier, 0)
    options = dict(token=args.token, verifier=verifier, version=args.version,
                   architecture=args.architecture, manifest_sha=args.manifest_sha,
                   key_sha=args.key_sha, allow_development=args.allow_development)
    if args.operation == 'stage':
        if not args.archive or not args.public_key or not args.archive_sha or args.archive_size is None:
            parser.error('staging requires exact host archive identity and public key')
        stage(archive=args.archive,archive_sha=args.archive_sha,archive_size=args.archive_size,public_key=args.public_key, **options)
    elif args.operation == 'check':
        assert_staged(**options)
    else:
        for path,sha in assert_installed(**options).items():print(sha+'  '+path)


if __name__ == '__main__':
    main()
