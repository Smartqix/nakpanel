#!/usr/bin/env python3
"""Create a private Debian package without modifying the build host."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import tarfile


def archive(files, epoch):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT) as tar:
        directories={'.'}
        for name,_,_ in files:
            directories.update(str(parent) for parent in Path(name).parents if str(parent)!='.')
        for directory in sorted(directories,key=lambda value:(value.count('/'),value)):
            entry=tarfile.TarInfo('./' if directory=='.' else './'+directory+'/')
            entry.type=tarfile.DIRTYPE;entry.mode=0o755;entry.uid=entry.gid=0
            entry.uname=entry.gname='root';entry.mtime=epoch;tar.addfile(entry)
        for name,data,mode in sorted(files):
            entry=tarfile.TarInfo('./'+name);entry.mode=mode
            entry.uid=entry.gid=0;entry.uname=entry.gname='root';entry.mtime=epoch
            if isinstance(data,str):
                entry.type=tarfile.SYMTYPE;entry.linkname=data;tar.addfile(entry)
            else:
                entry.size=len(data);tar.addfile(entry,io.BytesIO(data))
    return gzip.compress(stream.getvalue(),mtime=epoch)


def ar(members,epoch):
    result=b'!<arch>\n'
    for name,data in members:
        header=f'{name+"/":<16}{epoch:<12}{0:<6}{0:<6}{"100644":<8}{len(data):<10}`\n'.encode()
        result+=header+data+(b'\n' if len(data)%2 else b'')
    return result


def package(args):
    if args.minor not in ('8.3','8.4') or not re.fullmatch(re.escape(args.minor)+r'\.\d+',args.version):
        raise ValueError('unsupported PHP package version')
    prefix='opt/nakpanel/php/'+args.minor+'/'
    payload=[]
    for path in args.stage.rglob('*'):
        if not path.is_file() and not path.is_symlink():continue
        name=path.relative_to(args.stage).as_posix()
        if not name.startswith(prefix):raise ValueError('payload outside private version prefix')
        if path.is_symlink():
            target=os.readlink(path)
            private=(args.stage/prefix).resolve()
            if Path(target).is_absolute() or not path.resolve().is_relative_to(private) or not path.resolve().is_file():
                raise ValueError('package link must resolve to a private regular file')
            payload.append((name,target,0o777))
        else:
            payload.append((name,path.read_bytes(),path.stat().st_mode&0o777))
    names={f[0] for f in payload}
    if not all(prefix+x in names for x in ('bin/php','sbin/php-fpm','etc/cli/php.ini','etc/fpm/php.ini')):
        raise ValueError('private runtime incomplete')
    dependencies=args.dependencies.read_text().strip()
    # Dependencies are produced by native dpkg-shlibdeps. Restrict to library
    # packages, never a second PHP provider, replacement libc, or alternatives.
    if not dependencies or not re.fullmatch(r'(?:lib[a-z0-9.+-]+|zlib1g)(?: \((?:>=|=) [A-Za-z0-9.+:~\-]+\))?(?:, (?:lib[a-z0-9.+-]+|zlib1g)(?: \((?:>=|=) [A-Za-z0-9.+:~\-]+\))?)*',dependencies):
        raise ValueError('invalid native library dependency inventory')
    name='nakpanel-php'+args.minor.replace('.','')
    for required in ('provenance.json','sbom.spdx.json','sources.lock.json','build-dependencies.txt'):
        path=args.evidence/required
        if not path.is_file() or path.is_symlink():raise ValueError('missing source/SBOM/provenance evidence')
    for path in sorted(args.evidence.rglob('*')):
        if path.is_symlink():raise ValueError('symlink provenance evidence forbidden')
        if path.is_file():payload.append(('usr/share/doc/'+name+'/'+path.relative_to(args.evidence).as_posix(),path.read_bytes(),0o644))
    control=f'''Package: {name}
Version: {args.version}-1nakpanel1~resolute
Section: web
Priority: optional
Architecture: {args.architecture}
Maintainer: Nakpanel Release Engineering <releases@nakpanel.invalid>
Depends: {dependencies}
Description: Private Nakpanel PHP {args.minor} CLI/FPM runtime
 Isolated runtime rooted at /opt/nakpanel/php/{args.minor}.
 Qualification and security-update ownership must be established before rollout.
'''
    # An absent CLI, a database failure or ANY ambiguous output blocks removal.
    # Upgrade/deconfigure/failed-upgrade must remain usable for dpkg recovery.
    prerm='''#!/bin/sh
set -eu
case "${1:-}" in
  remove)
    [ -x /usr/local/bin/panelctl ] || { echo 'runtime usage checker unavailable' >&2; exit 1; }
    result="$(/usr/local/bin/panelctl runtime-provider-in-use --provider nakpanel --php-version VERSION)" || { echo 'runtime usage check failed' >&2; exit 1; }
    [ "$result" = unused ] || { echo 'PHP runtime remains in use; migrate sites and internal tools first' >&2; exit 1; }
    ;;
  upgrade|deconfigure|failed-upgrade) ;;
  *) echo 'unknown package removal action' >&2; exit 1 ;;
esac
'''.replace('VERSION',args.minor)
    conffiles=''.join('/'+x+'\n' for x,_,_ in payload if x.startswith(prefix+'etc/'))
    md5sums=''.join(hashlib.md5(data).hexdigest()+'  '+path+'\n' for path,data,_ in payload if isinstance(data,bytes)) # Debian metadata; release integrity uses SHA256/signatures.
    controls=[('control',control.encode(),0o644),('prerm',prerm.encode(),0o755),('conffiles',conffiles.encode(),0o644),('md5sums',md5sums.encode(),0o644)]
    data=ar([('debian-binary',b'2.0\n'),('control.tar.gz',archive(controls,args.epoch)),('data.tar.gz',archive(payload,args.epoch))],args.epoch)
    args.output.mkdir(parents=True,exist_ok=True)
    output=args.output/f'{name}_{args.version}-1nakpanel1~resolute_{args.architecture}.deb'
    if output.exists():raise ValueError('refusing to replace existing package')
    output.write_bytes(data)
    output.with_suffix('.deb.sha256').write_text(hashlib.sha256(data).hexdigest()+'  '+output.name+'\n')
    print(output)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for field in ('stage','dependencies','evidence','output'):parser.add_argument('--'+field,type=Path,required=True)
    parser.add_argument('--minor',required=True);parser.add_argument('--version',required=True)
    parser.add_argument('--architecture',choices=('amd64','arm64'),required=True)
    parser.add_argument('--epoch',type=int,default=1790208000)
    args=parser.parse_args()
    try:package(args)
    except (ValueError,OSError,tarfile.TarError) as error:
        print('private PHP packaging failed: '+str(error),file=sys.stderr);return 1
    return 0

if __name__=='__main__':sys.exit(main())
