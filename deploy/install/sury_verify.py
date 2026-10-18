#!/usr/bin/env python3
"""Pinned Sury public-key and authenticated Release policy; never installs PHP."""
import hashlib
import io
from pathlib import Path
import sys
import tarfile

FINGERPRINT='15058500A0235D97F5D10063B188E2B695BD4743'
KEY_SHA256='b486fd5488185c4c46467960fa69c53d5085fec492cf76b9eaf3db33561c9d7c'
KEYRING_DEB_SHA256='7511384559c9ddf1d5ce5f60be429ae9d4e7d01d9480d6f1b7a30c0810cf8b60'


def key_fingerprint(data):
    if hashlib.sha256(data).hexdigest()!=KEY_SHA256:
        raise ValueError('Sury public key SHA256 pin mismatch')
    offset=0;primaries=[]
    while offset<len(data):
        header=data[offset];offset+=1
        if header&0x80==0:raise ValueError('invalid OpenPGP packet')
        if header&0x40:
            tag=header&63;first=data[offset];offset+=1
            if first<192:length=first
            elif first<224:length=((first-192)<<8)+data[offset]+192;offset+=1
            elif first==255:length=int.from_bytes(data[offset:offset+4],'big');offset+=4
            else:raise ValueError('partial key packets unsupported')
        else:
            tag=(header>>2)&15;kind=header&3
            if kind==3:raise ValueError('indeterminate key packet unsupported')
            size=(1,2,4)[kind];length=int.from_bytes(data[offset:offset+size],'big');offset+=size
        payload=data[offset:offset+length];offset+=length
        if len(payload)!=length:raise ValueError('truncated key packet')
        if tag==6:
            if not payload or payload[0]!=4 or length>65535:raise ValueError('requires pinned v4 primary key')
            primaries.append(hashlib.sha1(b'\x99'+length.to_bytes(2,'big')+payload).hexdigest().upper())
    if primaries!=[FINGERPRINT]:raise ValueError('Sury primary fingerprint mismatch')
    return FINGERPRINT


def extract_key(deb):
    if hashlib.sha256(deb).hexdigest()!=KEYRING_DEB_SHA256:raise ValueError('official Sury keyring .deb SHA256 pin mismatch')
    if not deb.startswith(b'!<arch>\n'):raise ValueError('invalid keyring Debian archive')
    offset=8
    while offset<len(deb):
        header=deb[offset:offset+60];length=int(header[48:58]);name=header[:16].decode().strip().rstrip('/')
        body=deb[offset+60:offset+60+length];offset+=60+length+(length%2)
        if name=='data.tar.xz':
            with tarfile.open(fileobj=io.BytesIO(body),mode='r:xz') as archive:
                member=archive.getmember('./usr/share/keyrings/deb.sury.org-php.gpg')
                if not member.isfile():raise ValueError('keyring member is not regular')
                key=archive.extractfile(member).read()
                key_fingerprint(key);return key
    raise ValueError('PHP-specific key missing from official keyring .deb')


def release_fields(text, architecture):
    if text.startswith('-----BEGIN PGP SIGNED MESSAGE-----\n'):
        if text.count('\n-----BEGIN PGP SIGNATURE-----\n')!=1 or not text.rstrip().endswith('-----END PGP SIGNATURE-----'):
            raise ValueError('invalid clearsigned Release framing')
        text=text.split('\n\n',1)[1].split('\n-----BEGIN PGP SIGNATURE-----\n',1)[0]
        text='\n'.join(line[2:] if line.startswith('- ') else line for line in text.splitlines())
    fields={}
    for line in text.splitlines():
        if line.startswith((' ','\t')) or not line:continue
        if ': ' not in line and not line.endswith(':'):raise ValueError('invalid Release field')
        key,value=line.split(':',1)
        if key in fields:raise ValueError('duplicate Release field: '+key)
        fields[key]=value.strip()
    if fields.get('Origin')!='deb.sury.org' or fields.get('Suite')!='resolute' or fields.get('Codename')!='resolute':
        raise ValueError('Sury Release origin/suite/codename mismatch')
    if architecture not in ('amd64','arm64') or architecture not in fields.get('Architectures','').split():
        raise ValueError('Sury Release does not support host architecture')
    return fields


def signature_status(text):
    bad=('BADSIG','ERRSIG','EXPSIG','EXPKEYSIG','REVKEYSIG')
    if any(line.startswith('[GNUPG:] '+status+' ') for line in text.splitlines() for status in bad):
        raise ValueError('Sury signature expired/revoked/invalid')
    matches=[line.split() for line in text.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
    if not matches or any(len(fields)<12 or fields[-1]!=FINGERPRINT for fields in matches):
        raise ValueError('Sury signature primary fingerprint mismatch')


def host_identity(text):
    fields={}
    for line in text.splitlines():
        if not line or line.lstrip().startswith('#') or '=' not in line:continue
        key,value=line.split('=',1)
        if key not in ('ID','VERSION_ID','VERSION_CODENAME'):continue
        if key in fields:raise ValueError('duplicate OS identity field')
        if len(value)>=2 and value[0] in ("'",'"') and value[-1]==value[0]:value=value[1:-1]
        fields[key]=value
    if (fields.get('ID'),fields.get('VERSION_ID'),fields.get('VERSION_CODENAME'))!=('ubuntu','26.04','resolute'):
        raise ValueError('Sury profile requires actual Ubuntu 26.04 Resolute')


def main():
    command=sys.argv[1];path=Path(sys.argv[2])
    if command=='identity':host_identity(path.read_text());print('verified Ubuntu 26.04 Resolute identity')
    elif command=='key':print(key_fingerprint(path.read_bytes()))
    elif command=='extract-key':Path(sys.argv[3]).write_bytes(extract_key(path.read_bytes()))
    elif command=='release':release_fields(path.read_text(),sys.argv[3]);print('verified Sury Release policy')
    elif command=='status':signature_status(path.read_text());print('verified Sury signature primary pin')
    else:raise ValueError('unknown Sury verification command')

if __name__=='__main__':
    try:main()
    except (OSError,ValueError,IndexError,KeyError,tarfile.TarError) as error:
        print('Sury verification failed: '+str(error),file=sys.stderr);sys.exit(1)
