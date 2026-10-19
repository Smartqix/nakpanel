#!/usr/bin/env python3
"""Retain nonsecret administrator intent across interrupted native bootstrap."""
import json
import os
from pathlib import Path
import stat
import sys
from platform_state import atomic_write

RELATIVE_PATH=Path('etc/nakpanel/native-admin-required.json')


def normalize(email):
    email=email.strip().lower()
    if email and ('@' not in email or len(email)>320 or any(char.isspace() for char in email)):
        raise ValueError('invalid required administrator identity')
    return email


def record(root,email):
    email=normalize(email)
    if email:
        atomic_write(root/RELATIVE_PATH,json.dumps({'email':email})+'\n',0o600)


def resolve(root,provided,owner=0):
    provided=normalize(provided)
    path=root/RELATIVE_PATH
    try:info=path.lstat()
    except FileNotFoundError:return provided
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=owner or info.st_mode&0o077:
        raise ValueError('required administrator intent must be a private root-owned regular file')
    required=normalize(json.loads(path.read_text())['email'])
    if not required or (provided and provided!=required):
        raise ValueError('administrator differs from interrupted installation; supply the original administrator and password file')
    return required


def clear(root,owner=0):
    resolve(root,'',owner=owner)
    try:(root/RELATIVE_PATH).unlink()
    except FileNotFoundError:pass


if __name__=='__main__':
    try:
        if os.geteuid()!=0:raise ValueError('administrator intent requires root')
        command=sys.argv[1]
        if command=='record':record(Path('/'),sys.argv[2])
        elif command=='resolve':print(resolve(Path('/'),sys.argv[2]))
        elif command=='clear':clear(Path('/'))
        else:raise ValueError('unknown administrator intent operation')
    except (OSError,ValueError,KeyError,IndexError) as error:
        sys.exit('platform: '+str(error))
