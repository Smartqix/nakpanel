#!/usr/bin/env python3
"""Fetch pinned upstream sources; PHP additionally requires a trusted keyring."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import subprocess
import sys
import urllib.request


def has_allowed_signer(status, fingerprints):
    for line in status.splitlines():
        fields=line.split()
        if len(fields)>=12 and fields[:2]==['[GNUPG:]','VALIDSIG']:
            # GnuPG's final VALIDSIG field is the primary key fingerprint,
            # including when a signing subkey created the signature.
            primary=fields[-1]
            if re.fullmatch(r'[0-9A-F]{40}',primary) and primary in fingerprints:
                return True
    return False


def fetch(entry, output):
    target=output / entry['url'].rsplit('/',1)[-1]
    if not target.exists():
        with urllib.request.urlopen(entry['url'],timeout=120) as response:
            target.write_bytes(response.read())
    if hashlib.sha256(target.read_bytes()).hexdigest()!=entry['sha256']:
        raise ValueError('upstream SHA256 mismatch: '+str(target))
    return target


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--minor',choices=('8.3','8.4'),required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--php-keyring',type=Path,required=True,help='out-of-band verified PHP release signer keyring')
    args=parser.parse_args()
    try:
        lock=json.loads(Path(__file__).with_name('sources.lock.json').read_text())
        args.output.mkdir(parents=True,exist_ok=True)
        php=lock['php'][args.minor];target=fetch(php,args.output)
        signature=target.with_suffix(target.suffix+'.asc')
        with urllib.request.urlopen(php['signature_url'],timeout=120) as response:
            signature.write_bytes(response.read())
        status=subprocess.run(['gpgv','--status-fd','1','--keyring',str(args.php_keyring.resolve()),str(signature),str(target)],check=True,capture_output=True,text=True)
        if not has_allowed_signer(status.stdout,php['signer_fingerprints']):raise ValueError('upstream PHP signature did not use a branch-pinned release signer')
        (args.output/'php-signature-status.txt').write_text(status.stdout)
        for extension in lock['extensions'].values():fetch(extension,args.output)
    except (ValueError,OSError,subprocess.CalledProcessError) as error:
        print('source verification failed: '+str(error),file=sys.stderr);return 1
    return 0

if __name__=='__main__':sys.exit(main())
