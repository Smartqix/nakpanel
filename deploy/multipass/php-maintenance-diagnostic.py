#!/usr/bin/env python3
"""Credential-free package reproduction; no application/reboot qualification."""
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import urllib.request

sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('maintenance',Path(__file__).with_name('sury-maintenance-drill.py'))
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)


class DiagnosticBackend(M.GuestBackend):
    def record(self,step,data):
        super().record(step,data)
        print(json.dumps(dict(step=step,data=data)),flush=True)

    def reinstall(self,minor=None):
        result=super().reinstall(minor)
        print(json.dumps(dict(minor=minor,returncode=result.returncode,archives=sorted(p.name for p in self.cache.glob('*.deb')))),flush=True)
        return result


def main(token):
    M.require(re.fullmatch(r'php-diag-[0-9]+-[0-9]+',token) is not None,'unsafe diagnostic token')
    M.require(os.geteuid()==0,'diagnostic requires root in an owned disposable guest')
    M.require(M.root_regular('/etc/nakpanel-qualification-owner').decode().strip()==token,'diagnostic owner differs')
    M.require(M.command(['systemd-detect-virt','--vm']).stdout.strip()=='kvm','disposable KVM guest required')
    M.require(M.command(['dpkg','--print-architecture']).stdout.strip()=='amd64','AMD64 diagnostic required')
    M.command([sys.executable,str(Path(__file__).parents[1]/'install/sury_verify.py'),'identity','/etc/os-release'])
    M.require(not Path('/etc/nakpanel/platform.json').exists(),'package diagnostic refuses installed application')
    root=Path('/var/lib/nakpanel-qualification')/token/'package-diagnostic';root.mkdir(mode=0o700)
    packages=[]
    for name,(version,status) in sorted(M.package_inventory().items()):
        name=name.removesuffix(':amd64')
        if not M.PHP_NAME.fullmatch(name):continue
        M.require(status=='install ok installed','preexisting package state differs')
        rows=list(M.deb822(M.command(['apt-cache','show',name+'='+version]).stdout.encode()))
        rows=[r for r in rows if r.get('Version')==version and r.get('Architecture') in ('amd64','all') and 'SHA256' in r and 'Filename' in r]
        M.require(len(rows)==1,'exact authenticated APT package row required')
        row={k:rows[0][k] for k in ('Package','Version','Architecture','Filename','SHA256','Size')}
        M.require(re.fullmatch(r'pool/[A-Za-z0-9_+./~%-]+\.deb',row['Filename']) and '..' not in Path(row['Filename']).parts,'unsafe provider filename')
        with urllib.request.urlopen('https://packages.sury.org/php/'+row['Filename'],timeout=30) as response:data=response.read(16*2**20)
        M.require(len(data)==int(row['Size']) and M.digest(data)==row['SHA256'],'authenticated package bytes differ')
        M.write_private(root/Path(row['Filename']).name,data);packages.append(row)
    backend=DiagnosticBackend(root,dict(architecture='amd64',maintenance_id=token),packages)
    try:
        backend.prepare()
        M.require(backend.reinstall().returncode==0,'initial same-version delivery failed')
        for minor in M.MINORS:
            print('DIAGNOSTIC_MINOR='+minor,flush=True)
            M.drill_minor(minor,token,Path('/etc/php')/minor/'fpm/pool.d',backend,backend.record)
        print(json.dumps(dict(schema='nakpanel-php-package-diagnostic-v1',status='PASS',product_qualified=False,reboots_verified=False)),flush=True)
    finally:
        for minor in M.MINORS:
            for args in (['systemctl','show','php'+minor+'-fpm.service','--property=Result,ActiveState,ExecMainStatus,NRestarts'],['journalctl','-b','--no-pager','-n','40','-u','php'+minor+'-fpm.service']):
                result=M.command(args,check=False);print(result.stdout,result.stderr,flush=True)


if __name__=='__main__':
    main(sys.argv[1])
