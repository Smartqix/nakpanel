import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

PACKAGE = Path(__file__).with_name('php') / 'package.py'

class PrivatePHPPackage(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stage = self.root/'stage'
        for name in ('bin/php','sbin/php-fpm','lib/extensions/redis.so','etc/cli/php.ini','etc/fpm/php.ini'):
            path=self.stage/'opt/nakpanel/php/8.3'/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text('package payload')
        self.evidence=self.root/'evidence';self.evidence.mkdir()
        for name in ('provenance.json','sbom.spdx.json','sources.lock.json','build-dependencies.txt'):
            (self.evidence/name).write_text('{}')
        self.deps=self.root/'deps';self.deps.write_text('libc6 (>= 2.38), libssl3t64 (>= 3.0)')

    def package(self,*extra):
        return subprocess.run(['python3',str(PACKAGE),'--stage',str(self.stage),'--minor','8.3','--version','8.3.35','--architecture','arm64','--dependencies',str(self.deps),'--evidence',str(self.evidence),'--output',str(self.root/'out'),*extra],capture_output=True,text=True)

    def members(self):
        data=next((self.root/'out').glob('*.deb')).read_bytes()
        self.assertEqual(data[:8],b'!<arch>\n')
        found={};pos=8
        while pos<len(data):
            header=data[pos:pos+60];size=int(header[48:58]);name=header[:16].decode().strip().rstrip('/')
            found[name]=data[pos+60:pos+60+size];pos+=60+size+(size%2)
        return found

    def test_emits_real_deb_with_private_paths_metadata_dependencies_and_guard(self):
        result=self.package();self.assertEqual(result.returncode,0,result.stderr)
        members=self.members();self.assertEqual(members['debian-binary'],b'2.0\n')
        with tarfile.open(fileobj=io.BytesIO(members['control.tar.gz'])) as control:
            metadata=control.extractfile('./control').read().decode()
            self.assertIn('Package: nakpanel-php83\n',metadata)
            self.assertIn('Architecture: arm64\n',metadata)
            self.assertIn('Depends: libc6 (>= 2.38), libssl3t64 (>= 3.0)',metadata)
            guard=control.extractfile('./prerm').read().decode()
            # Execute guard below as a real shell program; text here only locates it.
        guard_path=self.root/'prerm';guard_path.write_text(guard);guard_path.chmod(0o755)
        # Missing authoritative panelctl must fail closed, even on a fresh machine.
        self.assertNotEqual(subprocess.run([str(guard_path),'remove'],capture_output=True).returncode,0)
        self.assertEqual(subprocess.run([str(guard_path),'upgrade','8.3.36-1'],capture_output=True).returncode,0)
        with tarfile.open(fileobj=io.BytesIO(members['data.tar.gz'])) as data:
            paths=data.getnames()
            self.assertIn('./opt/nakpanel/php/8.3/bin/php',paths)
            self.assertIn('./usr/share/doc/nakpanel-php83/provenance.json',paths)
            self.assertFalse(any(p.startswith('./usr/bin/php') or p.startswith('./etc/php') for p in paths))

    def test_accepts_native_zlib_dependency_without_allowing_other_providers(self):
        self.deps.write_text('libc6 (>= 2.38), zlib1g (>= 1:1.2.0)')
        result=self.package();self.assertEqual(result.returncode,0,result.stderr)

    def test_preserves_upstream_private_phar_symlink(self):
        binary=self.stage/'opt/nakpanel/php/8.3/bin/phar.phar'
        binary.write_text('private phar executable')
        (binary.parent/'phar').symlink_to('phar.phar')
        result=self.package();self.assertEqual(result.returncode,0,result.stderr)
        with tarfile.open(fileobj=io.BytesIO(self.members()['data.tar.gz'])) as data:
            link=data.getmember('./opt/nakpanel/php/8.3/bin/phar')
            self.assertTrue(link.issym());self.assertEqual(link.linkname,'phar.phar')

    def test_rejects_global_overwrite_and_symlink_payload(self):
        for linked in (False,True):
            with self.subTest(linked=linked):
                if linked:
                    path=self.stage/'opt/nakpanel/php/8.3/escape';path.symlink_to('/etc/passwd')
                else:
                    path=self.stage/'usr/bin/php';path.parent.mkdir(parents=True);path.write_text('global overwrite')
                self.assertNotEqual(self.package().returncode,0)
                path.unlink()

    def test_rejects_cross_version_payload_and_unknown_dependencies(self):
        path=self.stage/'opt/nakpanel/php/8.4/bin/php';path.parent.mkdir(parents=True);path.write_text('wrong version')
        self.assertNotEqual(self.package().returncode,0)
        path.unlink()
        self.deps.write_text('php8.3, plesk-php83')
        self.assertNotEqual(self.package().returncode,0)

if __name__=='__main__':unittest.main()
