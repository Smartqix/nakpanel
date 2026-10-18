"""Behavioral release policy tests; fixtures are independently constructed."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('verify', Path(__file__).with_name('verify.py'))

class ReleaseVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        cls.private = Path(cls.keys.name) / 'private.pem'
        cls.public = Path(cls.keys.name) / 'public.pem'
        subprocess.run(['openssl', 'genrsa', '-out', str(cls.private), '2048'], check=True, capture_output=True)
        subprocess.run(['openssl', 'rsa', '-in', str(cls.private), '-pubout', '-out', str(cls.public)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.files = {'VERSION': b'1.2.3\n', 'Makefile': b'goose-up:\n', 'go.mod': b'module example\n', 'go.sum': b'checksums\n', 'deploy/install/install.sh': b'#!/bin/sh\n', 'migrations/00001.sql': b'-- migration\n'}
        # A minimal, independently encoded ELF64 executable with a load segment.
        for name in ('panel', 'agent', 'panelctl'):
            self.files['bin/' + name] = self.elf()
        self.manifest = dict(schema_version=1, version='1.2.3', commit='a'*40,
                             go_toolchain='go1.26.9', cgo_enabled=False, os='linux',
                             architecture='amd64', cpu_baseline='v1', files={})

    def elf(self, machine=62, segment=1):
        ident = b'\x7fELF\x02\x01\x01' + b'\0'*9
        header = struct.pack('<16sHHIQQQIHHHHHH', ident, 2, machine, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        return header + struct.pack('<IIQQQQQQ', segment, 5, 0, 0, 0, 120, 120, 4096)

    def seal(self):
        for name, data in self.files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.manifest['files'] = {k: hashlib.sha256(v).hexdigest() for k,v in self.files.items()}
        (self.root/'manifest.json').write_text(json.dumps(self.manifest))
        subprocess.run(['openssl','dgst','-sha256','-sign',str(self.private),'-out',str(self.root/'manifest.sig'),str(self.root/'manifest.json')], check=True, capture_output=True)

    def run_verify(self, *extra):
        return subprocess.run(['python3', str(Path(__file__).with_name('verify.py')), '--bundle', str(self.root), '--public-key',str(self.public), '--version','1.2.3','--architecture','amd64',*extra], capture_output=True, text=True)

    def test_accepts_signed_static_matching_bundle(self):
        self.seal()
        result = self.run_verify()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_tampered_file_before_install(self):
        self.seal()
        (self.root/'bin/panel').write_bytes(b'changed')
        self.assertNotEqual(self.run_verify().returncode, 0)

    def test_rejects_modified_manifest_signature(self):
        self.seal()
        (self.root/'manifest.json').write_text('{}')
        self.assertNotEqual(self.run_verify().returncode, 0)

    def test_rejects_unlisted_files_and_links(self):
        for linked in (False, True):
            with self.subTest(linked=linked):
                self.seal()
                path = self.root/'extra'
                if linked:
                    path.symlink_to('/etc/passwd')
                else:
                    path.write_text('untrusted')
                self.assertNotEqual(self.run_verify().returncode, 0)
                path.unlink()

    def test_rejects_wrong_version_architecture_and_cpu(self):
        for key, value in [('version','1.2.2'),('architecture','arm64'),('cpu_baseline','v3'),('cgo_enabled',True),('os','darwin')]:
            with self.subTest(key=key):
                old = self.manifest[key]
                self.manifest[key] = value
                self.seal()
                self.assertNotEqual(self.run_verify().returncode, 0)
                self.manifest[key] = old

    def test_rejects_loader_dynamic_dependencies_and_wrong_elf_arch(self):
        for data in (self.elf(segment=3),self.elf(segment=2),self.elf(machine=183),b'not ELF'):
            with self.subTest(data=data[:20]):
                self.files['bin/panel'] = data
                self.seal()
                self.assertNotEqual(self.run_verify().returncode, 0)

    def test_rejects_missing_migrations_and_version_mismatch(self):
        del self.files['migrations/00001.sql']
        self.seal()
        self.assertNotEqual(self.run_verify().returncode, 0)
        self.files['migrations/00001.sql'] = b'sql'
        self.files['VERSION'] = b'9.9.9'
        self.seal()
        self.assertNotEqual(self.run_verify().returncode, 0)

    def test_rejects_development_bundle_without_explicit_override(self):
        self.manifest['development'] = True
        self.seal()
        self.assertNotEqual(self.run_verify().returncode, 0)
        self.assertEqual(self.run_verify('--allow-development').returncode, 0)

    def test_rejects_traversal_in_signed_manifest(self):
        self.seal()
        self.manifest['files']['../escape'] = '0'*64
        (self.root/'manifest.json').write_text(json.dumps(self.manifest))
        subprocess.run(['openssl','dgst','-sha256','-sign',str(self.private),'-out',str(self.root/'manifest.sig'),str(self.root/'manifest.json')], check=True,capture_output=True)
        self.assertNotEqual(self.run_verify().returncode, 0)

if __name__ == '__main__':
    unittest.main()
