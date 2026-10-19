import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile
import tempfile
import unittest


class QualificationArtifacts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).with_name('qualification_artifacts.py')
        spec = importlib.util.spec_from_file_location('qualification_artifacts', path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        cls.keys = tempfile.TemporaryDirectory()
        cls.private = Path(cls.keys.name) / 'private.pem'
        cls.key = Path(cls.keys.name) / 'public.pem'
        subprocess.run(['openssl', 'genrsa', '-out', str(cls.private), '2048'], check=True, capture_output=True)
        subprocess.run(['openssl', 'rsa', '-in', str(cls.private), '-pubout', '-out', str(cls.key)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.guest = self.root / 'var/lib/nakpanel-qualification'
        self.volatile = self.root / 'tmp'
        self.volatile.mkdir()
        self.bundle = self.root / 'bundle'
        self.bundle.mkdir()
        ident = b'\x7fELF\x02\x01\x01' + b'\0' * 9
        elf = struct.pack('<16sHHIQQQIHHHHHH', ident, 2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0) + struct.pack('<IIQQQQQQ', 1, 5, 0, 0, 0, 120, 120, 4096)
        files = {'VERSION': b'1.2.3\n', 'go.mod': b'module example\n', 'go.sum': b'fixture\n', 'Makefile': b'goose-up:\n', 'migrations/00001.sql': b'-- fixture\n', 'deploy/install/install.sh': b'#!/bin/sh\n'}
        files.update({'bin/' + name: elf for name in ['panel', 'agent', 'panelctl']})
        for name, data in files.items():
            path = self.bundle / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o755 if name.startswith('bin/') else 0o644)
        manifest = dict(schema_version=1,version='1.2.3',commit='a'*40,go_toolchain='go1.26.9',cgo_enabled=False,os='linux',architecture='amd64',cpu_baseline='v1',files={name:hashlib.sha256(data).hexdigest() for name,data in files.items()})
        (self.bundle/'manifest.json').write_text(json.dumps(manifest))
        subprocess.run(['openssl','dgst','-sha256','-sign',str(self.private),'-out',str(self.bundle/'manifest.sig'),str(self.bundle/'manifest.json')],check=True,capture_output=True)
        self.archive = self.volatile/'release.tar'
        with tarfile.open(self.archive, 'w') as archive:
            archive.add(self.bundle, arcname='.')
        self.archive_sha=self.module.digest(self.archive)
        self.archive_size=self.archive.stat().st_size
        self.verifier = Path(__file__).resolve().parents[1]/'release/verify.py'
        self.args = dict(token='test-run123', verifier=self.verifier, version='1.2.3', architecture='amd64', manifest_sha=self.module.digest(self.bundle/'manifest.json'), key_sha=self.module.digest(self.key), allow_development=False, root=self.guest, owner_uid=os.getuid())

    def stage(self):
        return self.module.stage(archive=self.archive, archive_sha=self.archive_sha, archive_size=self.archive_size, public_key=self.key, **self.args)

    def test_reboot_clears_tmp_but_staged_release_still_authenticates(self):
        self.stage()
        shutil.rmtree(self.volatile)
        self.module.assert_staged(**self.args)
        root = self.guest/'test-run123'
        self.assertEqual(root.stat().st_mode & 0o777, 0o700)
        self.assertTrue((root/'release/bin/panel').is_file())
        self.assertEqual((root/'public.pem').stat().st_mode & 0o777, 0o600)

    def test_missing_durable_artifact_rejects_before_use(self):
        self.stage()
        shutil.rmtree(self.guest/'test-run123/release')
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.module.assert_staged(**self.args)

    def test_payload_tampering_cannot_pass_a_reboot_check(self):
        self.stage()
        (self.guest/'test-run123/release/bin/panel').write_bytes(b'tampered')
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            self.module.assert_staged(**self.args)

    def test_selected_manifest_and_public_key_are_exact(self):
        self.stage()
        for field in ['manifest_sha', 'key_sha']:
            with self.subTest(field=field):
                args = dict(self.args, **{field:'0'*64})
                with self.assertRaises(ValueError):
                    self.module.assert_staged(**args)

    def test_untrusted_parent_or_symlink_is_rejected(self):
        self.stage()
        parent = self.guest/'test-run123'
        parent.chmod(0o777)
        with self.assertRaises(ValueError):
            self.module.assert_staged(**self.args)
        parent.chmod(0o700)
        release = parent/'release'
        release.rename(parent/'original')
        release.symlink_to(parent/'original', target_is_directory=True)
        with self.assertRaises(ValueError):
            self.module.assert_staged(**self.args)

    def test_unsafe_token_never_creates_a_directory(self):
        with self.assertRaises(ValueError):
            self.module.stage(archive=self.archive, archive_sha=self.archive_sha, archive_size=self.archive_size, public_key=self.key, **dict(self.args,token='../escape'))
        self.assertFalse(self.guest.exists())

    def test_archive_links_cannot_escape_private_staging(self):
        with tarfile.open(self.archive, 'w') as archive:
            entry=tarfile.TarInfo('payload');entry.type=tarfile.SYMTYPE;entry.linkname='/etc/passwd'
            archive.addfile(entry)
        with self.assertRaises(ValueError):
            self.stage()
        self.assertFalse((self.guest/'test-run123/release').exists())

    def test_frozen_source_survives_reboot_and_is_not_panel_writable(self):
        source=self.module.stage_source('test-run123',self.archive,self.archive_sha,self.archive_size,root=self.guest,owner_uid=os.getuid())
        shutil.rmtree(self.volatile)
        self.assertEqual(source,self.guest/'test-run123/source')
        self.assertTrue((source/'go.mod').is_file())
        for path in [self.guest,source.parent,source]:
            self.assertEqual(path.stat().st_mode & 0o777,0o700)

    def test_public_probe_is_exact_frozen_code_without_private_assets(self):
        source=self.module.stage_source('test-run123',self.archive,self.archive_sha,self.archive_size,root=self.guest,owner_uid=os.getuid())
        probe=source/'deploy/multipass/roundcube-dr-canary.php'
        probe.parent.mkdir(parents=True);probe.write_bytes(b'<?php echo "fixture";')
        expected=self.module.digest(probe)
        public=self.root/'run/probes'
        target=self.module.stage_public_probe('test-run123','roundcube-dr-canary.php',expected,root=self.guest,public_root=public,owner_uid=os.getuid())
        self.assertEqual(target.read_bytes(),b'<?php echo "fixture";')
        self.assertEqual(target.stat().st_mode & 0o777,0o644)
        self.assertEqual(sorted(p.name for p in target.parent.iterdir()),['roundcube-dr-canary.php'])
        with self.assertRaises(ValueError):
            self.module.stage_public_probe('test-run123','../../public.pem',expected,root=self.guest,public_root=public,owner_uid=os.getuid())
        with self.assertRaises(ValueError):
            self.module.stage_public_probe('test-run123','roundcube-dr-canary.php','0'*64,root=self.guest,public_root=public,owner_uid=os.getuid())

    def test_installed_inventory_must_match_the_selected_signed_binaries(self):
        self.stage()
        installed=self.root/'usr/local/bin';installed.mkdir(parents=True)
        for artifact,name in [('panel','nakpanel-panel'),('agent','nakpanel-agent'),('panelctl','panelctl')]:
            shutil.copyfile(self.bundle/'bin'/artifact,installed/name)
        self.module.assert_installed(installed_prefix=installed,**self.args)
        (installed/'nakpanel-agent').write_bytes(b'new unsigned build')
        with self.assertRaises(ValueError):
            self.module.assert_installed(installed_prefix=installed,**self.args)

    def test_source_never_reopens_guest_writable_archive_after_sealing(self):
        extract=self.module.extract_regular_archive
        def mutate_transfer_before_parse(archive,destination):
            self.archive.write_bytes(b'changed by transfer owner after private copy')
            return extract(archive,destination)
        self.module.extract_regular_archive=mutate_transfer_before_parse
        self.addCleanup(setattr,self.module,'extract_regular_archive',extract)
        source=self.module.stage_source('test-run123',self.archive,self.archive_sha,self.archive_size,root=self.guest,owner_uid=os.getuid())
        self.assertEqual((source/'go.mod').read_bytes(),b'module example\n')

    def test_guest_transfer_symlink_is_never_followed(self):
        alias=self.root/'archive-link';alias.symlink_to(self.archive)
        with self.assertRaises((ValueError,OSError)):
            self.module.stage_source('test-run123',alias,self.archive_sha,self.archive_size,root=self.guest,owner_uid=os.getuid())

    def test_modified_valid_source_tar_is_rejected_before_publication(self):
        with tarfile.open(self.archive) as archive:
            member=next(m for m in archive if Path(m.name).as_posix()=='go.mod')
        with self.archive.open('r+b') as transfer:
            transfer.seek(member.offset_data);transfer.write(b'module exploit\n')
        with self.assertRaises(ValueError):
            self.module.stage_source('test-run123',self.archive,self.archive_sha,self.archive_size,root=self.guest,owner_uid=os.getuid())
        self.assertFalse((self.guest/'test-run123/source').exists())

    def test_transfer_size_and_key_symlinks_are_rejected(self):
        with self.assertRaises(ValueError):
            self.module.stage_source('test-run123',self.archive,self.archive_sha,self.archive_size+1,root=self.guest,owner_uid=os.getuid())
        alias=self.root/'key-link';alias.symlink_to(self.key)
        with self.assertRaises(OSError):
            self.module.stage(archive=self.archive,archive_sha=self.archive_sha,archive_size=self.archive_size,public_key=alias,**self.args)


if __name__ == '__main__':
    unittest.main()
