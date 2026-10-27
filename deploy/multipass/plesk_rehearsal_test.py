"""Local checks for the bounded R0/R1 rehearsal harness."""
import copy
import importlib.util
import json
import os
import subprocess
import struct
import shutil
import zlib
import tempfile
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

HERE = Path(__file__).resolve().parent


def verifier():
    path = HERE / "plesk-rehearsal-verify.py"
    if not path.is_file():
        raise AssertionError("R0/R1 hosted rehearsal verifier is missing")
    spec = importlib.util.spec_from_file_location("plesk_rehearsal", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RehearsalTests(unittest.TestCase):
    def setUp(self):
        self.m = verifier()
        self.inventory = json.loads((HERE.parents[1] / "docs/migration/fixtures/plesk-customers.synthetic.json").read_text())

    def test_only_three_supported_dummy_customers_selected(self):
        cases = self.m.validate_inventory(self.inventory)
        self.assertEqual([(case["id"], case["source_php"]) for case in cases], [("S01", "8.3"), ("S02", "8.4"), ("S03", "8.5")])

    def test_rehearsal_plan_allows_the_declared_child_mail_workload(self):
        drill = self.m.Drill.__new__(self.m.Drill)
        drill.token = "p2-123-1"
        drill.cases = []
        drill.records = []
        calls = []
        drill.api = lambda path, fields: calls.append((path, fields))
        drill.stage = drill.containment = drill.passed = lambda *args: None
        drill.db = lambda *args: "1"
        drill.provision()
        path, fields = calls[0]
        self.assertEqual(path, "/plans")
        for resource in ("max_sites", "max_subdomains", "max_databases", "max_mailboxes", "max_backups"):
            self.assertGreaterEqual(fields.get(resource, 0), 1, resource)
        for permission in ("hosting_enabled", "allow_mail", "allow_dns", "allow_backups", "allow_scheduled_tasks"):
            self.assertEqual(fields[permission], "true", permission)
        self.assertEqual(fields["php_allowlist"], "8.3,8.4,8.5")

    def test_unsupported_platform_runtime_and_real_data_rejected(self):
        for field, value in (("os", "Ubuntu 24.04 LTS"), ("hosting_php", ["8.5"]), ("php_provider", "native")):
            data = copy.deepcopy(self.inventory)
            data["target_contract"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.m.validate_inventory(data)
        data = copy.deepcopy(self.inventory)
        data["real_customers_assessed"] = 1
        with self.assertRaises(ValueError):
            self.m.validate_inventory(data)
        data = copy.deepcopy(self.inventory)
        data["cases"][0]["source_php"] = "8.2"
        with self.assertRaises(ValueError):
            self.m.validate_inventory(data)

    def test_duplicate_identity_and_unreserved_domain_rejected(self):
        for key, value in (("id", "S02"), ("domain", "nakpanel.com"), ("customer_ref", "DEMO-C02")):
            data = copy.deepcopy(self.inventory)
            data["cases"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.m.validate_inventory(data)

    def test_containment_denies_new_traffic_without_silent_network_waits(self):
        _, rules = self.m.firewall_rules("p2-123-1", "52:54:00:aa:bb:cc", "mpqemubr0")
        self.assertEqual(rules.count("counter reject with icmpx type admin-prohibited"), 3)
        self.assertIn("meta l4proto tcp ct direction reply ct state established,related accept", rules)
        self.assertIn("udp sport 68 udp dport 67 accept", rules)
        self.assertNotIn("counter drop", rules)

    def test_dns_deny_counter_does_not_count_unrelated_packets(self):
        drill = self.m.Drill.__new__(self.m.Drill)
        drill.table = "p2_123_1"
        rules = {"nftables": [{"rule": {"comment": "nakpanel-rehearsal-dns-deny", "expr": [{"counter": {"packets": 2}}]}}, {"rule": {"expr": [{"counter": {"packets": 1000}}]}}]}
        drill.cmd = lambda *args: json.dumps(rules)
        self.assertEqual(drill.denial_count(dns_only=True), 2)
        self.assertEqual(drill.denial_count(), 1002)

    def test_firewall_rejects_unowned_or_injected_identifiers(self):
        for token, mac, bridge in (("other-run", "52:54:00:aa:bb:cc", "mpqemubr0"), ("p2-123-1", "bad; flush ruleset", "mpqemubr0"), ("p2-123-1", "52:54:00:aa:bb:cc", "eth0\nflush ruleset")):
            with self.subTest(token=token, mac=mac, bridge=bridge), self.assertRaises(ValueError):
                self.m.firewall_rules(token, mac, bridge)

    def test_manifest_checks_bytes_permissions_links_and_mapped_owner(self):
        expected = {"file.txt": {"type": "file", "sha256": "a"*64, "mode": 0o640}, "link.txt": {"type": "link", "target": "file.txt", "mode": 0o777}}
        observed = {name: dict(value, uid=1004) for name, value in expected.items()}
        self.m.verify_manifest(expected, observed, 1004)
        for name, field, value in (("file.txt", "sha256", "b"*64), ("file.txt", "mode", 0o666), ("file.txt", "uid", 0), ("link.txt", "target", "../outside")):
            wrong = copy.deepcopy(observed)
            wrong[name][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.m.verify_manifest(expected, wrong, 1004)
        with self.assertRaises(ValueError):
            self.m.verify_manifest(expected, {}, 1004)

    def test_failure_diagnostics_redact_fixture_secrets_and_private_keys(self):
        secret = "P2_private_fixture_value"
        raw = secret + "\n-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n"
        output = self.m.redact(raw, [secret])
        self.assertNotIn(secret, output)
        self.assertNotIn("abc", output)

    def test_import_link_emits_symbolic_sftp_operation(self):
        drill = self.m.Drill.__new__(self.m.Drill)
        commands = []
        drill.sftp = lambda record, batch: commands.append(batch)
        drill.import_symlink({})
        self.assertEqual(commands, ["ln -s files/content.txt content-link.txt\npwd\nls\n"])

    def test_private_bootstrap_file_rejects_symlink_and_public_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "password"
            path.write_text("SyntheticPrivatePassword!123\n")
            path.chmod(0o600)
            self.assertEqual(self.m.read_admin_password(path), "SyntheticPrivatePassword!123")
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                self.m.read_admin_password(path)
            path.chmod(0o600)
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                self.m.read_admin_password(link)

    def test_current_stalwart_paths_and_sql_content_preservation(self):
        path = HERE / "plesk-rehearsal-guest.py"
        spec = importlib.util.spec_from_file_location("plesk_guest_tests", path)
        guest = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guest)
        self.assertEqual(guest.service_certificate_path("%{file:/etc/stalwart/server.crt}%"), Path("/etc/stalwart/server.crt"))
        for value in ("%{file:/etc/stalwart/server.crt}", "%{file:/tmp/arbitrary}%", "/etc/stalwart/server.crt"):
            with self.assertRaises(ValueError):
                guest.service_certificate_path(value)
        with self.assertRaises(ValueError):
            guest.verify_sql_export("INSERT INTO records VALUES(1,'expected');", "INSERT INTO records VALUES(1,'changed');")
        guest.verify_sql_export("INSERT INTO records VALUES(1,'expected');", "INSERT INTO records VALUES(1,'expected');")

    def test_imported_cron_uses_site_relative_php_task(self):
        drill = self.m.Drill.__new__(self.m.Drill)
        calls = []
        drill.api = lambda path, fields: calls.append((path, fields))
        drill.create_cron({"sub": 4, "site": 2, "root": "/home/nps4/domains/atlas-studio.test/public_html"})
        path, fields = calls[0]
        self.assertEqual(path, "/subscriptions/4/scheduled-tasks")
        self.assertEqual(fields["working_directory"], ".")
        self.assertEqual((fields["kind"], fields["script"]), ("php", "cron.php"))
        self.assertNotIn("/home/", json.dumps(fields))

    def test_run_now_sends_a_csrf_authenticated_post(self):
        drill = self.m.Drill.__new__(self.m.Drill)
        drill.records = [{}, {"sub": 4, "uid": 1004, "source_php": "8.4"}]
        drill.state = {}
        drill.secret_values = []
        drill.db = lambda *args: json.dumps({"id": 7, "status": "succeeded", "exit_code": 0, "output": ""})
        drill.task = 9
        response = Mock()
        response.code = 202
        response.read.return_value = b"{}"
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response
        http = self.m.TrustedHTTP.__new__(self.m.TrustedHTTP)
        http.base = "https://panel.rehearsal.test"
        http.cookies = [SimpleNamespace(name="nakpanel_session", value="synthetic-session")]
        http.opener = opener
        drill.http = http
        drill.until = lambda *args: None
        drill.helper = lambda *args: {"uid": 1004, "php": "8.4", "marker": "R1-CRON", "runs": 1}
        drill.run_cron()
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.full_url, "https://panel.rehearsal.test/subscriptions/4/scheduled-tasks/9/run")
        self.assertTrue(request.has_header("X-nakpanel-csrf"))

    def test_negative_dns_covers_provider_name_and_search_suffixes_only(self):
        spec = importlib.util.spec_from_file_location("guest_dns_tests", HERE / "plesk-rehearsal-guest.py")
        guest = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guest)
        self.assertEqual(guest.sandbox_negative_zones(["multipass", "ci.example"]), ["telemetry.sury.org", "telemetry.sury.org.multipass", "telemetry.sury.org.ci.example"])
        for invalid in ('x"; include "/tmp/evil', "../outside", "", "*"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                guest.sandbox_negative_zones([invalid])

    def test_cron_canary_proves_each_fresh_execution(self):
        php = shutil.which("php")
        if php is None:
            self.skipTest("local PHP unavailable; native rehearsal is authoritative")
        spec = importlib.util.spec_from_file_location("guest_cron_tests", HERE / "plesk-rehearsal-guest.py")
        guest = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guest)
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "cron.php"
            script.write_text(guest.CRON)
            for expected in (1, 2):
                subprocess.run([php, str(script)], check=True, capture_output=True)
                result = json.loads((Path(directory) / "cron-result.json").read_text())
                self.assertEqual(result["runs"], expected)
                self.assertEqual(result["uid"], os.getuid())

    def test_wordpress_media_canary_is_a_valid_nonempty_png(self):
        spec = importlib.util.spec_from_file_location("guest_media_tests", HERE / "plesk-rehearsal-guest.py")
        guest = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guest)
        data = guest.MEDIA_PNG
        self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
        offset = 8
        chunks = {}
        while offset < len(data):
            length = struct.unpack("!I", data[offset:offset+4])[0]
            payload = data[offset+4:offset+8+length]
            checksum = struct.unpack("!I", data[offset+8+length:offset+12+length])[0]
            self.assertEqual(zlib.crc32(payload) & 0xffffffff, checksum, payload[:4])
            chunks[payload[:4]] = payload[4:]
            offset += 12 + length
        self.assertEqual(struct.unpack("!II", chunks[b"IHDR"][:8]), (1, 1))
        self.assertGreater(len(zlib.decompress(chunks[b"IDAT"])), 1)

    def test_site_leaf_is_single_certificate_and_validates_against_fixture_ca(self):
        spec = importlib.util.spec_from_file_location("guest_certificate_tests", HERE / "plesk-rehearsal-guest.py")
        guest = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guest)
        with tempfile.TemporaryDirectory() as directory:
            fixture = guest.Fixture.__new__(guest.Fixture)
            fixture.base = Path(directory)
            ca = fixture.base / "fixture-ca"
            ca.mkdir()
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca / "root.key"), "-out", str(ca / "root.crt"), "-days", "1", "-subj", "/CN=Synthetic test CA"], check=True, capture_output=True)
            leaf, _ = fixture.cert("harbor-cafe.test", "DNS:harbor-cafe.test", fixture.base / "S01", full_chain=False)
            self.assertEqual(leaf.read_text().count("-----BEGIN CERTIFICATE-----"), 1)
            subprocess.run(["openssl", "verify", "-CAfile", str(ca / "root.crt"), "-verify_hostname", "harbor-cafe.test", str(leaf)], check=True, capture_output=True)

    def test_directory_permissions_and_owner_are_in_manifest(self):
        path = HERE / "plesk-rehearsal-guest.py"
        spec = importlib.util.spec_from_file_location("plesk_guest_manifest_tests", path)
        guest = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guest)
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / "private"
            private.mkdir(mode=0o750)
            manifest = guest.file_manifest(Path(directory), True)
            self.assertEqual(manifest["private"], {"type": "directory", "mode": 0o750, "uid": os.getuid()})


if __name__ == "__main__":
    unittest.main()
