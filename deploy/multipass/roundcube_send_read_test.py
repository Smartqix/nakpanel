import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


HERE = Path(__file__).resolve().parent
PASSWORD = "PrivateFixture!2026"
MAILBOX = "phase29@example.test"


class RoundcubeServer:
    def __init__(self, mode="ready"):
        self.mode = mode
        self.sends = []
        self.reads = 0
        self.requests = []
        self.subject = None
        self.body = None
        self.probes = 0
        state = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def reply(self, code, body="", location=None, cookie=None):
                self.send_response(code)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                if location:
                    self.send_header("Location", location)
                if cookie:
                    self.send_header("Set-Cookie", cookie)
                self.end_headers()
                try:
                    self.wfile.write(body.encode())
                except BrokenPipeError:
                    pass

            def do_GET(self):
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                action = query.get("_action", [""])[0]
                task = query.get("_task", [""])[0]
                state.requests.append(("GET", task, action))
                if task == "login":
                    if state.mode == "login-hung":
                        time.sleep(2)
                    token = "" if state.mode == "login-csrf" else '<input name="_token" value="login-csrf">'
                    return self.reply(200, '<form method="post">' + token + '</form>', cookie="roundcube_sessid=private-session; Path=/")
                if "private-session" not in self.headers.get("Cookie", ""):
                    return self.reply(403)
                if action == "compose":
                    if "_id" not in query:
                        location = "https://outside.invalid/steal" if state.mode == "compose-redirect" else "./?_task=mail&_action=compose&_id=compose123"
                        if state.mode == "compose-loop":
                            location = "./?_task=mail&_action=compose"
                        return self.reply(302, location=location)
                    token = "" if state.mode == "compose-csrf" else '<input type="hidden" name="_token" value="compose-csrf">'
                    return self.reply(200, '<form method="post" action="./?_task=mail">' + token + '<input name="_task" value="mail"><input name="_action" value="send"><input name="_id" value="compose123"><select name="_from"><option value="7">phase29@example.test</option></select><textarea name="_message"></textarea></form>')
                if action == "show":
                    state.reads += 1
                    if query.get("_uid") != ["41"] or query.get("_mbox") != ["INBOX"]:
                        return self.reply(400)
                    if state.mode == "render-timeout":
                        return self.reply(200, "<html>not ready</html>")
                    body = "wrong body" if state.mode == "body-mismatch" else state.body
                    return self.reply(200, '<html><div id="messagebody"><div class="message-part"><pre>' + body + '</pre></div></div></html>')
                return self.reply(200, '<html>authenticated mailbox</html>')

            def do_POST(self):
                data = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
                form = urllib.parse.parse_qs(data, keep_blank_values=True)
                action = form.get("_action", [""])[0]
                state.requests.append(("POST", form.get("_task", [""])[0], action))
                if action == "login":
                    if form.get("_token") != ["login-csrf"] or form.get("_user") != [MAILBOX] or form.get("_pass") != [PASSWORD]:
                        return self.reply(403)
                    location = "https://outside.invalid/steal" if state.mode == "login-redirect" else "./?_task=mail"
                    return self.reply(302, location=location)
                if action == "send":
                    state.sends.append(form)
                    if form.get("_token") != ["compose-csrf"] or form.get("_id") != ["compose123"] or form.get("_from") != ["7"] or form.get("_to") != [MAILBOX] or form.get("_cc", [""]) != [""] or form.get("_bcc", [""]) != [""] or form.get("_is_html") != ["0"]:
                        return self.reply(403)
                    state.subject = form["_subject"][0]
                    state.body = form["_message"][0]
                    if state.mode == "send-lost-response":
                        self.connection.shutdown(socket.SHUT_RDWR)
                        self.connection.close()
                        return
                    if state.mode == "send-hung":
                        time.sleep(2)
                    if state.mode == "send-rejected":
                        return self.reply(200, '<script>parent.rcmail.display_message("rejected","error");</script>')
                    if state.mode == "send-redirect":
                        return self.reply(307, location="./?_task=mail&_action=send")
                    return self.reply(200, '<script>if (window.parent && parent.rcmail) { parent.rcmail.sent_successfully("confirmation","Message sent",[],false); }</script>')
                return self.reply(400)

        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.url = "http://127.0.0.1:" + str(self.http.server_port)

    def close(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join()

    def inbox(self, *_args, **_kwargs):
        state = self

        class Inbox:
            def find(self, subject):
                state.probes += 1
                if state.mode == "preexisting":
                    return {"uid": "40", "subject": subject, "message_id": "<old@example.test>"}
                if not state.sends or subject != state.subject or state.mode == "delivery-timeout":
                    return None
                if state.mode == "duplicate":
                    raise self_error("duplicate-delivery")
                return {"uid": "41", "message_id": "<server-generated-41@example.test>", "subject": subject, "self_recipient_verified": True}

            def close(self):
                pass

        self_error = load_helper().QualificationError
        return Inbox()


_module = None


def load_helper():
    global _module
    if _module is None:
        spec = importlib.util.spec_from_file_location("roundcube_send_read", HERE / "roundcube-send-read.py")
        _module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_module)
    return _module


class RoundcubeQualificationTest(unittest.TestCase):
    def test_full_wrapper_boolean_guards_stop_before_later_operations_on_each_host_bash(self):
        # The system Bash may be 3.2 on macOS; qualified Bash5 is selected by
        # normal PATH. Test both real interpreters when they differ.
        interpreters = list(dict.fromkeys(os.path.realpath(path) for path in [shutil.which("bash"), "/bin/bash"] if path and Path(path).is_file()))
        cases = [("site", 1, 0, 0), ("mailbox", 1, 0, 0), ("domain", 1, 0, 0),
                 ("file-site", 1, 0, 0), ("file-mailbox", 1, 0, 0), ("http", 1, 0, 0),
                 ("pending", 1, 120, 0), ("active", 29, 1, 1)]
        for interpreter in interpreters:
            for mode, code, queries, flows in cases:
                with self.subTest(bash=interpreter, mode=mode), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    script = root / "internal-tools-verify.sh"
                    script.write_bytes((HERE / script.name).read_bytes())
                    (root / "common.sh").write_text('''NAKPANEL_MULTIPASS_VM=nakpanel-fixture123
NAKPANEL_MULTIPASS_IMAGE=26.04
assert_current_vm_identity(){ echo identity >>"$TRACE"; }
assert_qualification_bundle_staged(){ echo staged >>"$TRACE"; }
assert_qualification_installed_release(){ printf actual-private-proof; }
csrf_token(){ printf private-token; }
vm_ip(){ echo ip >>"$TRACE";echo 192.0.2.10; }
multipass_exec_short(){
 if [[ "$*" == *psql* ]];then
  echo query >>"$TRACE"
  if [[ "$MODE" == pending ]];then printf '';else printf active;fi
 else printf public-cert;fi
}
''')
                    programs = {
                        "curl": '''#!/bin/bash
set -eu
output=''
for ((i=1;i<=$#;i++));do if [[ "${!i}" == -o ]];then j=$((i+1));output="${!j}";fi;done
if [[ "$*" == *"/login"* ]];then
 echo login >>"$TRACE"
 printf '<html data-np-role="admin"></html>' >"$output"
else
 echo configure >>"$TRACE"
 printf private-response >"$output"
 if [[ "$MODE" == http ]];then printf 500;else printf 303;fi
fi
''',
                        "python3": '#!/bin/bash\necho flow >>"$TRACE"\nexit 29\n',
                        "sleep": '#!/bin/bash\nexit 0\n',
                    }
                    for name, body in programs.items():
                        path = root / name;path.write_text(body);path.chmod(0o700)
                    env = dict(os.environ, PATH=str(root) + ":" + os.environ["PATH"], MODE=mode, TRACE=str(root / "trace"),
                               NAKPANEL_RELEASE_BUNDLE=folder, NAKPANEL_RUN_TOKEN="fixture123", NAKPANEL_RELEASE_VERSION="29.0.0",
                               NAKPANEL_INTERNAL_TOOLS_RECEIPT=str(root / "result.json"), NAKPANEL_VERIFY_DATABASE_MANAGER="0",
                               NAKPANEL_INTERNAL_TOOLS_SITE_ID="not-an-id" if mode == "site" else "1",
                               NAKPANEL_INTERNAL_TOOLS_MAILBOX="invalid-private-mailbox" if mode == "mailbox" else "phase29@invalid/private-domain" if mode == "domain" else MAILBOX)
                    env.pop("NAKPANEL_CELL_REPORT_DIR", None)
                    if mode.startswith("file-"):
                        report = root / "report";report.mkdir(mode=0o700)
                        (report / "phase29-fixtures.tsv").write_text(("invalid-site" if mode == "file-site" else "1") + "\t" + ("invalid-private-mailbox" if mode == "file-mailbox" else MAILBOX) + "\n")
                        env["NAKPANEL_CELL_REPORT_DIR"] = str(report)
                    result = subprocess.run([interpreter, str(script)], env=env, capture_output=True, text=True, timeout=10)
                    calls = (root / "trace").read_text().splitlines() if (root / "trace").exists() else []
                    self.assertEqual(result.returncode, code, result.stderr)
                    self.assertEqual(calls.count("query"), queries)
                    self.assertEqual(calls.count("flow"), flows)
                    if mode in {"site", "mailbox", "domain", "file-site", "file-mailbox"}:self.assertEqual(calls, [], "malformed local fixture reached external operations")
                    if mode == "http":self.assertNotIn("query", calls)
                    self.assertNotIn("invalid-private-mailbox", result.stdout + result.stderr)

    def test_wrapper_stage_markers_identify_failure_without_exposing_private_inputs(self):
        cases = [("admin", "admin-login", 17), ("configure", "webmail-configure", 18),
                 ("readiness", "webmail-readiness", 19), ("flow", "roundcube-flow", 23),
                 ("enrich", "roundcube-enrich", 24), ("install", "database-manager-install", 25),
                 ("browser", "database-manager-browser", 26), ("ready", "complete", 0)]
        for mode, stage, code in cases:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                script = root / "internal-tools-verify.sh"
                script.write_bytes((HERE / script.name).read_bytes())
                (root / "common.sh").write_text('''NAKPANEL_MULTIPASS_VM=nakpanel-fixture123
NAKPANEL_MULTIPASS_IMAGE=26.04
assert_current_vm_identity(){ :; }
assert_qualification_bundle_staged(){ :; }
assert_qualification_installed_release(){ printf actual-private-proof; }
csrf_token(){ printf PRIVATE_CSRF_SENTINEL; }
vm_ip(){ echo 192.0.2.10; }
multipass_exec_short(){
 if [[ "$*" == *psql* ]];then
  echo readiness >>"$TRACE"
  if [[ "$MODE" == readiness ]];then return 19;else echo active;fi
 else printf public-cert;fi
}
''')
                programs = {
                    "curl": '''#!/bin/bash
set -eu
output=''
for ((i=1;i<=$#;i++));do if [[ "${!i}" == -o ]];then j=$((i+1));output="${!j}";fi;done
if [[ "$*" == *"/login"* ]];then
 echo admin >>"$TRACE"
 [[ "$MODE" != admin ]] || exit 17
 printf '<html data-np-role="admin">PRIVATE_RESPONSE_SENTINEL</html>' >"$output"
else
 echo configure >>"$TRACE"
 printf PRIVATE_RESPONSE_SENTINEL >"$output"
 if [[ "$MODE" == configure ]];then exit 18;else printf 303;fi
fi
''',
                    "python3": '''#!/bin/bash
set -eu
if [[ "$2" == enrich ]];then
 echo enrich >>"$TRACE";[[ "$MODE" != enrich ]] || exit 24
else
 echo flow >>"$TRACE";[[ "$MODE" != flow ]] || exit 23
fi
''',
                    "multipass": '#!/bin/bash\ncat >/dev/null\necho install >>"$TRACE"\n[[ "$MODE" != install ]] || exit 25\n',
                    "node": '#!/bin/bash\necho browser >>"$TRACE"\n[[ "$MODE" != browser ]] || exit 26\n',
                    "sleep": '#!/bin/bash\nexit 0\n',
                }
                for name, body in programs.items():
                    path = root / name
                    path.write_text(body)
                    path.chmod(0o700)
                env = dict(os.environ, PATH=str(root) + ":" + os.environ["PATH"], MODE=mode,
                           TRACE=str(root / "trace"), NAKPANEL_RELEASE_BUNDLE=folder, NAKPANEL_RUN_TOKEN="fixture123",
                           NAKPANEL_INTERNAL_TOOLS_RECEIPT=str(root / "result.json"), NAKPANEL_RELEASE_VERSION="29.0.0",
                           NAKPANEL_INTERNAL_TOOLS_SITE_ID="1", NAKPANEL_INTERNAL_TOOLS_MAILBOX=MAILBOX,
                           NAKPANEL_INTERNAL_TOOLS_PASSWORD="PRIVATE_PASSWORD_SENTINEL", NAKPANEL_VERIFY_DATABASE_MANAGER="1",
                           NAKPANEL_REMOTE_SRC=folder, NAKPANEL_MULTIPASS_ARCH="amd64",
                           NAKPANEL_QUALIFICATION_PROFILE="ubuntu-26.04-native", NAKPANEL_QUALIFICATION_PHP_PROVIDER="native")
                env.pop("NAKPANEL_CELL_REPORT_DIR", None)
                result = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, code, result.stderr + (root / "trace").read_text())
                self.assertIn("internal-tools stage=" + stage + "\n", result.stdout)
                self.assertIn("internal-tools exit=" + str(code) + " stage=" + stage, result.stdout)
                for secret in ("PRIVATE_PASSWORD_SENTINEL", "PRIVATE_CSRF_SENTINEL", "PRIVATE_RESPONSE_SENTINEL", MAILBOX):
                    self.assertNotIn(secret, result.stdout + result.stderr)
                calls = (root / "trace").read_text().splitlines()
                if mode in {"admin", "configure", "readiness"}:
                    self.assertNotIn("flow", calls)
                if mode not in {"install", "browser", "ready"}:
                    self.assertNotIn("install", calls)
                self.assertEqual(calls.count("flow"), int(mode not in {"admin", "configure", "readiness"}))

    def test_internal_tools_requires_workflow_after_login(self):
        text = (HERE / "internal-tools-verify.sh").read_text()
        block = text.split("# Login renders", 1)[1].split('\nif [[ "${NAKPANEL_VERIFY_DATABASE_MANAGER', 1)[0]
        block = "# Login renders" + block
        if "verify_roundcube_send_read() {" in text:
            function = text.split("verify_roundcube_send_read() {", 1)[1].split("\n}", 1)[0]
            block = "verify_roundcube_send_read() {" + function + "\n}\n" + block
        server = RoundcubeServer()
        self.addCleanup(server.close)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fake = root / "bin"
            fake.mkdir()
            shim = fake / "python3"
            shim.write_text('#!/bin/bash\nif [[ "$1" == */roundcube-send-read.py ]];then\n if [[ "$2" == enrich ]];then\n [[ "$*" == *"--before-proof"* && "$*" == *"--after-proof"* ]] || exit 72\n printf "enrich\\n" >>"$WORKFLOW_TRACE"\n else\n [[ "$*" == *"--password-file"* && "$*" == *"--receipt-dir"* ]] || exit 71\n printf "flow\\n" >>"$WORKFLOW_TRACE"\n fi\nelse\n exec ' + sys.executable + ' "$@"\nfi\n')
            shim.chmod(0o700)
            program = 'set -euo pipefail\ntmpdir="$TEST_TMP";VM_IP="$TEST_VM";VM_NAME=owned-test;domain=example.test;mailbox=' + MAILBOX + ';SCRIPT_DIR="$TEST_SCRIPT_DIR"\nassert_current_vm_identity(){ :; }\nassert_qualification_installed_release(){ :; }\nmultipass_exec_short(){ printf public-test-certificate; }\n' + block
            env = dict(os.environ, PATH=str(fake) + ":" + os.environ["PATH"], TEST_TMP=folder, TEST_VM=server.url.removeprefix("http://"), TEST_SCRIPT_DIR=str(HERE), WORKFLOW_TRACE=str(root / "workflow"), NAKPANEL_INTERNAL_TOOLS_PASSWORD=PASSWORD, NAKPANEL_RELEASE_BUNDLE=folder, NAKPANEL_RUN_TOKEN="fixture123", NAKPANEL_CELL_REPORT_DIR=str(root / "report"), IMAGE="26.04", NAKPANEL_MULTIPASS_ARCH="arm64", NAKPANEL_QUALIFICATION_PROFILE="ubuntu-26.04-native", NAKPANEL_QUALIFICATION_PHP_PROVIDER="native", NAKPANEL_RELEASE_VERSION="29.0.0")
            result = subprocess.run(["bash", "-c", program], env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / "workflow").exists(), "login-only acceptance omitted mandatory Roundcube compose/send/read")
            self.assertEqual((root / "workflow").read_text(), "flow\nenrich\n")

    def test_narrow_wrapper_runs_only_flow_and_publishes_after_both_runtime_proofs(self):
        for mode in ["ready", "before-failed", "after-failed", "flow-failed", "existing-output"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                script = root / "internal-tools-verify.sh"
                script.write_bytes((HERE / "internal-tools-verify.sh").read_bytes())
                (root / "common.sh").write_text('''NAKPANEL_MULTIPASS_VM=nakpanel-26-04-arm64-fixture123
NAKPANEL_MULTIPASS_IMAGE=26.04
NAKPANEL_MULTIPASS_ARCH=arm64
NAKPANEL_QUALIFICATION_PROFILE=ubuntu-26.04-native
NAKPANEL_QUALIFICATION_PHP_PROVIDER=native
assert_current_vm_identity(){ echo identity >>"$TRACE"; }
assert_qualification_bundle_staged(){ echo staged >>"$TRACE"; }
assert_qualification_installed_release(){
 local n;n=$(cat "$COUNT");n=$((n+1));printf '%s' "$n" >"$COUNT";echo proof$n >>"$TRACE"
 if [[ "$MODE" == before-failed && "$n" == 1 || "$MODE" == after-failed && "$n" == 2 ]];then return 74;fi
 printf 'actual-three-binary-proof\\n'
}
multipass_exec_short(){ echo cert >>"$TRACE";printf owned-public-cert; }
vm_ip(){ echo 192.0.2.10; }
''')
                (root / "python3").write_text('''#!/bin/bash
set -euo pipefail
if [[ "$2" != enrich ]];then
 echo flow >>"$TRACE"
 [[ "$MODE" != flow-failed ]] || exit 75
else
 echo enrich >>"$TRACE"
 [[ "$(cat "$COUNT")" == 2 ]] || exit 76
 while [[ "$1" != --output ]];do shift;done
 printf envelope >"$2"
fi
''')
                (root / "python3").chmod(0o700)
                (root / "curl").write_text('#!/bin/bash\necho unexpected-admin-or-config-call >>"$TRACE";exit 77\n')
                (root / "curl").chmod(0o700)
                output = root / "result.json"
                if mode == "existing-output": output.write_text("prior-proof")
                count = root / "count"
                count.write_text("0")
                trace = root / "trace"
                env = dict(os.environ, PATH=str(root) + ":" + os.environ["PATH"], MODE=mode, TRACE=str(trace), COUNT=str(count), NAKPANEL_RELEASE_BUNDLE=folder, NAKPANEL_RUN_TOKEN="fixture123", NAKPANEL_RELEASE_VERSION="29.0.0", NAKPANEL_INTERNAL_TOOLS_RECEIPT=str(output), NAKPANEL_INTERNAL_TOOLS_SITE_ID="1", NAKPANEL_INTERNAL_TOOLS_MAILBOX=MAILBOX, NAKPANEL_VERIFY_DATABASE_MANAGER="1")
                env.pop("NAKPANEL_CELL_REPORT_DIR", None)
                result = subprocess.run(["bash", str(script), "--roundcube-only"], env=env, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode == 0, mode == "ready", result.stderr)
                calls = trace.read_text()
                self.assertNotIn("unexpected-admin-or-config-call", calls)
                if mode == "ready":
                    self.assertLess(calls.index("proof1"), calls.index("flow"))
                    self.assertLess(calls.index("flow"), calls.index("proof2"))
                    self.assertLess(calls.index("proof2"), calls.index("enrich"))
                    self.assertEqual(output.read_text(), "envelope")
                else:
                    self.assertNotIn("enrich", calls)
                    self.assertEqual(output.exists(), mode == "existing-output")
                    if mode == "existing-output": self.assertEqual(output.read_text(), "prior-proof")

    def test_real_http_workflow_and_fail_closed_receipts(self):
        helper = load_helper()
        for mode in ["ready", "login-csrf", "login-redirect", "compose-csrf", "compose-redirect", "compose-loop", "preexisting", "send-rejected", "send-lost-response", "send-hung", "send-redirect", "duplicate", "body-mismatch", "delivery-timeout", "render-timeout"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                server = RoundcubeServer(mode)
                try:
                    certificate = Path(folder) / "ca.pem"
                    certificate.write_text("owned-public-certificate")
                    stdout = io.StringIO()
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stdout):
                        try:
                            helper.qualify(server.url, "webmail.example.test", MAILBOX, PASSWORD, Path(folder), ca_file=certificate, timeout=0.45, poll_interval=0.01, inbox_factory=server.inbox)
                            passed = True
                        except helper.QualificationError:
                            passed = False
                    self.assertEqual(passed, mode == "ready")
                    receipts = list(Path(folder).glob("roundcube-send-read-*.json"))
                    self.assertEqual(len(receipts), 1)
                    receipt = json.loads(receipts[0].read_text())
                    self.assertEqual(receipts[0].stat().st_mode & 0o777, 0o600)
                    self.assertEqual(receipt["status"] == "PASS", passed)
                    self.assertEqual(receipt["send_attempts"], len(server.sends))
                    self.assertLessEqual(len(server.sends), 1, "uncertain send was replayed")
                    self.assertNotIn(PASSWORD, stdout.getvalue() + receipts[0].read_text())
                    self.assertNotIn("private-session", stdout.getvalue() + receipts[0].read_text())
                    self.assertNotIn("<html", stdout.getvalue() + receipts[0].read_text())
                    if server.body:
                        self.assertNotIn(server.body, stdout.getvalue() + receipts[0].read_text())
                    if mode == "ready":
                        self.assertEqual(len(server.sends), 1)
                        self.assertGreater(server.reads, 0)
                        self.assertEqual(receipt["message_id"], "<server-generated-41@example.test>")
                        self.assertTrue(receipt["roundcube_body_verified"])
                        for field in ["success", "http_send_completed", "self_recipient_verified", "imap_arrival_verified", "imap_message_id_verified"]:
                            self.assertIs(receipt[field], True)
                        self.assertEqual(len(receipt["qualifier_helper_sha256"]), 64)
                    if mode in {"send-lost-response", "send-hung"}:
                        self.assertEqual(receipt["status"], "SEND_UNCERTAIN")
                    if mode.startswith("send-"):
                        self.assertEqual(server.reads, 0)
                finally:
                    server.close()

    def test_cli_hard_deadline_leaves_private_failure_receipt(self):
        server = RoundcubeServer("login-hung")
        self.addCleanup(server.close)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            password = root / "password"
            password.write_text(PASSWORD)
            password.chmod(0o600)
            before = time.monotonic()
            result = subprocess.run([sys.executable, str(HERE / "roundcube-send-read.py"), "--base-url", server.url, "--host", "webmail.example.test", "--mailbox", MAILBOX, "--password-file", str(password), "--imap-ca-file", str(root / "unused-ca"), "--receipt-dir", str(root / "receipts"), "--timeout", "0.2"], capture_output=True, text=True, timeout=3)
            self.assertLess(time.monotonic() - before, 1)
            self.assertEqual(result.returncode, 1)
            receipts = list((root / "receipts").glob("*.json"))
            self.assertEqual(len(receipts), 1)
            state = json.loads(receipts[0].read_text())
            self.assertEqual(state["status"], "FAIL")
            self.assertEqual(state["send_attempts"], 0)
            self.assertNotIn(PASSWORD, result.stdout + result.stderr)

    def test_post_receipt_setup_failure_publishes_terminal_receipt(self):
        helper = load_helper()
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.object(helper.urllib.request, "build_opener", side_effect=helper.QualificationError("deadline")):
                with self.assertRaises(helper.QualificationError):
                    helper.qualify("http://127.0.0.1", "webmail.example.test", MAILBOX, PASSWORD, folder)
            receipts = list(Path(folder).glob("*.json"))
            self.assertEqual(len(receipts), 1)
            state = json.loads(receipts[0].read_text())
            self.assertEqual(state["status"], "FAIL")
            self.assertEqual(state["error"], "deadline")
            self.assertEqual(state["send_attempts"], 0)

    def test_cli_alarm_cannot_interrupt_terminal_failure_publication(self):
        helper = load_helper()
        opener = mock.Mock()
        opener.open.side_effect = TimeoutError("controlled transport failure")
        real_fsync = helper.os.fsync
        def terminal_fsync(descriptor):
            # The transport has already failed. Cross the original protocol
            # alarm while publishing its terminal receipt, not in an HTTP call.
            time.sleep(0.15)
            return real_fsync(descriptor)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            password = root / "password"
            password.write_text(PASSWORD)
            password.chmod(0o600)
            args = ["roundcube-send-read.py", "--base-url", "http://127.0.0.1", "--host", "webmail.example.test", "--mailbox", MAILBOX, "--password-file", str(password), "--imap-ca-file", str(root / "unused-ca"), "--receipt-dir", str(root / "receipts"), "--timeout", "0.05"]
            before = time.monotonic()
            with mock.patch.object(sys, "argv", args), mock.patch.object(helper.urllib.request, "build_opener", return_value=opener), mock.patch.object(helper.os, "fsync", side_effect=terminal_fsync), contextlib.redirect_stderr(io.StringIO()) as stderr:
                result = helper.main()
            self.assertEqual(result, 1)
            self.assertLess(time.monotonic() - before, 0.6)
            state = json.loads(next((root / "receipts").glob("*.json")).read_text())
            self.assertEqual(state["status"], "FAIL")
            self.assertEqual(state["error"], "transport-or-protocol")
            self.assertEqual(state["send_attempts"], 0)
            self.assertIs(state["success"], False)
            self.assertEqual(opener.open.call_count, 1)
            self.assertNotIn(PASSWORD, stderr.getvalue())

    def test_library_failure_preserves_callers_alarm(self):
        helper = load_helper()
        handler = helper.signal.getsignal(helper.signal.SIGALRM)
        previous_timer = helper.signal.setitimer(helper.signal.ITIMER_REAL, 30)
        try:
            with tempfile.TemporaryDirectory() as folder, mock.patch.object(helper.urllib.request, "build_opener", side_effect=OSError("controlled setup failure")):
                with self.assertRaises(helper.QualificationError):
                    helper.qualify("http://127.0.0.1", "webmail.example.test", MAILBOX, PASSWORD, folder)
            self.assertIs(helper.signal.getsignal(helper.signal.SIGALRM), handler)
            self.assertGreater(helper.signal.getitimer(helper.signal.ITIMER_REAL)[0], 29)
        finally:
            helper.signal.setitimer(helper.signal.ITIMER_REAL, *previous_timer)

    def test_cli_setup_alarm_and_uncertain_send_remain_terminal(self):
        helper = load_helper()
        for mode in ("setup", "send-hung"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                server = RoundcubeServer("send-hung")
                try:
                    password = root / "password"
                    password.write_text(PASSWORD)
                    password.chmod(0o600)
                    args = ["roundcube-send-read.py", "--base-url", server.url, "--host", "webmail.example.test", "--mailbox", MAILBOX, "--password-file", str(password), "--imap-ca-file", str(root / "unused-ca"), "--receipt-dir", str(root / "receipts"), "--timeout", "0.2"]
                    def delayed_setup(*_args):
                        time.sleep(2)
                    with contextlib.ExitStack() as stack:
                        stack.enter_context(mock.patch.object(sys, "argv", args))
                        stack.enter_context(mock.patch.object(helper, "Inbox", side_effect=server.inbox))
                        stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                        if mode == "setup":
                            stack.enter_context(mock.patch.object(helper.urllib.request, "build_opener", side_effect=delayed_setup))
                        before = time.monotonic()
                        self.assertEqual(helper.main(), 1)
                        self.assertLess(time.monotonic() - before, 1)
                    state = json.loads(next((root / "receipts").glob("*.json")).read_text())
                    self.assertEqual(state["status"], "FAIL" if mode == "setup" else "SEND_UNCERTAIN")
                    self.assertEqual(state["send_attempts"], 0 if mode == "setup" else 1)
                    self.assertEqual(len(server.sends), state["send_attempts"])
                    self.assertIs(state["success"], False)
                finally:
                    server.close()

    def test_deadline_after_final_identity_check_cannot_publish_pass(self):
        helper = load_helper()
        server = RoundcubeServer()
        self.addCleanup(server.close)
        clock = [0]
        def inbox(*args):
            oracle = server.inbox(*args)
            find = oracle.find
            def final_find(subject):
                result = find(subject)
                if server.reads:
                    clock[0] = 2
                return result
            oracle.find = final_find
            return oracle
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(helper.time, "monotonic", side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(helper.QualificationError, "deadline"):
                helper.qualify(server.url, "webmail.example.test", MAILBOX, PASSWORD, folder, timeout=1, inbox_factory=inbox)
            state = json.loads(next(Path(folder).glob("*.json")).read_text())
            self.assertEqual(state["status"], "FAIL")
            self.assertIs(state["success"], False)
            self.assertEqual(state["send_attempts"], 1)
            self.assertEqual(len(server.sends), 1)

    def test_imap_oracle_is_readonly_and_pins_server_identity(self):
        helper = load_helper()

        class Client:
            def __init__(self):
                self.sock = mock.Mock()
                self.commands = []

            def login(self, user, password):
                self.commands.append(("login", user))
                return "OK", []

            def select(self, mailbox, readonly=False):
                self.commands.append(("select", mailbox, readonly))
                return "OK", []

            def noop(self):
                self.commands.append(("NOOP",))
                return "OK", []

            def uid(self, *args):
                self.commands.append(args)
                if args[0] == "SEARCH":
                    return "OK", [b"41"]
                return "OK", [(b"41 (BODY[HEADER.FIELDS])", b"Subject: own-subject\r\nMessage-ID: <server41@example.test>\r\nTo: phase29@example.test\r\nFrom: phase29@example.test\r\n\r\n")]

            def shutdown(self):
                self.commands.append(("shutdown",))

        client = Client()
        context = helper.ssl.create_default_context()
        with mock.patch.object(helper.ssl, "create_default_context", return_value=context) as ssl_factory, mock.patch.object(helper.imaplib, "IMAP4_SSL", return_value=client) as factory:
            inbox = helper.Inbox("192.0.2.10", MAILBOX, PASSWORD, Path("owned-stalwart.pem"), lambda: 5)
            self.assertEqual(inbox.find("own-subject"), {"uid": "41", "subject": "own-subject", "message_id": "<server41@example.test>", "self_recipient_verified": True})
            inbox.close()
        ssl_factory.assert_called_once_with(cafile="owned-stalwart.pem")
        self.assertFalse(context.check_hostname)
        self.assertEqual(context.verify_mode, helper.ssl.CERT_REQUIRED)
        self.assertIs(factory.call_args.kwargs["ssl_context"], context)
        self.assertIn(("select", "INBOX", True), client.commands)
        self.assertIn(("FETCH", "41", "(BODY.PEEK[HEADER.FIELDS (SUBJECT MESSAGE-ID TO FROM)])"), client.commands)
        self.assertEqual([command[0] for command in client.commands], ["login", "select", "NOOP", "SEARCH", "FETCH", "shutdown"])

    def test_imap_oracle_rejects_wrong_recipient_and_ambiguous_server_headers(self):
        helper = load_helper()
        good = b"Subject: own-subject\r\nMessage-ID: <server41@example.test>\r\nTo: phase29@example.test\r\nFrom: phase29@example.test\r\n\r\n"
        for mode in ["wrong-to", "wrong-from", "duplicate-to", "duplicate-message-id", "missing-message-id", "duplicate-uid", "zero-uid"]:
            with self.subTest(mode=mode):
                headers = good
                if mode == "wrong-to": headers = good.replace(b"To: phase29@example.test", b"To: outside@external.invalid")
                if mode == "wrong-from": headers = good.replace(b"From: phase29@example.test", b"From: outside@external.invalid")
                if mode == "duplicate-to": headers = good.replace(b"To: phase29@example.test", b"To: phase29@example.test, outside@external.invalid")
                if mode == "duplicate-message-id": headers = good.replace(b"Message-ID:", b"Message-ID: <other@example.test>\r\nMessage-ID:")
                if mode == "missing-message-id": headers = good.replace(b"Message-ID: <server41@example.test>\r\n", b"")
                client = mock.Mock()
                client.login.return_value = ("OK", [])
                client.select.return_value = ("OK", [])
                client.noop.return_value = ("OK", [])
                identifiers = b"41 41" if mode == "duplicate-uid" else b"0" if mode == "zero-uid" else b"41"
                client.uid.side_effect = [("OK", [identifiers]), ("OK", [(b"headers", headers)])]
                with mock.patch.object(helper.ssl, "create_default_context", return_value=mock.Mock()), mock.patch.object(helper.imaplib, "IMAP4_SSL", return_value=client):
                    inbox = helper.Inbox("192.0.2.10", MAILBOX, PASSWORD, Path("owned-stalwart.pem"), lambda: 5)
                    with self.assertRaises(helper.QualificationError):
                        inbox.find("own-subject")
                    inbox.close()

    def imap_candidates(self, identifiers, messages, remaining=lambda: 5):
        helper = load_helper()
        client = mock.Mock()
        client.login.return_value = ("OK", [])
        client.select.return_value = ("OK", [])
        client.noop.return_value = ("OK", [])
        client.fetches = []
        def uid(command, *args):
            if command == "SEARCH":
                return "OK", [identifiers]
            self.assertEqual(command, "FETCH")
            self.assertEqual(args[1], "(BODY.PEEK[HEADER.FIELDS (SUBJECT MESSAGE-ID TO FROM)])")
            client.fetches.append(args[0])
            return "OK", [(b"headers", messages[args[0]])]
        client.uid.side_effect = uid
        with mock.patch.object(helper.ssl, "create_default_context", return_value=mock.Mock()), mock.patch.object(helper.imaplib, "IMAP4_SSL", return_value=client):
            inbox = helper.Inbox("192.0.2.10", MAILBOX, PASSWORD, Path("owned-stalwart.pem"), remaining)
        self.addCleanup(inbox.close)
        return inbox, client

    def test_imap_search_candidates_require_exact_subject_before_delivery_identity(self):
        # Actual candidate12 Stalwart response shape: a new shared-prefix
        # subject found UID1, whose historical Subject differed and whose
        # Message-ID/To/From were all absent. It is not our delivery.
        unrelated = b"Subject: Nakpanel Roundcube historical fixture\r\n\r\n"
        exact = b"Subject: own-subject\r\nMessage-ID: <server41@example.test>\r\nTo: phase29@example.test\r\nFrom: phase29@example.test\r\n\r\n"
        for identifiers in [b"1", b"1 41", b"41 1", b""]:
            with self.subTest(identifiers=identifiers):
                inbox, client = self.imap_candidates(identifiers, {"1": unrelated, "41": exact})
                found = inbox.find("own-subject")
                if b"41" in identifiers.split():
                    self.assertEqual(found, {"uid": "41", "subject": "own-subject", "message_id": "<server41@example.test>", "self_recipient_verified": True})
                else:
                    self.assertIsNone(found)
                self.assertEqual(client.fetches, [value.decode() for value in identifiers.split()])

    def test_imap_candidate_bounds_and_exact_identity_fail_closed(self):
        helper = load_helper()
        good = b"Subject: own-subject\r\nMessage-ID: <server41@example.test>\r\nTo: phase29@example.test\r\nFrom: phase29@example.test\r\n\r\n"
        unrelated = b"Subject: older-subject\r\n\r\n"
        bad_headers = {
            "duplicate-exact": (b"1 41 42", {"1": unrelated, "41": good, "42": good}),
            "matching-missing-id": (b"1 41", {"1": unrelated, "41": good.replace(b"Message-ID: <server41@example.test>\r\n", b"")}),
            "matching-wrong-to": (b"1 41", {"1": unrelated, "41": good.replace(b"To: phase29@example.test", b"To: other@example.test")}),
            "matching-wrong-from": (b"1 41", {"1": unrelated, "41": good.replace(b"From: phase29@example.test", b"From: other@example.test")}),
            "matching-duplicate-to": (b"41", {"41": good.replace(b"To:", b"To: phase29@example.test\r\nTo:")}),
            "matching-duplicate-from": (b"41", {"41": good.replace(b"From:", b"From: phase29@example.test\r\nFrom:")}),
            "unrelated-duplicate-subject": (b"1", {"1": unrelated.replace(b"Subject:", b"Subject: another\r\nSubject:")}),
            "unrelated-missing-subject": (b"1", {"1": b"Message-ID: <older@example.test>\r\n\r\n"}),
            "malformed-headers": (b"1", {"1": b"not a header\r\nSubject: older-subject\r\n\r\n"}),
            "oversized-headers": (b"1", {"1": b"Subject: " + b"x" * 65536 + b"\r\n\r\n"}),
        }
        bad_uids = [b"1 1", b"0", b"-1", b"x", b"01", b"4294967296", b"9999999999999999999999999999999", b" ".join(str(i).encode() for i in range(1, 66))]
        for mode, (identifiers, messages) in list(bad_headers.items()) + [("uids-" + str(i), (ids, {})) for i, ids in enumerate(bad_uids)]:
            with self.subTest(mode=mode):
                inbox, client = self.imap_candidates(identifiers, messages)
                with self.assertRaises(helper.QualificationError):
                    inbox.find("own-subject")
                if mode.startswith("uids-"):
                    self.assertEqual(client.fetches, [], "invalid/overflow UID inventory must fail before fetching")
        inbox, client = self.imap_candidates(b" ".join(str(i).encode() for i in range(1, 65)), {str(i): unrelated for i in range(1, 65)})
        self.assertIsNone(inbox.find("own-subject"))
        self.assertEqual(len(client.fetches), 64)

    def test_imap_candidate_fetches_share_existing_deadline(self):
        helper = load_helper()
        clock = [5]
        def remaining():
            if clock[0] <= 0:
                raise helper.QualificationError("deadline")
            return clock[0]
        inbox, client = self.imap_candidates(b"1 2", {"1": b"Subject: old\r\n\r\n"}, remaining)
        fetch = client.uid.side_effect
        def expire(command, *args):
            result = fetch(command, *args)
            if command == "FETCH":
                clock[0] = 0
            return result
        client.uid.side_effect = expire
        with self.assertRaisesRegex(helper.QualificationError, "deadline"):
            inbox.find("own-subject")
        self.assertEqual(client.fetches, ["1"])

    def test_imap_candidates_reject_malformed_subject_and_search_envelopes(self):
        helper = load_helper()
        for malformed in [b"Subject: old\x00subject\r\n\r\n", b"Subject: old\x7fsubject\r\n\r\n"]:
            with self.subTest(headers=malformed):
                inbox, _ = self.imap_candidates(b"1", {"1": malformed})
                with self.assertRaises(helper.QualificationError):
                    inbox.find("own-subject")
        for response in [("NO", [b""]), ("OK", []), ("OK", [None]), ("OK", [b"", b"1"])]:
            with self.subTest(response=response):
                inbox, client = self.imap_candidates(b"", {})
                client.uid.side_effect = None
                client.uid.return_value = response
                with self.assertRaisesRegex(helper.QualificationError, "imap-search"):
                    inbox.find("own-subject")
        good = b"Subject: own-subject\r\nMessage-ID: <max@example.test>\r\nTo: phase29@example.test\r\nFrom: phase29@example.test\r\n\r\n"
        inbox, _ = self.imap_candidates(b"4294967295", {"4294967295": good})
        self.assertEqual(inbox.find("own-subject")["uid"], "4294967295")

    def test_real_http_flow_ignores_unrelated_imap_candidate_without_replaying_send(self):
        helper = load_helper()
        for mode in ["ready", "wrong-to", "wrong-from", "missing-message-id", "duplicate-exact"]:
            with self.subTest(mode=mode):
                server = RoundcubeServer()
                self.addCleanup(server.close)
                client = mock.Mock()
                client.login.return_value = ("OK", [])
                client.select.return_value = ("OK", [])
                client.noop.return_value = ("OK", [])
                def uid(command, *args):
                    if command == "SEARCH":
                        return "OK", [b"1 41 42" if server.sends and mode == "duplicate-exact" else b"1 41" if server.sends else b"1"]
                    self.assertEqual((command, args[1]), ("FETCH", "(BODY.PEEK[HEADER.FIELDS (SUBJECT MESSAGE-ID TO FROM)])"))
                    headers = b"Subject: Nakpanel Roundcube historical fixture\r\n\r\n" if args[0] == "1" else ("Subject: " + server.subject + "\r\nMessage-ID: <server41@example.test>\r\nTo: " + MAILBOX + "\r\nFrom: " + MAILBOX + "\r\n\r\n").encode()
                    if args[0] != "1":
                        if mode == "wrong-to": headers = headers.replace(b"To: phase29@example.test", b"To: other@example.test")
                        if mode == "wrong-from": headers = headers.replace(b"From: phase29@example.test", b"From: other@example.test")
                        if mode == "missing-message-id": headers = headers.replace(b"Message-ID: <server41@example.test>\r\n", b"")
                    return "OK", [(b"headers", headers)]
                client.uid.side_effect = uid
                with tempfile.TemporaryDirectory() as folder, mock.patch.object(helper.ssl, "create_default_context", return_value=mock.Mock()), mock.patch.object(helper.imaplib, "IMAP4_SSL", return_value=client):
                    if mode == "ready":
                        receipt = helper.qualify(server.url, "webmail.example.test", MAILBOX, PASSWORD, folder, timeout=5, poll_interval=.01)
                    else:
                        with self.assertRaises(helper.QualificationError):
                            helper.qualify(server.url, "webmail.example.test", MAILBOX, PASSWORD, folder, timeout=5, poll_interval=.01)
                        receipt = next(Path(folder).glob("*.json"))
                    state = json.loads(Path(receipt).read_text())
                self.assertEqual(state["status"], "PASS" if mode == "ready" else "FAIL")
                self.assertIs(state["success"], mode == "ready")
                self.assertIs(state["roundcube_body_verified"], mode == "ready")
                self.assertIs(state["imap_message_id_verified"], mode == "ready")
                self.assertEqual(state["send_attempts"], 1)
                self.assertEqual(len(server.sends), 1)

    def test_stale_selected_imap_session_refreshes_before_search_and_sends_once(self):
        helper = load_helper()
        for mode in ["ready", "refresh-status", "refresh-transport"]:
            with self.subTest(mode=mode):
                server = RoundcubeServer()
                self.addCleanup(server.close)
                client = mock.Mock()
                client.login.return_value = ("OK", [])
                client.select.return_value = ("OK", [])
                visible = [False]
                commands = []
                def noop():
                    commands.append("NOOP")
                    if server.sends and mode == "refresh-status":
                        return "NO", []
                    if server.sends and mode == "refresh-transport":
                        raise OSError("unit transport unavailable")
                    # Actual Stalwart selected-session behavior: delivery is
                    # already present, but SEARCH sees it only after NOOP.
                    visible[0] = bool(server.sends)
                    return "OK", []
                def uid(command, *args):
                    commands.append(command)
                    if command == "SEARCH":
                        return "OK", [b"41" if visible[0] else b""]
                    self.assertEqual((command, args[1]), ("FETCH", "(BODY.PEEK[HEADER.FIELDS (SUBJECT MESSAGE-ID TO FROM)])"))
                    return "OK", [(b"headers", ("Subject: " + server.subject + "\r\nMessage-ID: <server41@example.test>\r\nTo: " + MAILBOX + "\r\nFrom: " + MAILBOX + "\r\n\r\n").encode())]
                client.noop.side_effect = noop
                client.uid.side_effect = uid
                with tempfile.TemporaryDirectory() as folder, mock.patch.object(helper.ssl, "create_default_context", return_value=mock.Mock()), mock.patch.object(helper.imaplib, "IMAP4_SSL", return_value=client):
                    if mode == "ready":
                        receipt = helper.qualify(server.url, "webmail.example.test", MAILBOX, PASSWORD, folder, timeout=1, poll_interval=.01)
                    else:
                        with self.assertRaises(helper.QualificationError):
                            helper.qualify(server.url, "webmail.example.test", MAILBOX, PASSWORD, folder, timeout=1, poll_interval=.01)
                        receipt = next(Path(folder).glob("*.json"))
                    state = json.loads(Path(receipt).read_text())
                self.assertEqual(state["status"], "PASS" if mode == "ready" else "FAIL")
                self.assertIs(state["roundcube_body_verified"], mode == "ready")
                self.assertIs(state["imap_message_id_verified"], mode == "ready")
                self.assertIs(state["http_send_completed"], True)
                self.assertEqual(state["send_attempts"], 1)
                self.assertEqual(len(server.sends), 1)
                client.select.assert_called_once_with("INBOX", readonly=True)
                self.assertGreaterEqual(client.noop.call_count, 3 if mode == "ready" else 2)
                for index, command in enumerate(commands):
                    if command == "SEARCH":
                        self.assertEqual(commands[index - 1], "NOOP")

    def test_imap_refresh_failure_or_exhausted_budget_cannot_search(self):
        helper = load_helper()
        for mode in ["status", "numeric-status", "transport", "deadline", "already-expired"]:
            with self.subTest(mode=mode):
                budget = [5]
                def remaining():
                    if budget[0] <= 0:
                        raise helper.QualificationError("deadline")
                    return budget[0]
                inbox, client = self.imap_candidates(b"", {}, remaining)
                def noop():
                    if mode == "status": return "NO", []
                    if mode == "numeric-status": return 1, []
                    if mode == "transport": raise OSError("unit unavailable")
                    budget[0] = 0
                    return "OK", []
                client.noop.side_effect = noop
                if mode == "already-expired": budget[0] = 0
                with self.assertRaises((helper.QualificationError, OSError)):
                    inbox.find("own-subject")
                client.uid.assert_not_called()
                self.assertEqual(client.noop.call_count, 0 if mode == "already-expired" else 1)

    def test_supplement_enrichment_binds_actual_proofs_and_refuses_false_success(self):
        helper = load_helper()
        for mode in ["ready", "captured-native-proof", "boolean-attempt", "numeric-success", "numeric-http", "missing-http", "missing-php-body", "wrong-helper", "missing-message-id", "wrong-certificate", "generic-pass", "public-raw", "noncanonical-raw", "multiple-raw", "wrong-profile", "wrong-architecture", "wrong-app-version", "missing-binary", "duplicate-binary", "after-drift", "wrong-binary-path", "missing-header", "wrong-header-version", "wrong-header-arch", "wrong-header-commit", "extra-header", "extra-line", "existing-output"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                raw_dir = root / "raw"
                raw_dir.mkdir()
                bindings = dict(source_vm="nakpanel-26-04-arm64-fixture123", run_token="fixture123", release="26.04", architecture="arm64", profile="ubuntu-26.04-sury", php_provider="sury", app_version="29.0.0")
                binary = dict(panel="a" * 64, agent="b" * 64, panelctl="c" * 64)
                manifest_data = dict(version="29.0.0", architecture="arm64", commit="1" * 40, files={"bin/" + name: sha for name, sha in binary.items()})
                if mode == "captured-native-proof":
                    # Exact public output captured by the native11 installed
                    # verifier, including its release-authentication header.
                    binary = dict(panel="f0b6b37fa0f5d1d50c20c00a069626d5b689619686ccb16caed272cfc8c87678", agent="447aa2f7d745d300aec00bb24dd654139b9e5d66a4b88a8c3a900b18989a1e88", panelctl="5df34cb61ee14680e7c6470b956b73ce19d8e392ac044ea05f450000de096538")
                    manifest_data["commit"] = "1d86dad9c5bb9a4a2cff8af48990e160777ac95f"
                    manifest_data["files"] = {"bin/" + name: sha for name, sha in binary.items()}
                raw = dict(schema="nakpanel-roundcube-send-read-v1", status="PASS", success=True, send_attempts=1,
                           http_send_completed=True, self_recipient_verified=True, imap_arrival_verified=True,
                           imap_message_id_verified=True, roundcube_body_verified=True, uid="41", message_id="<server41@example.test>",
                           subject_sha256="1" * 64, body_sha256="2" * 64, recipient_sha256="3" * 64,
                           qualifier_helper_sha256=hashlib.sha256((HERE / "roundcube-send-read.py").read_bytes()).hexdigest(), certificate_sha256="4" * 64)
                if mode == "boolean-attempt": raw["send_attempts"] = True
                if mode == "numeric-success": raw["success"] = 1
                if mode == "numeric-http": raw["http_send_completed"] = 1
                if mode == "missing-http": raw["http_send_completed"] = False
                if mode == "missing-php-body": raw["roundcube_body_verified"] = False
                if mode == "wrong-helper": raw["qualifier_helper_sha256"] = "f" * 64
                if mode == "missing-message-id": raw.pop("message_id")
                if mode == "wrong-certificate": raw["certificate_sha256"] = None
                if mode == "generic-pass": raw = {"status": "PASS", "success": True}
                if mode == "wrong-profile": bindings["profile"] = "ubuntu-26.04-native"
                if mode == "wrong-architecture": manifest_data["architecture"] = "amd64"
                if mode == "wrong-app-version": bindings["app_version"] = "29.0.1"
                raw_path = raw_dir / "roundcube-send-read-fixture.json"
                raw_path.write_bytes(helper.canonical_json(raw))
                raw_path.chmod(0o600)
                if mode == "public-raw": raw_path.chmod(0o644)
                if mode == "noncanonical-raw": raw_path.write_bytes(json.dumps(raw).encode())
                if mode == "multiple-raw": (raw_dir / "roundcube-send-read-other.json").write_bytes(raw_path.read_bytes())
                manifest = root / "manifest.json"
                manifest.write_text(json.dumps(manifest_data))
                proof = "verified 29.0.0 linux/arm64 " + manifest_data["commit"] + "\n" + "".join(sha + "  /usr/local/bin/" + {"panel": "nakpanel-panel", "agent": "nakpanel-agent", "panelctl": "panelctl"}[name] + "\n" for name, sha in binary.items())
                before, after = root / "before", root / "after"
                before.write_text(proof)
                after.write_text(proof)
                before.chmod(0o600)
                after.chmod(0o600)
                if mode == "missing-binary": before.write_text(proof.splitlines()[0] + "\n")
                if mode == "duplicate-binary": before.write_text(proof + proof.splitlines()[1] + "\n")
                if mode == "after-drift": after.write_text(proof.replace("a" * 64, "e" * 64))
                if mode == "wrong-binary-path": after.write_text(proof.replace("/usr/local/bin/", "/tmp/"))
                if mode == "missing-header": before.write_text("\n".join(proof.splitlines()[1:]) + "\n")
                if mode == "wrong-header-version": before.write_text(proof.replace("verified 29.0.0", "verified 29.0.1"))
                if mode == "wrong-header-arch": before.write_text(proof.replace("linux/arm64", "linux/amd64"))
                if mode == "wrong-header-commit": before.write_text(proof.replace("1" * 40, "2" * 40))
                if mode == "extra-header": after.write_text(proof.splitlines()[0] + "\n" + proof)
                if mode == "extra-line": after.write_text(proof + "unrelated diagnostic\n")
                output = root / "roundcube-send-read.json"
                if mode == "existing-output": output.write_text("prior-evidence")
                try:
                    helper.enrich(raw_dir, manifest, before, after, output, HERE / "internal-tools-verify.sh", bindings)
                    passed = True
                except helper.QualificationError:
                    passed = False
                self.assertEqual(passed, mode in {"ready", "captured-native-proof"})
                if passed:
                    envelope = json.loads(output.read_text())
                    self.assertEqual(envelope["schema"], "nakpanel-roundcube-supplement-v1")
                    self.assertIs(envelope["success"], True)
                    self.assertEqual(envelope["installed_binary_sha256"], binary)
                    self.assertEqual(envelope["raw_receipt_sha256"], hashlib.sha256(raw_path.read_bytes()).hexdigest())
                    self.assertEqual(envelope["raw_receipt"], raw)
                    self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                    for field, value in bindings.items(): self.assertEqual(envelope[field], value)
                elif mode == "existing-output":
                    self.assertEqual(output.read_text(), "prior-evidence")
                else:
                    self.assertFalse(output.exists(), "invalid proof published a success envelope")


class CanonicalExecutionTest(unittest.TestCase):
    def test_report_default_stays_outside_source_and_preserves_explicit_override(self):
        text = (HERE / "ubuntu-platform-verify.sh").read_text()
        assignment = next(line for line in text.splitlines() if line.startswith("export NAKPANEL_CELL_REPORT_DIR="))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            for override in (None, "", str(root / "explicit report")):
                env = {key: value for key, value in os.environ.items() if key != "NAKPANEL_CELL_REPORT_DIR"}
                env.update(ROOT_DIR=str(root / "source"), NAKPANEL_OWNERSHIP_DIR=str(root / "owned"), NAKPANEL_RUN_TOKEN="owned-token", NAKPANEL_MULTIPASS_IMAGE="26.04", NAKPANEL_MULTIPASS_ARCH="arm64")
                if override is not None:
                    env["NAKPANEL_CELL_REPORT_DIR"] = override
                result = subprocess.check_output(["bash", "-c", "set -eu\n" + assignment + '\nprintf "%s" "$NAKPANEL_CELL_REPORT_DIR"'], env=env, text=True)
                self.assertEqual(result, override or str(root / "owned/owned-token/reports/26.04-arm64"))
                self.assertFalse(Path(result).is_relative_to(root / "source"))

    def test_actual_gate_loop_records_internal_tools_once(self):
        text = (HERE / "ubuntu-platform-verify.sh").read_text()
        loop = "for gate in phase28" + text.split("for gate in phase28", 1)[1].split("\ndone", 1)[0] + "\ndone"
        shell = '''set -euo pipefail
run_gate(){ python3 -c 'import json,sys;print(json.dumps(sys.argv[1:]))' "$@"; }
SCRIPT_DIR="$1"
''' + loop
        result = subprocess.run(["bash", "-c", shell, "_", str(HERE)], text=True, capture_output=True, check=True)
        records = [json.loads(line) for line in result.stdout.splitlines()]
        internal = [record for record in records if record[0] == "internal-tools"]
        self.assertEqual(len(internal), 1)
        self.assertEqual(internal[0], ["internal-tools", "env", "NAKPANEL_SKIP_PRIOR_PHASES=1", "python3", str(HERE / "roundcube-send-read.py"), "execute-canonical"])
        for record in records:
            if record[0] != "internal-tools":
                self.assertEqual(record, [record[0], "env", "NAKPANEL_SKIP_PRIOR_PHASES=1", str(HERE / (record[0] + "-verify.sh"))])

    def fixture(self, folder, mode="ready", marker=None, development=True, profile="sury26", architecture="amd64"):
        root = Path(folder).resolve()
        source, case = root / "source", root / "case"
        case.mkdir(mode=0o700)
        names = ["internal-tools-verify.sh", "roundcube-send-read.py", "roundcube_send_read_test.py", "roundcube_send_read_test.go", "ubuntu-platform-verify.sh"]
        directory = source / "deploy/multipass"
        directory.mkdir(parents=True)
        for name in names:
            shutil.copyfile(HERE / name, directory / name)
        wrapper = directory / "internal-tools-verify.sh"
        wrapper.write_text('#!/bin/bash\nexec python3 "$CANONICAL_TEST_CHILD"\n')
        wrapper.chmod(0o700)
        (source / "README.md").write_text("Owned canonical fixture.\n")
        def git(*args):
            return subprocess.check_output(["git", "-C", str(source), *args], stderr=subprocess.DEVNULL)
        for args in [("init", "-q"), ("config", "user.name", "Owned fixture"), ("config", "user.email", "fixture@example.test"), ("add", "."), ("commit", "-qm", "owned fixture")]:
            git(*args)
        commit = git("rev-parse", "HEAD").decode().strip()
        if marker:
            with (source / "README.md").open("a") as stream:
                stream.write(marker)
        manifest = root / "manifest.json"
        payload = dict(version="29.0.0", architecture=architecture, commit=commit, development=development, files={"bin/" + name: hashlib.sha256(name.encode()).hexdigest() for name in ["panel", "agent", "panelctl"]})
        manifest.write_text(json.dumps(payload))
        token = "20261019000000-canonicalfixture"
        release, provider, selected_profile = {"noble": ("24.04", "native", "ubuntu-24.04"), "native26": ("26.04", "native", "ubuntu-26.04-native"), "sury26": ("26.04", "sury", "ubuntu-26.04-sury")}[profile]
        bindings = dict(source_vm="nakpanel-" + release.replace(".", "-") + "-" + architecture + "-" + token, run_token=token, release=release, architecture=architecture, profile=selected_profile, php_provider=provider, app_version="29.0.0")
        (case / "phase29-fixtures.tsv").write_text("41\tphase29@example.test\n")
        (case / "phase29-fixtures.tsv").chmod(0o600)
        data = root / "child-data.json"
        data.write_text(json.dumps(dict(source=str(source), case=str(case), manifest=str(manifest), bindings=bindings, mode=mode)))
        child = root / "child.py"
        child.write_text(r'''import hashlib, importlib.util, json, os, pathlib, signal, sys, time
v=json.loads(pathlib.Path(os.environ['CANONICAL_TEST_DATA']).read_text())
source=pathlib.Path(v['source']);case=pathlib.Path(v['case']);manifest=pathlib.Path(v['manifest'])
with (case/'child-count').open('a') as stream:stream.write('invoked\n')
(case/'owned-child-group').write_text(str(os.getpgrp()))
if v['mode']=='hang':time.sleep(10)
if v['mode']=='interrupt':os.kill(os.getppid(),signal.SIGINT);time.sleep(10)
if v['mode']=='terminate':os.kill(os.getppid(),signal.SIGTERM);time.sleep(10)
if v['mode']=='missing-envelope':raise SystemExit(0)
if v['mode']=='early-exit':raise SystemExit(17)
helper_path=source/'deploy/multipass/roundcube-send-read.py'
spec=importlib.util.spec_from_file_location('owned_helper',helper_path);helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
m=json.loads(manifest.read_text());flow=case/'.roundcube-flow.canonical';flow.mkdir(mode=0o700)
proof=('verified '+m['version']+' linux/'+m['architecture']+' '+m['commit']+'\n'+''.join(m['files']['bin/'+name]+'  '+path+'\n' for name,path in [('panel','/usr/local/bin/nakpanel-panel'),('agent','/usr/local/bin/nakpanel-agent'),('panelctl','/usr/local/bin/panelctl')])).encode()
for name in ['installed-before.txt','installed-after.txt']:
 p=flow/name;p.write_bytes(proof);p.chmod(0o600)
raw=dict(schema='nakpanel-roundcube-send-read-v1',status='PASS',success=True,send_attempts=1,http_send_completed=True,self_recipient_verified=True,imap_arrival_verified=True,imap_message_id_verified=True,roundcube_body_verified=True,uid='41',message_id='<owned-test-server@example.test>',subject_sha256='1'*64,body_sha256='2'*64,recipient_sha256=hashlib.sha256(b'phase29@example.test').hexdigest(),qualifier_helper_sha256=hashlib.sha256(helper_path.read_bytes()).hexdigest(),certificate_sha256='3'*64)
if v['mode'].startswith('diagnostic-'):
 raw.update(status='FAIL',success=False,error='compose-identity',send_attempts=0,password='PRIVATE_PASSWORD_SENTINEL',message_id='PRIVATE_MESSAGE_SENTINEL')
 if v['mode']=='diagnostic-error':raw['error']='PRIVATE_EXCEPTION_SENTINEL'
 if v['mode']=='diagnostic-status':raw['status']='PRIVATE_STATUS_SENTINEL'
 if v['mode']=='diagnostic-bool':raw['send_attempts']=True
 if v['mode']=='diagnostic-string':raw['send_attempts']='0'
 if v['mode']=='diagnostic-success':raw['success']=1
 if v['mode']=='diagnostic-helper':raw['qualifier_helper_sha256']='0'*64
 p=flow/'roundcube-send-read-owned.json';p.write_bytes(helper.canonical_json(raw));p.chmod(0o600)
 if v['mode']=='diagnostic-public':p.chmod(0o644)
 if v['mode']=='diagnostic-large':p.write_bytes(b' '*(16*1024+1))
 if v['mode']=='diagnostic-json':p.write_text('{bad JSON')
 if v['mode']=='diagnostic-duplicate':p.write_bytes(p.read_bytes().replace(b'"status":"FAIL"',b'"status":"PASS","status":"FAIL"'))
 if v['mode']=='diagnostic-entries':
  for i in range(33):(flow/('extra-'+str(i))).write_text('')
 if v['mode']=='diagnostic-multiple':(flow/'roundcube-send-read-second.json').write_bytes(p.read_bytes())
 if v['mode']=='diagnostic-link':
  q=flow/'.private';p.rename(q);p.symlink_to(q)
 if v['mode']=='diagnostic-fifo':p.unlink();os.mkfifo(p,0o600)
 raise SystemExit(17)
if v['mode']=='wrong-recipient':raw['recipient_sha256']='0'*64
p=flow/'roundcube-send-read-owned.json';p.write_bytes(helper.canonical_json(raw));p.chmod(0o600)
envelope=case/'roundcube-send-read.json'
helper.enrich(flow,manifest,flow/'installed-before.txt',flow/'installed-after.txt',envelope,source/'deploy/multipass/internal-tools-verify.sh',v['bindings'])
if v['mode']=='dbmanager-failed':raise SystemExit(17)
if v['mode']=='raw-partial':raw['roundcube_body_verified']=False;p.write_bytes(helper.canonical_json(raw))
if v['mode']=='raw-uncertain':raw.update(status='SEND_UNCERTAIN',success=False);p.write_bytes(helper.canonical_json(raw))
if v['mode']=='helper-drift':helper_path.write_text(helper_path.read_text()+'\n# drift\n')
if v['mode']=='driver-drift':
 p=source/'deploy/multipass/ubuntu-platform-verify.sh';p.write_text(p.read_text()+'\n# drift\n')
if v['mode']=='readme-drift':
 p=source/'README.md';p.write_text(p.read_text()+'unexpected README mutation\n')
if v['mode']=='manifest-drift':manifest.write_bytes(manifest.read_bytes()+b' ')
if v['mode']=='extra-flow':(case/'.roundcube-flow.extra').mkdir(mode=0o700)
if v['mode']=='wrong-envelope':
 p=json.loads(envelope.read_text());p['source_vm']='wrong';envelope.write_bytes(helper.canonical_json(p))
if v['mode']=='noncanonical-envelope':envelope.write_bytes(envelope.read_bytes()+b' ')
if v['mode'] in {'background','failure-background'}:
 import subprocess
 subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 if v['mode']=='failure-background':raise SystemExit(17)
''')
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", CANONICAL_TEST_CHILD=str(child), CANONICAL_TEST_DATA=str(data))
        return source, case, manifest, bindings, env, payload

    def test_actual_child_success_records_one_execution_and_exact_source_envelope(self):
        helper = load_helper()
        with tempfile.TemporaryDirectory() as folder:
            source, case, manifest, bindings, env, payload = self.fixture(folder)
            handlers = {signum: helper.signal.getsignal(signum) for signum in (helper.signal.SIGINT, helper.signal.SIGTERM)}
            result = helper.execute_canonical(source, manifest, case, bindings, environment=env, timeout=5)
            for signum, handler in handlers.items():
                self.assertIs(helper.signal.getsignal(signum), handler)
            path = case / "roundcube-send-read.execution.json"
            self.assertEqual(result, json.loads(path.read_text()))
            self.assertIs(result["success"], True)
            self.assertIs(type(result["exit_code"]), int)
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["qualifier_commit"], payload["commit"])
            self.assertEqual(result["runtime_commit"], payload["commit"])
            self.assertEqual(set(result["qualifier_files_sha256"]), {"deploy/multipass/" + n for n in ["internal-tools-verify.sh", "roundcube-send-read.py", "roundcube_send_read_test.py", "roundcube_send_read_test.go"]})
            self.assertEqual(result["envelope_sha256"], hashlib.sha256((case / "roundcube-send-read.json").read_bytes()).hexdigest())
            self.assertRegex(result["started_at"], r"Z$")
            self.assertLessEqual(result["started_at"], result["finished_at"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(helper.QualificationError):
                helper.execute_canonical(source, manifest, case, bindings, environment=env, timeout=5)
            self.assertEqual((case / "child-count").read_text().splitlines(), ["invoked"])

    def test_failure_diagnostic_projects_actual_outcome_without_becoming_success_evidence(self):
        helper = load_helper()
        for mode, code, validation, status, attempts in [
                ("early-exit", 17, "absent", None, None),
                ("diagnostic-ready", 17, "valid", "FAIL", 0),
                ("raw-uncertain", 0, "valid", "SEND_UNCERTAIN", 1),
                ("dbmanager-failed", 17, "valid", "PASS", 1),
                ("hang", -9, "absent", None, None)]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                source, case, manifest, bindings, env, _ = self.fixture(folder, mode)
                with self.assertRaises(helper.QualificationError):
                    helper.execute_canonical(source, manifest, case, bindings, environment=env, timeout=0.2 if mode == "hang" else 5)
                path = case / "internal-tools-diagnostic.json"
                self.assertTrue(path.is_file(), "failed hosted gate omitted its nonhidden safe diagnostic")
                diagnostic = json.loads(path.read_text())
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertIs(diagnostic["diagnostic_only"], True)
                self.assertIs(diagnostic["success"], False)
                self.assertEqual(diagnostic["child"]["exit_code"], code)
                self.assertIs(type(diagnostic["child"]["exit_code"]), int)
                self.assertIs(diagnostic["child"]["owned_group_empty"], True)
                self.assertEqual(diagnostic["raw"], dict(validation=validation, status=status,
                                 error_code="compose-identity" if mode == "diagnostic-ready" else None, send_attempts=attempts))
                for secret in ("PRIVATE_PASSWORD_SENTINEL", "PRIVATE_MESSAGE_SENTINEL", MAILBOX, "raw_receipt", "message_id"):
                    self.assertNotIn(secret, path.read_text())
                self.assertFalse((case / "roundcube-send-read.execution.json").exists())
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(helper.QualificationError):
                    helper.execute_canonical(source, manifest, case, bindings, environment=env, timeout=5)
                self.assertEqual((case / "child-count").read_text().splitlines(), ["invoked"])

    def test_failure_diagnostic_refuses_unsafe_raw_files_types_and_unknown_error_text(self):
        helper = load_helper()
        for mode in ["error", "status", "bool", "string", "success", "helper", "public", "large", "json", "duplicate", "entries", "multiple", "link", "fifo"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                source, case, manifest, bindings, env, _ = self.fixture(folder, "diagnostic-" + mode)
                with self.assertRaises(helper.QualificationError):
                    helper.execute_canonical(source, manifest, case, bindings, environment=env, timeout=5)
                path = case / "internal-tools-diagnostic.json"
                self.assertTrue(path.is_file(), "unsafe raw evidence still needs a bounded unknown diagnostic")
                diagnostic = json.loads(path.read_text())
                self.assertEqual(diagnostic["child"]["exit_code"], 17)
                self.assertEqual(diagnostic["raw"], dict(validation="invalid", status=None, error_code=None, send_attempts=None))
                self.assertNotIn("PRIVATE_", path.read_text())
                self.assertLess(len(path.read_bytes()), 4096)

    def test_failure_diagnostic_rechecks_the_opened_flow_directory(self):
        helper = load_helper()
        with tempfile.TemporaryDirectory() as folder:
            source, case, manifest, bindings, env, _ = self.fixture(folder, "diagnostic-ready")
            original = helper.os.open
            def changed(path, flags, *args, **kwargs):
                if str(path).endswith("/.roundcube-flow.canonical"):
                    Path(path).chmod(0o755)
                return original(path, flags, *args, **kwargs)
            with mock.patch.object(helper.os, "open", side_effect=changed), self.assertRaises(helper.QualificationError):
                helper.execute_canonical(source, manifest, case, bindings, environment=env, timeout=5)
            diagnostic = json.loads((case / "internal-tools-diagnostic.json").read_text())
            self.assertEqual(diagnostic["raw"], dict(validation="invalid", status=None, error_code=None, send_attempts=None))

    def test_prechild_diagnostics_keep_unknowns_null_and_never_write_to_untrusted_case(self):
        helper = load_helper()
        for mode in ["source-drift", "unknown-error", "unsafe-case"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                source, case, manifest, bindings, env, _ = self.fixture(folder)
                if mode == "source-drift":(source / "README.md").write_text("unexpected source mutation")
                if mode == "unsafe-case":case.chmod(0o755)
                replacement = mock.patch.object(helper, "_canonical_source", side_effect=helper.QualificationError("PRIVATE_EXCEPTION_SENTINEL")) if mode == "unknown-error" else contextlib.nullcontext()
                with replacement, self.assertRaises(helper.QualificationError):
                    helper.execute_canonical(source, manifest, case, bindings, environment=env, timeout=5)
                path = case / "internal-tools-diagnostic.json"
                self.assertFalse((case / "child-count").exists())
                if mode == "unsafe-case":
                    self.assertFalse(path.exists())
                else:
                    diagnostic = json.loads(path.read_text())
                    self.assertEqual(diagnostic["error_code"], "canonical-source-drift" if mode == "source-drift" else None)
                    self.assertTrue(all(value is None for value in diagnostic["child"].values()))
                    self.assertEqual(diagnostic["raw"], dict(validation="unknown", status=None, error_code=None, send_attempts=None))
                    self.assertNotIn("PRIVATE_", path.read_text())

    def test_diagnostic_publication_failure_preserves_original_exception_and_existing_bytes(self):
        helper = load_helper()
        class BrokenStderr(io.StringIO):
            def write(self, _value):
                raise OSError("PRIVATE_STDERR_SENTINEL")
        for mode in ["existing", "write-failed", "interrupted-write", "stderr-failed"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                source, case, manifest, bindings, env, _ = self.fixture(folder, "early-exit")
                path = case / "internal-tools-diagnostic.json"
                if mode == "existing":path.write_text("retained-original")
                original = helper._canonical_publish
                def publish(target, value):
                    if Path(target) == path and mode == "interrupted-write":
                        raise KeyboardInterrupt()
                    if Path(target) == path and mode in {"write-failed", "stderr-failed"}:
                        raise OSError("PRIVATE_EXCEPTION_SENTINEL")
                    return original(target, value)
                stderr = BrokenStderr() if mode == "stderr-failed" else io.StringIO()
                error = None
                with mock.patch.object(helper, "_canonical_publish", side_effect=publish), contextlib.redirect_stderr(stderr):
                    try:
                        helper.execute_canonical(source, manifest, case, bindings, environment=env, timeout=5)
                    except BaseException as caught:
                        error = caught
                self.assertIsInstance(error, helper.QualificationError)
                self.assertEqual(str(error), "canonical-child-failed-no-replay")
                self.assertNotIn("PRIVATE_", stderr.getvalue())
                if mode == "existing":self.assertEqual(path.read_text(), "retained-original")
                else:self.assertFalse(path.exists())
                self.assertEqual((case / "child-count").read_text().splitlines(), ["invoked"])

    def test_diagnostic_child_types_are_strict_and_success_has_no_failure_summary(self):
        helper = load_helper()
        with tempfile.TemporaryDirectory() as folder:
            source, case, manifest, bindings, env, _ = self.fixture(folder, "early-exit")
            original = helper._canonical_child
            def malformed(*args):
                result = original(*args)
                return dict(result, exit_code=True, timed_out=1, interrupted="false", unexpected_descendants=0,
                            owned_group_empty="true", termination_signal=True)
            with mock.patch.object(helper, "_canonical_child", side_effect=malformed):
                with self.assertRaises(helper.QualificationError):
                    helper.execute_canonical(source, manifest, case, bindings, environment=env, timeout=5)
            diagnostic = json.loads((case / "internal-tools-diagnostic.json").read_text())
            self.assertEqual(diagnostic["child"], dict(exit_code=None, timed_out=None, interrupted=None,
                             unexpected_descendants=None, owned_group_empty=None, termination_signal=None))
        with tempfile.TemporaryDirectory() as folder:
            source, case, manifest, bindings, env, _ = self.fixture(folder)
            helper.execute_canonical(source, manifest, case, bindings, environment=env, timeout=5)
            self.assertFalse((case / "internal-tools-diagnostic.json").exists())

    def test_actual_child_failures_never_publish_or_replay(self):
        helper = load_helper()
        modes = ["early-exit", "dbmanager-failed", "failure-background", "hang", "interrupt", "missing-envelope", "raw-partial", "raw-uncertain", "helper-drift", "driver-drift", "readme-drift", "manifest-drift", "extra-flow", "wrong-envelope", "wrong-recipient", "noncanonical-envelope"]
        for mode in modes:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                source, case, manifest, bindings, env, _ = self.fixture(folder, mode)
                with self.assertRaises(helper.QualificationError):
                    helper.execute_canonical(source, manifest, case, bindings, environment=env, timeout=0.2 if mode == "hang" else 5)
                self.assertFalse((case / "roundcube-send-read.execution.json").exists())
                outcome = json.loads((case / ".roundcube-canonical-execution/outcome.json").read_text())
                self.assertEqual(outcome["exit_code"], 17 if mode in {"early-exit", "dbmanager-failed", "failure-background"} else -9 if mode in {"hang", "interrupt"} else 0)
                self.assertIs(outcome["success"], False)
                self.assertEqual(outcome["timed_out"], mode == "hang")
                self.assertEqual(outcome["interrupted"], mode == "interrupt")
                self.assertIs(outcome["owned_group_empty"], True)
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(helper.QualificationError):
                    helper.execute_canonical(source, manifest, case, bindings, environment=env, timeout=5)
                self.assertEqual((case / "child-count").read_text().splitlines(), ["invoked"])

    def test_actual_recording_supports_each_qualified_profile_and_architecture(self):
        helper = load_helper()
        for profile in ("noble", "native26", "sury26"):
            for architecture in ("amd64", "arm64"):
                with self.subTest(profile=profile, architecture=architecture), tempfile.TemporaryDirectory() as folder:
                    source, case, manifest, bindings, env, _ = self.fixture(folder, profile=profile, architecture=architecture)
                    result = helper.execute_canonical(source, manifest, case, bindings, environment=env, timeout=5)
                    for field in ("release", "architecture", "profile", "php_provider", "source_vm", "run_token"):
                        self.assertEqual(result[field], bindings[field])
                    self.assertEqual((case / "child-count").read_text().splitlines(), ["invoked"])

    def test_normal_exit_with_background_descendant_refuses_and_cleans_owned_group(self):
        helper = load_helper()
        with tempfile.TemporaryDirectory() as folder:
            source, case, manifest, bindings, env, _ = self.fixture(folder, "background")
            try:
                with self.assertRaises(helper.QualificationError):
                    helper.execute_canonical(source, manifest, case, bindings, environment=env, timeout=5)
                group = int((case / "owned-child-group").read_text())
                with self.assertRaises(ProcessLookupError):
                    os.killpg(group, 0)
                self.assertFalse((case / "roundcube-send-read.execution.json").exists())
                outcome = json.loads((case / ".roundcube-canonical-execution/outcome.json").read_text())
                self.assertEqual(outcome["exit_code"], 0)
                self.assertIs(outcome["unexpected_descendants"], True)
                self.assertIs(outcome["owned_group_empty"], True)
            finally:
                if (case / "owned-child-group").exists():
                    try: os.killpg(int((case / "owned-child-group").read_text()), helper.signal.SIGKILL)
                    except ProcessLookupError: pass

    def test_real_sigterm_records_actual_exit_and_cleans_only_fresh_child_group(self):
        helper = load_helper()
        with tempfile.TemporaryDirectory() as folder:
            source, case, manifest, bindings, env, _ = self.fixture(folder, "terminate")
            runner = Path(folder) / "record.py"
            runner.write_text("import importlib.util\nfrom pathlib import Path\ns=importlib.util.spec_from_file_location('h'," + repr(str(HERE / "roundcube-send-read.py")) + ");h=importlib.util.module_from_spec(s);s.loader.exec_module(h)\ntry:h.execute_canonical(Path(" + repr(str(source)) + "),Path(" + repr(str(manifest)) + "),Path(" + repr(str(case)) + ")," + repr(bindings) + ",timeout=5)\nexcept h.QualificationError:raise SystemExit(1)\n")
            try:
                result = subprocess.run([sys.executable, "-B", str(runner)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
                self.assertEqual(result.returncode, 1)
                group = int((case / "owned-child-group").read_text())
                with self.assertRaises(ProcessLookupError):
                    os.killpg(group, 0)
                self.assertFalse((case / "roundcube-send-read.execution.json").exists())
                outcome = json.loads((case / ".roundcube-canonical-execution/outcome.json").read_text())
                self.assertEqual(outcome["exit_code"], -9)
                self.assertIs(outcome["interrupted"], True)
                self.assertIs(outcome["owned_group_empty"], True)
            finally:
                if (case / "owned-child-group").exists():
                    try: os.killpg(int((case / "owned-child-group").read_text()), helper.signal.SIGKILL)
                    except ProcessLookupError: pass

    def test_only_exact_development_readme_markers_allow_source_drift(self):
        helper = load_helper()
        modes = ["local", "hosted", "untracked", "other-tracked", "wrong-marker", "marker-production", "hosted-wrong-run"]
        for mode in modes:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                marker = "\nQualification development snapshot; not a production release.\n" if mode in {"local", "marker-production"} else "\n<!-- hosted development qualification 12345 -->\n" if mode in {"hosted", "hosted-wrong-run"} else "unexpected text\n" if mode == "wrong-marker" else None
                source, case, manifest, bindings, env, _ = self.fixture(folder, marker=marker, development=mode != "marker-production")
                env["GITHUB_RUN_ID"] = "12345" if mode == "hosted" else "99999"
                if mode == "untracked": (source / "unexpected.py").write_text("uncommitted")
                if mode == "other-tracked":
                    path = source / "deploy/multipass/ubuntu-platform-verify.sh"
                    path.write_text(path.read_text() + "\n# uncommitted\n")
                if mode in {"local", "hosted"}:
                    helper.execute_canonical(source, manifest, case, bindings, environment=env, timeout=5)
                    self.assertTrue((case / "roundcube-send-read.execution.json").exists())
                else:
                    with self.assertRaises(helper.QualificationError):
                        helper.execute_canonical(source, manifest, case, bindings, environment=env, timeout=5)
                    self.assertFalse((case / "child-count").exists())

if __name__ == "__main__":
    unittest.main()
