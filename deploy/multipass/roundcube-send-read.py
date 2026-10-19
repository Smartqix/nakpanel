#!/usr/bin/env python3
"""Bounded Roundcube self-mail qualification through its real HTTP forms.

Roundcube 1.6.6/1.6.19 compose/send and Elastic message templates are the
protocol reference. Never retry a send POST: an interrupted response is not
proof that SMTP delivery failed. IMAP is a read-only identity/arrival oracle;
the exact body must also render through Roundcube's PHP message view.
"""

import argparse
import email
import email.policy
import email.utils
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
import http.cookiejar
import imaplib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


class QualificationError(RuntimeError):
    """Only a fixed, non-sensitive error code may reach output/receipts."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class Forms(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.current = None
        self.select = None
        self.option = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.current = {"action": attrs.get("action", ""), "fields": {}, "identities": []}
            self.forms.append(self.current)
        elif self.current is not None and tag == "input" and attrs.get("name"):
            field, value = attrs["name"], attrs.get("value", "")
            if field in self.current["fields"] and self.current["fields"][field] != value:
                raise QualificationError("ambiguous-form")
            self.current["fields"][field] = value
        elif tag == "select":
            self.select = attrs.get("name")
        elif self.current is not None and self.select == "_from" and tag == "option":
            self.option = [attrs.get("value", ""), ""]

    def handle_data(self, text):
        if self.option is not None:
            self.option[1] += text

    def handle_endtag(self, tag):
        if tag == "option" and self.option is not None:
            self.current["identities"].append(self.option)
            self.option = None
        elif tag == "select":
            self.select = None
        elif tag == "form":
            self.current = None


class Body(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth = 0
        self.parts = []
        self.found = 0

    def handle_starttag(self, tag, attrs):
        if dict(attrs).get("id") == "messagebody":
            self.found += 1
            self.depth = 1
        elif self.depth and tag not in {"br", "hr", "img", "input", "meta", "link"}:
            self.depth += 1
        if self.depth and tag == "br":
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if self.depth and tag not in {"br", "hr", "img", "input", "meta", "link"}:
            self.depth -= 1

    def handle_data(self, value):
        if self.depth:
            self.parts.append(value)


class Inbox:
    def __init__(self, host, mailbox, password, ca_file, remaining):
        context = ssl.create_default_context(cafile=str(ca_file))
        # The VM-identity-checked Stalwart certificate is the explicit trust
        # anchor. Transport uses its private IP rather than its DNS hostname.
        context.check_hostname = False
        self.client = imaplib.IMAP4_SSL(host, 993, ssl_context=context, timeout=min(10, remaining()))
        self.remaining = remaining
        self.mailbox = mailbox.lower()
        try:
            self._bound()
            if self.client.login(mailbox, password)[0] != "OK":
                raise QualificationError("imap-authentication")
            self._bound()
            if self.client.select("INBOX", readonly=True)[0] != "OK":
                raise QualificationError("imap-inbox")
        except Exception:
            self.close()
            raise

    def _bound(self):
        self.client.sock.settimeout(min(10, self.remaining()))

    def find(self, subject):
        self._bound()
        status, rows = self.client.uid("SEARCH", None, "HEADER", "Subject", '"' + subject + '"')
        if status != "OK" or not rows or not isinstance(rows[0], bytes):
            raise QualificationError("imap-search")
        identifiers = rows[0].split()
        if not identifiers:
            return None
        if len(identifiers) != 1 or not identifiers[0].isdigit() or int(identifiers[0]) == 0:
            raise QualificationError("duplicate-delivery")
        uid = identifiers[0].decode("ascii")
        self._bound()
        status, rows = self.client.uid("FETCH", uid, "(BODY.PEEK[HEADER.FIELDS (SUBJECT MESSAGE-ID TO FROM)])")
        payloads = [row[1] for row in rows if isinstance(row, tuple) and isinstance(row[1], bytes)]
        if status != "OK" or len(payloads) != 1:
            raise QualificationError("imap-headers")
        headers = email.message_from_bytes(payloads[0], policy=email.policy.default)
        if len(headers.get_all("Subject", [])) != 1 or str(headers.get("Subject", "")) != subject or len(headers.get_all("Message-ID", [])) != 1:
            raise QualificationError("delivery-identity")
        for field in ("To", "From"):
            if [address.lower() for _, address in email.utils.getaddresses(headers.get_all(field, []))] != [self.mailbox]:
                raise QualificationError("delivery-self-recipient")
        message_id = str(headers["Message-ID"])
        if not re.fullmatch(r"<[^\s<>]{1,220}@[^\s<>]{1,220}>", message_id):
            raise QualificationError("delivery-message-id")
        return {"uid": uid, "subject": subject, "message_id": message_id, "self_recipient_verified": True}

    def close(self):
        # No CLOSE/EXPUNGE, flag update, append or SMTP call is allowed here.
        try:
            self.client.shutdown()
        except Exception:
            pass


def qualify(base_url, host, mailbox, password, receipt_dir, *, ca_file=None,
            timeout=120, poll_interval=1, inbox_factory=None, cancel_deadline=None):
    endpoint = urllib.parse.urlsplit(base_url)
    if endpoint.scheme != "http" or endpoint.path not in {"", "/"} or endpoint.query or endpoint.fragment or endpoint.username:
        raise QualificationError("invalid-endpoint")
    try:
        private = ipaddress.ip_address(endpoint.hostname).is_private
    except ValueError:
        private = False
    if not private or not re.fullmatch(r"[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.test", mailbox) or host != "webmail." + mailbox.split("@", 1)[1] or timeout <= 0 or poll_interval <= 0:
        raise QualificationError("invalid-local-fixture")
    deadline = time.monotonic() + timeout
    nonce = secrets.token_hex(16)
    subject = "Nakpanel Roundcube " + nonce
    body = "Nakpanel Roundcube self delivery " + nonce
    receipt_dir = Path(receipt_dir)
    receipt_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    receipt = receipt_dir / ("roundcube-send-read-" + nonce + ".json")
    state = {"schema": "nakpanel-roundcube-send-read-v1", "status": "CREATED", "success": False, "send_attempts": 0,
             "subject_sha256": hashlib.sha256(subject.encode()).hexdigest(),
             "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
             "recipient_sha256": hashlib.sha256(mailbox.lower().encode()).hexdigest(),
             "qualifier_helper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             "certificate_sha256": hashlib.sha256(Path(ca_file).read_bytes()).hexdigest() if ca_file and Path(ca_file).is_file() else None,
             "http_send_completed": False, "self_recipient_verified": False,
             "imap_arrival_verified": False, "imap_message_id_verified": False, "roundcube_body_verified": False}
    descriptor = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        output.write(canonical_json(state).decode("ascii"))

    def save():
        temporary = None
        try:
            descriptor, temporary = tempfile.mkstemp(prefix=".roundcube-receipt-", dir=receipt_dir)
            with os.fdopen(descriptor, "w") as output:
                output.write(canonical_json(state).decode("ascii"))
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, receipt)
        finally:
            if temporary is not None and os.path.exists(temporary):
                os.unlink(temporary)

    def remaining():
        left = deadline - time.monotonic()
        if left <= 0:
            raise QualificationError("deadline")
        return left

    inbox = None
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        virtual = "http://" + host + "/"

        def local_path(value):
            target = urllib.parse.urlsplit(urllib.parse.urljoin(virtual, value))
            if target.scheme != "http" or target.netloc != host or target.username or target.fragment:
                raise QualificationError("unsafe-redirect")
            return (target.path or "/") + ("?" + target.query if target.query else "")

        def request(path, fields=None):
            payload = urllib.parse.urlencode(fields).encode() if fields is not None else None
            req = urllib.request.Request(base_url.rstrip("/") + local_path(path), data=payload,
                                         headers={"Host": host, "Referer": virtual, "Origin": virtual.rstrip("/")})
            try:
                response = opener.open(req, timeout=min(10, remaining()))
            except urllib.error.HTTPError as error:
                response = error
            with response:
                content = response.read(2 * 1024 * 1024 + 1)
                if len(content) > 2 * 1024 * 1024:
                    raise QualificationError("response-size")
                return response.status, response.headers, content.decode("utf-8", errors="strict")

        def get(path):
            for _ in range(6):
                status, headers, html = request(path)
                if status in {301, 302, 303}:
                    path = local_path(headers.get("Location", ""))
                    continue
                if status != 200 or "text/html" not in headers.get("Content-Type", ""):
                    raise QualificationError("http-page")
                return html
            raise QualificationError("redirect-limit")

        forms = Forms()
        forms.feed(get("/?_task=login"))
        tokens = [form["fields"]["_token"] for form in forms.forms if form["fields"].get("_token")]
        if len(tokens) != 1:
            raise QualificationError("login-csrf")
        status, headers, _ = request("/?_task=login", {"_token": tokens[0], "_task": "login", "_action": "login", "_user": mailbox, "_pass": password, "_timezone": "UTC", "_url": ""})
        target = local_path(headers.get("Location", ""))
        if status not in {302, 303} or urllib.parse.parse_qs(urllib.parse.urlsplit(target).query).get("_task") != ["mail"]:
            raise QualificationError("roundcube-login")
        get(target)
        state["status"] = "AUTHENTICATED"
        save()
        forms = Forms()
        forms.feed(get("/?_task=mail&_action=compose"))
        candidates = [form for form in forms.forms if form["fields"].get("_action") == "send"]
        if len(candidates) != 1:
            raise QualificationError("compose-form")
        form = candidates[0]
        fields = form["fields"]
        if not fields.get("_token") or not fields.get("_id") or fields.get("_task") != "mail":
            raise QualificationError("compose-csrf")
        identities = [identifier for identifier, label in form["identities"] if email.utils.parseaddr(label)[1].lower() == mailbox.lower()]
        if not identities and email.utils.parseaddr(fields.get("_from", ""))[1].lower() == mailbox.lower():
            identities = [fields["_from"]]
        if len(identities) != 1:
            raise QualificationError("compose-identity")
        send_path = local_path(form["action"] or "/?_task=mail")
        fields = {"_token": fields["_token"], "_task": "mail", "_action": "send", "_id": fields["_id"],
                  "_from": identities[0], "_to": mailbox, "_cc": "", "_bcc": "", "_subject": subject,
                  "_message": body, "_is_html": "0", "_charset": "UTF-8", "_attachments": ""}
        inbox = (inbox_factory or Inbox)(endpoint.hostname, mailbox, password, ca_file, remaining)
        if inbox.find(subject) is not None:
            raise QualificationError("preexisting-canary")
        state.update(status="SUBMITTING", send_attempts=1)
        save()
        try:
            status, _, html = request(send_path, fields)
        except (OSError, urllib.error.URLError):
            state["status"] = "SEND_UNCERTAIN"
            raise QualificationError("send-result-uncertain") from None
        acknowledgements = re.findall(r"(?:parent\.)?rcmail\.sent_successfully\((.*?)\);", html, flags=re.S)
        try:
            acknowledgement = json.loads("[" + acknowledgements[0] + "]") if len(acknowledgements) == 1 else []
        except ValueError:
            acknowledgement = []
        if status != 200 or len(acknowledgement) != 4 or acknowledgement[0] != "confirmation" or acknowledgement[3] is not False:
            raise QualificationError("send-not-confirmed")
        state.update(status="SENT", http_send_completed=True)
        save()
        while True:
            remaining()
            message = inbox.find(subject)
            if message is not None:
                break
            time.sleep(min(poll_interval, remaining()))
        if message.get("self_recipient_verified") is not True:
            raise QualificationError("delivery-self-recipient")
        state.update(status="DELIVERED", uid=message["uid"], message_id=message["message_id"],
                     self_recipient_verified=True, imap_arrival_verified=True, imap_message_id_verified=True)
        save()
        while True:
            remaining()
            parser = Body()
            parser.feed(get("/?" + urllib.parse.urlencode({"_task": "mail", "_action": "show", "_uid": message["uid"], "_mbox": "INBOX", "_safe": "1"})))
            if parser.found:
                if parser.found != 1 or "".join(parser.parts).replace("\r\n", "\n").strip() != body:
                    raise QualificationError("roundcube-body-mismatch")
                break
            time.sleep(min(poll_interval, remaining()))
        if inbox.find(subject) != message:
            raise QualificationError("delivery-changed")
        remaining()
        if cancel_deadline is not None:
            cancel_deadline()
        state.update(status="PASS", success=True, roundcube_body_verified=True)
        save()
        return receipt
    except Exception as error:
        if cancel_deadline is not None:
            cancel_deadline()
        code = str(error) if isinstance(error, QualificationError) else "transport-or-protocol"
        if state["status"] == "SUBMITTING":
            state["status"] = "SEND_UNCERTAIN"
        elif state["status"] != "SEND_UNCERTAIN":
            state["status"] = "FAIL"
        state["error"] = code
        save()
        raise QualificationError(code) from None
    finally:
        if inbox is not None:
            inbox.close()


def canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def enrich(raw_dir, manifest_path, before_proof, after_proof, output, wrapper, bindings):
    """Publish a supplement only after the shell's two identity-checked proofs.

    These proofs come from assert_qualification_installed_release, which
    authenticates the selected signed inventory and reads all three binaries.
    This formatter must not turn a generic PASS text or stale receipt into
    runtime qualification evidence.
    """
    def regular(path, private=False):
        path = Path(path)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or private and info.st_mode & 0o077:
            raise QualificationError("untrusted-proof-file")
        return path.read_bytes()

    def digest(value):
        return hashlib.sha256(value).hexdigest()

    def sha(value):
        return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)

    output = Path(output)
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise QualificationError("supplement-output")
    profile = {("24.04", "native"): "ubuntu-24.04", ("26.04", "native"): "ubuntu-26.04-native", ("26.04", "sury"): "ubuntu-26.04-sury"}
    required = {"source_vm", "run_token", "release", "architecture", "profile", "php_provider", "app_version"}
    if set(bindings) != required or not all(isinstance(value, str) for value in bindings.values()):
        raise QualificationError("supplement-binding")
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{5,63}", bindings["run_token"])
            or not re.fullmatch(r"nakpanel-[A-Za-z0-9-]+", bindings["source_vm"])
            or bindings["run_token"] not in bindings["source_vm"]
            or bindings["architecture"] not in {"arm64", "amd64"}
            or profile.get((bindings["release"], bindings["php_provider"])) != bindings["profile"]):
        raise QualificationError("supplement-binding")
    manifest_bytes = regular(manifest_path)
    manifest = json.loads(manifest_bytes)
    if (not isinstance(manifest, dict) or not isinstance(manifest.get("files"), dict)
            or manifest.get("architecture") != bindings["architecture"] or manifest.get("version") != bindings["app_version"]
            or not isinstance(manifest.get("commit"), str) or not re.fullmatch(r"[0-9a-f]{40}", manifest["commit"])):
        raise QualificationError("supplement-manifest")
    expected = {name: manifest.get("files", {}).get("bin/" + name) for name in ("panel", "agent", "panelctl")}
    if not all(sha(value) for value in expected.values()):
        raise QualificationError("supplement-manifest-binaries")
    paths = {"/usr/local/bin/nakpanel-panel": "panel", "/usr/local/bin/nakpanel-agent": "agent", "/usr/local/bin/panelctl": "panelctl"}
    for proof in (before_proof, after_proof):
        rows = regular(proof, private=True).decode("ascii").splitlines()
        header = "verified " + manifest["version"] + " linux/" + manifest["architecture"] + " " + manifest["commit"]
        if len(rows) != 4 or rows[0] != header:
            raise QualificationError("installed-release-proof")
        found = {}
        for row in rows[1:]:
            match = re.fullmatch(r"([0-9a-f]{64})  (/usr/local/bin/[A-Za-z-]+)", row)
            if match is None or match[2] not in paths or paths[match[2]] in found:
                raise QualificationError("installed-binary-proof")
            found[paths[match[2]]] = match[1]
        if found != expected:
            raise QualificationError("installed-binary-proof")
    candidates = list(Path(raw_dir).glob("roundcube-send-read-*.json"))
    if len(candidates) != 1:
        raise QualificationError("supplement-raw-count")
    raw_bytes = regular(candidates[0], private=True)
    raw = json.loads(raw_bytes)
    helper_sha = digest(Path(__file__).read_bytes())
    if (not isinstance(raw, dict) or canonical_json(raw) != raw_bytes
            or raw.get("schema") != "nakpanel-roundcube-send-read-v1" or raw.get("status") != "PASS"
            or type(raw.get("send_attempts")) is not int or raw["send_attempts"] != 1 or "error" in raw
            or any(raw.get(field) is not True for field in ("success", "http_send_completed", "self_recipient_verified", "imap_arrival_verified", "imap_message_id_verified", "roundcube_body_verified"))
            or raw.get("qualifier_helper_sha256") != helper_sha
            or not all(sha(raw.get(field)) for field in ("subject_sha256", "body_sha256", "recipient_sha256", "certificate_sha256"))
            or not isinstance(raw.get("uid"), str) or not re.fullmatch(r"[1-9][0-9]*", raw["uid"])
            or not isinstance(raw.get("message_id"), str) or not raw["message_id"].isascii()
            or not re.fullmatch(r"<[^\s<>]{1,220}@[^\s<>]{1,220}>", raw["message_id"])):
        raise QualificationError("supplement-raw-proof")
    envelope = dict(bindings, schema="nakpanel-roundcube-supplement-v1", success=True,
                    runtime_commit=manifest["commit"], manifest_sha256=digest(manifest_bytes),
                    installed_binary_sha256=expected, qualifier_wrapper_sha256=digest(regular(wrapper)),
                    qualifier_helper_sha256=helper_sha, raw_receipt_sha256=digest(raw_bytes), raw_receipt=raw)
    descriptor, temporary = tempfile.mkstemp(prefix=".roundcube-supplement-", dir=output.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_json(envelope))
            stream.flush()
            os.fsync(stream.fileno())
        # Atomic, exclusive publication: neither a race nor a failed later
        # attempt may overwrite an existing successful receipt.
        os.link(temporary, output)
    finally:
        os.unlink(temporary)
    return output


def enrich_main(argv):
    parser = argparse.ArgumentParser(description="Bind a real Roundcube receipt to exact installed runtime proofs")
    for field in ("raw-dir", "manifest", "before-proof", "after-proof", "output", "wrapper"):
        parser.add_argument("--" + field, required=True, type=Path)
    for field in ("source-vm", "run-token", "release", "architecture", "profile", "php-provider", "app-version"):
        parser.add_argument("--" + field, required=True)
    args = parser.parse_args(argv)
    try:
        bindings = {field: getattr(args, field) for field in ("source_vm", "run_token", "release", "architecture", "profile", "php_provider", "app_version")}
        enrich(args.raw_dir, args.manifest, args.before_proof, args.after_proof, args.output, args.wrapper, bindings)
    except (QualificationError, OSError, ValueError, TypeError):
        print("FAIL Roundcube supplement proof; no success envelope published", file=sys.stderr)
        return 1
    print("PASS exact-runtime Roundcube supplemental receipt")
    return 0


QUALIFIER_FILES = tuple("deploy/multipass/" + name for name in (
    "internal-tools-verify.sh", "roundcube-send-read.py", "roundcube_send_read_test.py", "roundcube_send_read_test.go"))


def _canonical_read(path, private=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022
                or private and stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1048576):
            raise QualificationError("canonical-private-input")
        return stream.read()


def _canonical_publish(path, value):
    descriptor, temporary = tempfile.mkstemp(prefix=".canonical-receipt-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_json(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


def _canonical_source(source, manifest, environment):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(source), *args], stderr=subprocess.DEVNULL, timeout=30)
    commit = git("rev-parse", "HEAD").decode("ascii").strip()
    if commit != manifest["commit"]:
        raise QualificationError("canonical-runtime-commit")
    status = git("status", "--porcelain", "--untracked-files=all")
    readme = _canonical_read(source / "README.md")
    original = git("show", commit + ":README.md")
    if not status and readme != original:
        raise QualificationError("canonical-readme-byte-proof")
    if status:
        markers = [b"\nQualification development snapshot; not a production release.\n"]
        run_id = environment.get("GITHUB_RUN_ID", "")
        if re.fullmatch(r"[0-9]+", run_id):
            markers.append(("\n<!-- hosted development qualification " + run_id + " -->\n").encode("ascii"))
        if (manifest.get("development") is not True or status != b" M README.md\n"
                or readme not in [original + marker for marker in markers]):
            raise QualificationError("canonical-source-drift")
    files = {}
    for name in (*QUALIFIER_FILES, "deploy/multipass/ubuntu-platform-verify.sh"):
        value = _canonical_read(source / name)
        if value != git("show", commit + ":" + name):
            raise QualificationError("canonical-committed-byte-proof")
        files[name] = hashlib.sha256(value).hexdigest()
    return dict(commit=commit, source_status=status.decode("utf-8"), readme_sha256=hashlib.sha256(readme).hexdigest(),
                qualifier_files_sha256={name: files[name] for name in QUALIFIER_FILES},
                canonical_driver_sha256=files["deploy/multipass/ubuntu-platform-verify.sh"])


class _CanonicalTermination(BaseException):
    pass


def _canonical_group_exists(group):
    try:
        os.killpg(group, 0)
        return True
    except ProcessLookupError:
        return False


def _canonical_group_wait(group, grace):
    deadline = time.monotonic() + grace
    while _canonical_group_exists(group):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    return True


def _canonical_child(command, environment, timeout):
    child = None
    previous = {}
    phase = "starting"
    received_signal = None
    timed_out = interrupted = unexpected_descendants = False
    def terminate(signum, _frame):
        nonlocal received_signal
        received_signal = signum
        # Startup must first acquire the child's actual PID, and cleanup must
        # finish even if another cancellation signal arrives during it.
        if phase == "waiting":
            raise _CanonicalTermination()
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, terminate)
        try:
            child = subprocess.Popen(command, env=environment, start_new_session=True)
            phase = "waiting"
            if received_signal is not None:
                raise _CanonicalTermination()
            child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        except _CanonicalTermination:
            interrupted = True
        finally:
            phase = "cleanup"
            if child is not None:
                # Only this fresh child's session/process group is owned. No
                # ambient controller, source VM group or guessed PID is used.
                if child.poll() is None:
                    try: os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                child.wait()
                if child.returncode == 0 and not timed_out and not interrupted and received_signal is None:
                    # Browser processes may be completing an awaited close.
                    # A leftover beyond this bounded grace is a failed gate,
                    # even after cleanup successfully removes it.
                    unexpected_descendants = not _canonical_group_wait(child.pid, 0.3)
                if _canonical_group_exists(child.pid):
                    try: os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                owned_group_empty = _canonical_group_wait(child.pid, 1)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    return dict(exit_code=child.returncode, timed_out=timed_out, interrupted=interrupted or received_signal is not None,
                unexpected_descendants=unexpected_descendants, owned_group_empty=owned_group_empty,
                termination_signal=received_signal)


def execute_canonical(source, manifest_path, case, bindings, *, environment=None, timeout=3600):
    """Record the existing complete internal-tools gate, invoking it once.

    This is provenance for a real gate subprocess, not all17 authorization.
    Failed/uncertain attempts remain owned evidence and are never replayed.
    """
    try:
        source, manifest_path, case = Path(source), Path(manifest_path), Path(case)
        environment = dict(os.environ if environment is None else environment)
        fields = {"source_vm", "run_token", "release", "architecture", "profile", "php_provider", "app_version"}
        profiles = {("24.04", "native"): "ubuntu-24.04", ("26.04", "native"): "ubuntu-26.04-native", ("26.04", "sury"): "ubuntu-26.04-sury"}
        if (set(bindings) != fields or not all(isinstance(v, str) for v in bindings.values())
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{5,63}", bindings["run_token"])
                or not re.fullmatch(r"nakpanel-[A-Za-z0-9-]+", bindings["source_vm"])
                or bindings["run_token"] not in bindings["source_vm"]
                or bindings["architecture"] not in {"amd64", "arm64"}
                or profiles.get((bindings["release"], bindings["php_provider"])) != bindings["profile"]
                or not 0 < timeout <= 3600):
            raise QualificationError("canonical-binding")
        if (not source.is_absolute() or source.resolve() != source or not source.is_dir()
                or not case.is_absolute() or case.resolve() != case or not case.is_dir()
                or case.stat().st_uid != os.getuid() or stat.S_IMODE(case.stat().st_mode) != 0o700):
            raise QualificationError("canonical-owned-case")
        manifest_bytes = _canonical_read(manifest_path)
        manifest = json.loads(manifest_bytes)
        if (not isinstance(manifest, dict) or not re.fullmatch(r"[0-9a-f]{40}", manifest.get("commit", ""))
                or manifest.get("architecture") != bindings["architecture"] or manifest.get("version") != bindings["app_version"]
                or type(manifest.get("development")) is not bool or not isinstance(manifest.get("files"), dict)):
            raise QualificationError("canonical-selected-manifest")
        binaries = {name: manifest["files"].get("bin/" + name) for name in ("panel", "agent", "panelctl")}
        if not all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in binaries.values()):
            raise QualificationError("canonical-selected-binaries")
        before = _canonical_source(source, manifest, environment)
        fixture_path = case / "phase29-fixtures.tsv"
        fixture_bytes = _canonical_read(fixture_path, private=True)
        fixture = fixture_bytes.decode("ascii").splitlines()
        if len(fixture) != 1:
            raise QualificationError("canonical-mailbox-fixture")
        fixture = fixture[0].split("\t")
        if len(fixture) != 2 or not re.fullmatch(r"[1-9][0-9]*", fixture[0]) or not re.fullmatch(r"[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.test", fixture[1]):
            raise QualificationError("canonical-mailbox-fixture")
        envelope_path, execution_path = case / "roundcube-send-read.json", case / "roundcube-send-read.execution.json"
        if any(path.exists() or path.is_symlink() for path in (envelope_path, execution_path)):
            raise QualificationError("canonical-fresh-output")
        if environment.get("NAKPANEL_INTERNAL_TOOLS_RECEIPT", str(envelope_path)) != str(envelope_path):
            raise QualificationError("canonical-receipt-path")
        attempt = case / ".roundcube-canonical-execution"
        attempt.mkdir(mode=0o700)
        _canonical_publish(attempt / "inputs.json", dict(before, manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
                                                        fixture_sha256=hashlib.sha256(fixture_bytes).hexdigest(), bindings=bindings))
        old_flows = set(case.glob(".roundcube-flow.*"))
        child_env = dict(environment, NAKPANEL_INTERNAL_TOOLS_RECEIPT=str(envelope_path))
        env_names = dict(source_vm="NAKPANEL_MULTIPASS_VM", run_token="NAKPANEL_RUN_TOKEN", release="NAKPANEL_MULTIPASS_IMAGE",
                         architecture="NAKPANEL_MULTIPASS_ARCH", profile="NAKPANEL_QUALIFICATION_PROFILE", php_provider="NAKPANEL_QUALIFICATION_PHP_PROVIDER", app_version="NAKPANEL_RELEASE_VERSION")
        child_env.update({name: bindings[field] for field, name in env_names.items()})
        child_env["NAKPANEL_CELL_REPORT_DIR"] = str(case)
        started = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        child_result = _canonical_child(["bash", str(source / "deploy/multipass/internal-tools-verify.sh")], child_env, timeout)
        exit_code = child_result["exit_code"]
        finished = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        identity = {field: bindings[field] for field in ("source_vm", "run_token", "release", "architecture", "profile", "php_provider")}
        identity.update(runtime_commit=manifest["commit"], qualifier_commit=before["commit"])
        _canonical_publish(attempt / "outcome.json", dict(identity, schema="nakpanel-roundcube-canonical-attempt-v1", success=False,
                                                         **child_result, started_at=started, finished_at=finished))
        if (exit_code != 0 or child_result["timed_out"] or child_result["interrupted"]
                or child_result["unexpected_descendants"] or not child_result["owned_group_empty"]):
            raise QualificationError("canonical-child-failed-no-replay")
        if (_canonical_source(source, manifest, environment) != before or _canonical_read(manifest_path) != manifest_bytes
                or _canonical_read(fixture_path, private=True) != fixture_bytes):
            raise QualificationError("canonical-input-changed")
        new_flows = set(case.glob(".roundcube-flow.*")) - old_flows
        if len(new_flows) != 1:
            raise QualificationError("canonical-one-actual-flow")
        flow = new_flows.pop()
        if flow.is_symlink() or not flow.is_dir() or flow.stat().st_uid != os.getuid() or stat.S_IMODE(flow.stat().st_mode) != 0o700:
            raise QualificationError("canonical-private-flow")
        envelope_bytes = _canonical_read(envelope_path, private=True)
        envelope = json.loads(envelope_bytes)
        if canonical_json(envelope) != envelope_bytes:
            raise QualificationError("canonical-envelope-bytes")
        revalidated = attempt / "revalidated-envelope.json"
        enrich(flow, manifest_path, flow / "installed-before.txt", flow / "installed-after.txt", revalidated,
               source / "deploy/multipass/internal-tools-verify.sh", bindings)
        if (_canonical_read(revalidated, private=True) != envelope_bytes
                or envelope.get("runtime_commit") != manifest["commit"] or envelope.get("installed_binary_sha256") != binaries
                or envelope.get("manifest_sha256") != hashlib.sha256(manifest_bytes).hexdigest()
                or envelope["raw_receipt"]["recipient_sha256"] != hashlib.sha256(fixture[1].lower().encode("ascii")).hexdigest()
                or _canonical_source(source, manifest, environment) != before
                or _canonical_read(envelope_path, private=True) != envelope_bytes
                or _canonical_read(manifest_path) != manifest_bytes or _canonical_read(fixture_path, private=True) != fixture_bytes):
            raise QualificationError("canonical-actual-envelope-binding")
        execution = dict(identity, schema="nakpanel-roundcube-supplement-execution-v1", success=True, exit_code=exit_code,
                         qualifier_files_sha256=before["qualifier_files_sha256"], envelope_sha256=hashlib.sha256(envelope_bytes).hexdigest(),
                         started_at=started, finished_at=finished)
        _canonical_publish(execution_path, execution)
        return execution
    except QualificationError:
        raise
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        raise QualificationError("canonical-execution-proof") from None


def canonical_main(argv):
    parser = argparse.ArgumentParser(description="Record one actual complete canonical internal-tools gate")
    parser.parse_args(argv)
    try:
        mapping = dict(source_vm="NAKPANEL_MULTIPASS_VM", run_token="NAKPANEL_RUN_TOKEN", release="NAKPANEL_MULTIPASS_IMAGE",
                       architecture="NAKPANEL_MULTIPASS_ARCH", profile="NAKPANEL_QUALIFICATION_PROFILE", php_provider="NAKPANEL_QUALIFICATION_PHP_PROVIDER", app_version="NAKPANEL_RELEASE_VERSION")
        bindings = {field: os.environ[name] for field, name in mapping.items()}
        execute_canonical(Path(__file__).resolve().parents[2], Path(os.environ["NAKPANEL_RELEASE_BUNDLE"]) / "manifest.json",
                          Path(os.environ["NAKPANEL_CELL_REPORT_DIR"]), bindings)
    except (QualificationError, KeyError):
        print("FAIL canonical internal-tools execution; inspect private gate evidence; never replay", file=sys.stderr)
        return 1
    print("PASS actual canonical internal-tools exit + runtime-bound Roundcube execution receipt")
    return 0


def main():
    if sys.argv[1:2] == ["execute-canonical"]:
        return canonical_main(sys.argv[2:])
    if sys.argv[1:2] == ["enrich"]:
        return enrich_main(sys.argv[2:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--mailbox", required=True)
    parser.add_argument("--password-file", type=Path, required=True)
    parser.add_argument("--imap-ca-file", type=Path, required=True)
    parser.add_argument("--receipt-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    previous_alarm = None
    try:
        if not 0 < args.timeout <= 180:
            raise QualificationError("invalid-deadline")
        info = args.password_file.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 1024:
            raise QualificationError("private-password-file")
        password = args.password_file.read_text()
        if not password or "\n" in password or "\r" in password:
            raise QualificationError("invalid-password-file")
        def expire(_signum, _frame):
            raise QualificationError("deadline")
        def cancel_deadline():
            # Only this CLI owns this alarm. Library callers retain their own
            # process timers; terminal receipt I/O performs no protocol work.
            if signal.getsignal(signal.SIGALRM) is expire:
                signal.setitimer(signal.ITIMER_REAL, 0)
        previous_alarm = signal.signal(signal.SIGALRM, expire)
        # A monotonic budget bounds each operation. This outer wall-clock
        # deadline also interrupts a peer that trickles HTTP headers/body.
        signal.setitimer(signal.ITIMER_REAL, args.timeout)
        qualify(args.base_url, args.host, args.mailbox, password, args.receipt_dir, ca_file=args.imap_ca_file, timeout=args.timeout, cancel_deadline=cancel_deadline)
    except (QualificationError, OSError):
        print("FAIL Roundcube compose/send/read; inspect private status receipt", file=sys.stderr)
        return 1
    finally:
        if previous_alarm is not None:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_alarm)
    print("PASS Roundcube compose/send/read through PHP with one self-send")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
