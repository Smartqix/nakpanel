#!/usr/bin/env python3
import hashlib
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

OUTPUT = os.environ.get("WEBHOOK_SINK_OUTPUT", "/tmp/phase20-webhooks.jsonl")
SECRET = os.environ["WEBHOOK_SINK_SECRET"].encode()


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        timestamp = self.headers.get("X-Nakpanel-Timestamp", "")
        supplied = self.headers.get("X-Nakpanel-Signature", "")
        expected = "sha256=" + hmac.new(SECRET, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
        record = {
            "event": self.headers.get("X-Nakpanel-Event", ""),
            "delivery": self.headers.get("X-Nakpanel-Delivery", ""),
            "valid": hmac.compare_digest(supplied, expected),
            "body": json.loads(body),
        }
        with open(OUTPUT, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, separators=(",", ":")) + "\n")
        self.send_response(204)
        self.end_headers()

    def log_message(self, _format, *_args):
        return


HTTPServer(("127.0.0.1", 18080), Handler).serve_forever()
