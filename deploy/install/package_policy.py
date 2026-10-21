#!/usr/bin/env python3
"""Validate the selected APT candidate's recorded repository and release."""
import re
import sys
from urllib.parse import urlparse


def allowed(policy, codename, provider="native", package=""):
    if codename != "resolute":
        return False
    match = re.search(r"^\s*Candidate:\s*(\S+)", policy, re.M)
    if match is None or match[1] == "(none)":
        return False
    candidate = match[1]
    selected = False
    for line in policy.splitlines():
        version = re.fullmatch(r"\s*(?:\*\*\*\s+)?(\S+)\s+-?\d+\s*", line)
        if version:
            selected = version[1] == candidate
            continue
        repository = re.fullmatch(r"\s*-?\d+\s+(https?://\S+)\s+(\S+)\s+\S+\s+Packages\s*", line)
        if not selected or repository is None:
            continue
        url = urlparse(repository[1])
        suite = repository[2].split("/", 1)[0]
        if suite not in (codename, codename + "-updates", codename + "-security", codename + "-backports"):
            continue
        host = url.hostname or ""
        ubuntu = host in ("archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com", "esm.ubuntu.com") or host.endswith(".archive.ubuntu.com")
        sury = (provider == "sury" and codename == "resolute" and suite == "resolute"
                and url.scheme == "https" and host == "packages.sury.org"
                and url.path.rstrip("/") == "/php"
                and re.fullmatch(r"php(?:-common|8\.[345]-[a-z0-9]+)", package))
        if ubuntu or sury:
            return True
    return False


if __name__ == "__main__":
    if len(sys.argv) not in (2, 4) or not allowed(sys.stdin.read(), *sys.argv[1:]):
        sys.exit("platform: selected APT candidate lacks an allowed origin and release")
