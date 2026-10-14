"""
rasd_web.py - shared plumbing for the RASD-Red web tests (Python 3.9+, standard library only).

Safety first: a target is accepted only when every address its host resolves to is a
loopback or private (RFC 1918 / ULA) address. The tests are meant for a lab copy of an
application, such as OWASP Juice Shop on localhost - never for a site on the internet.
For a lab in the cloud, reach it through an SSH tunnel to localhost.

Every request carries the run marker in its User-Agent (RASD-Red/<marker>) so the web
server and WAF logs of the run can be found with one search.
"""
from __future__ import annotations

import argparse
import email.message
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

MARKER_RE = re.compile(r"^rasd_[0-9a-f]{8}$")
PAUSE = 0.2          # seconds between requests: telemetry, not load


class Refused(SystemExit):
    pass


def base_parser(description: str) -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=description)
    ap.add_argument("--target", required=True, help="base URL of the lab application, e.g. http://127.0.0.1:3000")
    ap.add_argument("--marker", required=True, help="run marker (rasd_xxxxxxxx), set by the runner")
    ap.add_argument("--lab-confirmed", action="store_true", help="confirm the target is a lab you own")
    return ap


def check_args(args) -> str:
    if not args.lab_confirmed:
        raise Refused("Refusing to run without --lab-confirmed.")
    if not MARKER_RE.match(args.marker):
        raise Refused("--marker must look like rasd_1a2b3c4d")
    return lab_target(args.target)


LAB_NETWORKS = [ipaddress.ip_network(n) for n in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                                  "::1/128", "fc00::/7")]


def lab_address(ip) -> bool:
    """Loopback, RFC 1918 or IPv6 ULA only - ipaddress.is_private would also accept link-local,
    documentation (TEST-NET) and benchmarking (198.18/15) ranges, which are not lab hosts."""
    ip = ip.ipv4_mapped or ip if ip.version == 6 else ip
    return any(ip in net for net in LAB_NETWORKS if net.version == ip.version)


def lab_target(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise Refused(f"not an http(s) URL: {url}")
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))
    except socket.gaierror as e:
        raise Refused(f"cannot resolve {parts.hostname}: {e}") from e
    for info in infos:
        ip = ipaddress.ip_address(str(info[4][0]).split("%")[0])
        if not lab_address(ip):
            raise Refused(f"{parts.hostname} resolves to {ip}, which is not a loopback or private address - "
                          "RASD web tests only run against lab targets")
    return url.rstrip("/")


class Client:
    def __init__(self, base: str, marker: str):
        self.base, self.marker = base, marker
        self.log: list[dict] = []

    def request(self, method: str, path: str, *, token: str | None = None, json_body=None,
                body: bytes | None = None, headers: dict | None = None) -> tuple[int, email.message.Message, bytes]:
        """Status, response headers and body. The headers keep every value of a repeated
        header - use headers.get_all("Set-Cookie") - and are looked up case-insensitively."""
        h = {"User-Agent": f"RASD-Red/{self.marker}", "Accept": "application/json"}
        if token is not None:
            h["Authorization"] = f"Bearer {token}"
        if json_body is not None:
            body = json.dumps(json_body).encode()
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        # self.base passed lab_target(): http(s) only, resolving to loopback or private addresses
        req = urllib.request.Request(self.base + path, data=body, method=method, headers=h)  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310
                status, rh, data = r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            status, rh, data = e.code, e.headers or email.message.Message(), e.read() or b""
        except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
            status, rh, data = 0, email.message.Message(), str(e).encode()
        self.log.append({"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "method": method,
                         "path": path, "status": status})
        time.sleep(PAUSE)
        return status, rh, data

    def login(self, email: str, password: str) -> dict:
        status, _h, data = self.request("POST", "/rest/user/login", json_body={"email": email, "password": password})
        if status != 200:
            raise SystemExit(f"login failed for {email} (HTTP {status}) - check RASD_LAB_EMAIL / RASD_LAB_PASSWORD")
        return json.loads(data).get("authentication", {})


def lab_credentials() -> tuple[str, str]:
    email, password = os.environ.get("RASD_LAB_EMAIL"), os.environ.get("RASD_LAB_PASSWORD")
    if not email or not password:
        raise Refused("set RASD_LAB_EMAIL and RASD_LAB_PASSWORD to a lab test account (never a real one)")
    return email, password


def report(test: str, marker: str, findings: list[dict], client: Client) -> int:
    """Print the findings, save them for the runner, and return the exit code (0 = test ran)."""
    issues = [f for f in findings if f["result"] == "FINDING"]
    for f in findings:
        print(f"  {f['result']:<8} {f['check']}: {f['detail']}")
    print(f"{len(findings)} check(s), {len(issues)} finding(s)")
    out_dir = os.environ.get("RASD_OUT_DIR")
    if out_dir:
        path = Path(out_dir) / f"{test}-findings.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"test": test, "marker": marker, "target": client.base, "findings": findings,
                                    "requests": client.log}, indent=2) + "\n", encoding="utf-8")
        print(str(path))
    return 0


def run(main) -> None:
    try:
        sys.exit(main())
    except Refused as e:
        print(f"refused: {e.code}", file=sys.stderr)
        sys.exit(2)
