"""
rasd_web.py - shared plumbing for the RASD-Red web tests (Python 3.9+, standard library only).

Safety first: the machine running a test must be marked as a lab (lab_host_problems, the same
marking the Linux and Windows tests check), and a target is accepted only when every address its
host resolves to is a loopback or private (RFC 1918 / ULA) address. Every connection then goes to the address that
was checked (the name is never resolved again, so a DNS answer that changes mid-run cannot
move the test to another host), redirects are never followed (a 3xx is reported as its
status), and proxy settings from the environment are ignored. The tests are meant for a lab copy of an
application, such as OWASP Juice Shop on localhost - never for a site on the internet.
For a lab in the cloud, reach it through an SSH tunnel to localhost.

Every request carries the run marker in its User-Agent (RASD-Red/<marker>) so the web
server and WAF logs of the run can be found with one search.
"""
from __future__ import annotations

import argparse
import email.message
import http.client
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
    assert_lab_host()
    return lab_target(args.target)


LAB_MARK = Path("/etc/rasd-lab-host")
WINDOWS_MACHINE_ENV = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"


def lab_host_problems() -> list[str]:
    """Why this machine is not marked as a RASD lab; an empty list means it is one. --lab-confirmed
    is typed and cannot tell a lab VM from a work laptop, and an intranet application has a private
    address too, so the machine itself is checked - the same marking as red/linux/lab_guard.sh and
    red/lab/RasdLabGuard.ps1:
      Linux, macOS: /etc/rasd-lab-host exists, is owned by root and names this host;
      Windows: the machine-level variable RASD_LAB_HOST names this computer."""
    if sys.platform == "win32":
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WINDOWS_MACHINE_ENV) as key:
                marked = str(winreg.QueryValueEx(key, "RASD_LAB_HOST")[0]).strip()
        except OSError:
            marked = ""
        computer = os.environ.get("COMPUTERNAME", "")
        if not marked:
            return ["the machine variable RASD_LAB_HOST is not set. On the lab VM only, as administrator: "
                    "[Environment]::SetEnvironmentVariable('RASD_LAB_HOST', $env:COMPUTERNAME, 'Machine')"]
        if marked.lower() != computer.lower():
            return [f"RASD_LAB_HOST is '{marked}' but this computer is '{computer}'"]
        return []
    host = socket.gethostname().split(".")[0]
    if not LAB_MARK.is_file():
        return [f"{LAB_MARK} is missing. On the lab machine only: hostname -s | sudo tee {LAB_MARK} >/dev/null"]
    if LAB_MARK.stat().st_uid != 0:
        return [f"{LAB_MARK} must be owned by root"]
    named = "".join(LAB_MARK.read_text(encoding="utf-8", errors="replace").split())
    if named != host:
        return [f"{LAB_MARK} names '{named}' but this host is '{host}'"]
    return []


def assert_lab_host() -> None:
    problems = lab_host_problems()
    if problems:
        raise Refused("Refusing to run: this machine is not marked as a RASD lab.\n  - " + "\n  - ".join(problems)
                      + "\nSee red/lab/README.md (Lab guard).")


LAB_NETWORKS = [ipaddress.ip_network(n) for n in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                                  "::1/128", "fc00::/7")]


def lab_address(ip) -> bool:
    """Loopback, RFC 1918 or IPv6 ULA only - ipaddress.is_private would also accept link-local,
    documentation (TEST-NET) and benchmarking (198.18/15) ranges, which are not lab hosts."""
    ip = ip.ipv4_mapped or ip if ip.version == 6 else ip
    return any(ip in net for net in LAB_NETWORKS if net.version == ip.version)


_PINNED: dict[str, list[str]] = {}   # host name (lower case) -> the checked addresses, the only ones ever connected to


def lab_target(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise Refused(f"not an http(s) URL: {url}")
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))
    except socket.gaierror as e:
        raise Refused(f"cannot resolve {parts.hostname}: {e}") from e
    addresses = []
    for info in infos:
        ip = ipaddress.ip_address(str(info[4][0]).split("%")[0])
        if not lab_address(ip):
            raise Refused(f"{parts.hostname} resolves to {ip}, which is not a loopback or private address - "
                          "RASD web tests only run against lab targets")
        addresses.append(str(ip))
    if not addresses:
        raise Refused(f"{parts.hostname} resolves to no address")
    _PINNED[parts.hostname.lower()] = list(dict.fromkeys(addresses))
    return url.rstrip("/")


def pinned_addresses(host: str) -> list[str]:
    """The addresses lab_target checked for this host. A host that was never checked - a redirect
    target, a proxy, a name changed after the check - is refused instead of resolved."""
    ips = _PINNED.get(host.strip("[]").lower())
    if not ips:
        raise Refused(f"{host} was not checked by lab_target - refusing to connect")
    return ips


def _connect_pinned(host: str, port: int, timeout, source_address) -> socket.socket:
    """Connect to the first checked address that answers (as urllib would try each resolved one)."""
    last: OSError | None = None
    for ip in pinned_addresses(host):
        try:
            return socket.create_connection((ip, port), timeout, source_address)
        except OSError as e:
            last = e
    raise last or OSError(f"no address for {host}")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = _connect_pinned(self.host, self.port, self.timeout, self.source_address)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        sock = _connect_pinned(self.host, self.port, self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)   # TLS still verifies the name


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_PinnedHTTPConnection, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_PinnedHTTPSConnection, req)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None          # urllib then raises HTTPError: the test records the 3xx and never follows it


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect,
                                     _PinnedHTTPHandler, _PinnedHTTPSHandler)


class Client:
    def __init__(self, base: str, marker: str):
        self.base, self.marker = lab_target(base), marker     # checked (and pinned) here too, whoever built the client
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
        # self.base passed lab_target(): http(s) only, pinned to a loopback or private address
        req = urllib.request.Request(self.base + path, data=body, method=method, headers=h)  # noqa: S310
        try:
            with OPENER.open(req, timeout=15) as r:
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
