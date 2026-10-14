#!/usr/bin/env python3
"""
RASD-Red · HTTP security headers and cookie flags (configuration review).

Fetches the start page and reports which browser protections the response sets:
HSTS (HTTPS only), Content-Security-Policy, X-Content-Type-Options, clickjacking
protection, Referrer-Policy, Permissions-Policy, and the Secure / HttpOnly / SameSite
flags of every cookie. One GET request. Lab targets only (see rasd_web.py).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rasd_web


def cookie_attributes(set_cookie: str) -> tuple[str, set[str]]:
    """Cookie name and its attribute names. Only the parts after the first ';' are
    attributes, so a value that merely contains 'secure' does not count as the flag."""
    pair, _, rest = set_cookie.partition(";")
    attrs = {a.split("=", 1)[0].strip().lower() for a in rest.split(";") if a.strip()}
    return pair.split("=", 1)[0].strip(), attrs


def main() -> int:
    ap = rasd_web.base_parser(__doc__)
    ap.add_argument("--path", default="/", help="page to fetch (default /)")
    args = ap.parse_args()
    target = rasd_web.check_args(args)
    client = rasd_web.Client(target, args.marker)
    status, headers, _b = client.request("GET", args.path)
    h = {k.lower(): v for k, v in headers.items()}
    findings = [{"check": f"GET {args.path}", "result": "INFO", "detail": f"HTTP {status}"}]

    def need(name: str, ok, detail_ok: str, detail_bad: str):
        findings.append({"check": name, "result": "PASS" if ok else "FINDING", "detail": detail_ok if ok else detail_bad})

    if target.startswith("https://"):
        need("Strict-Transport-Security", "strict-transport-security" in h, h.get("strict-transport-security", ""), "missing")
    csp = h.get("content-security-policy", "")
    need("Content-Security-Policy", bool(csp), csp[:80], "missing")
    need("X-Content-Type-Options", h.get("x-content-type-options", "").lower() == "nosniff", "nosniff", "missing or not nosniff")
    frame_ok = h.get("x-frame-options", "").upper() in ("DENY", "SAMEORIGIN") or "frame-ancestors" in csp
    need("Clickjacking protection", frame_ok, h.get("x-frame-options", "frame-ancestors"), "no X-Frame-Options or CSP frame-ancestors")
    need("Referrer-Policy", "referrer-policy" in h, h.get("referrer-policy", ""), "missing")
    need("Permissions-Policy", "permissions-policy" in h, h.get("permissions-policy", "")[:80], "missing")
    for c in headers.get_all("Set-Cookie") or []:          # every cookie, not only the first header
        name, attrs = cookie_attributes(c)
        missing = [f for f in ("secure", "httponly", "samesite") if f not in attrs]
        if target.startswith("http://") and missing == ["secure"]:
            detail = "Secure is missing - expected on plain HTTP in a lab; required in production"
        else:
            detail = f"missing {', '.join(missing)}"
        need(f"cookie {name}", not missing, "Secure, HttpOnly, SameSite", detail)
    return rasd_web.report("security_headers_testing", args.marker, findings, client)


if __name__ == "__main__":
    rasd_web.run(main)
