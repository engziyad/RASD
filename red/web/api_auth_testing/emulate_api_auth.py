#!/usr/bin/env python3
"""
RASD-Red · API authentication enforcement (OWASP API2:2023 Broken Authentication).

Calls each protected endpoint three ways - no token, a malformed token, and a well-formed
JWT signed with a key the server never issued - and reports any response that is not
401/403 as a FINDING. Read-only GET requests. Lab targets only (see rasd_web.py).
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rasd_web  # noqa: E402

DEFAULT_ENDPOINTS = ["/rest/basket/1", "/api/Cards", "/api/Users", "/api/Addresss", "/rest/wallet/balance",
                     "/rest/user/authentication-details"]       # protected in OWASP Juice Shop 17


def b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")


def main() -> int:
    ap = rasd_web.base_parser(__doc__)
    ap.add_argument("--endpoints", help="comma-separated protected paths (default: Juice Shop examples)")
    args = ap.parse_args()
    target = rasd_web.check_args(args)
    client = rasd_web.Client(target, args.marker)
    endpoints = [e.strip() for e in (args.endpoints.split(",") if args.endpoints else DEFAULT_ENDPOINTS) if e.strip()]
    foreign = f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64({'data': {'email': 'nobody@lab.local'}})}.c2lnbmF0dXJl"
    tokens = {"no token": None, "malformed token": "not-a-jwt", "foreign-signed JWT": foreign}
    findings = []
    for path in endpoints:
        for label, token in tokens.items():
            status, _h, _b = client.request("GET", path, token=token)
            if status in (401, 403):
                result, detail = "PASS", f"HTTP {status}"
            elif status == 0:
                result, detail = "ERROR", "no response (the application may have crashed - check its log)"
            elif 200 <= status < 300:
                result, detail = "FINDING", f"HTTP {status}: protected data served"
            else:
                result, detail = "REVIEW", f"HTTP {status}: not an explicit 401/403"
            findings.append({"check": f"GET {path} with {label}", "result": result, "detail": detail})
    return rasd_web.report("api_auth_testing", args.marker, findings, client)


if __name__ == "__main__":
    rasd_web.run(main)
