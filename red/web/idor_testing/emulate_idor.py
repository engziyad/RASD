#!/usr/bin/env python3
"""
RASD-Red · object-level authorization (OWASP API1:2023 BOLA / IDOR).

Logs in as one lab test account, then reads the basket of every ID in a small range with
that account's token. Any basket other than the account's own that comes back 200 is a
FINDING. One login, then read-only GET requests against a lab target (see rasd_web.py). Credentials come
from RASD_LAB_EMAIL / RASD_LAB_PASSWORD so they never appear on a command line.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rasd_web


def main() -> int:
    ap = rasd_web.base_parser(__doc__)
    ap.add_argument("--path", default="/rest/basket/{id}", help="object path with {id} (default: Juice Shop basket)")
    ap.add_argument("--max-id", type=int, default=5, help="highest object ID to request (default 5, at most 20)")
    args = ap.parse_args()
    target = rasd_web.check_args(args)
    if not 1 <= args.max_id <= 20:
        raise rasd_web.Refused("--max-id must be between 1 and 20")
    client = rasd_web.Client(target, args.marker)
    auth = client.login(*rasd_web.lab_credentials())
    token, own = auth.get("token"), auth.get("bid")
    findings = []
    for oid in range(1, args.max_id + 1):
        path = args.path.format(id=oid)
        status, _h, _b = client.request("GET", path, token=token)
        if oid == own:
            findings.append({"check": f"GET {path} (own object)", "result": "INFO", "detail": f"HTTP {status}"})
        elif status == 200:
            findings.append({"check": f"GET {path} (another user's object)", "result": "FINDING",
                             "detail": "HTTP 200: object served to a user who does not own it"})
        else:
            findings.append({"check": f"GET {path} (another user's object)", "result": "PASS", "detail": f"HTTP {status}"})
    return rasd_web.report("idor_testing", args.marker, findings, client)


if __name__ == "__main__":
    rasd_web.run(main)
