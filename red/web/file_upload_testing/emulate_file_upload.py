#!/usr/bin/env python3
"""
RASD-Red · file upload restrictions (unrestricted upload, the path to web shells).

Uploads small, harmless text files that a strict upload handler must refuse: a disallowed
extension, a double extension, a spoofed content type, and an oversized file. Each file
contains only a harmless sentence with the run marker (the oversized file repeats it). Any
upload accepted with 2xx is a FINDING.
Lab targets only (see rasd_web.py).
"""
from __future__ import annotations

import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rasd_web


def multipart(field: str, filename: str, content_type: str, data: bytes) -> tuple[bytes, str]:
    boundary = f"----rasd{uuid.uuid4().hex}"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\n"
            f"Content-Type: {content_type}\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


def main() -> int:
    ap = rasd_web.base_parser(__doc__)
    ap.add_argument("--path", default="/file-upload", help="upload endpoint (default: Juice Shop complaint upload)")
    ap.add_argument("--field", default="file", help="multipart field name (default: file)")
    ap.add_argument("--max-bytes", type=int, default=100_000, help="the size limit the application claims (default 100 kB)")
    args = ap.parse_args()
    target = rasd_web.check_args(args)
    client = rasd_web.Client(target, args.marker)
    note = f"RASD-Red upload test {args.marker} - harmless text\n".encode()
    cases = [
        ("disallowed extension", f"{args.marker}.exe", "application/octet-stream", note),
        ("double extension", f"{args.marker}.pdf.exe", "application/pdf", note),
        ("content type spoofed as PDF", f"{args.marker}.html", "application/pdf", note),
        ("over the size limit", f"{args.marker}.pdf", "application/pdf", note * (args.max_bytes // len(note) + 2)),
    ]
    findings = []
    for label, filename, ctype, data in cases:
        body, header = multipart(args.field, filename, ctype, data)
        status, _h, _b = client.request("POST", args.path, body=body, headers={"Content-Type": header})
        result = "FINDING" if 200 <= status < 300 else ("ERROR" if status == 0 else "PASS")
        findings.append({"check": f"upload {filename} ({label}, {len(data)} bytes)", "result": result,
                         "detail": f"HTTP {status}"})
    return rasd_web.report("file_upload_testing", args.marker, findings, client)


if __name__ == "__main__":
    rasd_web.run(main)
