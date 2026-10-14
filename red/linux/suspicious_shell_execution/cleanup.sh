#!/usr/bin/env bash
# RASD-Red cleanup · suspicious_shell_execution. Exit code 0 only when verified clean.
set -euo pipefail
marker=""
while [[ $# -gt 0 ]]; do case "$1" in --marker) marker="${2:-}"; shift 2 ;; *) shift ;; esac; done
[[ "$marker" =~ ^rasd_[0-9a-f]{8}$ ]] || { echo "--marker must look like rasd_1a2b3c4d" >&2; exit 2; }
rm -f -- "/tmp/$marker.sh"
[[ ! -e "/tmp/$marker.sh" ]] || { echo "[cleanup] /tmp/$marker.sh still exists" >&2; exit 1; }
echo "[cleanup] verified: /tmp/$marker.sh removed"
