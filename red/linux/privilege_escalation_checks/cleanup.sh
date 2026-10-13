#!/usr/bin/env bash
# RASD-Red cleanup · privilege_escalation_checks. Read-only test: nothing to remove.
set -euo pipefail
marker=""
while [[ $# -gt 0 ]]; do case "$1" in --marker) marker="${2:-}"; shift 2 ;; *) shift ;; esac; done
[[ "$marker" =~ ^purplelab_[0-9a-f]{8}$ ]] || { echo "--marker must look like purplelab_1a2b3c4d" >&2; exit 2; }
echo "[cleanup] verified: read-only test, nothing changed"
