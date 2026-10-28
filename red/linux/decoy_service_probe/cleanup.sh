#!/usr/bin/env bash
# RASD-Red cleanup · decoy_service_probe. Exit code 0 only when verified clean.
# The probe opens one TCP connection and sends one HTTP request; nothing is written on this host or on the
# decoy (the decoy's log entries are the point). Nothing to remove, so this verifies and exits 0.
set -euo pipefail
marker=""
while [[ $# -gt 0 ]]; do case "$1" in --marker) marker="${2:-}"; shift 2 ;; *) shift ;; esac; done
[[ "$marker" =~ ^rasd_[0-9a-f]{8}$ ]] || { echo "--marker must look like rasd_1a2b3c4d" >&2; exit 2; }
echo "[cleanup] verified: nothing persisted (one connection and one request; the decoy keeps the records)"
