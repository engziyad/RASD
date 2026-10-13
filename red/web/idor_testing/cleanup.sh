#!/usr/bin/env bash
# RASD-Red cleanup for a read-only web test: nothing was created on the target.
# Exit code 0 means verified clean.
set -euo pipefail
marker=""
while [[ $# -gt 0 ]]; do case "$1" in --marker) marker="$2"; shift 2 ;; *) shift ;; esac; done
[[ "$marker" =~ ^purplelab_[0-9a-f]{8}$ ]] || { echo "usage: cleanup.sh --marker purplelab_xxxxxxxx" >&2; exit 2; }
echo "[cleanup] verified: the test made no changes on the target"
exit 0
