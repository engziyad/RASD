#!/usr/bin/env bash
# RASD-Red cleanup for file_upload_testing.
# The uploaded files live on the target, where this script cannot reach. Exit code 3 tells
# the runner that cleanup needs a manual check: delete every stored file whose name
# contains the marker.
set -euo pipefail
marker=""
while [[ $# -gt 0 ]]; do case "$1" in --marker) marker="$2"; shift 2 ;; *) shift ;; esac; done
[[ "$marker" =~ ^purplelab_[0-9a-f]{8}$ ]] || { echo "usage: cleanup.sh --marker purplelab_xxxxxxxx" >&2; exit 2; }
echo "[cleanup] manual: delete any file on the target whose name contains $marker"
exit 3
