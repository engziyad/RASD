#!/usr/bin/env bash
# RASD-Red collect · cron_persistence. Saves only the marker line of the crontab (never the
# user's other entries) to $RASD_OUT_DIR and prints the file path.
set -euo pipefail
marker=""
while [[ $# -gt 0 ]]; do case "$1" in --marker) marker="${2:-}"; shift 2 ;; *) shift ;; esac; done
[[ "$marker" =~ ^purplelab_[0-9a-f]{8}$ ]] || { echo "--marker must look like purplelab_1a2b3c4d" >&2; exit 2; }
out="${RASD_OUT_DIR:-.}/crontab-$marker.txt"
mkdir -p "$(dirname "$out")"
{ echo "# user: $(id -un)"; crontab -l 2>/dev/null | grep -F -- "$marker" || true; } > "$out"
echo "$out"
