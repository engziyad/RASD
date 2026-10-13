#!/usr/bin/env bash
# RASD-Red cleanup · cron_persistence. Removes every crontab line containing the marker.
# Exit code 0 only when verified clean.
set -euo pipefail
marker=""
while [[ $# -gt 0 ]]; do case "$1" in --marker) marker="${2:-}"; shift 2 ;; *) shift ;; esac; done
[[ "$marker" =~ ^purplelab_[0-9a-f]{8}$ ]] || { echo "--marker must look like purplelab_1a2b3c4d" >&2; exit 2; }
command -v crontab >/dev/null || { echo "[cleanup] verified: crontab is not installed, nothing was added"; exit 0; }
if crontab -l >/dev/null 2>&1; then
  remaining=$(crontab -l 2>/dev/null | grep -v -F -- "$marker" || true)   # read fully before writing
  if [[ -n "$remaining" ]]; then printf '%s\n' "$remaining" | crontab -; else crontab -r 2>/dev/null || printf '' | crontab -; fi
fi
if crontab -l 2>/dev/null | grep -q -F -- "$marker"; then
  echo "[cleanup] the marker entry is still in the crontab" >&2; exit 1
fi
echo "[cleanup] verified: no crontab line contains $marker"
