#!/usr/bin/env bash
# RASD-Red · T1053.003 · user crontab entry that only echoes the run marker.
# Adds one line to the current user's crontab: every 30 minutes, echo the marker to /dev/null.
# cleanup.sh removes exactly that line. Lab use only.
set -euo pipefail
marker=""; confirmed=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --marker) marker="${2:-}"; shift 2 ;;
    --lab-confirmed) confirmed=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ "$marker" =~ ^purplelab_[0-9a-f]{8}$ ]] || { echo "--marker must look like purplelab_1a2b3c4d" >&2; exit 2; }
[[ $confirmed -eq 1 ]] || { echo "Refusing to run without --lab-confirmed." >&2; exit 2; }
command -v crontab >/dev/null || { echo "crontab is not installed - install cron (Debian/Ubuntu) or cronie (RHEL) on the lab host" >&2; exit 2; }

entry="*/30 * * * * /bin/echo $marker >/dev/null 2>&1 # $marker"
current=$(crontab -l 2>/dev/null || true)          # read fully before writing: never race the install
if [[ -n "$current" ]]; then printf '%s\n%s\n' "$current" "$entry"; else printf '%s\n' "$entry"; fi | crontab -
echo "added crontab entry: $entry"
