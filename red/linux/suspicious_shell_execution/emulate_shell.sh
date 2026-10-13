#!/usr/bin/env bash
# RASD-Red · T1059.004 · two shell patterns intruders rely on, with harmless payloads:
#   1. a Base64-encoded command piped into sh
#   2. a script written to /tmp, made executable and run from there
# Both only print the run marker. cleanup.sh removes the /tmp script. Lab use only.
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

encoded=$(printf 'echo %s' "$marker" | base64 | tr -d '\n')
echo "$encoded" | base64 -d | sh

script="/tmp/$marker.sh"
printf '#!/bin/sh\necho %s from /tmp\n' "$marker" > "$script"
chmod +x "$script"
"$script"
