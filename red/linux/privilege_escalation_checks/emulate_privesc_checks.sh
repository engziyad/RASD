#!/usr/bin/env bash
# RASD-Red · T1083 / T1548 · read-only privilege-escalation reconnaissance.
# Runs the checks enumeration scripts start with - sudo rights, SUID binaries, file
# capabilities, sensitive file permissions, writable PATH entries - prints counts and
# saves the lists to $RASD_OUT_DIR. Changes nothing. Lab use only.
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

out="${RASD_OUT_DIR:-}"
save() { if [[ -n "$out" ]]; then mkdir -p "$out"; cat > "$out/$1"; echo "$out/$1" >> "$out/.paths"; else cat >/dev/null; fi; }

echo "user: $(id)"
echo "kernel: $(uname -r)"
sudo_rights=$(sudo -n -l 2>&1 || true)
echo "$sudo_rights" | save "sudo-l-$marker.txt"
echo "sudo -n -l: $(echo "$sudo_rights" | head -1)"
suid=$(find / -xdev -perm -4000 -type f 2>/dev/null || true)
echo "$suid" | save "suid-$marker.txt"
echo "SUID binaries: $(echo "$suid" | grep -c . || true)"
if command -v getcap >/dev/null; then
  caps=$(getcap -r / 2>/dev/null || true)
  echo "$caps" | save "capabilities-$marker.txt"
  echo "files with capabilities: $(echo "$caps" | grep -c . || true)"
fi
for f in /etc/passwd /etc/shadow /etc/sudoers; do
  [[ -e "$f" ]] && echo "$(stat -c '%A %U:%G' "$f") $f $([[ -w "$f" ]] && echo WRITABLE || true)"
done
writable=""
IFS=: read -r -a dirs <<< "$PATH"
for d in "${dirs[@]}"; do [[ -d "$d" && -w "$d" ]] && writable+="$d "; done
echo "writable PATH directories: ${writable:-none}"
if [[ -n "$out" && -f "$out/.paths" ]]; then cat "$out/.paths"; rm -f "$out/.paths"; fi
