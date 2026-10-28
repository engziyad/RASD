#!/usr/bin/env bash
# RASD-Red · T1046 · touch the decoy host the way a scan and a credential guess do:
#   1. a TCP connection to the decoy's SSH port (OpenCanary logs 4000, SSH new connection)
#   2. one login attempt on the decoy web portal, with the run marker as the user name
#      (OpenCanary logs 3001, HTTP POST login attempt, with the marker in logdata.USERNAME)
# --target is the decoy portal's URL (http://<decoy address>); the SSH port is 22 unless --ssh-port says
# otherwise. Nothing is left on the decoy or on this host. Lab use only.
set -euo pipefail
marker=""; confirmed=0; target=""; ssh_port=22
while [[ $# -gt 0 ]]; do
  case "$1" in
    --marker) marker="${2:-}"; shift 2 ;;
    --lab-confirmed) confirmed=1; shift ;;
    --target) target="${2:-}"; shift 2 ;;
    --ssh-port) ssh_port="${2:-}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ "$marker" =~ ^rasd_[0-9a-f]{8}$ ]] || { echo "--marker must look like rasd_1a2b3c4d" >&2; exit 2; }
[[ $confirmed -eq 1 ]] || { echo "Refusing to run without --lab-confirmed." >&2; exit 2; }
[[ "$target" =~ ^https?://[A-Za-z0-9._:\[\]-]+/?$ ]] || { echo "--target must be the decoy portal's URL, e.g. http://10.0.0.40" >&2; exit 2; }
[[ "$ssh_port" =~ ^[0-9]{1,5}$ ]] || { echo "--ssh-port must be a port number" >&2; exit 2; }
# shellcheck source=../lab_guard.sh
source "$(dirname "$0")/../lab_guard.sh"; rasd_assert_lab

host="${target#*://}"; host="${host%%/*}"; host="${host%%:*}"
command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }

# 1. the connection a port scan or an SSH client makes: open and close, nothing sent
if timeout 5 bash -c "exec 3<>/dev/tcp/$host/$ssh_port" 2>/dev/null; then
  echo "connected to $host:$ssh_port (the decoy logs a new SSH connection)"
else
  echo "could not connect to $host:$ssh_port - is the decoy up and its ssh module enabled?" >&2
  exit 1
fi

# 2. one credential guess on the portal: the marker is the user name, so the decoy's record carries it
code=$(curl -sS -o /dev/null -m 10 -w '%{http_code}' -A 'curl/rasd-red' \
       --data-urlencode "username=$marker" --data-urlencode "password=probe" "${target%/}/index.html")
echo "posted one login attempt to ${target%/}/index.html as $marker (HTTP $code)"
