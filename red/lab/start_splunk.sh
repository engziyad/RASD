#!/usr/bin/env bash
# start_splunk.sh - a Splunk Enterprise container beside a Linux lab host, with the RASD apps in it.
#
#   export SPLUNK_PASSWORD=...          # the admin password of this lab Splunk: yours to choose
#   SPLUNK_TERMS=accept red/lab/start_splunk.sh <image> <feed folder> <inputs app folder>
#
# Starting Splunk Enterprise means accepting its licence and the Splunk General Terms
# (https://www.splunk.com/en_us/legal/splunk-general-terms.html). Nobody can do that for you:
# the script starts nothing until SPLUNK_TERMS=accept says the person running it has read them.
#
# What it does, on a host its owner marked as a RASD lab:
#   - starts the container; no port is published, the lab host reaches it on the Docker bridge
#   - mounts the feed folder read-only at /lab (the files the inputs app tells Splunk to read)
#   - copies in queries/splunk_app/rasd, queries/splunk_app/rasd_fields and the inputs app
#   - restarts Splunk and prints the management URL as the last line
# A fresh Splunk Enterprise runs as a trial, which schedules alerts; Splunk Free does not.
# Remove it with: docker rm --force rasd-splunk
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=../linux/lab_guard.sh
source "$here/../linux/lab_guard.sh"; rasd_assert_lab

if [[ $# -ne 3 ]]; then
  echo "usage: SPLUNK_TERMS=accept SPLUNK_PASSWORD=... $0 <image> <feed folder> <inputs app folder>" >&2
  exit 2
fi
image=$1 feed=$2 inputs=$3
name=rasd-splunk
apps="$here/../../queries/splunk_app"

if [[ "${SPLUNK_TERMS:-}" != "accept" ]]; then
  echo "Refusing to start Splunk: it runs under the Splunk General Terms and its licence." >&2
  echo "Read https://www.splunk.com/en_us/legal/splunk-general-terms.html and, if you accept them, set SPLUNK_TERMS=accept." >&2
  exit 2
fi
if [[ -z "${SPLUNK_PASSWORD:-}" ]]; then
  echo "Set SPLUNK_PASSWORD in the environment: the admin password this lab Splunk starts with." >&2
  exit 2
fi
for folder in "$feed" "$inputs/default" "$apps/rasd/default" "$apps/rasd_fields/default"; do
  if [[ ! -d "$folder" ]]; then echo "Missing folder: $folder" >&2; exit 2; fi
done

docker pull --quiet "$image" >&2
docker run --detach --name "$name" --hostname "$name" \
  --env SPLUNK_START_ARGS=--accept-license \
  --env SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com \
  --env SPLUNK_PASSWORD \
  --volume "$feed:/lab:ro" "$image" >/dev/null

state=starting
for _ in $(seq 1 120); do
  state=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$name" 2>/dev/null || echo gone)
  running=$(docker inspect --format '{{.State.Running}}' "$name" 2>/dev/null || echo false)
  if [[ "$state" == healthy || "$running" != true ]]; then break; fi
  sleep 5
done
if [[ "$state" != healthy ]]; then
  echo "Splunk did not come up (state: $state). The end of its log:" >&2
  docker logs --tail 80 "$name" >&2 || true
  exit 1
fi

for app in "$apps/rasd" "$apps/rasd_fields" "$inputs"; do
  docker cp "$app" "$name:/opt/splunk/etc/apps/" >&2
  docker exec --user root "$name" chown -R splunk:splunk "/opt/splunk/etc/apps/$(basename "$app")"
done
docker exec --user splunk "$name" /opt/splunk/bin/splunk restart >&2

address=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name")
if [[ -z "$address" ]]; then echo "The container has no address on the Docker bridge." >&2; exit 1; fi
echo "https://$address:8089"
