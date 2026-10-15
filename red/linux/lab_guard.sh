#!/usr/bin/env bash
# RASD lab guard for the Linux tests: --lab-confirmed is typed, this checks the machine itself.
# The lab VM's owner marks it once, as root (never on a work machine):
#   hostname -s | sudo tee /etc/rasd-lab-host >/dev/null
# The file must be owned by root and name this host, so a copied file or a renamed VM refuses.
rasd_assert_lab() {
  local f=/etc/rasd-lab-host host named
  host=$(hostname -s 2>/dev/null || hostname)
  if [[ ! -f $f ]]; then
    echo "Refusing to run: this host is not marked as a RASD lab ($f is missing)." >&2
    echo "On the lab VM only: hostname -s | sudo tee $f >/dev/null   (see red/lab/README.md, Lab guard)" >&2
    exit 2
  fi
  if [[ "$(stat -c %u "$f")" != "0" ]]; then
    echo "Refusing to run: $f must be owned by root." >&2; exit 2
  fi
  named=$(tr -d '[:space:]' < "$f")
  if [[ "$named" != "$host" ]]; then
    echo "Refusing to run: $f names '$named' but this host is '$host'." >&2; exit 2
  fi
}
