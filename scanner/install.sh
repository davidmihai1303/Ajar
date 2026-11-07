#!/usr/bin/env bash
# One-time host setup for the netcheck scanner (Linux). Run from the repo root:
#   sudo ./scanner/install.sh [username]          (default: the user who ran sudo)
#   sudo EXTRA_TCP_PORTS=1883,2323,6379 ./scanner/install.sh    (optional lab ports)
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo ./scanner/install.sh" >&2
  exit 1
fi

TARGET_USER="${1:-${SUDO_USER:-}}"
if [[ -z "$TARGET_USER" || "$TARGET_USER" == "root" ]]; then
  echo "Give the normal user that will run the agent: sudo ./scanner/install.sh <username>" >&2
  exit 1
fi
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[1/5] Packages (nmap, iproute2, iw)"
apt-get install -y nmap iproute2 iw >/dev/null

echo "[2/5] Root wrapper -> /usr/local/sbin/netcheck-nmap (owned by root, not editable by users)"
install -o root -g root -m 0755 "$HERE/netcheck-nmap" /usr/local/sbin/netcheck-nmap

echo "[3/5] Scan output folder -> /var/lib/netcheck/scans"
install -d -o root -g root -m 0755 /var/lib/netcheck /var/lib/netcheck/scans

echo "[4/5] Group 'netcheck' + sudoers rule (wrapper only, never nmap directly)"
getent group netcheck >/dev/null || groupadd --system netcheck
usermod -aG netcheck "$TARGET_USER"
SUDOERS_TMP="$(mktemp)"
echo '%netcheck ALL=(root) NOPASSWD: /usr/local/sbin/netcheck-nmap' > "$SUDOERS_TMP"
visudo -cf "$SUDOERS_TMP" >/dev/null
install -o root -g root -m 0440 "$SUDOERS_TMP" /etc/sudoers.d/netcheck
rm -f "$SUDOERS_TMP"

echo "[5/5] Optional extra TCP ports -> /etc/netcheck/extra_tcp_ports"
install -d -o root -g root -m 0755 /etc/netcheck
if [[ -n "${EXTRA_TCP_PORTS:-}" ]]; then
  printf '%s\n' "$EXTRA_TCP_PORTS" > /etc/netcheck/extra_tcp_ports
  chmod 0644 /etc/netcheck/extra_tcp_ports
fi

echo
echo "Done. Log out and back in (or run: newgrp netcheck) so '$TARGET_USER' joins the group."
echo "Test:  python3 scanner/agent.py network"
echo "       python3 scanner/agent.py scan --confirm"
echo "Undo:  sudo rm /usr/local/sbin/netcheck-nmap /etc/sudoers.d/netcheck && sudo groupdel netcheck"
