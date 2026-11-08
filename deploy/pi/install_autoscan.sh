#!/usr/bin/env bash
# Install (or remove) the Ajar scheduled scan on the Raspberry Pi.
# Run as the normal user that owns the repository (NOT with sudo); it asks for sudo only to
# write the two systemd units.
#   ./deploy/pi/install_autoscan.sh            install + start the timer
#   ./deploy/pi/install_autoscan.sh --remove   stop + remove the timer and service
set -euo pipefail

if [[ $EUID -eq 0 ]]; then
  echo "Rulează ca utilizator normal, nu cu sudo / Run as your normal user, not with sudo." >&2
  exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
UNITS=/etc/systemd/system

if [[ "${1:-}" == "--remove" ]]; then
  sudo systemctl disable --now ajar-autoscan.timer 2>/dev/null || true
  sudo rm -f "$UNITS/ajar-autoscan.timer" "$UNITS/ajar-autoscan.service"
  sudo systemctl daemon-reload
  echo "Scanarea programată a fost oprită și ștearsă / Scheduled scan stopped and removed."
  exit 0
fi

for unit in ajar-autoscan.service ajar-autoscan.timer; do
  sed -e "s|@USER@|$USER|g" -e "s|@REPO@|$REPO|g" "$HERE/$unit" | sudo tee "$UNITS/$unit" > /dev/null
done
chmod 0755 "$HERE/ajar_autoscan.py"
sudo systemctl daemon-reload
sudo systemctl enable --now ajar-autoscan.timer

echo
echo "Instalat pentru $USER, repo $REPO / Installed for $USER, repo $REPO."
echo "Pasul următor / Next: python3 deploy/pi/ajar_autoscan.py consent grant"
systemctl list-timers ajar-autoscan.timer --no-pager || true
