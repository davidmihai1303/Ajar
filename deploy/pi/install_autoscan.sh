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

UNIT_FILES=(ajar-autoscan.service ajar-autoscan.timer ajar-discover.service ajar-discover.timer)
TIMERS=(ajar-autoscan.timer ajar-discover.timer)

if [[ "${1:-}" == "--remove" ]]; then
  sudo systemctl disable --now "${TIMERS[@]}" 2>/dev/null || true
  for unit in "${UNIT_FILES[@]}"; do sudo rm -f "$UNITS/$unit"; done
  sudo systemctl daemon-reload
  echo "Scanările programate au fost oprite și șterse / Scheduled scans stopped and removed."
  exit 0
fi

for unit in "${UNIT_FILES[@]}"; do
  sed -e "s|@USER@|$USER|g" -e "s|@REPO@|$REPO|g" "$HERE/$unit" | sudo tee "$UNITS/$unit" > /dev/null
done
chmod 0755 "$HERE/ajar_autoscan.py"
sudo systemctl daemon-reload
sudo systemctl enable --now "${TIMERS[@]}"

echo
echo "Instalat pentru $USER, repo $REPO / Installed for $USER, repo $REPO."
echo "Important: wrapper-ul root s-a schimbat (modul --discover). Rulează și:"
echo "           the root wrapper changed (--discover mode). Also run:  sudo ./scanner/install.sh $USER"
echo "Pasul următor / Next: python3 deploy/pi/ajar_autoscan.py consent grant"
systemctl list-timers "${TIMERS[@]}" --no-pager || true
