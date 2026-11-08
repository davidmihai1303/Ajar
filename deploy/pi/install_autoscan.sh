#!/usr/bin/env bash
# Install (or remove) Ajar's background services on the Raspberry Pi.
# Run as the normal user that owns the repository (NOT with sudo); it asks for sudo only to
# write the systemd units (and the optional avahi announcement).
#
#   ./deploy/pi/install_autoscan.sh              full scan every 3 h + new-device watch + phone events
#   ./deploy/pi/install_autoscan.sh --announce   same, plus the mDNS announcement _ajar._tcp
#   ./deploy/pi/install_autoscan.sh --remove     stop and remove everything above
set -euo pipefail

if [[ $EUID -eq 0 ]]; then
  echo "Rulează ca utilizator normal, nu cu sudo / Run as your normal user, not with sudo." >&2
  exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
UNITS=/etc/systemd/system
AVAHI=/etc/avahi/services/ajar.service

UNIT_FILES=(ajar-autoscan.service ajar-autoscan.timer ajar-watch.service ajar-notify.service)
LEGACY=(ajar-discover.timer ajar-discover.service)    # stage 2, replaced by ajar-watch.service
TOKEN="${AJAR_STATE_DIR:-$HOME/.config/ajar}/notify.token"

remove_legacy() {
  sudo systemctl disable --now "${LEGACY[@]}" 2>/dev/null || true
  for unit in "${LEGACY[@]}"; do sudo rm -f "$UNITS/$unit"; done
}

if [[ "${1:-}" == "--remove" ]]; then
  sudo systemctl disable --now ajar-autoscan.timer ajar-watch.service ajar-notify.service 2>/dev/null || true
  for unit in "${UNIT_FILES[@]}"; do sudo rm -f "$UNITS/$unit"; done
  remove_legacy
  if [[ -f "$AVAHI" ]]; then sudo rm -f "$AVAHI"; sudo systemctl restart avahi-daemon || true; fi
  sudo systemctl daemon-reload
  echo "Serviciile Ajar au fost oprite și șterse / Ajar services stopped and removed."
  exit 0
fi

remove_legacy
for unit in "${UNIT_FILES[@]}"; do
  sed -e "s|@USER@|$USER|g" -e "s|@REPO@|$REPO|g" "$HERE/$unit" | sudo tee "$UNITS/$unit" > /dev/null
done
chmod 0755 "$HERE/ajar_autoscan.py" "$HERE/ajar_notify.py"
sudo systemctl daemon-reload
sudo systemctl enable --now ajar-autoscan.timer ajar-watch.service

if [[ -f "$TOKEN" ]]; then
  sudo systemctl enable --now ajar-notify.service
  sudo systemctl restart ajar-notify.service
else
  echo "Serviciul pentru telefon pornește după împerechere / The phone service starts after pairing:"
  echo "  python3 deploy/pi/ajar_notify.py pair && sudo systemctl enable --now ajar-notify.service"
fi

if [[ "${1:-}" == "--announce" ]]; then
  sudo install -m 0644 "$HERE/avahi-ajar.service" "$AVAHI"
  sudo systemctl restart avahi-daemon
  echo "Anunț mDNS activ / mDNS announcement active: _ajar._tcp port 8002"
fi

echo
echo "Instalat pentru $USER, repo $REPO / Installed for $USER, repo $REPO."
echo "Important: wrapper-ul root are modul --discover. Dacă nu l-ai reinstalat / if not reinstalled yet:"
echo "  sudo ./scanner/install.sh $USER && sudo systemctl restart netcheck-agent"
echo "Acordul pentru rețea / Network consent: python3 deploy/pi/ajar_autoscan.py consent grant"
systemctl list-timers ajar-autoscan.timer --no-pager || true
systemctl --no-pager --lines=0 status ajar-watch.service ajar-notify.service || true
