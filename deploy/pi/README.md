# Ajar pe Raspberry Pi: scanare programată cu acord legat de rețea

Etapa 1: Pi-ul face o **scanare completă la 3 ore**, dar **doar în rețeaua pentru care ai dat acordul**.
În orice altă rețea (Wi-Fi-ul sălii, la un prieten, la hotel) refuză și scrie motivul în log.

## De ce un acord legat de rețea

Brief-ul cere confirmare explicită pentru orice scanare live (FR-02). O scanare programată nu are pe
nimeni care să confirme, așa că proprietarul confirmă **o singură dată pentru fiecare rețea**:

| Ce se salvează | De ce |
|---|---|
| numele Wi-Fi + subnetul + IP-ul routerului | rețeaua confirmată |
| **amprenta routerului**: HMAC-SHA256(cheie locală, MAC router) | toate hotspoturile de iPhone au `172.20.10.0/28`, iar numele Wi-Fi poate fi copiat. MAC-ul routerului **nu** e salvat |
| data expirării (implicit 30 de zile) | acordul nu rămâne valabil la nesfârșit |

Fișierele stau în `~/.config/ajar/` (`consent.json`, `consent.key`), cu drepturi `0600`.

## Cum funcționează

```
timer (la 3 ore) ──► ajar_autoscan.py run
                       ├─ GET  http://127.0.0.1:8001/api/network
                       ├─ amprenta routerului (ip neigh) == cea din acord?  și acordul nu a expirat?
                       │     NU ─► „Scanare sărită" în log, nimic trimis
                       │     DA ─► POST /api/scans  (aceeași cale ca butonul din UI:
                       │                             agent → gardă → netcheck-nmap → istoric)
                       └─ în log: scorul și numărul de probleme
```

Nu schimbă aplicația și nu rulează nimic ca root. Scanarea trece prin aceeași gardă și același wrapper ca
o scanare manuală, iar rezultatul apare în **Istoric** ca orice scanare.

## Instalare (o singură dată)

Ai nevoie de aplicație (containerul pe `127.0.0.1:8001`) și de serviciul `netcheck-agent`, ambele pornite.

```bash
cd ~/Smarthack
./deploy/pi/install_autoscan.sh                  # fără sudo; cere parola doar pentru systemd
python3 deploy/pi/ajar_autoscan.py consent grant # arată rețeaua, scrii DA
```

## Comenzi

| Comandă | Ce face |
|---|---|
| `python3 deploy/pi/ajar_autoscan.py consent grant [--days 30]` | dă acordul pentru rețeaua curentă (interactiv) |
| `python3 deploy/pi/ajar_autoscan.py consent show` | rețelele cu acord și data expirării |
| `python3 deploy/pi/ajar_autoscan.py consent revoke` | retrage acordul pentru rețeaua curentă |
| `python3 deploy/pi/ajar_autoscan.py consent revoke --all` | retrage toate acordurile |
| `python3 deploy/pi/ajar_autoscan.py check` | spune dacă o scanare ar rula acum (nu scanează) |
| `sudo systemctl start ajar-autoscan.service` | pornește o scanare programată **acum** (test) |
| `journalctl -u ajar-autoscan -n 20 --no-pager` | log: scanări rulate sau sărite și motivul |
| `systemctl list-timers ajar-autoscan.timer` | când rulează următoarea scanare |
| `./deploy/pi/install_autoscan.sh --remove` | oprește și șterge scanarea programată |

## Interval mai scurt pentru demo

```bash
sudo systemctl edit ajar-autoscan.timer
```
```ini
[Timer]
OnUnitActiveSec=
OnUnitActiveSec=10min
```
Revii la 3 ore cu `sudo systemctl revert ajar-autoscan.timer`.

## Test: altă rețea este refuzată

1. `consent grant` pe hotspotul echipei.
2. Muți Pi-ul pe alt hotspot (alt telefon).
3. `python3 deploy/pi/ajar_autoscan.py check` → „Scanarea automată NU ar rula (no consent for this network)".
4. Același nume Wi-Fi și același subnet, dar alt telefon → refuzat cu motivul `different gateway_fp`.

## Teste

```bash
python3 -m unittest discover -s deploy/pi/tests -v   # 19 teste, doar biblioteca standard, nu scanează nimic
```

## Reguli

- Doar rețele proprii sau cu permisiunea proprietarului. Acasă, cere acordul celor din casă.
- La hackathon, Pi-ul stă doar pe hotspotul echipei.
- Nu rula scriptul ca root (refuză singur).
