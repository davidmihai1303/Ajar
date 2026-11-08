# Ajar pe Raspberry Pi: scanare programată cu acord legat de rețea

- **Etapa 1:** o **scanare completă la 3 ore**.
- **Etapa 2:** la **10 minute**, o verificare rapidă: **cine e conectat** (fără porturi). Un device nou e
  scris în log și pornește o scanare completă (cel mult una la 30 de minute), ca să vezi ce porturi are.

Ambele rulează **doar în rețeaua pentru care ai dat acordul**. În orice altă rețea (Wi-Fi-ul sălii,
la un prieten, la hotel) refuză și scriu motivul în log.

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

## Etapa 2: device-uri noi (la 10 minute)

```
timer (la 10 min) ──► ajar_autoscan.py discover
                        ├─ acordul se potrivește? (la fel ca la etapa 1)      NU ─► sărit, motiv în log
                        ├─ POST http://127.0.0.1:8765/discover   (agentul, aceleași protecții ca /scan)
                        │     └─ sudo netcheck-nmap --discover <subnet>
                        │           nmap -sn -n --max-rate 100   (cine e conectat; fără porturi, fără DNS,
                        │                                          nimic scris pe disc)
                        ├─ fiecare MAC → amprentă HMAC (MAC-ul nu e salvat) → comparat cu inventarul rețelei
                        └─ device nou ─► „DISPOZITIV NOU în rețea: <producător>, IP …" în log
                                         + o scanare completă (dacă n-a fost una în ultimele 30 de minute)
```

- Prima rulare pe o rețea doar **notează ce e conectat** (inventar inițial), fără alertă.
- Inventarul e **separat pe fiecare rețea** (`~/.config/ajar/devices.json`, `0600`, doar amprente).
- Un device nevăzut 30 de zile e uitat; dacă revine, apare din nou ca nou.
- Telefoanele cu adresă Wi-Fi aleatorie o păstrează de obicei pe aceeași rețea, deci sunt recunoscute.
  Un telefon care își schimbă adresa aleatorie apare ca device nou.

## Instalare (o singură dată)

Ai nevoie de aplicație (containerul pe `127.0.0.1:8001`) și de serviciul `netcheck-agent`, ambele pornite.

```bash
cd ~/Smarthack
sudo ./scanner/install.sh $USER                  # wrapper-ul root s-a schimbat (modul --discover)
sudo systemctl restart netcheck-agent            # agentul are endpoint-ul nou /discover
./deploy/pi/install_autoscan.sh                  # fără sudo; instalează ambele timere
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
| `python3 deploy/pi/ajar_autoscan.py discover --no-scan` | verificarea de device-uri noi, acum, fără scanare completă |
| `python3 scanner/agent.py discover --confirm` | cine e conectat (MAC-uri afișate mascat) |
| `sudo systemctl start ajar-autoscan.service` | pornește o scanare completă programată **acum** (test) |
| `sudo systemctl start ajar-discover.service` | pornește verificarea de device-uri noi **acum** (test) |
| `journalctl -u ajar-autoscan -u ajar-discover -n 30 --no-pager` | log: ce a rulat sau a fost sărit, device-uri noi |
| `systemctl list-timers 'ajar-*'` | când rulează următoarele verificări |
| `./deploy/pi/install_autoscan.sh --remove` | oprește și șterge ambele timere |

## Interval mai scurt pentru demo

```bash
sudo systemctl edit ajar-autoscan.timer
```
```ini
[Timer]
OnUnitActiveSec=
OnUnitActiveSec=10min
```
Revii la 3 ore cu `sudo systemctl revert ajar-autoscan.timer`. La fel pentru verificarea de device-uri
noi (de exemplu la 1 minut, ca la demo să apară repede):
```bash
sudo systemctl edit ajar-discover.timer     # [Timer] / OnUnitActiveSec= / OnUnitActiveSec=1min
```

## Test: un device nou e observat

1. `consent grant`, apoi `sudo systemctl start ajar-discover.service` → în log: „Inventar inițial: N dispozitive".
2. Conectezi la hotspot un device care nu era (un telefon, un laptop).
3. `sudo systemctl start ajar-discover.service` → „DISPOZITIV NOU în rețea: <producător>, IP …",
   apoi pornește o scanare completă, care apare în **Istoric**.

## Test: altă rețea este refuzată

1. `consent grant` pe hotspotul echipei.
2. Muți Pi-ul pe alt hotspot (alt telefon).
3. `python3 deploy/pi/ajar_autoscan.py check` → „Scanarea automată NU ar rula (no consent for this network)".
4. Același nume Wi-Fi și același subnet, dar alt telefon → refuzat cu motivul `different gateway_fp`.

## Teste

```bash
python3 -m unittest discover -s deploy/pi/tests -v   # 32 de teste, doar biblioteca standard, nu scanează nimic
python3 -m unittest discover -s scanner/tests -v     # 51, inclusiv modul --discover al wrapper-ului și /discover
```

## Reguli

- Doar rețele proprii sau cu permisiunea proprietarului. Acasă, cere acordul celor din casă.
- La hackathon, Pi-ul stă doar pe hotspotul echipei.
- Nu rula scriptul ca root (refuză singur).
