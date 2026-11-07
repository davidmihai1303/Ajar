# Scanner (rulează pe host, nu în Docker)

```
app (Docker, user normal) ──HTTP 127.0.0.1:8765──► agent.py (host, user david)
                                                     │  detect.py  → FR-01
                                                     │  guard.py   → FR-02
                                                     ▼
                                   sudo -n /usr/local/sbin/netcheck-nmap <cidr>   ← SINGURUL pas ca root
                                                     │  re-verifică ținta (privată, ≤ /24, în subnetul curent)
                                                     │  comandă nmap FIXĂ, fără opțiuni de la utilizator
                                                     ▼
                                   /var/lib/netcheck/scans/scan_<data>.xml  (citit de app, read-only)
```

## Instalare (o singură dată, pe MSI)

```bash
sudo EXTRA_TCP_PORTS=1883,2323,6379 ./scanner/install.sh     # porturile extra sunt opționale (laboratorul)
newgrp netcheck                                              # sau logout/login
```

Scriptul instalează nmap, copiază wrapper-ul în `/usr/local/sbin` (deținut de root),
creează `/var/lib/netcheck/scans`, grupul `netcheck` și regula sudoers
`%netcheck ALL=(root) NOPASSWD: /usr/local/sbin/netcheck-nmap`.

**De ce nu `NOPASSWD: /usr/bin/nmap`?** nmap poate rula scripturi Lua (`--script`).
Cine poate rula `sudo nmap` cu orice argumente poate rula orice cod ca root.
Wrapper-ul acceptă un singur argument (subnetul) și construiește singur comanda.

**VPN / Docker:** interfețele `tun*`, `wg*`, `tailscale*`, `docker*`, `br-*` etc. sunt ignorate la detectare,
ca un VPN de firmă să nu fie confundat cu rețeaua de acasă.

**Mai multe rețele:** dacă laptopul e conectat la mai multe rețele fizice în același timp (de exemplu hotspot
pe Wi-Fi și cablul sălii), scanarea e refuzată, atât de agent, cât și de wrapper. Ruta implicită ar arăta
spre rețeaua sălii, iar aceasta ar ajunge în allowlist. Deconectează tot în afară de hotspot.

**Agentul HTTP** acceptă doar clientul aplicației: Host `127.0.0.1`/`localhost`, fără header `Origin`,
`Content-Type: application/json` la POST. O pagină web deschisă în browser nu poate porni o scanare.

## Teste

```bash
python3 -m unittest discover -s scanner/tests -v    # doar biblioteca standard, nu scanează nimic
```

**De ce e wrapper-ul copiat în `/usr/local/sbin`?** Dacă sudo ar rula un fișier din repo
(editabil de david), oricine cu acces la contul david l-ar putea modifica și rula ca root.
După orice modificare a wrapper-ului, rulați din nou `install.sh`.

## Utilizare

```bash
cd scanner
python3 agent.py network                          # rețeaua detectată
python3 agent.py scan --confirm                   # scanează subnetul detectat
python3 agent.py serve                            # server pentru UI (doar 127.0.0.1)
```

## Verificările live ale juriului (#4 Guardrail)

```bash
python3 agent.py scan --target 8.8.8.8 --confirm          # REFUZAT: rețea publică
python3 agent.py scan --target 192.168.0.0/24 --confirm   # REFUZAT: în afara allowlist-ului (ex. Wi-Fi-ul locației)
python3 agent.py scan                                     # REFUZAT: lipsește --confirm
sudo -n /usr/local/sbin/netcheck-nmap 8.8.8.8/32          # REFUZAT și de wrapper (a doua barieră)
sudo -n /usr/bin/nmap 8.8.8.8                             # cere parolă: nmap direct NU e permis
```

## Configurare (variabile de mediu, fără secrete în cod)

| Variabilă | Implicit | Rol |
|---|---|---|
| `NETCHECK_AGENT_PORT` | `8765` | portul agentului (doar 127.0.0.1) |
| `NETCHECK_ALLOWLIST` | gol | rețele private extra permise, separate prin virgulă |

## Legătura cu aplicația din Docker

Agentul ascultă doar pe `127.0.0.1`. Ca containerul să-l poată apela, aplicația
rulează pe MSI cu `network_mode: host` și pornește serverul web tot pe `127.0.0.1`
(ca UI-ul să nu fie vizibil pe hotspot):

```yaml
services:
  app:
    build: ./app
    network_mode: host
    environment:
      - NETCHECK_AGENT_URL=http://127.0.0.1:8765
    volumes:
      - /var/lib/netcheck/scans:/data/scans:ro
      - ./data:/data/db
```

Pentru o scanare prin HTTP, aplicația citește `GET /network` înainte de confirmare.
Cererea `POST /scan` trebuie să conțină `confirm: true` și obiectul `expected_network`
cu valorile afișate pentru `interface`, `subnet`, `gateway` și `ssid`. Pentru un
gateway sau SSID necunoscut se trimite `null`. Agentul detectează din nou rețeaua
și refuză scanarea dacă valorile diferă.
