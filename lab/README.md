# Laboratorul (hotspot RSH-Byte_me, 172.20.10.0/28)

| Rol | Dispozitiv | IP |
|---|---|---|
| Gateway | iPhone (hotspot) | 172.20.10.1 |
| Scaner | MSI (Ubuntu, nmap 7.98) | 172.20.10.9 |
| Țintă | Mac (Docker Desktop) | 172.20.10.11 |

**Setup:** A (Docker: Redis, Mosquitto 1.6, nginx „Router Admin Login") + C (Telnet și FTP false)
+ servicii reale macOS (tip B: Screen Sharing, File Sharing, Remote Login, AirPlay).

## Pornire (pe Mac)
```bash
cd lab && docker compose up -d
python3 fake_services.py          # tab separat
```

## Before / after
- `scan_01.xml` (before): 10 tipuri de finding, scor **0**
- reparații: Screen Sharing, File Sharing, Remote Login, AirPlay Receiver oprite; `fake_services.py` oprit; `docker compose stop redis`
- `scan_03_after.xml` (after): rămân FTP pe iPhone, admin HTTP, dispozitiv necunoscut → scor **75**

## Observații (pentru limitări)
- nmap 7.98 cu `mqtt-subscribe` suprascrie numele serviciului 1883 cu `mosquitto version …` (nu `mqtt`)
- AirPlay (5000, 7000) e raportat ca `rtsp` → CAMERA_STREAM_EXPOSED conform regulii
- Mac-ul și iPhone-ul folosesc MAC randomizat → fără vendor
