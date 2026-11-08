# Laboratorul (hotspot RSH-Byte_me, 172.20.10.0/28)

| Rol | Dispozitiv | IP |
|---|---|---|
| Gateway (și țintă) | iPhone (hotspot) | 172.20.10.1 |
| Scaner | MSI (Ubuntu, nmap 7.98) | 172.20.10.9 |
| Țintă | Mac (Docker Desktop + servicii macOS) | 172.20.10.11 |
| Țintă | Laptop Windows | 172.20.10.12 |
| Țintă | Raspberry Pi | 172.20.10.13 |

**Setup:** A (Docker: nginx „Router Admin Login"; opțional Redis, Mosquitto 1.6) + B (servicii reale pe
dispozitivele echipei: macOS Screen Sharing / File Sharing / Remote Login, Windows RDP / SMB / MySQL,
VNC și SSH pe Pi) + C (Telnet și vsftpd 2.3.4 false, `fake_services.py`, fără login sau shell în spate).

## Pornire (pe Mac)
```bash
cd lab && docker compose up -d
python3 fake_services.py          # tab separat
```

## Scanări (`scans/`)

MAC-urile sunt mascate: rămâne partea de producător (`AA:BB:CC:00:00:00`), atributul `vendor` rămâne,
deci finding-urile și scorurile nu se schimbă.

| Fișier | Ce arată | Scor |
|---|---|---|
| `scan_20261108_104602_before.xml` | **before:** 4 ținte, 9 tipuri de finding | **0** |
| `scan_20261108_105232.xml` | Mac: Screen Sharing, File Sharing, Remote Login, `fake_services.py` oprite | 5 |
| `scan_20261108_111252.xml` | laptopul Windows (RDP, SMB, MySQL) scos din hotspot | 55 |
| `scan_20261108_112146_after.xml` | **after:** și VNC oprit pe Pi | **75** |
| `scan_20261107_214638_before.xml` / `scan_20261107_215525_after.xml` | prima pereche (doar iPhone + Mac) | 0 → 75 |

Perechea before/after (`104602_before` → `112146_after`) e copiată în `backend/tests/fixtures/lab/`
și verificată de `tests/test_lab.py`. Rămân în „after": FTP pe iPhone, pagina „Router Admin Login" pe
Mac (HTTP), Mac-ul fără nume (dispozitiv necunoscut) și SSH (doar informativ).

În pitch: laptopul Windows a fost **scos din rețea**, nu reparat; istoricul îl arată ca dispozitiv dispărut.

## Observații (pentru limitări)
- AirPlay (5000, 7000) e raportat ca `rtsp` → CAMERA_STREAM_EXPOSED conform regulii
- Mac-ul și iPhone-ul folosesc MAC randomizat → fără vendor; Mac-ul fără hostname apare ca `UNKNOWN_DEVICE`
- Serviciile reale (RDP, MySQL) rămân doar pe dispozitivele echipei, fără date reale, oprite după demo
