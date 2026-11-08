# Technical summary (1 page)

**Ajar: a local network security checker** · R Systems Hackathon 2026, "Secure Networks, Simply Explained"

## Lab setup

One iPhone hotspot (`RSH-Byte_me`, WPA2, `172.20.10.0/28`). The scanner is an MSI laptop running Ubuntu and
nmap 7.98, with no other network connected. The target is a Mac with Docker Desktop (setups A + B + C):
Redis, Mosquitto 1.6, nginx serving "Router Admin Login", fake Telnet / vsftpd 2.3.4 banners
(`lab/fake_services.py`, no real shell behind them), plus the Mac's own Screen Sharing, File Sharing,
Remote Login and AirPlay. Before/after: `scan_01.xml` scores **0**. After switching those services off,
`scan_03_after.xml` scores **75**. Details: `lab/README.md`.

## Architecture

```
host (Linux)                                   Docker (non-root, 127.0.0.1:8001)
scanner/agent.py ── guard.py (scope) ──┐       api/ (FastAPI) ── frontend/ (React)
   127.0.0.1:8765                      │          │
sudo netcheck-nmap <cidr>  (only root) │          ├─ analysis/  parser → rules → score → CSV   (pure)
   fixed nmap -sS -sU -sV  ────────────┴─ XML ──► ├─ history/   SQLite, diff by IP
                                                  └─ explain/   RO/EN YAML texts (+ optional LLM)
```

- **The only contract** between the scanner and the backend is an nmap XML file. The backend never
  runs nmap, and the same `analysis/` code serves the CLI (`netcheck analyze <folder>`), the browser
  import and live scans.
- **Analysis is pure and deterministic.** The catalog is data (`analysis/catalog.py`), with no LLM,
  network or database access, so the live re-run always matches the upload.
- **Scope guard, checked twice.** The agent and the root-owned wrapper each require a private IPv4
  network of at most /24 inside the single detected subnet. Live scans need `--confirm`. Two
  connected networks (hotspot + venue) means refusal, never a guess.
- **Security.** `defusedxml` with a size limit, MACs masked in every output, banners and titles
  rendered only as escaped text, configuration only through environment variables, gitleaks clean,
  and a one-click "Delete my history".

## Assumptions (where the brief is silent)

| | Decision |
|---|---|
| D1 | Only HTTP has an SSL exception; `ftp` / `telnet` with `tunnel="ssl"` are still reported |
| D2 | Service names match exactly (`http`, not `http-proxy`; `mongodb`, not `mongod`) |
| D3 | A version range or wildcard that may include a newer release (`3.X - 4.X`, `7.X`) is not outdated |
| D4 | `OUTDATED_SERVICE` is reported even when the port has no finding of its own |
| D5 | One row per (IP, port, code); only `SMB_EXPOSED` and `UNKNOWN_DEVICE` are one per device |
| D6 | `netcheck analyze` reads every XML file in a folder, or one file with an explicit `--out` |
| D7 | CSVs are UTF-8 without BOM, CRLF line endings, same format as the official files |

Validation Set: all 24 rows, no extra rows, 8/8 scores (`tests/test_validation.py`).

## Limitations

- The scanner host must be Linux, and only IPv4 networks of /24 or smaller are supported.
- The tool cannot prove ownership of a network, only that the laptop is connected to it, so it asks the user to confirm.
- nmap 7.98's `mqtt-subscribe` script renames the 1883 service to `mosquitto version …`, so
  `MQTT_EXPOSED` is not raised for it. We apply the catalog literally instead of adding an exception.
- AirPlay (5000/7000) is reported as `rtsp`, so it counts as `CAMERA_STREAM_EXPOSED`. The text says "audio/video stream".
- Randomised MACs (iPhone, Mac) have no vendor, so the device may show as `UNKNOWN_DEVICE`.
- At ≤ 100 packets/s, a busy /24 can take longer than 5 minutes.

## LLM use

Optional. A local llama-server (Qwen, loopback only, no proxies or redirects) only *selects* scan records
by ID for the Q&A assistant and "explain for my device". Python renders every fact from the scan.
Unknown IDs, malformed replies, timeouts or a missing model fall back to the built-in texts.
Findings, severities and scores never touch the LLM. MAC addresses, raw banners and page titles are never sent to it.
