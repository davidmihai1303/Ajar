# Technical summary (1 page)

**Ajar: a local network security checker** · R Systems Hackathon 2026, "Secure Networks, Simply Explained"

## Lab setup

One iPhone hotspot (`RSH-Byte_me`, `172.20.10.0/28`). The scanner is an MSI laptop running Ubuntu and
nmap 7.98, joined only to the hotspot. Four team-owned targets (setups A + B + C): the iPhone, a Mac
(nginx serving "Router Admin Login", fake Telnet / vsftpd 2.3.4 banners from `lab/fake_services.py`
with no real shell behind them, and macOS sharing services), a Windows laptop (RDP, SMB, MySQL) and a
Raspberry Pi (SSH, VNC). Before/after in `lab/scans/` (MACs masked): 9 finding types, score **0** →
**75** after switching off the Mac's services and the Pi's VNC and taking the Windows laptop off the
hotspot. Details: `lab/README.md`.

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
  rendered only as escaped text, configuration only through environment variables (checked live with gitleaks),
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

Optional, only in **Ask** (the Q&A assistant). A local llama-server runs Qwen on loopback only, with no
proxies and no redirects. Findings, severities, scores, explanations and fix steps never come from the
model. The finding cards always show the team's own texts. "Explain for my device" only fills in an
Ask question built from catalog facts; the user reads it and sends it.

- **Free answers (default, `LLM_FREE_ANSWERS=1`):** the model writes the answer from the current scan's
  facts (score → findings, most severe first → devices and ports). It also gets the last 3 exchanges and
  the optional "About you" profile, which only adapts the wording and never counts as evidence.
  `explain/grounding.py` checks every reply (NFR-06). A reply that names an IP, a port (or a port on the
  wrong device), a version, a device maker, a CVE or a phone number the scan does not show is replaced
  by the verified answer. The check covers these concrete identifiers, not the meaning of every sentence.
- **Record-only (`LLM_FREE_ANSWERS=0`, strict mode):** the model only picks record IDs offered for that
  question, and Python writes every sentence from the scan. Model text is never shown.
- **Fallback:** an IP outside the scan, a timeout or a missing model give the built-in answer or "not
  available". MAC addresses, raw banners and page titles are never sent to the model.
