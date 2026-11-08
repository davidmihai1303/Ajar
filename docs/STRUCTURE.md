# File-by-file map

Overview and setup: see the main [README](../README.md). Numbers ①–⑨ match `docs/arhitectura.png`.

## Root

| File | Purpose |
|---|---|
| `docker-compose.yml` | App container: host network, non-root, volumes for scans (read-only), history and input |
| `demo.sh` | Demo laptop in one command: reuses or downloads the pinned Qwen weights, builds/pulls images, starts app + Qwen + scanner agent, opens Ajar; `stop`, `status`, `check` |
| `scripts/gitleaks.sh`, `.gitleaksignore` | Secret scan (NFR-01, live check 7): gitleaks 8.30.1 downloaded once into `.tools/` and SHA-256 checked; known false positives with their reason |
| `.env.example` | Names of the configuration variables, no values |
| `.gitignore` | Keeps `.env`, `.api_key`, `data/`, `input/`, build output out of git |
| `SmartHack_Setup.md` | Existing distributed llama-server setup (optional LLM backend) |

## `scanner/`: host, the only part that touches the network

| File | Purpose |
|---|---|
| `agent.py` | ①② CLI (`network`, `scan --confirm`, `serve`) and HTTP agent on 127.0.0.1:8765 |
| `detect.py` | ① Active interface, subnet, gateway, SSID. Ignores VPN / Docker / virtual interfaces |
| `guard.py` | ② Confirmation, private-only, ≤ /24, inside the allowlist. Bilingual refusal messages |
| `netcheck-nmap` | ③ Root wrapper: re-checks the target, runs a fixed nmap command, writes XML |
| `install.sh` | Installs the wrapper, scan folder, `netcheck` group and sudoers rule |

## `backend/netcheck/`: Docker

| File | Purpose |
|---|---|
| `config.py` | All settings from environment variables |
| `cli.py` | `netcheck analyze <folder> --out <dir>`, `netcheck serve` |
| `analysis/models.py` | Dataclasses: Port, Device, Finding, ScanResult |
| `analysis/parser.py` | ④ defusedxml, size limit, truncated file → error |
| `analysis/catalog.py` | The 15 finding codes as data: severity, points, services |
| `analysis/rules.py` | ⑤ Applies the catalog (open only, by service name, SSL tunnel, SMB, UNKNOWN_DEVICE) |
| `analysis/versions.py` | Outdated-version list and version parsing |
| `analysis/scoring.py` | `max(0, 100 − Σ points)` |
| `analysis/device_type.py` | Device-type guess (router, camera, printer, laptop…) |
| `analysis/privacy.py` | MAC masking |
| `analysis/export.py` | `findings.csv` + `scores.csv`, deterministic order, ERROR rows |
| `history/store.py` | ⑥ SQLite: save, list, delete all |
| `history/diff.py` | ⑥ Compare two scans by IP: devices, ports, findings, score |
| `explain/texts/ro.yaml`, `en.yaml` | ⑦ Explanation + fix steps per code |
| `explain/static.py` | ⑦ Picks the right text, including context variants |
| `explain/llm.py` | ⑧ Optional, grounded rephrasing and Q&A, falls back to static |
| `api/app.py` | ⑨ FastAPI app, serves the built frontend |
| `api/routes_scans.py` | Network info, start scan (via agent), import XML, get scan |
| `api/routes_history.py` | History list, diff, delete |
| `api/routes_explain.py` | Explanation per code, Q&A |
| `api/agent_client.py` | Calls the host agent; the app never runs nmap |
| `api/schemas.py` | Response models (MACs already masked) |

## `backend/tests/`

| File | Purpose |
|---|---|
| `fixtures/validation/` | The 8 official XML files + expected CSVs |
| `fixtures/lab/` | Our lab scans (`scan_01.xml`, `scan_02.xml`, `scan_03_after.xml`) |
| `test_validation.py` | 24 rows, 8 scores, no extra rows |
| `test_rules.py` | Rule traps |
| `test_parser.py` | Hostile and broken input |
| `test_history.py` | V6a → V6b diff |
| `test_lab.py` | 0 → 75 |
| `test_determinism.py` | Same output on every run |

## `frontend/src/`: React + TypeScript

| Path | Purpose |
|---|---|
| `pages/Dashboard.tsx` | Score, most dangerous device, "fix this first" |
| `pages/Devices.tsx`, `DeviceDetail.tsx` | Device list and per-device findings + fixes |
| `pages/History.tsx` | Scan list, trend, before/after, delete history |
| `pages/Scan.tsx` | Live scan with confirmation, import XML files |
| `pages/Ask.tsx` | Optional Q&A assistant |
| `pages/Report.tsx` | FR-14 one-page report (print / save as PDF) for the user's IT supplier |
| `pages/Inbox.tsx`, `state/Inbox.tsx` | Notification inbox (desktop + phone): messages derived from history and scan diffs; read checkboxes kept in localStorage |
| `lib/references.ts` | CIS Controls v8 / OWASP IoT Top 10 references per finding code (display only) |
| `components/` | ScoreBadge, FindingCard, DeviceCard, ConfirmScanDialog, HistoryChart, DiffList, LanguageToggle, ErrorBanner, AskAiButton (opens Ask; on phones explains chat is desktop-only), AjarWidget (phone widget, also `#/widget`), MobileHeader (logo + inbox bell) |
| `i18n/` | `ro.json`, `en.json` |
| `api/` | Typed client for `/api/*` |
| `styles/global.css` | Accessibility basics (16 px text, focus outlines) |

## `lab/`, `docs/`

| Path | Purpose |
|---|---|
| `lab/docker-compose.yml`, `web/index.html` | Redis, Mosquitto 1.6, nginx "Router Admin Login" |
| `lab/fake_services.py` | Fake Telnet (2323) and FTP vsftpd 2.3.4 (2121) banners |
| `lab/README.md` | Lab setup and before/after results |
| `docs/arhitectura.png/.svg` | Architecture diagram |
| `docs/plan_lab.md` | First 3 hours plan |
| `docs/technical_summary.md` | 1-page technical summary (deliverable) |
| `docs/live_checks.md` | The 7 jury checks |
| `docs/pitch/` | Pitch material |
