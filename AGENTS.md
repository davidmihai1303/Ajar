# AGENTS.md

Instructions for AI coding agents (and humans) working in this repository.
Read this before changing code. Project overview and setup: `README.md`. File map: `docs/STRUCTURE.md`.

## What this is

Hackathon project (R Systems Hackathon 2026, "Secure Networks, Simply Explained"): a local network
security checker. It scans a network the user owns (nmap), applies an official finding catalog,
computes a standard score, explains each finding in Romanian and English, and keeps a history.

**Grading reality:** 30% of the grade is an exact comparison of our `findings.csv` / `scores.csv`
with a secret answer key. Extra findings cost as much as missing ones. Correctness of
`backend/netcheck/analysis/` beats everything else.

## Architecture boundaries (do not break)

| Area | Runs | Rule |
|---|---|---|
| `scanner/` | host, Linux | Only place that touches the network. Python stdlib only. |
| `scanner/netcheck-nmap` | **root** via sudo | Self-contained: must **never** import from the repo. One argument (CIDR). Fixed nmap command. |
| `backend/netcheck/analysis/` | Docker | Pure and deterministic. Must **not** import `history`, `api`, `explain`, network code or any LLM. No I/O except reading the XML file. |
| `backend/netcheck/history/` | Docker | Local SQLite only. Compare scans **by IP, never by MAC**. |
| `backend/netcheck/explain/` | Docker | Static YAML texts always work. `llm.py` is optional and selects verified evidence. |
| `backend/netcheck/api/` | Docker | Never runs nmap; calls the host agent at `NETCHECK_AGENT_URL`. Binds to 127.0.0.1. |
| `frontend/` | built into the backend image | Talks only to `/api/*`. |

The only contract between scanner and backend is an **nmap XML file**.

## Finding rules (must match the official catalog exactly)

- Report only ports with `state="open"`. Ignore `filtered`, `closed`, `open|filtered`.
- Decide by `<service name="…">`, never by port number.
- HTTPS is `service name="http"` + `tunnel="ssl"` → not `HTTP_ADMIN_CLEARTEXT`.
- `HTTP_ADMIN_CLEARTEXT`: http without ssl tunnel **and** `http-title` contains (case-insensitive) login, admin, config, setup, router or settings.
- `SMB_EXPOSED`: one per device: port 445 if open, else 139.
- `OUTDATED_SERVICE` is **in addition** to the service's own finding. List: vsftpd 2.3.4; OpenSSH < 7.4; Apache httpd ≤ 2.2.x; Microsoft IIS ≤ 7.5; Samba ≤ 3.x. Parse versions like `8.4p1 Debian 5+deb11u3`.
- `UNKNOWN_DEVICE`: no MAC `vendor` attribute and no hostname and ≥ 1 open port; CSV port column empty.
- `UPNP_EXPOSED` / `SNMP_EXPOSED` only on UDP.
- One finding per (IP, port, code): the same service on two ports of one device gives two rows
  (e.g. AirPlay `rtsp` on 5000 and 7000). Exceptions: `SMB_EXPOSED` and `UNKNOWN_DEVICE` (one per
  device). The brief does not spell this out; it matches the Validation Set. Confirm at kickoff.
- Score = `max(0, 100 − Σ points)`. Points: High 20, Medium 10, Low 5, Info 0.
- Agreed interpretations where the brief is silent (D1–D7, covered by `tests/test_rules_decisions.py`).
  Follow the "Report when" column literally:
  - D1: only HTTP has an SSL condition; `ftp` / `telnet` with `tunnel="ssl"` are still reported.
  - D2: service names are exact (`http`, not `http-proxy` / `https-alt`; `mongodb`, not `mongod`).
  - D3: a version range or wildcard that may include a newer release (Samba `3.X - 4.X`, OpenSSH `7.X`) is not outdated.
  - D4: `OUTDATED_SERVICE` is reported even when the port has no finding of its own.
  - D5: see "one finding per (IP, port, code)" above.
  - D6: `netcheck analyze` reads every XML directly inside a folder, or one XML with an explicit `--out` directory.
  - D7: CSVs are byte-identical in format to the official answer files (UTF-8, no BOM, CRLF).
- CSV order: file → IP (numeric) → port (numeric, empty last) → code. Severity lowercase. Unreadable file → `ERROR` in `scores.csv`, continue with the other files.
- CSVs and CLI summaries use the same file label. Preserve ordinary timestamps such as
  `T5_202611081200.xml`, mask device MACs, and use the same collision suffix for folder exports and single-file reruns.
- The catalog lives as **data** in `analysis/catalog.py`. Change rules there, not with scattered `if`s.
- Never add a "smart" exception that is not in the catalog (e.g. treating `mosquitto version …` as `mqtt`). Document such cases in README → Limitations instead.

## Commands

```bash
docker compose up -d --build                     # app on http://127.0.0.1:8001
docker compose run --rm app pytest -q            # all backend tests
python3 -m unittest discover -s scanner/tests    # scanner tests (stdlib only, no network)
(cd frontend && npm test)                        # UI browser tests (Playwright, mocked API)
(cd frontend && PYTHONPATH=../backend npm run test:api)   # built UI against the real FastAPI app
docker compose run --rm app netcheck analyze /app/tests/fixtures/validation --out /data/input/validation_results
python3 scanner/agent.py network                 # detected network
python3 scanner/agent.py scan --confirm          # live scan (host, after scanner/install.sh)
gitleaks detect --source . --no-banner           # must be clean
```

## Definition of done for any change in `analysis/`

1. `test_validation.py` passes: exactly the 24 rows in `tests/fixtures/validation/expected_findings.csv`, no extra rows, all 8 scores.
2. `test_determinism.py` passes.
3. A new trap gets a test in `test_rules.py`.

## Security rules

- No secrets in code, tests, fixtures or docs. Configuration only via environment variables (`backend/netcheck/config.py`, `.env.example` lists names only). Never commit `.env` or `.api_key`.
- Parse XML only with `defusedxml`, with the size limit from config.
- Treat banners, titles and hostnames as untrusted text: escape in the UI, never `dangerouslySetInnerHTML`, never `shell=True`.
- Mask MAC addresses in **every** output (API, CSV, UI, logs) via `analysis/privacy.py`.
- Never widen the scope guard (`scanner/guard.py`, `netcheck-nmap`): private IPv4 only, ≤ /24, inside the detected subnet, explicit confirmation. Never let a client choose nmap options.
- Network detection must find **exactly one** physical network. With two (e.g. hotspot Wi-Fi + venue
  cable) it refuses; never "fix" this by picking one (the default route usually points at the venue,
  and scanning it disqualifies the team). The rule lives in both `detect.py` and `netcheck-nmap`.
- The agent HTTP API accepts only the app's server-side client: Host `127.0.0.1`/`localhost`, no
  `Origin` header, `Content-Type: application/json` on POST. Do not add CORS or relax these checks.
- Do not run anything as root except `netcheck-nmap`. The container runs as a non-root user.
- Never scan anything to "test" a change. Use the XML fixtures.

## LLM rules (`explain/llm.py`)

- Input: only facts of the current scan, plus (for Ask) the last few exchanges of the same conversation.
  Findings, severities and scores never come from the model.
- Two Ask modes (`LLM_FREE_ANSWERS`, team decision):
  - **Free answers (default, `1`):** the model writes the answer from the scan facts. Facts are ordered
    score → findings (most severe first) → devices and ports and capped (`MAX_FACT_CHARS`). The reply is
    passed through `plain_text()` (the chat shows plain text, so Markdown is removed). Empty reply, or a
    reply naming an IP, port, version, maker, CVE or phone number the scan does not show (`explain/grounding.py`, NFR-06) →
    record-based answer; unreachable model → "not available", without a second model call.
  - **Record-only (`0`):** the model only selects IDs from the records offered for that question and
    Python renders the answer. Unknown IDs and extra keys are dropped; over-selection keeps the most
    severe records (`MAX_SELECTED`). Model text is never shown.
- In record-only mode (and as the fallback when a free answer is empty) code answers without the model:
  the score question, overview questions ("what problems do I have?", "ce probleme am?": every finding,
  most severe first) and greetings (a short hint). In free mode these questions go to the model.
- Conversation (Ask is turn-based): the page sends up to 3 earlier exchanges (`AskRequest.history`,
  `ChatTurn`; the API accepts at most 10). Only free answers use them, as earlier chat turns, oldest
  dropped first (`MAX_HISTORY_TURNS`, `MAX_HISTORY_CHARS`), MACs masked and Markdown removed. Nothing is
  stored server-side. The conversation lives in `frontend/src/state/Conversation.tsx` (memory only), so
  it survives moving between pages and an answer in progress still arrives; it belongs to one scan and
  resets when another scan is opened, on **New conversation**, or on reload. A used `#/ask?q=` /
  `?draft=` link is replaced by `#/ask`, so Back never sends or fills it twice.
- "About you" (Ask page, `frontend/src/lib/profile.ts`, `ProfileDialog.tsx`): optional age range, tech
  familiarity and profession (max 60 characters), kept in the browser (`localStorage`, `ajar.profile`)
  and sent as `AskRequest.profile` (`UserProfile`). Only free answers use it, as data in the request
  (`"user"`), never as instructions; the profession is cleaned. The model must not mention the age or
  guess anything else about the user. Record-only mode ignores it.
- Everything sent to the model (scan facts, question, prompt, history, profile) must fit the bundled model's
  4,096-token context together with the answer (`max_tokens` 600). Re-check the budgets when adding input.
- Never invent ports, CVEs, versions, phone numbers or vendors. Say so when the scan cannot answer.
  The scan runs inside the user's network: do not prompt the model in a way that implies internet
  exposure or password checks the scan did not make.
- Always fall back to `explain/static.py` / built-in text on error or timeout.
- Check all explicit IPs in the question against the scan before contacting the model.
- Privacy: use a loopback model endpoint with proxies and redirects disabled. Never send MAC addresses to the model.
- Exclude raw banners and page titles from prompts. Treat recorded device labels, the question and the
  conversation history as untrusted data.
- Tests: `docker compose run --rm app pytest -q tests/test_llm.py` (mock server, no real model needed).
  Free-answer tests opt in; `tests/conftest.py` defaults every test to record-only mode.
- "Explain for my device" (finding card) does not call the model itself: it opens Ask with a prompt
  in the chat box (`#/ask?draft=…`, not sent) built only from catalog facts (problem title, severity,
  code), the device type, vendor, IP and port. No hostname, banner or page title. The user reads,
  edits and sends it; the answer then follows the Ask rules above. The finding card always shows the
  team's explanation and steps unchanged.

## User-facing text

- Romanian **and** English for everything the user sees (`explain/texts/*.yaml`, `frontend/src/i18n/*.json`).
- Explanations: max 2 sentences, no unexplained jargon, ~12-year-old reading level.
- Fixes: 1–5 ordered, concrete steps a non-expert can follow.
- Colour is never the only signal (icon + label); min 16 px text; keyboard navigable.

## Code conventions

- Python 3.11+, type hints on public functions, dataclasses for models, no global state in `analysis/`.
- Keep functions small and pure; pass data in, return data out.
- Frontend: React + TypeScript strict; types in `src/api/types.ts` mirror `api/schemas.py`.
- Do not add dependencies without a reason in the PR description.

## Git workflow (agents must follow this)

1. **Always work on a branch, never on `main`.** Before the first change, check the current branch
   (`git branch --show-current`). If it is `main`, create one: `git checkout -b feat/<area>-<short-topic>`
   (e.g. `feat/analysis-smb-rule`). `main` must always stay runnable.
2. **Commit periodically**, after each small, working step (a rule plus its test, a page, a text set),
   not one huge commit at the end. Each commit should leave tests passing.
   Messages: imperative, short subject (`Add SMB one-per-device rule`), optional body explaining why.
3. **Never push and never open a PR on your own.** Only `git push` and open a PR when the developer
   explicitly asks for it. Local commits are fine without asking.
4. **When the developer asks for a PR**, push the branch and open a PR to `main` whose description covers
   everything done on the branch:
   - **Summary:** what changed and why, in a few sentences
   - **Changes:** every file or module touched and what was done in it
   - **Requirements covered:** FR-/NFR- IDs from the brief
   - **Tests:** what was added/updated and the result of `pytest -q` (and the Validation Set result for `analysis/` changes)
   - **How to verify:** exact commands or UI steps for the reviewer
   - **Contract changes:** any change to `models.py`, `schemas.py`, `types.ts` or `mock.json` (needs both owners' approval)
   - **Known limitations / follow-ups:** anything left undone or deliberately skipped
5. Contract files need agreement of the analysis and API owners before changing:
   `analysis/models.py`, `api/schemas.py`, `frontend/src/api/types.ts`, `frontend/src/api/mock.json`.
   Keep `api/schemas.py` and `types.ts` in step (e.g. `ChatTurn` / `AskRequest.history`, `UserProfile`).
6. Never force-push, rewrite shared history or commit secrets, `data/` or `input/`.
7. After the Test Set upload (hour 20–21): **no code changes**. The live re-run must match the upload.

## Ownership

| Area | Owner |
|---|---|
| `backend/netcheck/analysis/`, `cli.py`, analysis tests | P1 |
| `backend/netcheck/api/`, `history/`, `scanner/`, Docker | P2 |
| `backend/netcheck/explain/`, `device_type.py`, `privacy.py` | P3 |
| `frontend/` Dashboard, Scan, core components | P4 |
| `frontend/` Devices, History; `lab/`, `docs/` | P5 |
