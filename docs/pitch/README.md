# Pitch: Ajar (5–7 min, English, ≥ 2 speakers)

Team **Byte_me**. Seven minutes of pitch, then eight minutes of live checks
([`docs/live_checks.md`](../live_checks.md)). The brief asks that juniors and seniors both speak:
give at least one section to a junior. Replace **A–D** with names. Timings add up to about 6:30, which
leaves 30 s of slack.

Before the session: `./demo.sh status` (app, scanner agent and local model running). Then in the app,
History holds the lab pair (`lab/scans/scan_20261108_104602_before.xml` → `…_112146_after.xml`) and a
Test Set file is open on the Dashboard. Keep a terminal open in the repo.

---

## 1. Problem (A, 0:45)

> Every phone, TV, printer and camera at home is a door into the network. Most people have no idea
> which doors are open, and the professional tools that show them speak to experts, not to the person
> who has to close them. Our tool is for a parent or a grandparent.
>
> Meet **Ajar**: a door that is never quite shut. It scans a network you own, tells you in plain
> Romanian or English what each open door means, and gives you one concrete thing to do first.

## 2. Demo (B, 2:30)

Show, don't tell. One path through the app, the same one the jury's hands-on task uses.

1. **Dashboard** (0:30). Score with a colour **and** a label, Ajar's face, and the most dangerous device
   with its first fix. *"If you only do one thing today, do this."*
2. **Finding card** (0:40). Open the worst finding: two plain sentences, 1–5 ordered steps, and a
   CIS / OWASP IoT reference for an IT supplier. Switch **RO ↔ EN**.
3. **Ask** (0:40). *"Is it safe that my printer has port 9100 open?"* or *"What should I fix first?"*
   The answer uses only this scan. Then ask about an IP that is not on the network: Ajar says the scan
   cannot answer.
4. **History** (0:40). Our own hotspot lab: **0 → 75**. Show the resolved findings and the closed ports.
   *"Proof, not a promise."*

If the model is slow, skip step 3: the assistant is optional, everything else works without it.

## 3. How it works and why it is trustworthy (C, 1:15)

- **One contract:** an nmap XML file. The scanner (Linux host) writes it, and the analyser (Docker,
  non-root) reads it. The same code serves live scans, the browser import and the Test Set command.
- **Deterministic rules, no AI in the grading.** The official catalog is data. Findings, severities and
  scores never touch the model, so a re-run always matches the upload.
- **Safe by design.** Only the private subnet the laptop is connected to, at most a /24, and `--confirm`
  is required. Two networks at once means refusal. Root only for the fixed nmap command, rate-limited
  to 100 packets/s. MACs are masked everywhere, scan files are parsed as hostile input, and "Delete my
  history" is one click.
- **Grounded AI.** Local model, no cloud. Every free answer is checked: an IP, port, version, maker, CVE
  or phone number that the scan does not show means the user gets the verified answer instead.

## 4. Numbers (C or D, 0:45)

| | |
|---|---|
| Validation Set | **24 / 24** finding rows, **0** extra, **8 / 8** scores, CSVs byte-identical |
| Broken file | `ERROR` row, no crash, the other files continue |
| Our hotspot lab | 4 team devices, 9 finding types, score **0 → 75** after the fixes |
| Tests | 373 backend tests + scanner tests + browser tests of the UI |
| Languages | every user-facing text in Romanian and English, all 15 catalog codes |

Update the Test Set line on the day: *"9 files, uploaded at hour 21, re-run matches."*

## 5. Trade-offs and limitations (D, 0:40)

Say them before the jury asks:

- **The catalog is applied literally.** No "smart" exceptions: a service nmap names differently is not
  reported. Extra findings cost as much as missing ones.
- **Linux scanner, IPv4, /24 or smaller.** At 100 packets/s a busy /24 can take more than 5 minutes.
  A phone hotspot (/28) takes a few minutes.
- **The tool cannot prove you own the network**, only that you are connected to it. That is why it asks.
- **AI check:** it catches invented identifiers, not every invented sentence. A strict mode
  (`LLM_FREE_ANSWERS=0`) lets the model only pick verified records.
- In the lab, the Windows laptop was **taken off the hotspot** rather than fixed. Say it plainly.

## 6. Next steps (D, 0:30)

- **Always-on watch:** a Raspberry Pi that rescans on its own and sends "new device" and "score
  dropped" alerts to a phone app on the same Wi-Fi. A prototype exists on a separate branch.
- **Router-specific guides:** "how to turn off WPS on this model", picked from the detected device.
- **Before/after in the report:** today's one-page report (print or PDF) shows one scan; next it shows
  the improvement, for an IT supplier or an insurer.

Close (A, 0:10): *"Build it simple, explain it simply, prove every claim with a scan. Thank you."*

---

## Likely jury questions

| Question | Short answer |
|---|---|
| What if the AI invents something? | It never decides findings or scores. Free answers are checked against the scan; strict mode shows only verified records. |
| Why not just nmap? | nmap shows doors to experts. Ajar says which door matters, why, and what to do, in Romanian. |
| How do you stop scanning the venue? | Private subnet only, the one we are connected to, `--confirm` required, refusal with two networks. Show it (live check 4). |
| Where is the data? | Only on this laptop: local SQLite, local model, MACs masked, one-click delete. |
| What did you not finish? | The limitations above, then the next steps. |
