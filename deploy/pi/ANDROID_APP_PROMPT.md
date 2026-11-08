# Prompt: Android companion app for Ajar on the Raspberry Pi

Give this whole file to a coding assistant or a developer. It describes the Pi's API exactly as
implemented in `deploy/pi/ajar_notify.py`; if the Pi changes, update this file.

---

# Task: Android companion app "Ajar" – instant network notifications from a Raspberry Pi

Build a small native Android app (Kotlin, Jetpack Compose, minSdk 26, targetSdk 35) that pairs with an
"Ajar" Raspberry Pi on the same Wi-Fi and shows a local notification within seconds when the Pi reports
an event. No backend, no Firebase/FCM, no external service: the phone talks only to the Pi on the LAN.

## 1. Finding the Pi
The Pi announces itself via mDNS / DNS-SD as type `_ajar._tcp` (TXT: `api=events/1`, `auth=bearer`),
instance name like `Ajar (raspberrypi)`, port 8002.
Use `NsdManager.discoverServices("_ajar._tcp", NsdManager.PROTOCOL_DNS_SD, …)`, resolve host + port,
hold a `WifiManager.MulticastLock` while discovering. Offer "Enter address manually" (IP + port) as a
fallback when discovery finds nothing (some hotspots block multicast).

## 2. Pairing (no QR code, numeric comparison like Bluetooth)
The owner first opens a 2-minute pairing window ON THE PI (`ajar_notify.py pair`). Then:

1. `POST http://<host>:<port>/pair` with header `Content-Type: application/json` and body
   `{"name": "<Build.MODEL or user-chosen name, max 40 chars>"}`.
   - 200 → `{"request_id": "<secret>", "code": "471", "expires_in": 118}`
   - 403 → no pairing window open: tell the user to run `pair` on the Pi, offer "Try again".
   - 409 → another phone is pairing right now: "Another request is pending, try again shortly."
   - 400 → bug in the request.
2. Show the 3-digit code very large, spaced ("4  7  1"), with the text
   "Confirmă pe Raspberry Pi că vezi același cod / Confirm on the Raspberry Pi that you see the same code".
   The phone has NO approve button: approval happens only on the Pi (security requirement).
3. Poll `GET /pair/<request_id>` every 1 s until `expires_in` runs out:
   - `{"status": "pending"}` → keep waiting
   - `{"status": "approved", "token": "…", "phone_id": "…"}` → save and finish (the token is sent ONCE)
   - `{"status": "rejected"}` → "Pairing was rejected on the Pi."
   - `{"status": "expired"}` or `{"status": "delivered"}` → "Pairing expired, start again."
   - 404 → unknown request (treat as expired).
4. Then call `GET /events` once (with the new token) to get `last_id` and start from "now".

Store host, port, phone_id, token and last_id in `EncryptedSharedPreferences` (androidx.security).
Never log, display, copy to clipboard, back up or send the token anywhere else. Exclude the prefs from
Auto Backup (`dataExtractionRules` / `fullBackupContent`).

Optional alternative (keep it small): the Pi can also show a QR code
`ajar://pair?host=…&port=8002&token=…&name=…` (`ajar_notify.py pair --qr`). If you support it, validate
strictly: scheme `ajar`, host `pair`, IPv4 literal or `*.local` host, port 1-65535, token 32-128 chars
of [A-Za-z0-9_-], name ≤ 64 printable chars.

## 3. Events API (needs `Authorization: Bearer <token>`)
### GET /events  (no `since`)  → `{"events": [], "last_id": 57}`
### GET /events?since=<id>&wait=<0..60>  (long-poll)
Answers immediately if there are events with id > since, otherwise holds the request up to `wait`
seconds and answers with an empty list. `wait` is capped at 60.
```json
{"events": [
   {"id": 58, "time": "2026-11-08T14:02:11+00:00", "type": "new_device",    "severity": "info",   "count": 1},
   {"id": 59, "time": "2026-11-08T14:05:40+00:00", "type": "new_high_risk", "severity": "high",   "count": 2},
   {"id": 60, "time": "2026-11-08T14:05:40+00:00", "type": "score_drop",    "severity": "medium", "count": 1,
    "score": 50, "previous": 90}
 ], "last_id": 60}
```
Types are exactly `new_device`, `new_high_risk`, `score_drop`; treat unknown types as "something
changed". Events never contain IPs, MACs or names.

| Code | Meaning | App behaviour |
|---|---|---|
| 200 | OK | notify, store `last_id` |
| 401 | phone was unpaired on the Pi | stop polling, show "Pair again" + one notification |
| 429 | rate limited (120 req/min per client) | wait 30 s |
| 503 | too many open long-polls | wait 30 s |
| 404/405 | wrong path/method | bug: log locally, wait 60 s |
| network error / timeout | Pi off or phone left the Wi-Fi | backoff 5 s → 60 s |

## 4. Background delivery
- A foreground service runs the long-poll loop while the phone is on Wi-Fi: start/stop it from a
  `ConnectivityManager.NetworkCallback` filtered to `TRANSPORT_WIFI`.
- `foregroundServiceType="specialUse"` with `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` = "local network
  monitoring" (not `dataSync`: Android 15 limits it to 6 h/day). Low-importance persistent
  notification "Ajar veghează rețeaua / Ajar is watching your network".
- Loop: `GET /events?since=<last_id>&wait=60`, connect timeout 5 s, read timeout 70 s, then the next
  request right away; persist `last_id` after every 200. Bind requests to the Wi-Fi `Network`
  (`network.openConnection(url)`) so they never go out over mobile data.
- Fallback: `WorkManager` periodic job (15 min, UNMETERED) with one short poll (`wait=0`) when the
  service is not running. Ask once for the battery-optimisation exemption (explain why; respect "no").
- Android 13+: request `POST_NOTIFICATIONS` during pairing. Coroutines only.

## 5. Notifications (bilingual, no details)
Channels: "Alerte rețea / Network alerts" (high) and "Supraveghere / Monitoring" (low).
| type | Romanian | English |
|---|---|---|
| new_device | "Un dispozitiv nou s-a conectat la rețea." | "A new device joined your network." |
| new_high_risk | "{count} probleme grave noi în rețea." | "{count} new serious problems on your network." |
| score_drop | "Scorul rețelei a scăzut: {previous} → {score}." | "Network score dropped: {previous} → {score}." |
| unknown | "Ceva s-a schimbat în rețea." | "Something changed on your network." |
Language follows the system locale (ro → Romanian, else English). Tap → event list.

## 6. Screens
1. Find & pair (discovered Pis, manual address, big verification code, status of the request).
2. Status: Pi name, connected / waiting / not on home Wi-Fi, last contact, "Monitoring" toggle.
3. Events: last 50 received (Room or a small JSON file), newest first.
4. Settings: Unpair (deletes everything locally), battery-optimisation shortcut.
Min 16 sp text, TalkBack labels, colour never the only signal, dark mode.

## 7. Security and privacy
- Cleartext HTTP is needed on the LAN only: `network_security_config.xml` with
  `cleartextTrafficPermitted="false"` in `base-config` and cleartext allowed only for local addresses;
  document the trade-off. Never contact any non-LAN host.
- Permissions only: INTERNET, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE, CHANGE_WIFI_MULTICAST_STATE,
  POST_NOTIFICATIONS, FOREGROUND_SERVICE, FOREGROUND_SERVICE_SPECIAL_USE,
  REQUEST_IGNORE_BATTERY_OPTIMIZATIONS (+ CAMERA only if the QR alternative is implemented).
  No location, contacts, analytics or crash-reporting SDKs.
- Treat responses as untrusted: strict JSON, cap body at 64 KB, ignore unknown fields, clamp `count`
  to 0..999, show the code only if it matches `^\d{3}$`.

## 8. Tests and acceptance
Unit tests: pairing state handling (200/403/409, pending/approved/rejected/expired/delivered), code
format check, event → text mapping ro/en incl. unknown type, backoff, status codes.
Integration (MockWebServer): full pairing flow, long-poll returning an event, empty timeout, 401 stop.

Done when:
- [ ] With `ajar_notify.py pair` open on the Pi, the app finds the Pi, both show the same code, the
      owner types DA on the Pi, and the app is paired. Rejecting on the Pi leaves the app unpaired.
- [ ] With the app in the background and the screen off, a new device on the Pi's network produces a
      notification in under ~70 s (typically seconds).
- [ ] Leaving the Wi-Fi stops polling; coming back resumes it without duplicates (`last_id` kept).
- [ ] `ajar_notify.py unpair <phone>` on the Pi makes the app ask to pair again (401).
- [ ] No request leaves the local network; the token never appears in logs or backups.
