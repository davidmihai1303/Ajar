# Ajar pe Raspberry Pi: supraveghere automată, cu acord legat de rețea

| Etapă | Ce face | Cât de des |
|---|---|---|
| 1 | **scanare completă** (porturi, probleme, scor) | la 3 ore (timer) |
| 2 + 3 | **cine e conectat** (fără porturi) → device nou = eveniment + o scanare completă | la **60 s** și **imediat** când tabela de vecini arată un MAC necunoscut (serviciul `watch`) |
| 3 | **evenimente pentru telefon** (device nou, problemă gravă nouă, scor scăzut), cu long-poll | instant, cât timp telefonul e în rețea |

Totul rulează **doar în rețeaua pentru care ai dat acordul**. În orice altă rețea (Wi-Fi-ul sălii, la un
prieten, la hotel) nu scanează și scrie motivul în log. Nimic nu iese din casă: niciun serviciu extern.

## Acordul legat de rețea

Brief-ul cere confirmare explicită pentru orice scanare live (FR-02). O scanare automată nu are pe nimeni
care să confirme, așa că proprietarul confirmă **o singură dată pentru fiecare rețea**:

| Ce se salvează | De ce |
|---|---|
| numele Wi-Fi + subnetul + IP-ul routerului | rețeaua confirmată |
| **amprenta routerului**: HMAC-SHA256(cheie locală, MAC router) | toate hotspoturile de iPhone au `172.20.10.0/28`, iar numele Wi-Fi poate fi copiat. MAC-ul **nu** e salvat |
| data expirării (implicit 30 de zile) | acordul nu rămâne valabil la nesfârșit |

Stare locală în `~/.config/ajar/` (toate `0600`): `consent.json`, `consent.key`, `devices.json`
(doar amprente HMAC ale MAC-urilor), `events.sqlite`, `notify.token`.

## Cum funcționează

```
                        ┌─ ajar-autoscan.timer (3 h) ─► run ──► POST /api/scans (aplicația, ca butonul din UI)
acord pentru rețea? ────┤                                            └─► scor mai mic / mai multe probleme grave
                        │                                                 = eveniment
                        └─ ajar-watch.service ─► discover la 60 s sau imediat la un MAC necunoscut
                                                  └─► POST 127.0.0.1:8765/discover (agentul)
                                                        └─► sudo netcheck-nmap --discover <subnet>
                                                              nmap -sn -n --max-rate 100 (fără porturi, fără DNS)
                                                  device nou ─► eveniment + o scanare completă (max. 1 / 30 min)

ajar-notify.service (port 8002) ─► GET /events?since=N&wait=60 + token ─► telefonul (aplicația Ajar)
```

- **`watch` e pasiv în plus:** urmărește tabela de vecini a kernelului (`ip monitor neigh`), fără pachete.
  Vede doar device-urile care comunică cu Pi-ul, de aceea descoperirea la 60 s rămâne plasa de siguranță.
  Pe un hotspot `/28` asta înseamnă ~16 pachete ARP pe minut; acasă, pe `/24`, ~256 pe minut.
- Prima descoperire pe o rețea doar **notează ce e conectat** (inventar inițial), fără eveniment.
- Un device nevăzut 30 de zile e uitat; dacă revine, apare din nou ca nou. Telefoanele cu adresă Wi-Fi
  aleatorie o păstrează de obicei pe aceeași rețea; dacă și-o schimbă, apar ca device nou.

## Serviciul pentru telefon (`ajar_notify.py`)

| Regulă | Detaliu |
|---|---|
| aproape doar citire | `GET /events` pentru evenimente. Singura scriere: `POST /pair`, cererea de împerechere a unui telefon, acceptată **doar** cât e deschisă fereastra. Nu poate porni scanări |
| token pe telefon | fiecare telefon are **propriul** token (`Authorization: Bearer <token>`); pe Pi se păstrează doar SHA-256 al lui (`phones.json`). Fără token valid → 401 |
| conținut minim | `id`, `time`, `type`, `severity`, `count` (+ `score`, `previous` la scăderea scorului). **Niciodată** IP, MAC, nume sau producător |
| long-poll | `?since=<ultimul id>&wait=<0..60>`: răspunde imediat ce apare un eveniment, altfel după `wait` secunde cu listă goală |
| fără `since` | răspunde doar `{"last_id": N}`, ca un telefon nou să pornească „de acum" |
| limite | 120 de cereri/minut pe client, maximum 8 long-poll-uri deschise |
| rețea | ascultă pe `0.0.0.0:8002` (`AJAR_NOTIFY_BIND`, `AJAR_NOTIFY_PORT`), **HTTP simplu**: cine poate citi traficul Wi-Fi ar putea vedea token-ul și, cu el, doar aceste evenimente minimale. Îl schimbi cu `pair --new` |

Tipuri de evenimente: `new_device` (info), `new_high_risk` (high), `score_drop` (medium).

## Împerecherea telefonului (fără cod QR)

Ca la Bluetooth: amândouă ecranele arată același cod, iar **aprobarea se face pe Pi**. Aprobarea nu se
poate face de pe telefon, altfel un telefon străin din Wi-Fi s-ar putea aproba singur.

```
Pi:       python3 deploy/pi/ajar_notify.py pair          → „Fereastră deschisă 2 min"
Telefon:  găsește Pi-ul (_ajar._tcp) → POST /pair {"name": "Pixel 7"}
          ← {"request_id": "…", "code": "471", "expires_in": 118}  → arată „Cod: 4 7 1"
Pi:       „Cerere de la «Pixel 7». Cod de verificare: 4  7  1. Scrie DA" → verifici telefonul → DA
Telefon:  GET /pair/<request_id> la ~1 s → {"status": "approved", "token": "…", "phone_id": "…"}
          (token-ul e dat o singură dată; apoi fereastra se închide)
```

| Situație | Răspuns |
|---|---|
| fereastra nu e deschisă sau a expirat | `POST /pair` → 403 |
| altă cerere așteaptă deja | `POST /pair` → 409 (o singură cerere odată) |
| respinsă pe Pi | `GET /pair/<id>` → `{"status": "rejected"}` |
| token deja luat | `GET /pair/<id>` → `{"status": "delivered"}` (fără token) |
| id greșit | 404 |

Alternativă: `python3 deploy/pi/ajar_notify.py pair --qr` creează un token pentru un telefon și îl arată
ca QR. Token-ul vechi (`notify.token`, dacă există) funcționează în continuare și apare în `devices` ca
`qr-legacy`.

## Instalare (o singură dată)

Ai nevoie de aplicație (containerul pe `127.0.0.1:8001`) și de serviciul `netcheck-agent`, ambele pornite.

```bash
cd ~/Smarthack
sudo ./scanner/install.sh $USER                   # wrapper-ul root are modul --discover
sudo systemctl restart netcheck-agent             # agentul are endpoint-ul /discover
python3 deploy/pi/ajar_autoscan.py consent grant  # arată rețeaua, scrii DA
./deploy/pi/install_autoscan.sh --announce        # fără sudo; --announce = anunț mDNS _ajar._tcp
python3 deploy/pi/ajar_notify.py pair             # deschizi fereastra, telefonul cere, aprobi cu DA
```

`install_autoscan.sh` șterge singur timer-ul de 10 minute de la etapa 2 (`ajar-discover`), dacă există.

## Comenzi

| Comandă | Ce face |
|---|---|
| `python3 deploy/pi/ajar_autoscan.py consent grant [--days 30]` | acord pentru rețeaua curentă (interactiv) |
| `python3 deploy/pi/ajar_autoscan.py consent show` / `revoke [--all]` | vezi / retragi acordurile |
| `python3 deploy/pi/ajar_autoscan.py check` | ar rula o scanare acum? (nu scanează) |
| `python3 deploy/pi/ajar_autoscan.py discover --no-scan` | o verificare de device-uri noi, acum |
| `python3 scanner/agent.py discover --confirm` | cine e conectat (MAC-uri afișate mascat) |
| `python3 deploy/pi/ajar_notify.py pair [--minutes 2]` | fereastră de împerechere cu cod de verificare |
| `python3 deploy/pi/ajar_notify.py pair --qr` | alternativ: token pentru un telefon, ca cod QR |
| `python3 deploy/pi/ajar_notify.py devices` | telefoanele împerecheate |
| `python3 deploy/pi/ajar_notify.py unpair <id\|nume>` / `--all` | scoate un telefon / toate |
| `sudo systemctl start ajar-autoscan.service` | o scanare completă **acum** (test) |
| `journalctl -u ajar-watch -u ajar-autoscan -u ajar-notify -f` | log în timp real |
| `systemctl status ajar-watch ajar-notify` | starea serviciilor |
| `./deploy/pi/install_autoscan.sh --remove` | oprește și șterge tot (inclusiv anunțul mDNS) |

Intervalul de descoperire: `AJAR_WATCH_INTERVAL` (30-600 s, implicit 60), de exemplu cu
`sudo systemctl edit ajar-watch.service` → `[Service]` / `Environment=AJAR_WATCH_INTERVAL=30`.

## Test complet (pe hotspotul echipei)

1. `journalctl -u ajar-watch -f` într-un terminal: „Inventar inițial: N dispozitive".
2. Împerechere de pe laptop (joacă rolul telefonului). Pe Pi: `python3 deploy/pi/ajar_notify.py pair`, apoi:
   ```bash
   curl -s -H "Content-Type: application/json" -d '{"name":"laptop-test"}' http://<pi>:8002/pair
   # → {"request_id": "…", "code": "471", …}   pe Pi apare același cod → scrii DA
   curl -s http://<pi>:8002/pair/<request_id>   # → {"status": "approved", "token": "…"}
   curl -s -H "Authorization: Bearer <token>" "http://<pi>:8002/events"
   curl -s -H "Authorization: Bearer <token>" "http://<pi>:8002/events?since=<last_id>&wait=60"
   ```
   Ultima comandă rămâne deschisă.
3. Conectezi la hotspot un device nou. În sub un minut: în log „DISPOZITIV NOU…", iar `curl`-ul de la
   pasul 2 răspunde imediat cu `{"type": "new_device", …}`. Apoi pornește o scanare completă.
4. Fără token: `curl -i http://<pi>:8002/events` → `401`.
5. Pi-ul pe **alt hotspot** → `ajar_autoscan.py check` spune că **NU** ar rula, iar `watch` nu scanează.

## Aplicația Android (schiță)

Împerechere: găsești Pi-ul cu `NsdManager` (`_ajar._tcp`), trimiți `POST /pair`, afișezi codul mare pe
ecran („Confirmă pe Pi că vezi 4 7 1"), apoi întrebi `GET /pair/<request_id>` la ~1 s până primești
`approved` + token (sau `rejected` / `expired`). Salvezi host, port și token în `EncryptedSharedPreferences`. Un **foreground service** (cu notificarea permanentă „Ajar veghează rețeaua")
rulează cât timp telefonul e pe Wi-Fi (`ConnectivityManager.NetworkCallback`); cere și excepția de la
optimizarea bateriei. Bucla de long-poll:

```kotlin
// Kotlin, kotlinx.coroutines + java.net (fără biblioteci externe)
suspend fun pollEvents(host: String, port: Int, token: String, store: Prefs) = withContext(Dispatchers.IO) {
    var since = store.lastId ?: fetchLastId(host, port, token)          // GET /events (fără since)
    while (isActive) {
        try {
            val url = URL("http://$host:$port/events?since=$since&wait=60")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                setRequestProperty("Authorization", "Bearer $token")
                connectTimeout = 5_000
                readTimeout = 70_000                                     // mai mult decât wait=60
            }
            when (conn.responseCode) {
                200 -> {
                    val body = JSONObject(conn.inputStream.bufferedReader().readText())
                    val events = body.getJSONArray("events")
                    for (i in 0 until events.length()) showNotification(events.getJSONObject(i))
                    since = body.getInt("last_id"); store.lastId = since
                }
                401 -> { stopAndAskToPairAgain(); return@withContext }
                else -> delay(30_000)                                    // 429 / 503 / altceva
            }
            conn.disconnect()
        } catch (e: IOException) {
            delay(15_000)                                                // Pi oprit / altă rețea
        }
    }
}
```

`showNotification` afișează texte scurte, fără detalii, de exemplu „Un device nou s-a conectat la rețea"
(`new_device`) sau „O problemă gravă nouă în rețea" (`new_high_risk`). Detaliile se văd în aplicație.
Pentru găsirea automată a Pi-ului: `NsdManager.discoverServices("_ajar._tcp", …)`.

## Teste

```bash
python3 -m unittest discover -s deploy/pi/tests -v   # 59, doar biblioteca standard, nu scanează nimic
python3 -m unittest discover -s scanner/tests -v     # 51, inclusiv --discover și /discover
```

## Reguli

- Doar rețele proprii sau cu permisiunea proprietarului. Acasă, cere acordul celor din casă.
- La hackathon, Pi-ul stă doar pe hotspotul echipei.
- Nimic din `deploy/pi` nu rulează ca root (scripturile refuză singure); pasul root rămâne `netcheck-nmap`.
- **Înainte de juriu**: decideți dacă `ajar-notify` și anunțul mDNS rămân pornite (`--remove` le oprește).
