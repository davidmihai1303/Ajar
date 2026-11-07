# Plan Lab (ora 0–3)

## Pasul 1 (Hotspot) – ora 0:00–0:30:

1. Configurare hotspot pe telefon: nume `RSH-<nr echipă>`, securitate WPA2/WPA3, parolă puternică
2. Setare limită de date mobile pe telefon
3. Conectarea tuturor laptopurilor la hotspot (Wi-Fi), și deconectarea lor de la orice altă rețea (Wi-Fi-ul locației, VPN, Tailscale)
4. Notarea IP-ului fiecărui laptop și a subnetului (doar pentru verificare, nu pentru cod)
5. Test de vizibilitate: laptopurile își dau `ping` unul altuia
6. Dacă ping-ul nu merge (izolare clienți), încercați alt telefon; dacă nici așa nu merge, treceți pe Setup D (totul pe un laptop)

✅ **Checkpoint 1:** toate laptopurile sunt pe `RSH-<nr>` și se văd între ele.

## Pasul 2 (Laptop Țintă) – ora 0:30–1:30:

1. Instalare / pornire Docker Desktop
2. Pornire container Redis (→ `DB_EXPOSED`)
3. Pornire container Mosquitto 1.6 (→ `MQTT_EXPOSED`)
4. Pornire container nginx cu o pagină intitulată „Admin Login" pe 8080 (→ `HTTP_ADMIN_CLEARTEXT`)
5. Pornire scripturi cu bannere false: Telnet pe 2323 (→ `TELNET_OPEN`), FTP „vsftpd 2.3.4" (→ `FTP_CLEARTEXT` + `OUTDATED_SERVICE`)
6. Permiterea porturilor în firewall-ul laptopului țintă (profil de rețea „Privat" pe Windows)
7. Opțional, a doua/a treia țintă reală: SMB pe un laptop Windows, SSH pe Raspberry Pi / alt laptop

✅ **Checkpoint 2:** minimum 3 ținte (dispozitive sau servicii) și minimum 5 tipuri de finding pornite.

## Pasul 3 (Laptop Scanner) – ora 1:30–2:30:

1. Instalare nmap și verificare că rulează ca administrator
2. Scanare rapidă a subnetului, pentru a vedea dacă apar toate țintele
3. Verificare pe fiecare țintă că porturile apar `open` (nu `filtered`) și că serviciul e recunoscut corect (telnet, ftp, redis, mqtt, http)
4. Dacă un serviciu fals nu e recunoscut (de ex. Telnet apare `unknown`), ajustați bannerul și reverificați
5. Scanarea completă: top 1.000 porturi TCP + UDP 53, 123, 161, 1900, 5353, cu detecție de versiune și titlul paginilor web, rate-limited (≤ 100 pachete/s)
6. Salvarea rezultatului ca `scan_01.xml`, în folderul de fixture-uri din repo

✅ **Checkpoint 3:** `scan_01.xml` salvat, cu toate cele ≥ 5 tipuri de finding vizibile în el.

## Pasul 4 (Before/After + încheiere) – ora 2:30–3:00:

1. Încă o scanare completă fără modificări → `scan_02.xml` (verifică stabilitatea rezultatelor)
2. „Reparare" a minimum 2 finding-uri (oprire Telnet fals + oprire container Redis)
3. Rescanare → `scan_03_after.xml`
4. Repornirea serviciilor oprite (lab-ul rămâne disponibil pentru teste)
5. Notarea setup-ului ales (A / B / C / D) și a ce rulează pe fiecare țintă, pentru rezumatul tehnic și pitch
6. Commit cu toate XML-urile în repo

✅ **Checkpoint 4 (ora 3):** 3+ scanări salvate, inclusiv o pereche before/after, iar laboratorul este documentat.
