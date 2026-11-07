# NetCheck Desktop Companion (Wrapper, Tray & Widget)

Aplicație companion de desktop pentru Windows / Linux / macOS:
- **System Tray cu 4 stări dinamice**:
  - 🟢 **Verde (✓ Sigur)**: Scor rețea ≥ 80 / 100
  - 🟡 **Galben (● Atenție)**: Scor rețea 50–79 / 100
  - 🔴 **Roșu (▲ Risc ridicat)**: Scor rețea < 50 / 100
  - 🔵 **Albastru (↻ Scanare în curs)**: Când rețeaua este scanată
- **Floating Desktop Widget**:
  - Fereastră plutitoare compactă, `always-on-top`, mutabilă pe ecran prin drag & drop.
  - Afișează SSID, scorul curent, numărul de vulnerabilități și butoane rapide de scanare și deschidere.
- **Notificări Desktop Native**:
  - Trimitere automată de notificări Windows la finalizarea scanării sau la apariția de amenințări noi.
- **Interacțiune cu interfața web**:
  - Deschide la 1-click panoul web la `http://127.0.0.1:5173/`.

### Lansare rapidă:
Dublu-click pe `start_desktop.bat` sau din terminal:
```bash
python desktop/netcheck_desktop.py
```
