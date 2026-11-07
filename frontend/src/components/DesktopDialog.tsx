// Dialog explaining and offering the desktop wrapper, System Tray integration and Widget.
import { useState } from "react";
import { useApp } from "../state/AppState";
import { IconDownload, IconShield, IconTerminal } from "./Icons";

export default function DesktopDialog({
  onClose,
  onOpenWidget,
}: {
  onClose: () => void;
  onOpenWidget: () => void;
}) {
  const { t } = useApp();
  const [downloaded, setDownloaded] = useState(false);

  const downloadBat = () => {
    const batContent = `@echo off
title NetCheck Desktop Companion
echo ==============================================
echo  NetCheck - Securitate Retea (Desktop Wrapper)
echo ==============================================
echo.
python "%~dp0netcheck_desktop.py"
if %errorlevel% neq 0 (
    echo Te rugam sa te asiguri ca Python si pystray sunt instalate:
    echo pip install pystray pillow
    pause
)
`;
    const blob = new Blob([batContent], { type: "application/x-bat" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "start_desktop.bat";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setDownloaded(true);
  };

  return (
    <div className="dialog-overlay" role="dialog" aria-modal="true" aria-labelledby="desktop-dialog-title">
      <div className="card dialog-content stack gap-m" style={{ maxWidth: 520, margin: "auto" }}>
        <div className="row spread center-y">
          <div className="row" style={{ gap: 8 }}>
            <IconShield />
            <h2 id="desktop-dialog-title" className="h3 serif">
              {t("desktop.downloadTitle")}
            </h2>
          </div>
          <button type="button" className="link-button" onClick={onClose} aria-label={t("common.close")}>
            ×
          </button>
        </div>

        <p className="muted">{t("desktop.downloadDesc")}</p>

        <div className="stack gap-m" style={{ gap: 12 }}>
          {/* Option 1: Native Desktop Companion */}
          <div className="card" style={{ background: "var(--canvas)", border: "1px solid var(--line)" }}>
            <div className="row spread center-y" style={{ marginBottom: 6 }}>
              <span className="strong">1. Desktop Wrapper (Tray, Widget & Notificări)</span>
              <span className="chip sev-low">Windows / Linux</span>
            </div>
            <p className="muted" style={{ fontSize: 14, marginBottom: 12 }}>
              Aplicație Python cu iconiță dinamică în System Tray:
              <br />
              🟢 <strong>Verde:</strong> Rețea sigură (Scor ≥ 80)
              <br />
              🟡 <strong>Galben:</strong> Atenție (Scor 50–79)
              <br />
              🔴 <strong>Roșu:</strong> Risc critic (Scor &lt; 50)
              <br />
              🔵 <strong>Albastru:</strong> Scanare în curs
            </p>
            <div className="row gap-m">
              <button type="button" className="button primary" onClick={downloadBat}>
                <IconDownload size={16} />
                {downloaded ? "Descărcat!" : t("desktop.downloadButton")}
              </button>
              <button
                type="button"
                className="button"
                onClick={() => {
                  onClose();
                  onOpenWidget();
                }}
              >
                {t("desktop.widgetOpen")}
              </button>
            </div>
          </div>

          {/* Option 2: PWA */}
          <div className="card" style={{ background: "var(--canvas)", border: "1px solid var(--line)" }}>
            <div className="row spread center-y" style={{ marginBottom: 6 }}>
              <span className="strong">2. {t("desktop.installPwa")}</span>
              <span className="chip sev-info">Browser / PWA</span>
            </div>
            <p className="muted" style={{ fontSize: 14 }}>
              Poți instala aplicația direct din bara de adrese a browserului (Edge / Chrome) apăsând pe pictograma de instalare pentru a o rula într-o fereastră nativă de desktop fără controale de browser.
            </p>
          </div>
        </div>

        <div className="row spread" style={{ marginTop: 8 }}>
          <button type="button" className="button self-start" onClick={onClose}>
            {t("common.close")}
          </button>
        </div>
      </div>
    </div>
  );
}
