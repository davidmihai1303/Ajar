// Dialog offering the standalone Linux desktop executable for Ajar.
import { useState } from "react";
import { downloadAjarLinux } from "../lib/downloadWrapper";
import { useApp } from "../state/AppState";
import { IconDownload, IconShield, IconTerminal } from "./Icons";

export default function DesktopDialog({
  onClose,
}: {
  onClose: () => void;
}) {
  const { t } = useApp();
  const [downloaded, setDownloaded] = useState(false);

  const handleDownload = () => {
    downloadAjarLinux();
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
          {/* Linux Executable */}
          <div className="card" style={{ background: "var(--canvas)", border: "1px solid var(--line)" }}>
            <div className="row spread center-y" style={{ marginBottom: 6 }}>
              <span className="strong">Executabil Ajar pentru Linux</span>
              <span className="chip sev-ok">Linux (x86_64 / arm64)</span>
            </div>
            <p className="muted" style={{ fontSize: 14, marginBottom: 12 }}>
              Lansează Ajar direct ca aplicație nativă de desktop pe Linux. Creează automat comanda <code>ajar</code> în terminal și scurtătura în meniul de aplicații.
            </p>
            <div className="stack" style={{ gap: 8 }}>
              <button type="button" className="button primary" onClick={handleDownload}>
                <IconDownload size={16} />
                {downloaded ? "✓ Descărcat (Ajar)" : t("desktop.downloadButton")}
              </button>
              <div className="card mono" style={{ fontSize: 13, padding: "8px 12px", background: "var(--surface)", border: "1px solid var(--line)" }}>
                <span className="muted"># Pași de pornire pe Linux:</span>
                <br />
                chmod +x Ajar
                <br />
                ./Ajar
              </div>
            </div>
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
