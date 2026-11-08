import { assessment } from "../lib/scan";
import { useApp } from "../state/AppState";
import { IconShield } from "./Icons";
import LanguageToggle from "./LanguageToggle";

export default function MobileHeader() {
  const { t, scan } = useApp();
  const score = scan?.score ?? null;
  const level = assessment(scan);

  return (
    <header className="mobile-header" role="banner">
      <div className="row" style={{ gap: 8 }}>
        <IconShield />
        <div className="stack" style={{ gap: 0 }}>
          <span className="strong" style={{ fontSize: 16 }}>Ajar</span>
          <span className="muted" style={{ fontSize: 12 }}>
            {scan?.ssid ?? t("network.unknownName")}
          </span>
        </div>
      </div>

      <div className="row" style={{ gap: 10 }}>
        <span className={`chip sev-${level}`} style={{ padding: "2px 8px", fontSize: 13 }} title={t(`assessment.${level}`)}>
          {score ?? "—"}
        </span>
        <LanguageToggle />
      </div>
    </header>
  );
}
