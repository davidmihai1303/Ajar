// First screen before any scan: a greeting and one action. Ajar stays in its corner (AjarDock).
import { href } from "../router";
import { useApp } from "../state/AppState";
import { IconWifi } from "../components/Icons";
import LanguageToggle from "../components/LanguageToggle";

export default function Welcome() {
  const { t, network, agentDown, startScanFlow } = useApp();
  return (
    <div className="welcome">
      <div className="welcome-top">
        <LanguageToggle />
      </div>
      <div className="welcome-center">
        <h1 className="serif welcome-title">{t("welcome.title")}</h1>
        <p className="welcome-sub">{t("welcome.subtitle")}</p>
        <div className="composer">
          <div className="composer-net">
            <IconWifi />
            <div className="stack">
              <span className="strong">{network?.ssid ?? (agentDown ? t("network.agentDownShort") : t("network.unknownName"))}</span>
              <span className="muted">{network ? t("welcome.connected", { subnet: network.subnet }) : t("welcome.notDetected")}</span>
            </div>
          </div>
          <button type="button" className="button primary large" onClick={startScanFlow} disabled={!network}>
            {t("welcome.start")}
          </button>
        </div>
        <div className="row center">
          <a href={href({ name: "scan" })}>{t("welcome.import")}</a>
          <span aria-hidden="true" className="muted">
            ·
          </span>
          <a href={href({ name: "ask" })}>{t("welcome.what")}</a>
        </div>
      </div>
      <p className="muted center">{t("welcome.ownOnly")}</p>
    </div>
  );
}
