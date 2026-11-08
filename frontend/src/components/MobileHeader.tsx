// Phone header: the Ajar logo (the real wordmark), the network name and the language switch.
import { useApp } from "../state/AppState";
import LanguageToggle from "./LanguageToggle";

export default function MobileHeader() {
  const { t, scan } = useApp();

  return (
    <header className="mobile-header" role="banner">
      <a href="#/dashboard" className="mobile-brand">
        <img src="/ajar-logo.svg" alt="Ajar" className="mobile-logo" width="101" height="48" />
        <span className="muted mobile-network">{scan?.ssid ?? t("network.unknownName")}</span>
      </a>
      <LanguageToggle />
    </header>
  );
}
