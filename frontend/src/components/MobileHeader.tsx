import { scoreLevel } from "../lib/scan";
import { useApp } from "../state/AppState";
import { IconBell, IconShield } from "./Icons";
import LanguageToggle from "./LanguageToggle";

export default function MobileHeader() {
  const { t, scan } = useApp();
  const score = scan?.score ?? null;
  const level = scoreLevel(score);
  const notifActive = typeof Notification !== "undefined" && Notification.permission === "granted";

  return (
    <header className="mobile-header" role="banner">
      <div className="row" style={{ gap: 8 }}>
        <IconShield />
        <div className="stack" style={{ gap: 0 }}>
          <span className="strong" style={{ fontSize: 16 }}>NetCheck</span>
          <span className="muted" style={{ fontSize: 12 }}>
            {scan?.ssid ?? t("network.unknownName")}
          </span>
        </div>
      </div>

      <div className="row" style={{ gap: 10 }}>
        <span className={`chip level-${level}`} style={{ padding: "2px 8px", fontSize: 13 }}>
          {score ?? "—"}
        </span>
        <div
          title={notifActive ? t("mobile.notifyActive") : t("mobile.notifyEnable")}
          style={{ position: "relative", display: "inline-flex", color: notifActive ? "var(--green)" : "var(--muted)" }}
        >
          <IconBell />
          {notifActive && (
            <span
              style={{
                position: "absolute",
                top: -2,
                right: -2,
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: "var(--green)",
              }}
            />
          )}
        </div>
        <LanguageToggle />
      </div>
    </header>
  );
}
