// Compact desktop floating widget displaying live security score, severity counts and quick actions.
import { useState } from "react";
import { href } from "../router";
import { scoreLevel, severityCounts } from "../lib/scan";
import { useApp } from "../state/AppState";
import { IconAsk, IconBell, IconDownload, IconRefresh, IconShield } from "./Icons";
import ScoreBadge, { SeverityBadge } from "./ScoreBadge";

export default function MiniWidget({
  onClose,
  onDownloadWrapper,
}: {
  onClose: () => void;
  onDownloadWrapper: () => void;
}) {
  const { t, scan, startScanFlow } = useApp();
  const [minimized, setMinimized] = useState(false);
  const [notifGranted, setNotifGranted] = useState(
    typeof Notification !== "undefined" && Notification.permission === "granted"
  );

  const enableNotifications = async () => {
    if (typeof Notification === "undefined") return;
    try {
      const res = await Notification.requestPermission();
      if (res === "granted") {
        setNotifGranted(true);
        new Notification("NetCheck", {
          body: t("desktop.notifyEnabled"),
        });
      }
    } catch {
      /* ignore */
    }
  };

  const score = scan?.score ?? null;
  const level = scoreLevel(score);
  const counts = scan ? severityCounts(scan) : { high: 0, medium: 0, low: 0, info: 0 };

  if (minimized) {
    return (
      <aside
        className="card row"
        style={{
          position: "fixed",
          bottom: 24,
          right: 24,
          zIndex: 9999,
          padding: "8px 16px",
          background: "var(--surface)",
          boxShadow: "0 8px 24px rgba(0,0,0,0.18)",
          border: "2px solid var(--line-strong)",
          borderRadius: 999,
          cursor: "pointer",
        }}
        onClick={() => setMinimized(false)}
        role="complementary"
        aria-label={t("desktop.widget")}
      >
        <span className={`chip level-${level}`} style={{ padding: "2px 8px" }}>
          {score ?? "—"}
        </span>
        <span className="strong" style={{ fontSize: 14 }}>
          {scan?.ssid ?? t("network.unknownName")}
        </span>
        <button
          type="button"
          className="link-button"
          style={{ fontSize: 18, padding: "0 4px" }}
          onClick={(e) => {
            e.stopPropagation();
            onClose();
          }}
          aria-label={t("common.close")}
        >
          ×
        </button>
      </aside>
    );
  }

  return (
    <aside
      className="card stack gap-m"
      style={{
        position: "fixed",
        bottom: 24,
        right: 24,
        width: 320,
        zIndex: 9999,
        background: "var(--surface)",
        boxShadow: "0 12px 32px rgba(0,0,0,0.2)",
        border: "2px solid var(--walnut)",
        borderRadius: 16,
        padding: 16,
      }}
      role="complementary"
      aria-label={t("desktop.widget")}
    >
      <div className="row spread center-y">
        <div className="row" style={{ gap: 8 }}>
          <IconShield />
          <span className="strong">{t("desktop.widget")}</span>
        </div>
        <div className="row" style={{ gap: 4 }}>
          <button
            type="button"
            className="link-button muted"
            style={{ fontSize: 13 }}
            onClick={() => setMinimized(true)}
          >
            _
          </button>
          <button
            type="button"
            className="link-button muted"
            style={{ fontSize: 18, lineHeight: 1 }}
            onClick={onClose}
            aria-label={t("common.close")}
          >
            ×
          </button>
        </div>
      </div>

      <div className="row spread center-y">
        <ScoreBadge score={score} size="large" />
        <div className="stack" style={{ textAlign: "right" }}>
          <span className="strong" style={{ fontSize: 15 }}>
            {scan?.ssid ?? t("network.unknownName")}
          </span>
          <span className="muted" style={{ fontSize: 13 }}>
            {scan?.devices.length ?? 0} {t("devices.title").toLowerCase()}
          </span>
        </div>
      </div>

      <div className="row wrap gap-m" style={{ justifyContent: "space-between" }}>
        <SeverityBadge severity="high" count={counts.high} />
        <SeverityBadge severity="medium" count={counts.medium} />
        <SeverityBadge severity="low" count={counts.low} />
      </div>

      <div className="stack gap-m" style={{ gap: 8 }}>
        <div className="row spread" style={{ gap: 8 }}>
          <button
            type="button"
            className="button primary grow"
            onClick={startScanFlow}
            style={{ minHeight: 38, fontSize: 14 }}
          >
            <IconRefresh size={16} />
            {t("dashboard.rescan")}
          </button>
          <a
            className="button grow"
            href={href({ name: "dashboard" })}
            onClick={onClose}
            style={{ minHeight: 38, fontSize: 14 }}
          >
            {t("nav.dashboard")}
          </a>
        </div>

        <div className="row spread" style={{ gap: 8 }}>
          <button
            type="button"
            className="button grow"
            style={{ minHeight: 36, fontSize: 13 }}
            onClick={enableNotifications}
            title={notifGranted ? t("desktop.notifyEnabled") : t("desktop.notifyEnable")}
          >
            <IconBell />
            {notifGranted ? t("desktop.notifyEnabled") : t("desktop.notifyEnable")}
          </button>
          <button
            type="button"
            className="button grow"
            style={{ minHeight: 36, fontSize: 13 }}
            onClick={onDownloadWrapper}
            title={t("desktop.downloadTitle")}
          >
            <IconDownload size={16} />
            {t("desktop.download")}
          </button>
        </div>
      </div>
    </aside>
  );
}
