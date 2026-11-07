// "How safe am I and what do I do first?", answered without a click (jury check #2).
// Kept short on purpose: score, one compact "fix this first" card, counts, and changes folded away.
import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import type { Explanation, ScanDiff, Severity } from "../api/proposedTypes";
import { formatDate } from "../i18n";
import { downloadDesktopWrapper } from "../lib/downloadWrapper";
import { bySeverity, fixFirst, scoreLevel, severityCounts } from "../lib/scan";
import { useIsMobile } from "../lib/useIsMobile";
import { href } from "../router";
import { useApp } from "../state/AppState";
import { useDeviceName } from "../components/DeviceCard";
import FindingCard from "../components/FindingCard";
import { DeviceIcon, IconAsk, IconBell, IconChevron, IconDownload, IconRefresh } from "../components/Icons";
import ScoreBadge, { SeverityBadge } from "../components/ScoreBadge";

const readOpen = () => {
  try {
    return window.localStorage.getItem("ajar.alerts") === "open";
  } catch {
    return false;
  }
};

export default function Dashboard() {
  const { t, lang, scan, history, setBubble, startScanFlow } = useApp();
  const deviceName = useDeviceName();
  const [text, setText] = useState<Explanation | null>(null);
  const [diff, setDiff] = useState<ScanDiff | null>(null);
  const [alertsOpen, setAlertsOpen] = useState(readOpen);
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | "all" | null>(null);
  const isMobile = useIsMobile();
  const [mobileWidgetMode, setMobileWidgetMode] = useState(false);
  const [mobileNotifActive, setMobileNotifActive] = useState(
    typeof Notification !== "undefined" && Notification.permission === "granted"
  );

  const enableMobileNotifications = async () => {
    if (typeof Notification === "undefined") return;
    try {
      const res = await Notification.requestPermission();
      if (res === "granted") {
        setMobileNotifActive(true);
        if (navigator.vibrate) navigator.vibrate([100, 50, 100]);
        new Notification("NetCheck", {
          body: t("mobile.notifyActive"),
        });
      }
    } catch {
      /* ignore */
    }
  };

  const testMobileNotification = () => {
    if (typeof Notification === "undefined" || Notification.permission !== "granted") return;
    if (navigator.vibrate) navigator.vibrate([200, 100, 200]);
    new Notification("NetCheck Alertă", {
      body: "Notificările pe telefon sunt active! Vei primi alerte instant când serverul detectează vulnerabilități.",
    });
  };

  const assessed = scan !== null && scan.score !== null && !scan.error;
  const first = assessed ? fixFirst(scan) : null;
  const finding = first?.findings[0] ?? null;
  const index = scan ? history.findIndex((item) => item.id === scan.id) : -1;
  const previous = index >= 0 ? history.slice(index + 1).find((item) => item.score !== null) : undefined;

  const allFindings = useMemo(() => {
    if (!scan) return [];
    const deviceMap = new Map(scan.devices.map((d) => [d.ip, d]));
    return [...scan.findings].sort(bySeverity).map((f) => ({
      finding: f,
      device: deviceMap.get(f.ip),
    }));
  }, [scan]);

  const displayedFindings = useMemo(() => {
    if (!selectedSeverity || selectedSeverity === "all") return allFindings;
    return allFindings.filter((item) => item.finding.severity === selectedSeverity);
  }, [allFindings, selectedSeverity]);

  useEffect(() => {
    if (!finding) return setText(null);
    let alive = true;
    api.explain(finding.code, lang).then((value) => alive && setText(value)).catch(() => alive && setText(null));
    return () => {
      alive = false;
    };
  }, [finding?.code, lang]);

  useEffect(() => {
    if (!assessed || !scan || !previous) return setDiff(null);
    let alive = true;
    api.diff(previous.id, scan.id).then((value) => alive && setDiff(value)).catch(() => alive && setDiff(null));
    return () => {
      alive = false;
    };
  }, [assessed, scan?.id, previous?.id]);

  // Ajar says where to start, once per scan.
  useEffect(() => {
    if (!first) return;
    setBubble(t("dashboard.bubble", { device: deviceName(first.device.device_type) }));
    const timer = window.setTimeout(() => setBubble(null), 7000);
    return () => {
      window.clearTimeout(timer);
      setBubble(null);
    };
  }, [scan?.id, lang]);

  const toggleAlerts = () => {
    const next = !alertsOpen;
    setAlertsOpen(next);
    try {
      window.localStorage.setItem("ajar.alerts", next ? "open" : "closed");
    } catch {
      /* remembered for this visit only */
    }
  };

  if (!scan) return null;
  if (!assessed) return (
    <div className="page">
      <h1 className="serif h1">{t("dashboard.unassessed")}</h1>
      <p className="banner banner-error">{t(scan.error ? "scan.unreadable" : "dashboard.noScore")}</p>
      <a className="button primary self-start" href={href({ name: "scan" })}>{t("nav.newScan")}</a>
    </div>
  );
  const counts = severityCounts(scan);
  const delta = previous && scan.score !== null && previous.score !== null ? scan.score - previous.score : null;
  const changes = diff ? diff.devices_added.length + diff.ports_opened.length : 0;

  return (
    <div className="page">
      {/* Mobile Mode Switcher & Mobile Real-time Notifications */}
      {isMobile && (
        <div className="stack gap-m" style={{ gap: 12 }}>
          <div className="segmented" style={{ width: "100%", justifyContent: "center" }}>
            <button
              type="button"
              className={!mobileWidgetMode ? "on" : ""}
              onClick={() => setMobileWidgetMode(false)}
              style={{ flex: 1, textAlign: "center" }}
            >
              📊 {t("mobile.modeFull")}
            </button>
            <button
              type="button"
              className={mobileWidgetMode ? "on" : ""}
              onClick={() => setMobileWidgetMode(true)}
              style={{ flex: 1, textAlign: "center" }}
            >
              📱 {t("mobile.modeWidget")}
            </button>
          </div>

          <section className="mobile-notify-card">
            <div className="row spread center-y">
              <div className="row" style={{ gap: 10 }}>
                <IconBell />
                <div className="stack" style={{ gap: 2 }}>
                  <span className="strong">{t("mobile.notifyTitle")}</span>
                  <span className="muted" style={{ fontSize: 13 }}>{t("mobile.notifySubtitle")}</span>
                </div>
              </div>
              <button
                type="button"
                className={`button ${mobileNotifActive ? "" : "primary"}`}
                style={{ minHeight: 36, fontSize: 13, padding: "0 12px" }}
                onClick={enableMobileNotifications}
              >
                {mobileNotifActive ? "✓ " + t("mobile.notifyActive") : t("mobile.notifyEnable")}
              </button>
            </div>
            {mobileNotifActive && (
              <button
                type="button"
                className="link-button muted"
                style={{ fontSize: 12, padding: 0 }}
                onClick={testMobileNotification}
              >
                {t("mobile.testNotify")} →
              </button>
            )}
          </section>
        </div>
      )}

      {/* When in Mobile Widget Mode, show the high-contrast mobile widget */}
      {isMobile && mobileWidgetMode ? (
        <section className="mobile-widget-card">
          <span className="strong" style={{ fontSize: 18, color: "var(--walnut)" }}>
            📱 {t("mobile.widgetTitle")}
          </span>
          <div className="center">
            <ScoreBadge score={scan.score} size="large" />
          </div>
          <div className="stack" style={{ gap: 4 }}>
            <span className="strong" style={{ fontSize: 17 }}>
              {scan.ssid ?? t("network.unknownName")}
            </span>
            <span className={allFindings.length > 0 ? "text-risky strong" : "text-safe strong"} style={{ fontSize: 14 }}>
              {allFindings.length > 0
                ? t("mobile.vulnerabilityDetected", { count: allFindings.length })
                : t("mobile.networkSafe")}
            </span>
          </div>

          <div className="row wrap center gap-m">
            <SeverityBadge severity="high" count={counts.high} />
            <SeverityBadge severity="medium" count={counts.medium} />
            <SeverityBadge severity="low" count={counts.low} />
          </div>

          <div className="stack" style={{ gap: 10, width: "100%" }}>
            <button
              type="button"
              className="button primary large"
              onClick={startScanFlow}
              style={{ width: "100%", justifyContent: "center" }}
            >
              <IconRefresh size={18} />
              {t("dashboard.rescan")}
            </button>
            <button
              type="button"
              className="button large"
              onClick={downloadDesktopWrapper}
              style={{ width: "100%", justifyContent: "center" }}
              title={t("desktop.downloadTitle")}
            >
              <IconDownload size={18} />
              {t("desktop.download")}
            </button>
          </div>
        </section>
      ) : (
        <>
          <section className="row spread end">
        <div className="stack">
          <ScoreBadge score={scan.score} />
          <span className="muted">
            {t("dashboard.context", {
              ssid: scan.ssid ?? t("network.unknownName"),
              devices: scan.devices.length,
              date: formatDate(scan.created_at, lang),
            })}
          </span>
        </div>
        {delta !== null && (
          <a href={href({ name: "history" })} className={delta < 0 ? "text-risky" : delta > 0 ? "text-safe" : ""}>
            {delta === 0 ? t("dashboard.same") : t(delta > 0 ? "dashboard.up" : "dashboard.down", { delta: Math.abs(delta) })}
          </a>
        )}
      </section>

      {first && finding ? (
        <section className={`fix-first tint-${finding.severity}`} aria-labelledby="fix-first-title">
          <div className="fix-first-head">
            <DeviceIcon type={first.device.device_type} />
            <div className="grow">
              <h2 id="fix-first-title" className="h3">
                {t("dashboard.startWith", { device: deviceName(first.device.device_type) })}
              </h2>
              <p className="muted">{text?.explanation ?? ""}</p>
            </div>
            <SeverityBadge severity={finding.severity} />
          </div>
          <div className="fix-first-action row wrap gap-m">
            {text && text.steps[0] && (
              <p className="grow">
                <span className="step-number" aria-hidden="true">
                  1
                </span>
                <span className="strong">{text.steps[0]}</span>
              </p>
            )}
            <div className="row wrap gap-m">
              <a
                className="button"
                href={href({
                  name: "ask",
                  query: t("finding.rephraseQuestion", {
                    code: finding.code,
                    device: deviceName(first.device.device_type),
                    ip: first.device.ip,
                  }),
                })}
                title={t("dashboard.askAi")}
              >
                <IconAsk />
                {t("dashboard.askAi")}
              </a>
              <button
                type="button"
                className="button"
                onClick={startScanFlow}
                title={t("dashboard.rescanNote")}
              >
                <IconRefresh />
                {t("dashboard.rescan")}
              </button>
              <a className="button primary" href={href({ name: "device", ip: first.device.ip })}>
                {t("dashboard.showMe")}
              </a>
            </div>
          </div>
        </section>
      ) : (
        <section className="fix-first tint-ok">
          <h2 className="h3">{t("dashboard.allGood")}</h2>
          <p className="muted">{t("dashboard.allGoodText")}</p>
        </section>
      )}

      <section className="dashboard-filter-section stack" style={{ gap: 12 }}>
        <div className="row spread baseline">
          <h2 className="h3 serif">{t("dashboard.filterTitle")}</h2>
          {selectedSeverity && (
            <button
              type="button"
              className="link-button muted"
              onClick={() => setSelectedSeverity(null)}
            >
              {t("common.hide")}
            </button>
          )}
        </div>
        <div className="row wrap gap-m" role="group" aria-label={t("dashboard.bySeverity")}>
          <button
            type="button"
            className={`pill${selectedSeverity === "all" ? " on" : ""}`}
            style={{
              cursor: "pointer",
              fontWeight: selectedSeverity === "all" ? 700 : 500,
              background: selectedSeverity === "all" ? "var(--hover)" : undefined,
            }}
            onClick={() => setSelectedSeverity(selectedSeverity === "all" ? null : "all")}
          >
            {t("dashboard.filterAll", { count: allFindings.length })}
          </button>
          {(["high", "medium", "low"] as const).map((severity) => {
            const isSelected = selectedSeverity === severity;
            return (
              <button
                key={severity}
                type="button"
                className={`pill${isSelected ? " on" : ""}`}
                style={{
                  cursor: "pointer",
                  padding: "0 10px",
                  borderColor: isSelected ? "var(--walnut)" : undefined,
                  boxShadow: isSelected ? "0 0 0 2px var(--walnut)" : undefined,
                  background: isSelected ? "var(--hover)" : undefined,
                }}
                onClick={() => setSelectedSeverity(isSelected ? null : severity)}
              >
                <SeverityBadge severity={severity} count={counts[severity]} />
              </button>
            );
          })}
        </div>

        {selectedSeverity && (
          <div className="dashboard-filtered-findings stack gap-m" style={{ marginTop: 8 }}>
            <p className="muted" style={{ fontWeight: 600 }}>
              {selectedSeverity === "all"
                ? t("dashboard.findingsList", { count: displayedFindings.length })
                : `${t(`severity.${selectedSeverity}`)} (${displayedFindings.length})`}
            </p>
            {displayedFindings.length === 0 ? (
              <p className="muted">{t("dashboard.noFindingsForSeverity")}</p>
            ) : (
              displayedFindings.map(({ finding: f, device: d }) => (
                <FindingCard
                  key={`${f.ip}-${f.code}-${f.port ?? "noport"}`}
                  finding={f}
                  deviceName={d ? deviceName(d.device_type) : t("device.type.unknown")}
                  device={d}
                  showDevice
                  onRescan={startScanFlow}
                />
              ))
            )}
          </div>
        )}
      </section>

      {diff && changes > 0 && (
        <section className="changes">
          <button type="button" className="changes-toggle" aria-expanded={alertsOpen} aria-controls="changes-list" onClick={toggleAlerts}>
            <IconBell />
            <span className="grow">{t("dashboard.changesCount", { count: changes })}</span>
            <span className="muted">{alertsOpen ? t("common.hide") : t("common.show")}</span>
            <IconChevron open={alertsOpen} />
          </button>
          {alertsOpen && (
            <ul id="changes-list" className="changes-list">
              {diff.devices_added.map((ip) => (
                <li key={ip}>
                  <span className="grow">{t("dashboard.newDevice", { ip })}</span>
                  <a href={href({ name: "device", ip })}>{t("common.open")}</a>
                </li>
              ))}
              {diff.ports_opened.map((port) => (
                <li key={`${port.ip}-${port.protocol}-${port.port}`}>{t("dashboard.newPort", { ip: port.ip, port: port.port, service: port.service ?? "" })}</li>
              ))}
            </ul>
          )}
        </section>
      )}
        </>
      )}
    </div>
  );
}
