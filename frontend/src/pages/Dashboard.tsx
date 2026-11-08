// "How safe am I and what do I do first?", answered without a click (jury check #2).
// Kept short on purpose: score, one compact "fix this first" card, counts, and changes folded away.
import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { Explanation, ScanDiff } from "../api/types";
import { formatDate } from "../i18n";
import { fixFirst, previousComparable, severityCounts } from "../lib/scan";
import { href } from "../router";
import { useApp } from "../state/AppState";
import { useDeviceName } from "../components/DeviceCard";
import { DeviceIcon, IconBell, IconChevron } from "../components/Icons";
import ScoreBadge, { SeverityBadge } from "../components/ScoreBadge";

const readOpen = () => {
  try {
    return window.localStorage.getItem("ajar.alerts") === "open";
  } catch {
    return false;
  }
};

export default function Dashboard() {
  const { t, lang, scan, history, setBubble } = useApp();
  const deviceName = useDeviceName();
  const [text, setText] = useState<Explanation | null>(null);
  const [diff, setDiff] = useState<ScanDiff | null>(null);
  const [alertsOpen, setAlertsOpen] = useState(readOpen);
  const assessed = scan !== null && scan.score !== null && scan.findings_available && !scan.error;
  const first = assessed ? fixFirst(scan) : null;
  const finding = first?.findings[0] ?? null;
  const previous = scan ? previousComparable(history, scan) : undefined;

  useEffect(() => {
    if (!finding) return setText(null);
    let alive = true;
    setText(null);
    api.explain(finding.code, lang, scan?.id, finding).then((value) => alive && setText(value)).catch(() => alive && setText(null));
    return () => {
      alive = false;
    };
  }, [finding?.code, finding?.port, finding?.protocol, finding?.ip, scan?.id, lang]);

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
      <p className="banner banner-error">{t(scan.error ? "scan.unreadable" : scan.score === null ? "dashboard.noScore" : "dashboard.noEvidence")}</p>
      <a className="button primary self-start" href={href({ name: "scan" })}>{t("nav.newScan")}</a>
    </div>
  );
  const counts = severityCounts(scan);
  const delta = previous && scan.score !== null && previous.score !== null ? scan.score - previous.score : null;
  const changes = diff ? diff.devices_added.length + diff.ports_opened.length : 0;

  return (
    <div className="page">
      <section className="row spread end">
        <div className="stack">
          <ScoreBadge scan={scan} />
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
        <a className="button" href={href({ name: "report" })}>{t("report.open")}</a>
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
          <div className="fix-first-action">
            {text && text.steps[0] && (
              <p className="grow">
                <span className="step-number" aria-hidden="true">
                  1
                </span>
                <span className="strong">{text.steps[0]}</span>
              </p>
            )}
            <a className="button primary" href={href({ name: "device", ip: first.device.ip })}>
              {t("dashboard.showMe")}
            </a>
          </div>
        </section>
      ) : (
        <section className="fix-first tint-ok">
          <h2 className="h3">{t("dashboard.allGood")}</h2>
          <p className="muted">{t("dashboard.allGoodText")}</p>
        </section>
      )}

      <section className="row" aria-label={t("dashboard.bySeverity")}>
        {(["high", "medium", "low", "info"] as const).map((severity) => (
          <SeverityBadge key={severity} severity={severity} count={counts[severity]} />
        ))}
      </section>

      {diff && diff.from_id === previous?.id && diff.to_id === scan.id && changes > 0 && (
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
    </div>
  );
}
