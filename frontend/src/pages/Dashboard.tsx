// "How safe am I and what do I do first?", answered without a click (jury check #2).
import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { Explanation, ScanDiff } from "../api/proposedTypes";
import { formatDate } from "../i18n";
import { fixFirst, severityCounts } from "../lib/scan";
import { href } from "../router";
import { useApp } from "../state/AppState";
import { useDeviceName } from "../components/DeviceCard";
import { DeviceIcon, IconBell } from "../components/Icons";
import ScoreBadge, { SeverityBadge } from "../components/ScoreBadge";

export default function Dashboard() {
  const { t, lang, scan, history, setBubble } = useApp();
  const deviceName = useDeviceName();
  const [text, setText] = useState<Explanation | null>(null);
  const [diff, setDiff] = useState<ScanDiff | null>(null);
  const first = scan ? fixFirst(scan) : null;
  const finding = first?.findings[0] ?? null;
  const index = scan ? history.findIndex((item) => item.id === scan.id) : -1;
  const previous = index >= 0 ? history.slice(index + 1).find((item) => item.score !== null) : undefined;

  useEffect(() => {
    if (!finding) return setText(null);
    let alive = true;
    api.explain(finding.code, lang).then((value) => alive && setText(value)).catch(() => alive && setText(null));
    return () => {
      alive = false;
    };
  }, [finding?.code, lang]);

  useEffect(() => {
    if (!scan || !previous) return setDiff(null);
    let alive = true;
    api.diff(previous.id, scan.id).then((value) => alive && setDiff(value)).catch(() => alive && setDiff(null));
    return () => {
      alive = false;
    };
  }, [scan?.id, previous?.id]);

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

  if (!scan) return null;
  const counts = severityCounts(scan);
  const delta = previous && scan.score !== null && previous.score !== null ? scan.score - previous.score : null;

  return (
    <div className="page">
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
          <a href={href({ name: "history" })}>{delta === 0 ? t("dashboard.same") : t(delta > 0 ? "dashboard.up" : "dashboard.down", { delta: Math.abs(delta) })}</a>
        )}
      </section>

      {scan.error && <p className="banner banner-error">{t("scan.unreadable")}</p>}

      {first && finding ? (
        <section className="fix-first">
          <span className="muted strong">{t("dashboard.fixFirst")}</span>
          <div className="row nowrap">
            <DeviceIcon type={first.device.device_type} />
            <div className="grow">
              <h2 className="h2">{deviceName(first.device.device_type)}</h2>
              <p className="muted">
                {first.device.vendor ?? first.device.hostname ?? first.device.ip}, {t("finding.points", { points: first.points })}
              </p>
            </div>
            <SeverityBadge severity={finding.severity} />
          </div>
          <p>{text?.explanation ?? ""}</p>
          {text && text.steps[0] && (
            <div className="first-step">
              <span className="step-number" aria-hidden="true">
                1
              </span>
              <span className="strong">{text.steps[0]}</span>
            </div>
          )}
          <a className="button primary" href={href({ name: "device", ip: first.device.ip })}>
            {t("dashboard.showMe")}
          </a>
        </section>
      ) : (
        <section className="fix-first all-good">
          <h2 className="h2">{t("dashboard.allGood")}</h2>
          <p className="muted">{t("dashboard.allGoodText")}</p>
        </section>
      )}

      <section className="row gap-l" aria-label={t("dashboard.bySeverity")}>
        {(["high", "medium", "low", "info"] as const).map((severity) => (
          <SeverityBadge key={severity} severity={severity} count={counts[severity]} />
        ))}
      </section>

      {diff && (diff.devices_added.length > 0 || diff.ports_opened.length > 0) && (
        <section className="alerts">
          {diff.devices_added.map((ip) => (
            <p key={ip} className="alert-line">
              <IconBell />
              <span className="grow">{t("dashboard.newDevice", { ip })}</span>
              <a href={href({ name: "device", ip })}>{t("common.open")}</a>
            </p>
          ))}
          {diff.ports_opened.map((port) => (
            <p key={`${port.ip}-${port.protocol}-${port.port}`} className="alert-line">
              <IconBell />
              <span className="grow">{t("dashboard.newPort", { ip: port.ip, port: port.port, service: port.service ?? "" })}</span>
            </p>
          ))}
        </section>
      )}
    </div>
  );
}
