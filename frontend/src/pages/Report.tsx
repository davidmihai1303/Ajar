// FR-14: a one-page report a user can print or save as PDF and send to their IT supplier.
// Built only from the current scan. Every scan string (vendor, hostname, evidence) is plain text,
// which React escapes. MACs arrive already masked from the API.
import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { Explanation, Finding, ScanDiff } from "../api/types";
import { formatDate } from "../i18n";
import { publicFilename } from "../lib/filename";
import { byDanger, deviceRisks, isUnknownDevice, previousComparable, severityCounts } from "../lib/scan";
import { href } from "../router";
import { useApp } from "../state/AppState";
import { useDeviceName } from "../components/DeviceCard";
import { References } from "../components/FindingCard";
import ScoreBadge, { SeverityBadge } from "../components/ScoreBadge";

const findingKey = (finding: Finding) => `${finding.ip}|${finding.protocol ?? ""}|${finding.port ?? ""}|${finding.code}`;

export default function Report() {
  const { t, lang, scan, history } = useApp();
  const deviceName = useDeviceName();
  const [texts, setTexts] = useState<Record<string, Explanation>>({});
  const [diff, setDiff] = useState<ScanDiff | null>(null);
  const assessed = scan !== null && scan.score !== null && scan.findings_available && !scan.error;
  const previous = scan ? previousComparable(history, scan) : undefined;

  useEffect(() => {
    if (!assessed || !scan) return setTexts({});
    let alive = true;
    Promise.all(
      scan.findings.map((finding) =>
        api.explain(finding.code, lang, scan.id, finding).then((text) => [findingKey(finding), text] as const).catch(() => null),
      ),
    ).then((list) => {
      if (!alive) return;
      const next: Record<string, Explanation> = {};
      list.forEach((entry) => entry && (next[entry[0]] = entry[1]));
      setTexts(next);
    });
    return () => {
      alive = false;
    };
  }, [assessed, scan?.id, lang]);

  useEffect(() => {
    if (!assessed || !scan || !previous) return setDiff(null);
    let alive = true;
    api.diff(previous.id, scan.id).then((value) => alive && setDiff(value)).catch(() => alive && setDiff(null));
    return () => {
      alive = false;
    };
  }, [assessed, scan?.id, previous?.id]);

  if (!scan) return null;
  if (!assessed) {
    return (
      <div className="page">
        <h1 className="serif h1">{t("report.title")}</h1>
        <p className="banner banner-error">{t(scan.error ? "scan.unreadable" : "report.unavailable")}</p>
        <a className="button primary self-start" href={href({ name: "dashboard" })}>{t("report.back")}</a>
      </div>
    );
  }

  const risks = deviceRisks(scan).sort(byDanger);
  const ordered = risks.flatMap((risk) => risk.findings.map((finding) => ({ risk, finding })));
  const counts = severityCounts(scan);
  const nameOf = (risk: (typeof risks)[number]) => (isUnknownDevice(risk.device) ? t("device.unknownTitle") : deviceName(risk.device.device_type));

  return (
    <div className="page wide report">
      <div className="row spread no-print">
        <a href={href({ name: "dashboard" })}>{t("report.back")}</a>
        <button type="button" className="button primary" onClick={() => window.print()}>
          {t("report.print")}
        </button>
      </div>

      <header className="stack">
        <h1 className="serif h1">{t("report.title")}</h1>
        <p className="muted">
          {scan.ssid || scan.subnet
            ? t("report.meta", {
                ssid: scan.ssid ?? t("network.unknownName"),
                subnet: scan.subnet ?? "—",
                date: formatDate(scan.created_at, lang),
                file: publicFilename(scan.file),
              })
            : t("report.metaFile", { date: formatDate(scan.created_at, lang), file: publicFilename(scan.file) })}
        </p>
      </header>

      <section className="row spread end report-summary" aria-label={t("report.summary")}>
        <ScoreBadge scan={scan} />
        <div className="row">
          {(["high", "medium", "low", "info"] as const).map((severity) => (
            <SeverityBadge key={severity} severity={severity} count={counts[severity]} />
          ))}
        </div>
      </section>
      <p className="muted">{t("report.scoreNote")}</p>

      {diff && diff.from_id === previous?.id && diff.to_id === scan.id && (
        <section className="stack">
          <h2 className="h2">{t("report.changes")}</h2>
          <p>
            {t("report.changesLine", {
              from: diff.score_before ?? "—",
              to: diff.score_after ?? "—",
              date: previous ? formatDate(previous.created_at, lang) : "—",
              fixed: diff.findings_resolved.length,
              added: diff.findings_new.length,
              devices: diff.devices_added.length,
            })}
          </p>
        </section>
      )}

      <section className="stack">
        <h2 className="h2">{t("report.devices", { count: scan.devices.length })}</h2>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>{t("report.col.device")}</th>
                <th>IP</th>
                <th>MAC</th>
                <th>{t("report.col.maker")}</th>
                <th>{t("report.col.ports")}</th>
                <th>{t("report.col.points")}</th>
              </tr>
            </thead>
            <tbody>
              {risks.map((risk) => (
                <tr key={risk.device.ip}>
                  <td>{nameOf(risk)}</td>
                  <td className="mono nowrap">{risk.device.ip}</td>
                  <td className="mono nowrap">{risk.device.mac_masked ?? "—"}</td>
                  <td>{[risk.device.vendor, risk.device.hostname].filter(Boolean).join(", ") || "—"}</td>
                  <td className="mono">
                    {risk.device.ports.map((port) => `${port.protocol}/${port.port}${port.service ? ` ${port.service}` : ""}`).join(", ") || "—"}
                  </td>
                  <td>{risk.points > 0 ? `−${risk.points}` : "0"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="stack">
        <h2 className="h2">{t("report.findings", { count: scan.findings.length })}</h2>
        {ordered.length === 0 ? (
          <p>{t("dashboard.allGoodText")}</p>
        ) : (
          <ol className="report-findings">
            {ordered.map(({ risk, finding }) => {
              const text = texts[findingKey(finding)];
              return (
                <li key={findingKey(finding)} className="report-finding">
                  <div className="row">
                    <SeverityBadge severity={finding.severity} />
                    <span className="strong">{text?.title ?? finding.code}</span>
                    <span className="muted">
                      {nameOf(risk)} · {finding.ip}
                      {finding.port !== null && ` · ${finding.protocol}/${finding.port}`} · {t("finding.points", { points: finding.points })}
                    </span>
                  </div>
                  {text && <p>{text.explanation}</p>}
                  {text && text.steps.length > 0 && (
                    <ol className="steps">
                      {text.steps.map((step) => (
                        <li key={step}>{step}</li>
                      ))}
                    </ol>
                  )}
                  <p className="mono report-evidence">
                    {finding.code} · {finding.evidence}
                  </p>
                  <References code={finding.code} />
                </li>
              );
            })}
          </ol>
        )}
      </section>

      <footer className="muted report-footer">{t("report.footer")}</footer>
    </div>
  );
}
