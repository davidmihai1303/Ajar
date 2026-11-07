// Before → after between two scans (compared by IP): resolved and new findings, devices, ports.
import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { Explanation, ScanDiff } from "../api/proposedTypes";
import { useApp } from "../state/AppState";

export default function DiffList({ diff }: { diff: ScanDiff }) {
  const { t, lang } = useApp();
  const [titles, setTitles] = useState<Record<string, string>>({});

  useEffect(() => {
    const codes = [...new Set([...diff.findings_resolved, ...diff.findings_new].map((item) => item.code))];
    let alive = true;
    Promise.all(codes.map((code) => api.explain(code, lang).catch(() => null))).then((list) => {
      if (!alive) return;
      const next: Record<string, string> = {};
      list.forEach((item: Explanation | null) => item && (next[item.code] = item.title));
      setTitles(next);
    });
    return () => {
      alive = false;
    };
  }, [diff, lang]);

  const before = diff.score_before ?? "—";
  const after = diff.score_after ?? "—";
  const better = (diff.score_after ?? 0) > (diff.score_before ?? 0);

  return (
    <div className="card diff">
      <div className="row baseline">
        <span className="serif diff-score">
          {before} → {after}
        </span>
        <span className="muted">{better ? t("history.better") : t("history.notBetter")}</span>
      </div>
      <div className="row diff-counts">
        <span>{t("history.resolved", { count: diff.findings_resolved.length })}</span>
        <span>{t("history.new", { count: diff.findings_new.length })}</span>
        <span>{t("history.portsClosed", { count: diff.ports_closed.length })}</span>
        <span>{t("history.portsOpened", { count: diff.ports_opened.length })}</span>
        <span>{t("history.devicesAdded", { count: diff.devices_added.length })}</span>
        <span>{t("history.devicesRemoved", { count: diff.devices_removed.length })}</span>
      </div>
      <ul className="diff-list">
        {diff.findings_resolved.map((item) => (
          <li key={`r-${item.ip}-${item.port}-${item.code}`}>
            <span className="diff-mark" aria-hidden="true">✓</span>
            <span className="grow">
              {titles[item.code] ?? item.code} ({item.ip})
            </span>
            <span className="muted">{t("history.tagResolved")}</span>
          </li>
        ))}
        {diff.findings_new.map((item) => (
          <li key={`n-${item.ip}-${item.port}-${item.code}`}>
            <span className="diff-mark" aria-hidden="true">!</span>
            <span className="grow">
              {titles[item.code] ?? item.code} ({item.ip})
            </span>
            <span className="muted">{t("history.tagNew")}</span>
          </li>
        ))}
        {diff.devices_added.map((ip) => (
          <li key={`d-${ip}`}>
            <span className="diff-mark" aria-hidden="true">+</span>
            <span className="grow">{ip}</span>
            <span className="muted">{t("history.tagDevice")}</span>
          </li>
        ))}
        {diff.ports_opened.map((port) => (
          <li key={`p-${port.ip}-${port.protocol}-${port.port}`}>
            <span className="diff-mark" aria-hidden="true">+</span>
            <span className="grow">
              {port.protocol.toUpperCase()} {port.port} {port.service ?? ""} ({port.ip})
            </span>
            <span className="muted">{t("history.tagPort")}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
