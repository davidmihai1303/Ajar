// Before → after between two scans (compared by IP). Shows only what actually changed.
import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { Explanation, ScanDiff } from "../api/types";
import { useApp } from "../state/AppState";

const portList = (ports: ScanDiff["ports_opened"]) => ports.map((p) => `${p.ip} ${p.protocol}/${p.port}`).join(", ");

export default function DiffList({ diff, showScore = true }: { diff: ScanDiff; showScore?: boolean }) {
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
  const nothing =
    diff.findings_resolved.length + diff.findings_new.length + diff.devices_added.length + diff.devices_removed.length + diff.ports_opened.length + diff.ports_closed.length === 0;

  return (
    <div className="card diff">
      {showScore && (
        <span className="serif diff-score">
          {before} → {after}
        </span>
      )}
      {nothing ? (
        <p className="muted">{t("history.noChanges")}</p>
      ) : (
        <ul className="diff-list">
          {diff.findings_resolved.map((item) => (
            <li key={`r-${item.ip}-${item.port}-${item.code}`}>
              <span className="diff-mark good" aria-hidden="true">✓</span>
              <span className="grow">{t("history.itemFixed", { what: titles[item.code] ?? item.code, ip: item.ip })}</span>
            </li>
          ))}
          {diff.findings_new.map((item) => (
            <li key={`n-${item.ip}-${item.port}-${item.code}`}>
              <span className="diff-mark bad" aria-hidden="true">!</span>
              <span className="grow">{t("history.itemNew", { what: titles[item.code] ?? item.code, ip: item.ip })}</span>
            </li>
          ))}
          {diff.devices_added.map((ip) => (
            <li key={`d-${ip}`}>
              <span className="diff-mark bad" aria-hidden="true">+</span>
              <span className="grow">{t("history.itemDevice", { ip })}</span>
            </li>
          ))}
          {diff.devices_removed.map((ip) => (
            <li key={`g-${ip}`}>
              <span className="diff-mark" aria-hidden="true">−</span>
              <span className="grow">{t("history.itemGone", { ip })}</span>
            </li>
          ))}
          {diff.ports_closed.length > 0 && (
            <li>
              <span className="diff-mark good" aria-hidden="true">✓</span>
              <span className="grow">{t("history.itemPortsClosed", { count: diff.ports_closed.length })} <span className="muted mono">{portList(diff.ports_closed)}</span></span>
            </li>
          )}
          {diff.ports_opened.length > 0 && (
            <li>
              <span className="diff-mark bad" aria-hidden="true">!</span>
              <span className="grow">{t("history.itemPortsOpened", { count: diff.ports_opened.length })} <span className="muted mono">{portList(diff.ports_opened)}</span></span>
            </li>
          )}
        </ul>
      )}
    </div>
  );
}
