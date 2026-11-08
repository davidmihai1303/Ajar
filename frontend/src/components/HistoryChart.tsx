// Score trend with labelled values on every bar (never colour alone).
import type { HistoryItem } from "../api/types";
import { formatDate } from "../i18n";
import { useApp } from "../state/AppState";

export default function HistoryChart({ items, currentId }: { items: HistoryItem[]; currentId: string | null }) {
  const { t, lang } = useApp();
  const points = [...items].filter((item) => item.score !== null).reverse().slice(-8);
  if (points.length === 0) return null;
  return (
    <figure className="card chart" aria-label={t("history.chartLabel")}>
      <figcaption className="h3">{t("history.chart")}</figcaption>
      <div className="chart-bars">
        {points.map((item) => (
          <div key={item.id} className={`chart-col${item.id === currentId ? " current" : ""}`}>
            <span className="chart-value">{item.score}</span>
            <div className="chart-bar" style={{ height: `${Math.max(4, (item.score ?? 0) * 1.6)}px` }} />
            <span className="chart-label muted">{formatDate(item.created_at, lang, false)}</span>
          </div>
        ))}
      </div>
    </figure>
  );
}
