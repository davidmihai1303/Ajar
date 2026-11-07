// Score + level. Colour is never the only signal (icon + text label).
import type { Scan, Severity } from "../api/types";
import { assessment } from "../lib/scan";
import { useApp } from "../state/AppState";

const LEVEL_ICON = { clear: "✓", high: "▲", medium: "●", low: "◆", info: "i", unknown: "?" } as const;

export default function ScoreBadge({ scan, size = "large" }: { scan: Scan; size?: "large" | "small" }) {
  const { t } = useApp();
  const level = assessment(scan);
  const score = scan.score;
  if (size === "small") {
    return (
      <span className="score-small">
        <span className="serif">{score ?? "—"}</span>
        <span>{t(`assessment.${level}`)}</span>
      </span>
    );
  }
  return (
    <div className="score-large">
      <span className={`serif score-number text-${level}`}>{score ?? "—"}</span>
      <div className="score-meta">
        <span className={`chip sev-${level}`}>
          <span aria-hidden="true">{LEVEL_ICON[level]}</span>
          {t(`assessment.${level}`)}
        </span>
        <span className="muted">{t("score.of100")}</span>
      </div>
    </div>
  );
}

const SEVERITY_ICON: Record<Severity, string> = { high: "▲", medium: "●", low: "◆", info: "i" };

export function SeverityBadge({ severity, count }: { severity: Severity; count?: number }) {
  const { t } = useApp();
  return (
    <span className={`chip sev-${severity}`}>
      <span aria-hidden="true">{SEVERITY_ICON[severity]}</span>
      {count === undefined ? t(`severity.${severity}`) : t(`severity.count.${severity}`, { count })}
    </span>
  );
}
