// Score + level. Colour is never the only signal (icon + text label).
import type { Severity } from "../api/proposedTypes";
import { scoreLevel } from "../lib/scan";
import { useApp } from "../state/AppState";

const LEVEL_ICON = { safe: "✓", attention: "●", risky: "▲", unknown: "?" } as const;

export default function ScoreBadge({ score, size = "large" }: { score: number | null; size?: "large" | "small" }) {
  const { t } = useApp();
  const level = scoreLevel(score);
  if (size === "small") {
    return (
      <span className="score-small">
        <span className="serif">{score ?? "—"}</span>
        <span>{t(`score.level.${level}`)}</span>
      </span>
    );
  }
  return (
    <div className="score-large">
      <span className={`serif score-number text-${level}`}>{score ?? "—"}</span>
      <div className="score-meta">
        <span className={`chip level-${level}`}>
          <span aria-hidden="true">{LEVEL_ICON[level]}</span>
          {t(`score.level.${level}`)}
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
