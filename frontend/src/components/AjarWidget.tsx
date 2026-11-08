// Phone widget: Ajar on the left, a few basic numbers on the right. Shown at the top of the
// mobile dashboard and on its own at #/widget (the home-screen shortcut of the installed app).
import { formatDate } from "../i18n";
import { assessment, mascotState, severityCounts } from "../lib/scan";
import { useApp } from "../state/AppState";
import AjarMascot from "./AjarMascot";
import ScanWord from "./ScanWord";
import { SEVERITY_ICON } from "./ScoreBadge";

export default function AjarWidget({ standalone = false }: { standalone?: boolean }) {
  const { t, lang, scan, scanning } = useApp();
  const level = assessment(scan);
  const state = scanning ? "shut" : mascotState(level);
  const score = scan && !scan.error ? scan.score : null;
  const counts = scan && score !== null ? severityCounts(scan) : null;

  return (
    <a
      className={`ajar-widget${standalone ? " standalone" : ""}`}
      href="#/dashboard"
      aria-label={`Ajar · ${score === null ? t("score.unknown") : t("score.outOf", { score })}`}
    >
      <div className="ajar-widget-mascot">
        <AjarMascot state={state} label={t(`ajar.state.${state}`)} />
      </div>
      <div className="ajar-widget-stats">
        <div className="ajar-widget-score">
          <span className={`serif ajar-widget-number text-${level}`}>{score ?? "—"}</span>
          <span className="muted">/ 100</span>
        </div>
        <span className={`chip sev-${level} ajar-widget-level`}>{scanning ? <ScanWord /> : t(`assessment.${level}`)}</span>
        {counts && (
          <ul className="ajar-widget-counts" aria-label={t("dashboard.bySeverity")}>
            {(["high", "medium", "low", "info"] as const).map((severity) => (
              <li key={severity} className={`text-${severity}`}>
                <span aria-hidden="true">{SEVERITY_ICON[severity]}</span> {t(`severity.count.${severity}`, { count: counts[severity] })}
              </li>
            ))}
          </ul>
        )}
        {scan && (
          <span className="muted ajar-widget-meta">
            {t("widget.devices", { count: scan.devices.length })} · {formatDate(scan.created_at, lang)}
          </span>
        )}
      </div>
    </a>
  );
}
