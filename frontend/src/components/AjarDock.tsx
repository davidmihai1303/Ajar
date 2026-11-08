// Ajar never disappears: one fixed element for the whole app. It moves (animated) between
// the top-left corner, the welcome text, the side of an open dialog and the centre during a scan.
import { useApp } from "../state/AppState";
import { assessment, mascotState } from "../lib/scan";
import AjarMascot from "./AjarMascot";

export default function AjarDock() {
  const { scan, scanning, ready, placement, anchor, bubble, setBubble, t } = useApp();
  const score = scan?.error ? null : scan?.score ?? null;
  // Until the last scan has loaded, Ajar waits calmly instead of flashing "locked".
  const level = assessment(scan);
  const state = scanning || !ready ? "shut" : mascotState(level);
  const label = t(`ajar.state.${state}`) + (score === null ? "" : `, ${t("score.outOf", { score })}`);

  return (
    <div
      className={`ajar-dock place-${placement}`}
      style={placement === "anchor" && anchor ? { transform: `translate(${anchor.x}px, ${anchor.y}px)` } : undefined}
    >
      <button
        type="button"
        className="ajar-dock-button"
        onClick={() => setBubble(bubble ? null : t(`ajar.say.${state}`))}
        aria-label={t("ajar.talk")}
      >
        <AjarMascot state={state} label={label} />
      </button>
      <div className="ajar-score" aria-live="polite">
        {!ready ? (
          <span className="muted">{t("common.loading")}</span>
        ) : scanning ? (
          <span className="visually-hidden">{t("scan.running.title")}</span>
        ) : score === null ? (
          <>
            <span className="serif ajar-score-unknown">{t("score.unknown")}</span>
            <span className="muted">{t(scan ? "dashboard.unassessed" : "score.noScanYet")}</span>
          </>
        ) : (
          <>
            <span>
              <span className="serif ajar-score-number">{score}</span>
              <span className="muted"> / 100</span>
            </span>
            <span className={`ajar-score-label sev-${level}`}>{t(`assessment.${level}`)}</span>
          </>
        )}
      </div>
      {bubble && (placement === "corner" || placement === "dialog") && (
        <div className="ajar-bubble" role="status">
          {bubble}
          <button type="button" className="link-button" onClick={() => setBubble(null)} aria-label={t("common.close")}>
            ×
          </button>
        </div>
      )}
    </div>
  );
}
