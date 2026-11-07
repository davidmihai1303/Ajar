// Ajar never disappears: one fixed element for the whole app. It moves (animated) between
// the top-left corner, the side of an open dialog and the centre of the screen during a scan.
import { useApp } from "../state/AppState";
import { mascotState, scoreLevel } from "../lib/scan";
import AjarMascot from "./AjarMascot";

export default function AjarDock() {
  const { scan, scanning, ready, placement, bubble, setBubble, t } = useApp();
  const score = scan?.score ?? null;
  // Until the last scan has loaded, Ajar waits calmly instead of flashing "locked".
  const state = scanning || !ready ? "shut" : mascotState(score);
  const level = scoreLevel(score);
  const label = t(`ajar.state.${state}`) + (score === null ? "" : `, ${t("score.outOf", { score })}`);

  return (
    <div className={`ajar-dock place-${placement}`}>
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
          <span className="muted">{t("scan.running.short")}</span>
        ) : score === null ? (
          <>
            <span className="serif ajar-score-unknown">{t("score.unknown")}</span>
            <span className="muted">{t("score.noScanYet")}</span>
          </>
        ) : (
          <>
            <span>
              <span className="serif ajar-score-number">{score}</span>
              <span className="muted"> / 100</span>
            </span>
            <span className="ajar-score-label">{t(`score.level.${level}`)}</span>
          </>
        )}
      </div>
      {bubble && placement === "corner" && (
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
