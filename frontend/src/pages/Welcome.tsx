// First screen before any scan: the text sits in the exact centre of the screen and Ajar stands
// just to its left. Ajar is still the one global AjarDock: this page only tells it where to stand
// (an "anchor"), so it walks from here to the dialogs, the scan and the corner without disappearing.
import { useLayoutEffect, useRef } from "react";
import { useIsMobile } from "../lib/useIsMobile";
import { href } from "../router";
import { useApp } from "../state/AppState";
import { IconWifi } from "../components/Icons";
import LanguageToggle from "../components/LanguageToggle";

const AJAR_W = 176; // keep in sync with --ajar-w
const AJAR_H = 240; // mascot + score lines
const GAP = 40;

export default function Welcome() {
  const isMobile = useIsMobile();
  const { t, demo, network, agentDown, scanProblem, lang, startScanFlow, setAnchor } = useApp();
  const column = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    const place = () => {
      const box = column.current?.getBoundingClientRect();
      if (!box) return;
      const x = box.left - GAP - AJAR_W;
      // Not enough room on the left (narrow window): stand above the text instead.
      if (x < 16) setAnchor({ x: box.left + box.width / 2 - AJAR_W / 2, y: Math.max(8, box.top - AJAR_H - 16) });
      else setAnchor({ x, y: box.top + box.height / 2 - AJAR_H / 2 });
    };
    place();
    const observer = new ResizeObserver(place);
    if (column.current) observer.observe(column.current);
    window.addEventListener("resize", place);
    return () => {
      observer.disconnect();
      window.removeEventListener("resize", place);
      setAnchor(null);
    };
  }, [setAnchor]);

  return (
    <div className="welcome">
      <div className="welcome-top">
        <LanguageToggle />
      </div>
      <div className="welcome-center">
        <div ref={column} className="welcome-column">
          <h1 className="serif welcome-title">{t("welcome.title")}</h1>
          <p className="welcome-sub">{t("welcome.subtitle")}</p>
          <div className="composer">
            <div className="composer-net">
              <IconWifi />
              <div className="stack">
                <span className="strong">{network?.ssid ?? (agentDown ? t("network.agentDownShort") : t("network.unknownName"))}</span>
                <span className="muted">{network ? t("welcome.connected", { subnet: network.subnet }) :
                  scanProblem?.kind === "refused" ? scanProblem.refusal[lang === "ro" ? "reason_ro" : "reason_en"] : t("welcome.notDetected")}</span>
              </div>
            </div>
            <button type="button" className="button primary large" onClick={startScanFlow}>
              {t(demo ? "scan.demo.button" : "welcome.start")}
            </button>
          </div>
          <div className="row center">
            <a href={href({ name: "scan" })}>{t("welcome.import")}</a>
            {!isMobile && <a href={href({ name: "ask" })}>{t("welcome.what")}</a>}
          </div>
        </div>
      </div>
      <p className="muted center">{t("welcome.ownOnly")}</p>
    </div>
  );
}
