// While the live scan runs, Ajar walks to the centre (AjarDock "center" placement) and waits here.
import { useEffect, useState } from "react";
import { useApp } from "../state/AppState";

export default function ScanProgress() {
  const { t, network } = useApp();
  const [seconds, setSeconds] = useState(0);
  useEffect(() => {
    const timer = window.setInterval(() => setSeconds((value) => value + 1), 1000);
    return () => window.clearInterval(timer);
  }, []);
  const minutes = Math.floor(seconds / 60);
  const rest = String(seconds % 60).padStart(2, "0");

  return (
    <div className="progress-screen">
      <div className="progress-center">
        <h1 className="serif progress-title">{t("scan.running.title")}</h1>
        <div className="progress-track" role="progressbar" aria-label={t("scan.running.title")} aria-valuetext={t("scan.running.elapsed", { time: `${minutes}:${rest}` })}>
          <div className="progress-indeterminate" />
        </div>
        <div className="row spread muted progress-meta">
          <span>{network ? `${network.ssid ?? ""} · ${network.subnet}` : ""}</span>
          <span>
            {t("scan.running.elapsed", { time: `${minutes}:${rest}` })} · {t("scan.running.estimate")}
          </span>
        </div>
        <p className="muted">{t("scan.running.dontClose")}</p>
      </div>
    </div>
  );
}
