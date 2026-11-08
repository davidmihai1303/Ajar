// One finding: plain title, ≤2-sentence explanation, ordered fix steps; technical evidence collapsed.
// Evidence is untrusted text from the scan: rendered as plain text only (React escapes it).
import { useEffect, useRef, useState } from "react";
import { api } from "../api/client";
import type { Device, Explanation, Finding } from "../api/proposedTypes";
import { useIsMobile } from "../lib/useIsMobile";
import { href } from "../router";
import { useApp } from "../state/AppState";
import { DeviceIcon, IconAsk, IconRefresh } from "./Icons";
import { SeverityBadge } from "./ScoreBadge";

export default function FindingCard({
  finding,
  deviceName,
  device,
  showDevice = false,
  onRescan,
}: {
  finding: Finding;
  deviceName: string;
  device?: Device;
  showDevice?: boolean;
  onRescan?: () => void;
}) {
  const { t, lang, scan, aiConsent } = useApp();
  const isMobile = useIsMobile();
  const [text, setText] = useState<Explanation | null>(null);
  const [rephrased, setRephrased] = useState<string | null>(null);
  const [rephraseState, setRephraseState] = useState<"idle" | "loading" | "off" | "noAnswer">("idle");
  const active = useRef<AbortController | null>(null);

  useEffect(() => {
    setRephrased(null);
    setRephraseState("idle");
    return () => {
      active.current?.abort();
      active.current = null;
    };
  }, [aiConsent, scan?.id, finding.code, finding.ip, finding.port, lang]);

  useEffect(() => {
    let alive = true;
    api
      .explain(finding.code, lang)
      .then((value) => alive && setText(value))
      .catch(() => alive && setText(null));
    return () => {
      alive = false;
    };
  }, [finding.code, lang]);

  const rephrase = async () => {
    if (!scan || aiConsent !== true) {
      setRephraseState("off");
      return;
    }
    if (active.current) return;
    const controller = new AbortController();
    active.current = controller;
    setRephraseState("loading");
    try {
      const question = t("finding.rephraseQuestion", { code: finding.code, device: deviceName, ip: finding.ip });
      const answer = await api.ask(scan.id, question, lang, controller.signal);
      if (controller.signal.aborted) return;
      if (!answer.available) setRephraseState("off");
      else if (!answer.can_answer || !answer.answer) setRephraseState("noAnswer");
      else {
        setRephrased(answer.answer);
        setRephraseState("idle");
      }
    } catch {
      if (!controller.signal.aborted) setRephraseState("off");
    } finally {
      if (active.current === controller) active.current = null;
    }
  };

  const askPrompt = t("finding.rephraseQuestion", {
    code: finding.code,
    device: deviceName,
    ip: finding.ip,
  });

  return (
    <article className={`card finding${finding.severity === "high" ? " finding-high" : ""}`}>
      {showDevice && (
        <div className="row spread center" style={{ marginBottom: 12, paddingBottom: 8, borderBottom: "1px solid var(--line)", flexWrap: "wrap", gap: 8 }}>
          <div className="row center" style={{ gap: 8, flexWrap: "wrap" }}>
            <DeviceIcon type={device?.device_type ?? "unknown"} size={18} />
            <a href={href({ name: "device", ip: finding.ip })} className="strong" style={{ color: "var(--walnut)", textDecoration: "none" }}>
              {deviceName}
            </a>
            <span className="muted mono" style={{ fontSize: 13 }}>IP {finding.ip}</span>
            {device?.hostname && <span className="muted" style={{ fontSize: 13 }}>({device.hostname})</span>}
            {device?.vendor && <span className="muted" style={{ fontSize: 13 }}>• {device.vendor}</span>}
          </div>
          <a href={href({ name: "device", ip: finding.ip })} className="link-button muted" style={{ fontSize: 13, minHeight: "auto", padding: "4px 8px" }}>
            {t("dashboard.viewDevice")} →
          </a>
        </div>
      )}
      <div className="row">
        <SeverityBadge severity={finding.severity} />
        <span className="muted">{t("finding.points", { points: finding.points })}</span>
      </div>
      <h3 className="finding-title">{text?.title ?? t("finding.loading")}</h3>
      <p className="finding-text">{rephrased ?? text?.explanation ?? ""}</p>
      {text && text.steps.length > 0 && (
        <ol className="steps">
          {text.steps.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>
      )}
      <div className="finding-footer">
        <div className="row wrap gap-m">
          <a
            className="button"
            href={href({ name: "ask", query: askPrompt })}
            title={t("dashboard.askAi")}
          >
            <IconAsk />
            {t("dashboard.askAi")}
          </a>
          {onRescan && (
            <button type="button" className="button" onClick={onRescan} title={t("dashboard.rescanNote")}>
              <IconRefresh />
              {t("dashboard.rescan")}
            </button>
          )}
          {!isMobile && (
            <button type="button" className="button" onClick={rephrase} disabled={rephraseState === "loading"}>
              {rephraseState === "loading" ? t("finding.rephrasing") : t("finding.rephrase")}
            </button>
          )}
        </div>
        {!isMobile && rephraseState === "off" && <span className="muted">{t("finding.assistantOff")}</span>}
        {!isMobile && rephraseState === "noAnswer" && <span className="muted">{t("ask.cannotAnswer")}</span>}
        <details className="tech">
          <summary>{t("common.technical")}</summary>
          <p className="mono">
            {finding.code} · {finding.port === null ? t("finding.noPort") : `${finding.protocol}/${finding.port}`} · {finding.evidence}
          </p>
        </details>
      </div>
    </article>
  );
}
