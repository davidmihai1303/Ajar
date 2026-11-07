// One finding: plain title, ≤2-sentence explanation, ordered fix steps; technical evidence collapsed.
// Evidence is untrusted text from the scan: rendered as plain text only (React escapes it).
import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { Explanation, Finding } from "../api/proposedTypes";
import { useApp } from "../state/AppState";
import { SeverityBadge } from "./ScoreBadge";

export default function FindingCard({ finding, deviceName }: { finding: Finding; deviceName: string }) {
  const { t, lang, scan, aiConsent } = useApp();
  const [text, setText] = useState<Explanation | null>(null);
  const [rephrased, setRephrased] = useState<string | null>(null);
  const [rephraseState, setRephraseState] = useState<"idle" | "loading" | "off" | "noAnswer">("idle");

  useEffect(() => {
    let alive = true;
    setRephrased(null);
    setRephraseState("idle");
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
    setRephraseState("loading");
    try {
      const answer = await api.ask(scan.id, t("finding.rephraseQuestion", { code: finding.code, device: deviceName, ip: finding.ip }), lang);
      if (!answer.available) setRephraseState("off");
      else if (!answer.can_answer || !answer.answer) setRephraseState("noAnswer");
      else {
        setRephrased(answer.answer);
        setRephraseState("idle");
      }
    } catch {
      setRephraseState("off");
    }
  };

  return (
    <article className={`card finding${finding.severity === "high" ? " finding-high" : ""}`}>
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
        <button type="button" className="button" onClick={rephrase} disabled={rephraseState === "loading"}>
          {rephraseState === "loading" ? t("finding.rephrasing") : t("finding.rephrase")}
        </button>
        {rephraseState === "off" && <span className="muted">{t("finding.assistantOff")}</span>}
        {rephraseState === "noAnswer" && <span className="muted">{t("ask.cannotAnswer")}</span>}
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
