// One finding: plain title, ≤2-sentence explanation, ordered fix steps; technical evidence collapsed.
// Evidence is untrusted text from the scan: rendered as plain text only (React escapes it).
import { useEffect, useRef, useState } from "react";
import { api } from "../api/client";
import type { Explanation, Finding } from "../api/types";
import { useApp } from "../state/AppState";
import { referencesFor } from "../lib/references";
import { SeverityBadge } from "./ScoreBadge";

export default function FindingCard({ finding }: { finding: Finding }) {
  const { t, lang, scan, aiConsent } = useApp();
  const [text, setText] = useState<Explanation | null>(null);
  const [rephrased, setRephrased] = useState<string | null>(null);
  const [rephraseState, setRephraseState] = useState<"idle" | "loading" | "off">("idle");
  const active = useRef<AbortController | null>(null);

  useEffect(() => {
    setRephrased(null);
    setRephraseState("idle");
    return () => {
      active.current?.abort();
      active.current = null;
    };
  }, [aiConsent, scan?.id, finding.code, finding.ip, finding.port, finding.protocol, lang]);

  useEffect(() => {
    let alive = true;
    setText(null);
    api
      .explain(finding.code, lang, scan?.id, finding)
      .then((value) => alive && setText(value))
      .catch(() => alive && setText(null));
    return () => {
      alive = false;
    };
  }, [finding, scan?.id, lang]);

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
      const answer = await api.personalize(scan.id, finding, lang, controller.signal);
      if (controller.signal.aborted) return;
      setRephrased(answer.explanation);
      setRephraseState("idle");
    } catch {
      if (!controller.signal.aborted) setRephraseState("off");
    } finally {
      if (active.current === controller) active.current = null;
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
        <details className="tech">
          <summary>{t("common.technical")}</summary>
          <p className="mono">
            {finding.code} · {finding.port === null ? t("finding.noPort") : `${finding.protocol}/${finding.port}`} · {finding.evidence}
          </p>
          <References code={finding.code} />
        </details>
      </div>
    </article>
  );
}

/** CIS Controls v8 / OWASP IoT Top 10 references, used here and in the printable report. */
export function References({ code }: { code: string }) {
  const { t } = useApp();
  const refs = referencesFor(code);
  if (refs.length === 0) return null;
  return (
    <p className="references">
      <span className="muted">{t("finding.references")}</span>{" "}
      {refs.map((ref, index) => (
        <span key={ref.id}>
          {index > 0 && " · "}
          <abbr title={ref.name}>{ref.id}</abbr>
        </span>
      ))}
    </p>
  );
}

