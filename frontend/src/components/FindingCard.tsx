// One finding: plain title, ≤2-sentence explanation, ordered fix steps; technical evidence collapsed.
// Evidence is untrusted text from the scan: rendered as plain text only (React escapes it).
import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { Device, Explanation, Finding } from "../api/types";
import { referencesFor } from "../lib/references";
import { useIsMobile } from "../lib/useIsMobile";
import { href } from "../router";
import { useApp } from "../state/AppState";
import AskAiButton from "./AskAiButton";
import { useDeviceName } from "./DeviceCard";
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
  deviceName?: string;
  device?: Device;
  showDevice?: boolean;
  onRescan?: () => void;
}) {
  const { t, lang, scan } = useApp();
  const isMobile = useIsMobile();
  const typeName = useDeviceName();
  const [text, setText] = useState<Explanation | null>(null);

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

  const askPrompt = t("finding.rephraseQuestion", {
    code: finding.code,
    device: deviceName ?? finding.ip,
    ip: finding.ip,
  });

  // A short prompt with the problem and the device, written into the chat box (not sent).
  // Only catalog facts and the vendor: no hostname, banner or page title (untrusted text).
  const target = device ?? scan?.devices.find((item) => item.ip === finding.ip);
  const explainPrompt = t("finding.explainPrompt", {
    problem: text?.title ?? finding.code,
    severity: t(`severity.${finding.severity}`).toLowerCase(),
    code: finding.code,
    device: target ? typeName(target.device_type) : t("device.unknownTitle"),
    vendor: target?.vendor ? t("finding.explainVendor", { vendor: target.vendor }) : "",
    ip: finding.ip,
    port: finding.port === null ? "" : t("finding.explainPort", { protocol: finding.protocol ?? "", port: finding.port }),
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
      <p className="finding-text">{text?.explanation ?? ""}</p>
      {text && text.steps.length > 0 && (
        <ol className="steps">
          {text.steps.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>
      )}
      <div className="finding-footer">
        <div className="row wrap gap-m">
          <AskAiButton question={askPrompt} />
          {onRescan && (
            <button type="button" className="button" onClick={onRescan} title={t("dashboard.rescanNote")}>
              <IconRefresh />
              {t("dashboard.rescan")}
            </button>
          )}
          {!isMobile && (
            <a className="button" href={href({ name: "ask", draft: explainPrompt })}>
              <IconAsk />
              {t("finding.rephrase")}
            </a>
          )}
        </div>
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

