// Start a live scan of the detected network, or analyse nmap XML files offline.
import { useState, type ChangeEvent, type DragEvent } from "react";
import type { ImportResult } from "../api/types";
import { href } from "../router";
import { publicFilename } from "../lib/filename";
import { useApp } from "../state/AppState";
import ErrorBanner from "../components/ErrorBanner";
import { IconAlert, IconShieldX, IconTerminal, IconUpload } from "../components/Icons";

const AGENT_COMMAND = "python3 scanner/agent.py serve";

export default function Scan() {
  const { t, lang, demo, network, agentDown, startScanFlow, scanProblem, importFiles, selectScan } = useApp();
  const [results, setResults] = useState<ImportResult[]>([]);
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [copied, setCopied] = useState(false);

  const handle = async (files: File[]) => {
    if (demo || busy) return;
    const xml = files.filter((file) => file.name.toLowerCase().endsWith(".xml"));
    if (xml.length === 0) return;
    setBusy(true);
    try {
      setResults(await importFiles(xml));
    } catch {
      setResults(xml.map(() => ({ file: "", scan_id: null, score: null, error: "failed" })));
    } finally {
      setBusy(false);
    }
  };

  const onPick = (event: ChangeEvent<HTMLInputElement>) => {
    void handle([...(event.target.files ?? [])]);
    event.target.value = "";
  };
  const onDrop = (event: DragEvent) => {
    event.preventDefault();
    setDragging(false);
    void handle([...event.dataTransfer.files]);
  };
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(AGENT_COMMAND);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  const showAgent = agentDown || scanProblem?.kind === "agent";

  return (
    <div className="page wide">
      <h1 className="serif h1">{t("scan.title")}</h1>

      {scanProblem?.kind === "refused" && (
        <div className="card problem" role="alert">
          <IconShieldX />
          <div className="stack">
            <h2 className="h3">{t("scan.refused.title")}</h2>
            <p>{lang === "ro" ? scanProblem.refusal.reason_ro : scanProblem.refusal.reason_en}</p>
            <p className="muted" lang={lang === "ro" ? "en" : "ro"}>
              {lang === "ro" ? scanProblem.refusal.reason_en : scanProblem.refusal.reason_ro}
            </p>
          </div>
        </div>
      )}
      {scanProblem?.kind === "failed" && <ErrorBanner>{t("scan.failed")}</ErrorBanner>}
      {scanProblem?.kind === "changed" && <ErrorBanner>{t("scan.changed")}</ErrorBanner>}

      {showAgent && (
        <div className="card problem" role="status">
          <IconTerminal />
          <div className="stack grow">
            <h2 className="h3">{t("scan.agent.title")}</h2>
            <p>{t("scan.agent.text")}</p>
            <div className="code-row">
              <code>{AGENT_COMMAND}</code>
              <button type="button" className="button" onClick={copy}>
                {copied ? t("common.copied") : t("common.copy")}
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="two-col">
        <section className="card">
          <h2 className="h3">{t("scan.live.title")}</h2>
          <dl className="facts">
            <dt>{t("network.wifi")}</dt>
            <dd className="strong">{network?.ssid ?? "—"}</dd>
            <dt>{t("network.subnet")}</dt>
            <dd>{network?.subnet ?? "—"}</dd>
            <dt>{t("network.gateway")}</dt>
            <dd>{network?.gateway ?? "—"}</dd>
          </dl>
          <div className="grow" />
          <button type="button" className="button primary large" onClick={startScanFlow}>
            {t(demo ? "scan.demo.button" : network ? "scan.live.button" : "common.retry")}
          </button>
          <p className="muted">{t("scan.live.duration")}</p>
        </section>

        <section className="card">
          <h2 className="h3">{t("scan.import.title")}</h2>
          {demo ? <p className="muted">{t("scan.import.demo")}</p> : (
            <label
              className={`dropzone${dragging ? " dragging" : ""}`}
              onDragOver={(event) => {
                event.preventDefault();
                setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={onDrop}
            >
              <IconUpload />
              <span>
                <span className="strong">{t("scan.import.drop")}</span> {t("scan.import.or")}
              </span>
              <input className="visually-hidden" type="file" disabled={busy} accept=".xml,text/xml,application/xml" multiple onChange={onPick} />
            </label>
          )}
          {busy && <p className="muted">{t("scan.import.busy")}</p>}
          {results.length > 0 && (
            <ul className="results">
              {results.map((result, index) => (
                <li key={index}>
                  {result.error ? (
                    <>
                      <span className="danger-icon">
                        <IconAlert />
                      </span>
                      <span className="grow">
                        <span className="block">{result.file ? publicFilename(result.file) : t("scan.import.fileNumber", { number: index + 1 })}</span>
                        <span className="danger-text">{t(result.file ? "scan.import.unreadable" : "scan.import.failed")}</span>
                      </span>
                    </>
                  ) : (
                    <>
                      <span className="grow">{publicFilename(result.file)}</span>
                      <span className="strong">{result.score}</span>
                      <a href={href({ name: "dashboard" })} onClick={() => result.scan_id && void selectScan(result.scan_id)}>
                        {t("common.view")}
                      </a>
                    </>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </div>
  );
}
