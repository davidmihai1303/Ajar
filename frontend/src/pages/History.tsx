// Proof the network got safer. Opens with one sentence about *your* last change, then the trend;
// comparing other scans and the full list are there but folded away.
import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { ScanDiff } from "../api/proposedTypes";
import { formatDate } from "../i18n";
import { scoreLevel } from "../lib/scan";
import { href } from "../router";
import { useApp } from "../state/AppState";
import Dialog from "../components/Dialog";
import DiffList from "../components/DiffList";
import HistoryChart from "../components/HistoryChart";
import { IconTrash } from "../components/Icons";

export default function History() {
  const { t, lang, history, scan, selectScan, deleteHistory } = useApp();
  const readable = history.filter((item) => item.score !== null);
  const latest = readable[0];
  const previous = readable[1];
  const [recent, setRecent] = useState<ScanDiff | null>(null);
  const [fromId, setFromId] = useState(readable[1]?.id ?? "");
  const [toId, setToId] = useState(readable[0]?.id ?? "");
  const [picked, setPicked] = useState<ScanDiff | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  useEffect(() => {
    if (!latest || !previous) return setRecent(null);
    let alive = true;
    api.diff(previous.id, latest.id).then((value) => alive && setRecent(value)).catch(() => alive && setRecent(null));
    return () => {
      alive = false;
    };
  }, [latest?.id, previous?.id]);

  useEffect(() => {
    if (!fromId || !toId || fromId === toId) return setPicked(null);
    let alive = true;
    api.diff(fromId, toId).then((value) => alive && setPicked(value)).catch(() => alive && setPicked(null));
    return () => {
      alive = false;
    };
  }, [fromId, toId]);

  let lead = t("history.empty");
  if (latest && !previous) lead = t("history.onlyOne", { date: formatDate(latest.created_at, lang) });
  if (latest && previous) {
    const vars = { from: previous.score ?? "—", to: latest.score ?? "—", date: formatDate(previous.created_at, lang) };
    const delta = (latest.score ?? 0) - (previous.score ?? 0);
    lead = delta < 0 ? t("history.leadWorse", vars) : delta > 0 ? t("history.leadBetter", vars) : t("history.leadSame", vars);
  }

  const option = (id: string) => {
    const item = history.find((entry) => entry.id === id);
    return item ? `${formatDate(item.created_at, lang)}, ${t("history.scoreShort", { score: item.score ?? "—" })}` : "";
  };

  return (
    <div className="page">
      <div className="stack">
        <h1 className="serif h1">{t("history.title")}</h1>
        <p className="history-lead">{lead}</p>
      </div>

      <HistoryChart items={history} currentId={scan?.id ?? null} />

      {recent && <DiffList diff={recent} showScore={false} />}

      {readable.length >= 2 && (
        <details className="fold">
          <summary className="h3">{t("history.compareOther")}</summary>
          <div className="stack gap-m fold-body">
            <div className="row end">
              <label className="field">
                <span className="muted">{t("history.before")}</span>
                <select value={fromId} onChange={(event) => setFromId(event.target.value)}>
                  {readable.map((item) => (
                    <option key={item.id} value={item.id}>
                      {option(item.id)}
                    </option>
                  ))}
                </select>
              </label>
              <span aria-hidden="true" className="muted arrow">
                →
              </span>
              <label className="field">
                <span className="muted">{t("history.after")}</span>
                <select value={toId} onChange={(event) => setToId(event.target.value)}>
                  {readable.map((item) => (
                    <option key={item.id} value={item.id}>
                      {option(item.id)}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            {fromId === toId ? <p className="muted">{t("history.pickTwo")}</p> : picked && <DiffList diff={picked} />}
          </div>
        </details>
      )}

      <details className="fold">
        <summary className="h3">{t("history.allCount", { count: history.length })}</summary>
        <ul className="scan-list fold-body">
          {history.map((item) => (
            <li key={item.id}>
              <span className={`chip level-${scoreLevel(item.score)}`}>{item.score ?? t("history.unreadable")}</span>
              <span className="grow">
                {formatDate(item.created_at, lang)}
                <span className="muted"> {item.source === "live" ? t("history.live") : t("history.importedFile", { file: item.file })}</span>
              </span>
              {item.score !== null && (
                <a href={href({ name: "dashboard" })} onClick={() => void selectScan(item.id)}>
                  {t("common.view")}
                </a>
              )}
            </li>
          ))}
        </ul>
      </details>

      <button type="button" className="button danger-link self-start" onClick={() => setConfirmDelete(true)}>
        {t("history.delete")}
      </button>

      {confirmDelete && (
        <Dialog
          role="alertdialog"
          title={t("history.deleteTitle")}
          icon={<IconTrash />}
          onCancel={() => setConfirmDelete(false)}
          actions={
            <>
              <button type="button" className="button" data-autofocus onClick={() => setConfirmDelete(false)}>
                {t("common.cancel")}
              </button>
              <button
                type="button"
                className="button danger"
                onClick={() => {
                  setConfirmDelete(false);
                  void deleteHistory();
                }}
              >
                {t("history.deleteConfirm")}
              </button>
            </>
          }
        >
          <p className="dialog-body">{t("history.deleteText")}</p>
        </Dialog>
      )}
    </div>
  );
}
