// Proof the network got safer: score trend, before/after comparison, scan list, delete history.
import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { ScanDiff } from "../api/proposedTypes";
import { formatDate } from "../i18n";
import { href } from "../router";
import { useApp } from "../state/AppState";
import Dialog from "../components/Dialog";
import DiffList from "../components/DiffList";
import HistoryChart from "../components/HistoryChart";
import { IconTrash } from "../components/Icons";

export default function History() {
  const { t, lang, history, scan, selectScan, deleteHistory } = useApp();
  const readable = history.filter((item) => item.score !== null);
  const [fromId, setFromId] = useState(readable[1]?.id ?? "");
  const [toId, setToId] = useState(readable[0]?.id ?? "");
  const [diff, setDiff] = useState<ScanDiff | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  useEffect(() => {
    if (!fromId || !toId || fromId === toId) return setDiff(null);
    let alive = true;
    api.diff(fromId, toId).then((value) => alive && setDiff(value)).catch(() => alive && setDiff(null));
    return () => {
      alive = false;
    };
  }, [fromId, toId]);

  const option = (id: string) => {
    const item = history.find((entry) => entry.id === id);
    return item ? `${formatDate(item.created_at, lang)} · ${t("history.scoreShort", { score: item.score ?? "—" })}` : "";
  };

  return (
    <div className="page">
      <h1 className="serif h1">{t("history.title")}</h1>
      <HistoryChart items={history} currentId={scan?.id ?? null} />

      {readable.length >= 2 && (
        <section className="stack gap-m">
          <h2 className="h3">{t("history.compare")}</h2>
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
          {fromId === toId ? <p className="muted">{t("history.pickTwo")}</p> : diff && <DiffList diff={diff} />}
        </section>
      )}

      <section className="stack">
        <h2 className="h3">{t("history.all")}</h2>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>{t("history.date")}</th>
                <th>{t("history.source")}</th>
                <th>{t("history.network")}</th>
                <th>{t("history.score")}</th>
                <th>
                  <span className="visually-hidden">{t("common.open")}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {history.map((item) => (
                <tr key={item.id}>
                  <td>{formatDate(item.created_at, lang)}</td>
                  <td>{item.source === "live" ? t("history.live") : `${t("history.imported")} · ${item.file}`}</td>
                  <td>{item.ssid ?? "—"}</td>
                  <td>{item.score ?? t("history.unreadable")}</td>
                  <td>
                    {item.score !== null && (
                      <a href={href({ name: "dashboard" })} onClick={() => void selectScan(item.id)}>
                        {t("common.view")}
                      </a>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <button type="button" className="button danger-link self-start" onClick={() => setConfirmDelete(true)}>
          {t("history.delete")}
        </button>
      </section>

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
