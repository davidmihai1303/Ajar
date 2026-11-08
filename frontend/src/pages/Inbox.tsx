// Notification inbox: every message has a "read" checkbox; the list can show only unread messages.
import { useState } from "react";
import { formatDate } from "../i18n";
import { useIsMobile } from "../lib/useIsMobile";
import { href, navigate } from "../router";
import { useApp } from "../state/AppState";
import { useInbox, type InboxItem } from "../state/Inbox";
import { IconBell, IconPlus, IconRefresh, IconShield, IconShieldX } from "../components/Icons";
import { SeverityBadge } from "../components/ScoreBadge";

const ICON: Record<InboxItem["kind"], JSX.Element> = {
  scan: <IconRefresh />,
  scanError: <IconShieldX />,
  newFinding: <IconBell />,
  resolved: <IconShield />,
  newDevice: <IconPlus />,
};

export default function Inbox() {
  const { t, lang, selectScan } = useApp();
  const { items, unread, isRead, setRead, markAll } = useInbox();
  const isMobile = useIsMobile();
  const [onlyUnread, setOnlyUnread] = useState(false);
  const shown = onlyUnread ? items.filter((item) => !isRead(item.id)) : items;

  const text = (item: InboxItem): string => {
    const severity = item.severity ? t(`severity.${item.severity}`) : "";
    switch (item.kind) {
      case "scan":
        return item.delta === null || item.delta === undefined || item.delta === 0
          ? t("inbox.scan", { score: item.score ?? "—" })
          : t(item.delta > 0 ? "inbox.scanUp" : "inbox.scanDown", { score: item.score ?? "—", delta: Math.abs(item.delta) });
      case "scanError":
        return t("inbox.scanError");
      case "newFinding":
        return t("inbox.newFinding", { severity, ip: item.ip ?? "" });
      case "resolved":
        return t("inbox.resolved", { severity, ip: item.ip ?? "" });
      case "newDevice":
        return t("inbox.newDevice", { ip: item.ip ?? "" });
    }
  };

  const open = async (item: InboxItem) => {
    setRead(item.id, true);
    await selectScan(item.scanId).catch(() => undefined);
    if (item.ip && !isMobile && item.kind !== "resolved") navigate({ name: "device", ip: item.ip });
    else navigate({ name: "dashboard" });
  };

  return (
    <div className="page">
      <header className="stack">
        <h1 className="serif h1">{t("inbox.title")}</h1>
        <p className="muted">{unread === 0 ? t("inbox.allRead") : t("inbox.unreadCount", { count: unread })}</p>
      </header>

      <div className="row wrap gap-m spread">
        <div className="segmented" role="group" aria-label={t("inbox.filter")}>
          <button type="button" className={onlyUnread ? "" : "on"} aria-pressed={!onlyUnread} onClick={() => setOnlyUnread(false)}>
            {t("inbox.all")}
          </button>
          <button type="button" className={onlyUnread ? "on" : ""} aria-pressed={onlyUnread} onClick={() => setOnlyUnread(true)}>
            {t("inbox.unread")}
          </button>
        </div>
        <button type="button" className="button" onClick={() => markAll(unread > 0)} disabled={items.length === 0}>
          {unread > 0 ? t("inbox.markAllRead") : t("inbox.markAllUnread")}
        </button>
      </div>

      {shown.length === 0 ? (
        <p className="card muted">{onlyUnread ? t("inbox.noUnread") : t("inbox.empty")}</p>
      ) : (
        <ul className="inbox-list">
          {shown.map((item) => {
            const done = isRead(item.id);
            const label = text(item);
            return (
              <li key={item.id} className={`inbox-item${done ? " read" : ""}`}>
                <label className="inbox-check">
                  <input type="checkbox" checked={done} onChange={(event) => setRead(item.id, event.target.checked)} aria-label={`${t("inbox.markRead")}: ${label}`} />
                </label>
                <span className="inbox-icon" aria-hidden="true">{ICON[item.kind]}</span>
                <div className="inbox-body">
                  <span className="inbox-text">
                    {!done && <span className="inbox-dot" aria-label={t("inbox.unreadLabel")} />}
                    {label}
                  </span>
                  <span className="row wrap" style={{ gap: 8 }}>
                    {item.severity && item.kind !== "resolved" && <SeverityBadge severity={item.severity} />}
                    <span className="muted inbox-date">{formatDate(item.createdAt, lang)}</span>
                  </span>
                </div>
                <a
                  className="link-button inbox-open"
                  href={href({ name: "dashboard" })}
                  onClick={(event) => {
                    event.preventDefault();
                    void open(item);
                  }}
                >
                  {t("common.open")}
                </a>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
