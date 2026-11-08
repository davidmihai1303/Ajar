// Left sidebar: room for Ajar at the top (Ajar itself lives in AjarDock and stays put when the
// sidebar hides), then "new scan", navigation, recent scans, language and the hide button.
import { formatDate } from "../i18n";
import { useIsMobile } from "../lib/useIsMobile";
import { href, type Route } from "../router";
import { isDesktopApp } from "../lib/desktop";
import { useApp } from "../state/AppState";
import { useState } from "react";
import DownloadDialog from "./DownloadDialog";
import { useInbox } from "../state/Inbox";
import {
  IconAsk,
  IconBell,
  IconDashboard,
  IconDevices,
  IconDownload,
  IconHistory,
  IconPlus,
  IconSidebar,
} from "./Icons";
import LanguageToggle from "./LanguageToggle";

const NAV = [
  { route: { name: "dashboard" } as Route, key: "nav.dashboard", icon: <IconDashboard /> },
  { route: { name: "devices" } as Route, key: "nav.devices", icon: <IconDevices /> },
  { route: { name: "history" } as Route, key: "nav.history", icon: <IconHistory /> },
  { route: { name: "inbox" } as Route, key: "nav.inbox", icon: <IconBell /> },
  { route: { name: "ask" } as Route, key: "nav.ask", icon: <IconAsk /> },
];

export default function Sidebar({
  current,
}: {
  current: Route["name"];
}) {
  const { t, lang, history, scan, selectScan, collapsed, setCollapsed, notificationsEnabled, enableNotifications, notificationProblem } = useApp();
  const isMobile = useIsMobile();
  const { unread } = useInbox();
  const [downloadOpen, setDownloadOpen] = useState(false);
  const offerDownload = !isMobile && !isDesktopApp();
  const active = current === "device" ? "devices" : current === "home" ? "dashboard" : current;
  const navItems = NAV.filter((item) => !(isMobile && item.route.name === "ask"));

  return (
    <aside id="sidebar" className={`sidebar${collapsed ? " hidden" : ""}`} aria-label={t("nav.label")} aria-hidden={collapsed}>
      <div className="sidebar-ajar-space" aria-hidden="true" />

      <div className="sidebar-scroll">
      <a className={`sidebar-new${active === "scan" ? " active" : ""}`} href={href({ name: "scan" })}>
        <IconPlus />
        {t("nav.newScan")}
      </a>

      <nav className="sidebar-nav">
        {navItems.map((item) => (
          <a key={item.key} href={href(item.route)} className={`sidebar-item${active === item.route.name ? " active" : ""}`} aria-current={active === item.route.name ? "page" : undefined}>
            {item.icon}
            {t(item.key)}
            {item.route.name === "inbox" && unread > 0 && (
              <span className="inbox-badge" aria-label={t("inbox.unreadCount", { count: unread })}>{unread}</span>
            )}
          </a>
        ))}
        <div style={{ marginTop: 10, paddingTop: 10, borderTop: "1px solid var(--line)", display: "flex", flexDirection: "column", gap: 4 }}>
          {offerDownload && (
            <button type="button" className="sidebar-item sidebar-button" onClick={() => setDownloadOpen(true)}>
              <IconDownload />
              {t("download.open")}
            </button>
          )}
          <button
            type="button"
            className={`sidebar-item${notificationsEnabled ? " active" : ""}`}
            onClick={() => void enableNotifications()}
            disabled={notificationsEnabled}
            style={{
              width: "100%",
              background: "transparent",
              border: 0,
              textAlign: "left",
              cursor: notificationsEnabled ? "default" : "pointer",
              display: "flex",
              alignItems: "center",
              gap: 10,
            }}
            title={notificationsEnabled ? t("desktop.notifyEnabledShort") : t("desktop.notifyEnable")}
          >
            <IconBell />
            <span>
              {notificationsEnabled
                ? "✓ " + t("desktop.notifyEnabledShort")
                : t("desktop.notifyEnable")}
            </span>
          </button>
          {notificationProblem && <p className="muted notify-problem" role="status">{t(`desktop.notifyProblem.${notificationProblem}`)}</p>}
        </div>
      </nav>

      {history.length > 0 && (
        <div className="sidebar-recents">
          <p className="muted sidebar-heading">{t("nav.recent")}</p>
          {history.slice(0, 5).map((item) => (
            <a key={item.id} href={href({ name: "dashboard" })} className={`sidebar-recent${scan?.id === item.id ? " active" : ""}`} onClick={() => void selectScan(item.id)}>
              <span>{formatDate(item.created_at, lang)}</span>
              <span className="chip recent-score">{item.score ?? "—"}</span>
            </a>
          ))}
        </div>
      )}
      </div>

      <div className="sidebar-footer">
        <LanguageToggle />
        <button type="button" className="sidebar-toggle" onClick={() => setCollapsed(true)} aria-controls="sidebar" aria-expanded={!collapsed}>
          <IconSidebar />
          {t("nav.hide")}
        </button>
      </div>
      {downloadOpen && <DownloadDialog onClose={() => setDownloadOpen(false)} />}
    </aside>
  );
}

/** Shown under Ajar while the sidebar is hidden, so the menu is always one click away. */
export function SidebarShowButton() {
  const { t, collapsed, setCollapsed } = useApp();
  if (!collapsed) return null;
  return (
    <button type="button" className="sidebar-show" onClick={() => setCollapsed(false)} aria-controls="sidebar" aria-expanded={false}>
      <IconSidebar />
      {t("nav.show")}
    </button>
  );
}
