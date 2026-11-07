// Left sidebar: room for Ajar at the top (Ajar itself lives in AjarDock and stays put when the
// sidebar hides), then "new scan", navigation, recent scans, language and the hide button.
import { formatDate } from "../i18n";
import { downloadDesktopWrapper } from "../lib/downloadWrapper";
import { scoreLevel } from "../lib/scan";
import { useIsMobile } from "../lib/useIsMobile";
import { href, type Route } from "../router";
import { useApp } from "../state/AppState";
import { IconAsk, IconDashboard, IconDevices, IconDownload, IconHistory, IconPlus, IconShield, IconSidebar } from "./Icons";
import LanguageToggle from "./LanguageToggle";

const NAV = [
  { route: { name: "dashboard" } as Route, key: "nav.dashboard", icon: <IconDashboard /> },
  { route: { name: "devices" } as Route, key: "nav.devices", icon: <IconDevices /> },
  { route: { name: "history" } as Route, key: "nav.history", icon: <IconHistory /> },
  { route: { name: "ask" } as Route, key: "nav.ask", icon: <IconAsk /> },
];

export default function Sidebar({
  current,
  onOpenWidget,
}: {
  current: Route["name"];
  onOpenWidget?: () => void;
  onOpenDesktopDialog?: () => void;
}) {
  const { t, lang, history, scan, selectScan, collapsed, setCollapsed } = useApp();
  const isMobile = useIsMobile();
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
          </a>
        ))}
        <div style={{ marginTop: 10, paddingTop: 10, borderTop: "1px solid var(--line)" }}>
          {onOpenWidget && (
            <button
              type="button"
              className="sidebar-item"
              onClick={onOpenWidget}
              style={{ width: "100%", background: "transparent", border: 0, textAlign: "left", cursor: "pointer" }}
            >
              <IconShield />
              {t("desktop.widget")}
            </button>
          )}
          <button
            type="button"
            className="sidebar-item"
            onClick={downloadDesktopWrapper}
            style={{ width: "100%", background: "transparent", border: 0, textAlign: "left", cursor: "pointer" }}
            title={t("desktop.downloadTitle")}
          >
            <IconDownload />
            {t("desktop.download")}
          </button>
        </div>
      </nav>

      {history.length > 0 && (
        <div className="sidebar-recents">
          <p className="muted sidebar-heading">{t("nav.recent")}</p>
          {history.slice(0, 5).map((item) => (
            <a key={item.id} href={href({ name: "dashboard" })} className={`sidebar-recent${scan?.id === item.id ? " active" : ""}`} onClick={() => void selectScan(item.id)}>
              <span>{formatDate(item.created_at, lang)}</span>
              <span className={`chip recent-score level-${scoreLevel(item.score)}`}>{item.score ?? "—"}</span>
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
