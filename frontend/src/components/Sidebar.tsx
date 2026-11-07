// Left sidebar: room for Ajar at the top (Ajar itself lives in AjarDock and stays put when the
// sidebar hides), then "new scan", navigation, recent scans, language and the hide button.
import { formatDate } from "../i18n";
import { href, type Route } from "../router";
import { useApp } from "../state/AppState";
import { IconAsk, IconDashboard, IconDevices, IconHistory, IconPlus, IconSidebar } from "./Icons";
import LanguageToggle from "./LanguageToggle";

const NAV = [
  { route: { name: "dashboard" } as Route, key: "nav.dashboard", icon: <IconDashboard /> },
  { route: { name: "devices" } as Route, key: "nav.devices", icon: <IconDevices /> },
  { route: { name: "history" } as Route, key: "nav.history", icon: <IconHistory /> },
  { route: { name: "ask" } as Route, key: "nav.ask", icon: <IconAsk /> },
];

export default function Sidebar({ current }: { current: Route["name"] }) {
  const { t, lang, history, scan, selectScan, collapsed, setCollapsed } = useApp();
  const active = current === "device" ? "devices" : current === "home" ? "dashboard" : current;

  return (
    <aside id="sidebar" className={`sidebar${collapsed ? " hidden" : ""}`} aria-label={t("nav.label")} aria-hidden={collapsed}>
      <div className="sidebar-ajar-space" aria-hidden="true" />

      <a className={`sidebar-new${active === "scan" ? " active" : ""}`} href={href({ name: "scan" })}>
        <IconPlus />
        {t("nav.newScan")}
      </a>

      <nav className="sidebar-nav">
        {NAV.map((item) => (
          <a key={item.key} href={href(item.route)} className={`sidebar-item${active === item.route.name ? " active" : ""}`} aria-current={active === item.route.name ? "page" : undefined}>
            {item.icon}
            {t(item.key)}
          </a>
        ))}
      </nav>

      {history.length > 0 && (
        <div className="sidebar-recents">
          <p className="muted sidebar-heading">{t("nav.recent")}</p>
          {history.slice(0, 5).map((item) => (
            <a key={item.id} href={href({ name: "dashboard" })} className={`sidebar-recent${scan?.id === item.id ? " active" : ""}`} onClick={() => void selectScan(item.id)}>
              <span>{formatDate(item.created_at, lang)}</span>
              <span className="muted">{item.score ?? "—"}</span>
            </a>
          ))}
        </div>
      )}

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
