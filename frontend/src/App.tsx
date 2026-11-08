// Layout + simple navigation between pages. First screen = Welcome until a scan exists,
// then Dashboard (the jury's hands-on task: "most dangerous device + what to do first").
// Ajar (AjarDock) is rendered once, outside every page, so it never disappears.
import { useEffect, useState } from "react";
import { switchDemo } from "./api/client";
import LanguageToggle from "./components/LanguageToggle";
import MobileHeader from "./components/MobileHeader";
import { useIsMobile } from "./lib/useIsMobile";
import { useMobilePoller } from "./lib/useMobilePoller";
import { navigate, useRoute } from "./router";
import { AppProvider, useApp } from "./state/AppState";
import AjarDock from "./components/AjarDock";
import DesktopDialog from "./components/DesktopDialog";
import ErrorBanner from "./components/ErrorBanner";
import PermissionDialog from "./components/PermissionDialog";
import Sidebar, { SidebarShowButton } from "./components/Sidebar";
import Ask from "./pages/Ask";
import Dashboard from "./pages/Dashboard";
import DeviceDetail from "./pages/DeviceDetail";
import Devices from "./pages/Devices";
import History from "./pages/History";
import Report from "./pages/Report";
import Scan from "./pages/Scan";
import ScanProgress from "./pages/ScanProgress";
import Welcome from "./pages/Welcome";

function Shell() {
  const app = useApp();
  const { t, ready, scan, scanning, flow, acceptFlow, cancelFlow, demo, collapsed } = app;
  const route = useRoute();
  const isMobile = useIsMobile();
  useMobilePoller(isMobile);
  const [showDesktopDialog, setShowDesktopDialog] = useState(false);

  useEffect(() => {
    if (ready && scan && route.name === "home") navigate({ name: "dashboard" });
    if (isMobile && route.name === "ask") navigate({ name: "dashboard" });
  }, [ready, scan, route.name, isMobile]);

  let content: JSX.Element;
  if (!ready) {
    content = <div className="loading muted">{t("common.loading")}</div>;
  } else if (app.loadFailed) {
    content = <main className="page">
      <LanguageToggle />
      <ErrorBanner>{t("common.backendError")}</ErrorBanner>
      <div className="row">
        <button className="button primary" onClick={() => window.location.reload()}>{t("common.retry")}</button>
        <button className="button" onClick={() => switchDemo(true)}>{t("common.openDemo")}</button>
      </div>
    </main>;
  } else if (scanning) {
    content = <ScanProgress />;
  } else if (!scan && (route.name === "home" || route.name === "dashboard")) {
    content = <Welcome />;
  } else {
    let page: JSX.Element;
    if (isMobile) {
      page = <Dashboard />;
    } else if (!scan && route.name !== "scan" && route.name !== "history" && route.name !== "ask") {
      page = (
        <div className="page">
          <p>{t("common.noScan")}</p>
          <a className="button primary self-start" href="#/">
            {t("welcome.start")}
          </a>
        </div>
      );
    } else {
      switch (route.name) {
        case "devices":
          page = <Devices />;
          break;
        case "device":
          page = <DeviceDetail ip={route.ip} />;
          break;
        case "scan":
          page = <Scan />;
          break;
        case "history":
          page = <History />;
          break;
        case "ask":
          page = <Ask key={`${scan?.id}-${route.query ?? ""}`} />;
          break;
        case "report":
          page = <Report />;
          break;
        default:
          page = <Dashboard />;
      }
    }
    if (isMobile) {
      content = (
        <div className="mobile-shell">
          <MobileHeader />
          <main className="mobile-main" id="main">
            {page}
          </main>
        </div>
      );
    } else {
      content = (
        <div className={`app${collapsed ? " sidebar-hidden" : ""}`}>
          <Sidebar current={route.name} />
          <SidebarShowButton />
          <main className="main" id="main">
            {page}
          </main>
        </div>
      );
    }
  }

  return (
    <>
      {demo && ready && (
        <div className="demo-banner">
          <ErrorBanner tone="info" action={<button className="link-button" onClick={() => switchDemo(false)}>{t("common.exitDemo")}</button>}>{t("common.demo")}</ErrorBanner>
        </div>
      )}
      {content}
      {!isMobile && !app.loadFailed && <AjarDock />}
      {flow && <PermissionDialog key={flow} kind={flow} onAccept={acceptFlow} onCancel={cancelFlow} />}
      {showDesktopDialog && (
        <DesktopDialog onClose={() => setShowDesktopDialog(false)} />
      )}
    </>
  );
}

export default function App() {
  return (
    <AppProvider>
      <Shell />
    </AppProvider>
  );
}
