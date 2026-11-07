// Layout + simple navigation between pages. First screen = Welcome until a scan exists,
// then Dashboard (the jury's hands-on task: "most dangerous device + what to do first").
// Ajar (AjarDock) is rendered once, outside every page, so it never disappears.
import { useEffect, useState } from "react";
import { navigate, useRoute } from "./router";
import { AppProvider, useApp } from "./state/AppState";
import AjarDock from "./components/AjarDock";
import DesktopDialog from "./components/DesktopDialog";
import ErrorBanner from "./components/ErrorBanner";
import MiniWidget from "./components/MiniWidget";
import PermissionDialog from "./components/PermissionDialog";
import Sidebar, { SidebarShowButton } from "./components/Sidebar";
import Ask from "./pages/Ask";
import Dashboard from "./pages/Dashboard";
import DeviceDetail from "./pages/DeviceDetail";
import Devices from "./pages/Devices";
import History from "./pages/History";
import Scan from "./pages/Scan";
import ScanProgress from "./pages/ScanProgress";
import Welcome from "./pages/Welcome";

function Shell() {
  const app = useApp();
  const { t, ready, scan, scanning, flow, acceptFlow, cancelFlow, demo, collapsed } = app;
  const route = useRoute();
  const [showWidget, setShowWidget] = useState(false);
  const [showDesktopDialog, setShowDesktopDialog] = useState(false);

  useEffect(() => {
    if (ready && scan && route.name === "home") navigate({ name: "dashboard" });
  }, [ready, scan, route.name]);

  let content: JSX.Element;
  if (!ready) {
    content = <div className="loading muted">{t("common.loading")}</div>;
  } else if (scanning) {
    content = <ScanProgress />;
  } else if (!scan && (route.name === "home" || route.name === "dashboard")) {
    content = <Welcome />;
  } else {
    let page: JSX.Element;
    if (!scan && route.name !== "scan" && route.name !== "history" && route.name !== "ask") {
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
            page = <Ask key={scan?.id} />;
          break;
        default:
          page = <Dashboard />;
      }
    }
    content = (
      <div className={`app${collapsed ? " sidebar-hidden" : ""}`}>
        <Sidebar
          current={route.name}
          onOpenWidget={() => setShowWidget((prev) => !prev)}
          onOpenDesktopDialog={() => setShowDesktopDialog(true)}
        />
        <SidebarShowButton />
        <main className="main" id="main">
          {page}
        </main>
      </div>
    );
  }

  return (
    <>
      {demo && ready && (
        <div className="demo-banner">
          <ErrorBanner tone="info">{t("common.demo")}</ErrorBanner>
        </div>
      )}
      {content}
      <AjarDock />
      {flow && <PermissionDialog key={flow} kind={flow} onAccept={acceptFlow} onCancel={cancelFlow} />}
      {showWidget && (
        <MiniWidget
          onClose={() => setShowWidget(false)}
          onDownloadWrapper={() => setShowDesktopDialog(true)}
        />
      )}
      {showDesktopDialog && (
        <DesktopDialog
          onClose={() => setShowDesktopDialog(false)}
          onOpenWidget={() => setShowWidget(true)}
        />
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
