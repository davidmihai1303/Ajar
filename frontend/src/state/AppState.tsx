// App-wide state: language, current scan, history, the live-scan flow and where Ajar stands.
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { ApiError, api, isDemo } from "../api/client";
import type { HistoryItem, ImportResult, Lang, NetworkInfo, Scan, ScanRefusal } from "../api/types";
import { makeT, type TFunction } from "../i18n";
import { playAlertChime } from "../lib/audioAlert";
import { desktopBridge, type AjarNotice } from "../lib/desktop";
import { previousComparable } from "../lib/scan";
import { navigate } from "../router";

export type FlowStep = "consent" | "admin" | "network" | "notify";
export type ScanProblem = { kind: "refused"; refusal: ScanRefusal } | { kind: "agent" | "changed" | "failed" };
export type AjarPlacement = "corner" | "dialog" | "center" | "anchor";
export interface AjarAnchor {
  x: number;
  y: number;
}

// Small per-viewer conveniences only (language, collapsed sidebar, one-time notices).
const onPhone = () => typeof window !== "undefined" && (window.matchMedia?.("(max-width: 768px)").matches ?? false);

const store = {
  get: (key: string) => {
    try {
      return window.localStorage.getItem(key);
    } catch {
      return null;
    }
  },
  set: (key: string, value: string) => {
    try {
      window.localStorage.setItem(key, value);
    } catch {
      /* storage unavailable: the app still works, it just asks again */
    }
  },
};

interface AppState {
  lang: Lang;
  setLang: (lang: Lang) => void;
  t: TFunction;
  ready: boolean;
  loadFailed: boolean;
  demo: boolean;
  network: NetworkInfo | null;
  consentNetwork: NetworkInfo | null;
  agentDown: boolean;
  history: HistoryItem[];
  scan: Scan | null;
  selectScan: (id: string) => Promise<void>;
  refreshHistory: () => Promise<HistoryItem[]>;
  scanning: boolean;
  scanProblem: ScanProblem | null;
  flow: FlowStep | null;
  startScanFlow: () => void;
  acceptFlow: () => void;
  cancelFlow: () => void;
  importFiles: (files: File[]) => Promise<ImportResult[]>;
  deleteHistory: () => Promise<void>;
  aiConsent: boolean | null;
  setAiConsent: (value: boolean) => void;
  collapsed: boolean;
  setCollapsed: (value: boolean) => void;
  dialogs: number;
  openDialog: () => () => void;
  notificationsEnabled: boolean;
  enableNotifications: () => Promise<void>;
  notificationProblem: "denied" | "unsupported" | null;
  /** Tell the user something: a normal system notification with Ajar's picture, and a chime. */
  notify: (notice: AjarNotice) => void;
  placement: AjarPlacement;
  anchor: AjarAnchor | null;
  setAnchor: (value: AjarAnchor | null) => void;
  bubble: string | null;
  setBubble: (text: string | null) => void;
}

const Ctx = createContext<AppState | null>(null);

export function useApp(): AppState {
  const value = useContext(Ctx);
  if (!value) throw new Error("useApp outside AppProvider");
  return value;
}

export function AppProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(() => (store.get("ajar.lang") === "en" ? "en" : "ro"));
  const [ready, setReady] = useState(false);
  const [loadFailed, setLoadFailed] = useState(false);
  const historyRequest = useRef(0);
  const selectionRequest = useRef(0);
  const deletion = useRef(0);
  const [network, setNetwork] = useState<NetworkInfo | null>(null);
  const [consentNetwork, setConsentNetwork] = useState<NetworkInfo | null>(null);
  const preparingConsent = useRef(false);
  const [agentDown, setAgentDown] = useState(false);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [scan, setScan] = useState<Scan | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanProblem, setScanProblem] = useState<ScanProblem | null>(null);
  const [flow, setFlow] = useState<FlowStep | null>(null);
  const [aiConsent, setAiConsentState] = useState<boolean | null>(() => {
    const saved = store.get("ajar.ai");
    return saved === null ? null : saved === "yes";
  });
  const [collapsed, setCollapsedState] = useState(() => {
    const saved = store.get("ajar.sidebar");
    if (saved) return saved === "hidden";
    // On narrow windows the sidebar would cover the page, so it starts hidden there.
    return typeof window.matchMedia === "function" && window.matchMedia("(max-width: 760px)").matches;
  });
  const [dialogs, setDialogs] = useState(0);
  const [bubble, setBubble] = useState<string | null>(null);
  const [anchor, setAnchor] = useState<AjarAnchor | null>(null);
  const t = useMemo(() => makeT(lang), [lang]);
  const scanRef = useRef<Scan | null>(null);
  scanRef.current = scan;

  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);

  const setLang = useCallback((next: Lang) => {
    setLangState(next);
    store.set("ajar.lang", next);
  }, []);

  const setCollapsed = useCallback((value: boolean) => {
    setCollapsedState(value);
    store.set("ajar.sidebar", value ? "hidden" : "open");
  }, []);

  const setAiConsent = useCallback((value: boolean) => {
    setAiConsentState(value);
    store.set("ajar.ai", value ? "yes" : "no");
  }, []);


  // One place for every notification: always the system's own, with Ajar's picture as the icon.
  const notify = useCallback((notice: AjarNotice) => {
    playAlertChime();
    const bridge = desktopBridge();
    if (bridge) {
      bridge.notify(notice);
      return;
    }
    if (typeof Notification === "undefined" || Notification.permission !== "granted") return;
    try {
      new Notification(notice.title, { body: notice.body, icon: "/ajar-192.png" });
    } catch {
      /* some phones only allow notifications from a service worker */
    }
  }, []);

  useEffect(() => {
    desktopBridge()?.setLang(lang);
  }, [lang]);

  // "Active" only when a notification can really appear: the desktop app, or browser permission.
  const [notificationsEnabled, setNotificationsEnabledState] = useState<boolean>(
    () => desktopBridge() !== null || (typeof Notification !== "undefined" && Notification.permission === "granted"),
  );
  const [notificationProblem, setNotificationProblem] = useState<"denied" | "unsupported" | null>(null);

  useEffect(() => {
    if (desktopBridge() || typeof navigator === "undefined" || !navigator.permissions?.query) return;
    let permStatus: PermissionStatus | null = null;
    const handleChange = () => {
      if (!permStatus) return;
      setNotificationsEnabledState(permStatus.state === "granted");
      if (permStatus.state === "granted") setNotificationProblem(null);
    };
    navigator.permissions
      .query({ name: "notifications" })
      .then((status) => {
        permStatus = status;
        status.addEventListener?.("change", handleChange);
      })
      .catch(() => undefined);
    return () => {
      permStatus?.removeEventListener?.("change", handleChange);
    };
  }, []);

  const enableNotifications = useCallback(async () => {
    const bridge = desktopBridge();
    const supported = typeof Notification !== "undefined";
    // Ask first, to keep the browser's user-activation gesture.
    const asked =
      !bridge && supported && Notification.permission === "default"
        ? Notification.requestPermission().catch(() => "default" as NotificationPermission)
        : null;
    if (typeof navigator !== "undefined" && navigator.vibrate) {
      try {
        navigator.vibrate([100, 50, 100]);
      } catch {
        /* ignore */
      }
    }
    if (asked) await asked;
    if (!bridge && (!supported || Notification.permission !== "granted")) {
      // A dismissed prompt ("default") stays off without a message: the user can simply ask again.
      setNotificationsEnabledState(false);
      setNotificationProblem(!supported ? "unsupported" : Notification.permission === "denied" ? "denied" : null);
      return;
    }
    setNotificationProblem(null);
    setNotificationsEnabledState(true);
    notify({ title: "Ajar", body: t(onPhone() ? "mobile.notifyActiveBody" : "desktop.testNotifyBody") });
  }, [notify, t]);

  useEffect(() => {
    const syncConsent = (event: StorageEvent) => {
      if (event.storageArea !== window.localStorage || (event.key !== null && event.key !== "ajar.ai")) return;
      const saved = store.get("ajar.ai");
      setAiConsentState(saved === null ? null : saved === "yes");
    };
    window.addEventListener("storage", syncConsent);
    return () => window.removeEventListener("storage", syncConsent);
  }, []);

  const refreshNetwork = useCallback(async () => {
    try {
      const current = await api.network();
      setNetwork(current);
      setAgentDown(false);
      return current;
    } catch (error) {
      setNetwork(null);
      if (error instanceof ApiError && error.refusal) {
        setAgentDown(false);
        setScanProblem({ kind: "refused", refusal: error.refusal });
      } else {
        setAgentDown(true);
        setScanProblem({ kind: "agent" });
      }
      return null;
    }
  }, []);

  const loadHistory = useCallback(async (): Promise<HistoryItem[]> => {
    const version = ++historyRequest.current;
    const items = [...(await api.history())].sort((a, b) => b.created_at.localeCompare(a.created_at));
    if (version !== historyRequest.current) return [];
    setHistory(items);
    return items;
  }, []);

  const selectScan = useCallback(async (id: string) => {
    const version = ++selectionRequest.current;
    try {
      const selected = await api.scan(id);
      if (version === selectionRequest.current) {
        setScan(selected);
        setLoadFailed(false);
      }
    } catch {
      if (version === selectionRequest.current) setLoadFailed(true);
    }
  }, []);

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const items = await loadHistory();
        if (!active) return;
        const latest = items.find((item) => item.score !== null) ?? items[0];
        if (latest) await selectScan(latest.id);
        if (active) await refreshNetwork();
      } catch {
        if (active) setLoadFailed(true);
      } finally {
        if (active) setReady(true);
      }
    })();
    return () => { active = false; };
  }, [loadHistory, refreshNetwork, selectScan]);

  const openDialog = useCallback(() => {
    setDialogs((count) => count + 1);
    return () => setDialogs((count) => Math.max(0, count - 1));
  }, []);

  // One notification per finished scan: the score, the worst problems and what changed.
  const notifyScan = useCallback(
    async (previousId: string | undefined, next: Scan) => {
      if (!notificationsEnabled) return;
      const generation = deletion.current;
      const high = next.findings.filter((f) => f.severity === "high").length;
      const medium = next.findings.filter((f) => f.severity === "medium").length;
      let body = t("desktop.scanCompletedBody", { high, medium });
      if (previousId) {
        try {
          const diff = await api.diff(previousId, next.id);
          if (generation !== deletion.current) return;
          if (diff.devices_added.length || diff.ports_opened.length) {
            body += " " + t("notify.changes", { devices: diff.devices_added.length, ports: diff.ports_opened.length });
          }
        } catch {
          /* the dashboard shows the same changes anyway */
        }
      }
      notify({ title: t("desktop.scanCompleted", { score: next.score ?? "—" }), body });
    },
    [notificationsEnabled, notify, t],
  );

  const runScan = useCallback(async () => {
    if (!consentNetwork) return;
    setFlow(null);
    setConsentNetwork(null);
    setScanProblem(null);
    setScanning(true);
    const generation = deletion.current;
    try {
      const current = await refreshNetwork();
      if (!current || current.interface !== consentNetwork.interface || current.subnet !== consentNetwork.subnet ||
          current.gateway !== consentNetwork.gateway || current.ssid !== consentNetwork.ssid ||
          current.confirmation_id !== consentNetwork.confirmation_id) {
        if (current) setScanProblem({ kind: "changed" });
        navigate({ name: "scan" });
        return;
      }
      const result = await api.startScan(consentNetwork);
      if (generation !== deletion.current) return;
      selectionRequest.current++;
      setScan(result);
      const items = await loadHistory().catch(() => []);
      if (generation !== deletion.current) return;
      navigate({ name: "dashboard" });
      void notifyScan(previousComparable(items, result)?.id, result);
      if (typeof Notification !== "undefined" && Notification.permission === "default" && !store.get("ajar.ack.notify")) {
        setFlow("notify");
      }
    } catch (error) {
      if (error instanceof ApiError && error.refusal) setScanProblem({ kind: "refused", refusal: error.refusal });
      else if (error instanceof ApiError && (error.status === 502 || error.status === 503 || error.status === 504)) setScanProblem({ kind: "agent" });
      else setScanProblem({ kind: "failed" });
      navigate({ name: "scan" });
    } finally {
      setScanning(false);
    }
  }, [consentNetwork, loadHistory, notifyScan, refreshNetwork]);

  const startScanFlow = useCallback(async () => {
    if (preparingConsent.current) return;
    preparingConsent.current = true;
    setScanProblem(null);
    const current = await refreshNetwork();
    preparingConsent.current = false;
    if (!current) return navigate({ name: "scan" });
    setConsentNetwork(current);
    setFlow("consent");
  }, [refreshNetwork]);

  const acceptFlow = useCallback(() => {
    if (flow === "consent") {
      if (!store.get("ajar.ack.admin")) return setFlow("admin");
      if (!store.get("ajar.ack.network")) return setFlow("network");
      void runScan();
    } else if (flow === "admin") {
      store.set("ajar.ack.admin", "yes");
      if (!store.get("ajar.ack.network")) return setFlow("network");
      void runScan();
    } else if (flow === "network") {
      store.set("ajar.ack.network", "yes");
      void runScan();
    } else if (flow === "notify") {
      store.set("ajar.ack.notify", "yes");
      setFlow(null);
      if (typeof Notification !== "undefined") void Notification.requestPermission();
    }
  }, [flow, runScan]);

  const cancelFlow = useCallback(() => {
    if (flow === "notify") store.set("ajar.ack.notify", "yes");
    setConsentNetwork(null);
    setFlow(null);
  }, [flow]);

  const importFiles = useCallback(
    async (files: File[]) => {
      const generation = deletion.current;
      const selection = selectionRequest.current;
      const results = await api.importFiles(files);
      if (generation !== deletion.current) return [];
      // Preserve the import response even if the follow-up history request fails.
      const items = await loadHistory().catch(() => []);
      if (generation !== deletion.current || selection !== selectionRequest.current) return results;
      const lastGood = [...results].reverse().find((item) => !item.error && item.scan_id);
      if (lastGood?.scan_id) await selectScan(lastGood.scan_id).catch(() => undefined);
      else if (!scanRef.current && items[0]) await selectScan(items[0].id).catch(() => undefined);
      return results;
    },
    [loadHistory, selectScan],
  );

  const deleteHistory = useCallback(async () => {
    await api.deleteHistory();
    deletion.current++;
    historyRequest.current++;
    selectionRequest.current++;
    setLoadFailed(false);
    setBubble(null);
    setHistory([]);
    setScan(null);
    navigate({ name: "home" });
  }, []);

  const placement: AjarPlacement = dialogs > 0 ? "dialog" : scanning ? "center" : anchor ? "anchor" : "corner";

  const value: AppState = {
    lang,
    setLang,
    t,
    ready,
    loadFailed,
    demo: isDemo(),
    network,
    consentNetwork,
    agentDown,
    history,
    scan,
    selectScan,
    refreshHistory: loadHistory,
    scanning,
    scanProblem,
    flow,
    startScanFlow,
    acceptFlow,
    cancelFlow,
    importFiles,
    deleteHistory,
    aiConsent,
    setAiConsent,
    collapsed,
    setCollapsed,
    dialogs,
    openDialog,
    notificationsEnabled,
    enableNotifications,
    notificationProblem,
    notify,
    placement,
    anchor,
    setAnchor,
    bubble,
    setBubble,
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
