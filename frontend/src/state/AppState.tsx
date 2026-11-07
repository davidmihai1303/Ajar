// App-wide state: language, current scan, history, the live-scan flow and where Ajar stands.
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { ApiError, api, connect, isDemo } from "../api/client";
import type { HistoryItem, ImportResult, Lang, NetworkInfo, Scan, ScanRefusal } from "../api/proposedTypes";
import { makeT, type TFunction } from "../i18n";
import { navigate } from "../router";

export type FlowStep = "consent" | "admin" | "network" | "notify";
export type ScanProblem = { kind: "refused"; refusal: ScanRefusal } | { kind: "agent" } | { kind: "failed" };
export type AjarPlacement = "corner" | "dialog" | "center" | "anchor";
export interface AjarAnchor {
  x: number;
  y: number;
}

// Small per-viewer conveniences only (language, collapsed sidebar, one-time notices).
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
  demo: boolean;
  network: NetworkInfo | null;
  agentDown: boolean;
  history: HistoryItem[];
  scan: Scan | null;
  selectScan: (id: string) => Promise<void>;
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
  placement: AjarPlacement;
  anchor: AjarAnchor | null;
  setAnchor: (value: AjarAnchor | null) => void;
  bubble: string | null;
  setBubble: (text: string | null) => void;
  refreshNetwork: () => Promise<void>;
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
  const [network, setNetwork] = useState<NetworkInfo | null>(null);
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

  const refreshNetwork = useCallback(async () => {
    try {
      setNetwork(await api.network());
      setAgentDown(false);
    } catch {
      setNetwork(null);
      setAgentDown(true);
    }
  }, []);

  const loadHistory = useCallback(async (): Promise<HistoryItem[]> => {
    const items = [...(await api.history())].sort((a, b) => b.created_at.localeCompare(a.created_at));
    setHistory(items);
    return items;
  }, []);

  const selectScan = useCallback(async (id: string) => {
    setScan(await api.scan(id));
  }, []);

  useEffect(() => {
    (async () => {
      await connect();
      const items = await loadHistory().catch(() => [] as HistoryItem[]);
      const latest = items.find((item) => item.score !== null) ?? items[0];
      if (latest) await selectScan(latest.id).catch(() => undefined);
      await refreshNetwork();
      setReady(true);
    })();
  }, [loadHistory, refreshNetwork, selectScan]);

  const openDialog = useCallback(() => {
    setDialogs((count) => count + 1);
    return () => setDialogs((count) => Math.max(0, count - 1));
  }, []);

  const notifyChanges = useCallback(
    async (previousId: string | undefined, next: Scan) => {
      if (!previousId || typeof Notification === "undefined" || Notification.permission !== "granted") return;
      try {
        const diff = await api.diff(previousId, next.id);
        if (diff.devices_added.length || diff.ports_opened.length) {
          new Notification("Ajar", {
            body: t("notify.changes", { devices: diff.devices_added.length, ports: diff.ports_opened.length }),
          });
        }
      } catch {
        /* the dashboard shows the same alerts anyway */
      }
    },
    [t],
  );

  const runScan = useCallback(async () => {
    setFlow(null);
    setScanProblem(null);
    setScanning(true);
    const previousId = history[0]?.id;
    try {
      const result = await api.startScan();
      setScan(result);
      await loadHistory();
      setScanning(false);
      navigate({ name: "dashboard" });
      void notifyChanges(previousId, result);
      if (typeof Notification !== "undefined" && Notification.permission === "default" && !store.get("ajar.ack.notify")) {
        setFlow("notify");
      }
    } catch (error) {
      setScanning(false);
      if (error instanceof ApiError && error.refusal) setScanProblem({ kind: "refused", refusal: error.refusal });
      else if (error instanceof ApiError && (error.status === 502 || error.status === 503 || error.status === 504)) setScanProblem({ kind: "agent" });
      else setScanProblem({ kind: "failed" });
      navigate({ name: "scan" });
    }
  }, [history, loadHistory, notifyChanges]);

  const startScanFlow = useCallback(() => {
    setScanProblem(null);
    setFlow("consent");
  }, []);

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
    setFlow(null);
  }, [flow]);

  const importFiles = useCallback(
    async (files: File[]) => {
      const results = await api.importFiles(files);
      const items = await loadHistory();
      const lastGood = [...results].reverse().find((item) => item.scan_id);
      if (lastGood?.scan_id) await selectScan(lastGood.scan_id);
      else if (!scanRef.current && items[0]) await selectScan(items[0].id);
      return results;
    },
    [loadHistory, selectScan],
  );

  const deleteHistory = useCallback(async () => {
    await api.deleteHistory();
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
    demo: isDemo(),
    network,
    agentDown,
    history,
    scan,
    selectScan,
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
    placement,
    anchor,
    setAnchor,
    bubble,
    setBubble,
    refreshNetwork,
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
