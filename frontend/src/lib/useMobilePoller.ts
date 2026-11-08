import { useEffect, useRef } from "react";
import { api } from "../api/client";
import { assessment } from "./scan";
import { useApp } from "../state/AppState";

/**
 * Mobile background poller that checks for new scans and vulnerabilities from the server.
 * Triggers mobile notifications, haptic vibration and audio alerts when threats are found.
 */
export function useMobilePoller(enabled = true, intervalMs = 8000) {
  const { scan, selectScan, refreshHistory, t, notificationsEnabled, notify } = useApp();
  const lastScanIdRef = useRef<string | null>(scan?.id ?? null);

  useEffect(() => {
    if (scan?.id) {
      lastScanIdRef.current = scan.id;
    }
  }, [scan?.id]);

  useEffect(() => {
    if (!enabled) return;

    let timer: number | undefined;

    const checkServer = async () => {
      try {
        const history = await api.history();
        if (!history || history.length === 0) return;

        const latest = history[0];
        if (latest && latest.id && latest.id !== lastScanIdRef.current) {
          lastScanIdRef.current = latest.id;
          // New scan detected on server: refresh the history (inbox, recents) and show it.
          await refreshHistory().catch(() => undefined);
          await selectScan(latest.id);

          if (!notificationsEnabled) return;

          const full = await api.scan(latest.id).catch(() => null);
          const high = full?.findings.filter((f) => f.severity === "high").length ?? 0;
          const medium = full?.findings.filter((f) => f.severity === "medium").length ?? 0;
          notify({
            title: t("desktop.scanCompleted", { score: latest.score ?? "—" }),
            body: full ? t("desktop.scanCompletedBody", { high, medium }) : t("mobile.notifySubtitle"),
            level: full ? assessment(full) : "unknown",
          });

          // Trigger mobile vibration
          if (typeof navigator !== "undefined" && navigator.vibrate) {
            try {
              navigator.vibrate([200, 100, 200, 100, 400]);
            } catch {
              /* ignore */
            }
          }
        }
      } catch {
        /* Backend unreachable or offline */
      }
    };

    timer = window.setInterval(checkServer, intervalMs);
    return () => {
      if (timer) window.clearInterval(timer);
    };
  }, [enabled, intervalMs, notificationsEnabled, notify, refreshHistory, selectScan, t]);
}
