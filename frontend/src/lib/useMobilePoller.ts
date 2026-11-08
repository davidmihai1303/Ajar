import { useEffect, useRef } from "react";
import { api } from "../api/client";
import { playAlertChime } from "./audioAlert";
import { useApp } from "../state/AppState";

/**
 * Mobile background poller that checks for new scans and vulnerabilities from the server.
 * Triggers mobile notifications, haptic vibration and audio alerts when threats are found.
 */
export function useMobilePoller(enabled = true, intervalMs = 8000) {
  const { scan, selectScan, refreshHistory, t, notificationsEnabled } = useApp();
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

          // If notifications are permitted, trigger mobile notification
          if (typeof Notification !== "undefined" && Notification.permission === "granted") {
            try {
              const score = latest.score ?? "—";
              new Notification(t("desktop.scanCompleted", { score }), {
                body: t("mobile.notifySubtitle"),
                icon: "/ajar-192.png",
              });
            } catch {
              /* ignore mobile Notification constructor restriction */
            }
          }

          // Trigger mobile vibration
          if (typeof navigator !== "undefined" && navigator.vibrate) {
            try {
              navigator.vibrate([200, 100, 200, 100, 400]);
            } catch {
              /* ignore */
            }
          }

          // Play alert chime
          playAlertChime();
        }
      } catch {
        /* Backend unreachable or offline */
      }
    };

    timer = window.setInterval(checkServer, intervalMs);
    return () => {
      if (timer) window.clearInterval(timer);
    };
  }, [enabled, intervalMs, notificationsEnabled, refreshHistory, selectScan, t]);
}
