import { useEffect, useRef } from "react";
import { api } from "../api/client";
import { playAlertChime } from "./audioAlert";
import { useApp } from "../state/AppState";

/**
 * Mobile background poller that checks for new scans and vulnerabilities from the server.
 * Triggers mobile notifications, haptic vibration and audio alerts when threats are found.
 */
export function useMobilePoller(enabled = true, intervalMs = 8000) {
  const { scan, selectScan, t } = useApp();
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
          // New scan detected on server!
          await selectScan(latest.id);

          // If notifications are permitted, trigger mobile notification
          if (typeof Notification !== "undefined" && Notification.permission === "granted") {
            const score = latest.score ?? "—";
            new Notification(t("desktop.scanCompleted", { score }), {
              body: t("mobile.notifySubtitle"),
              icon: "/favicon.ico",
            });
          }

          // Trigger mobile vibration
          if (typeof navigator !== "undefined" && navigator.vibrate) {
            navigator.vibrate([200, 100, 200, 100, 400]);
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
  }, [enabled, intervalMs, selectScan, t]);
}
