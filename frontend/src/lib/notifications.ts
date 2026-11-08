import { playAlertChime } from "./audioAlert";

export type NotificationStatus = "unsupported" | "default" | "granted" | "denied";

export function isNotificationSupported(): boolean {
  return typeof window !== "undefined" && "Notification" in window;
}

export function getNotificationPermission(): NotificationStatus {
  if (!isNotificationSupported()) return "unsupported";
  return Notification.permission as NotificationStatus;
}

export async function requestDesktopNotification(): Promise<NotificationStatus> {
  if (!isNotificationSupported()) return "unsupported";
  try {
    const res = await Notification.requestPermission();
    return res as NotificationStatus;
  } catch {
    return "denied";
  }
}

export function sendDesktopNotification(
  title: string,
  options?: NotificationOptions,
  withAudio = true
): boolean {
  if (!isNotificationSupported() || Notification.permission !== "granted") {
    return false;
  }
  try {
    new Notification(title, {
      icon: "/favicon.ico",
      ...options,
    });
    if (withAudio) {
      playAlertChime();
    }
    return true;
  } catch {
    return false;
  }
}
