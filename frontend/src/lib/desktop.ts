// Bridge to the Ajar desktop app (Electron, desktop/preload.js). In a normal browser it is absent.
import type { Lang, Severity } from "../api/types";

/** One notification, already in the user's language. `level` decides how Ajar looks. */
export interface AjarNotice {
  id: string;
  title: string;
  body: string;
  level: Severity | "clear" | "unknown";
}

/** A built desktop app file offered by the running Ajar app (GET /api/downloads). */
export interface DesktopDownload {
  name: string;
  size: number;
  arch: "x64" | "arm64";
  kind: "appimage" | "deb";
}

interface DesktopBridge {
  isDesktop: true;
  notify: (notice: AjarNotice) => void;
  setLang: (lang: Lang) => void;
  onToast: (callback: (notice: AjarNotice) => void) => () => void;
  toastClosed: () => void;
  openMain: () => void;
}

declare global {
  interface Window {
    ajarDesktop?: DesktopBridge;
  }
}

export const desktopBridge = (): DesktopBridge | null =>
  typeof window !== "undefined" && window.ajarDesktop?.isDesktop === true ? window.ajarDesktop : null;

export const isDesktopApp = (): boolean => desktopBridge() !== null;
