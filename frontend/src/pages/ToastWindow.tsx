// The desktop app's notification window (#/toast): a small transparent, always-on-top window in
// the corner of the screen that shows Ajar and the text. It runs outside AppProvider on purpose,
// so it never calls the API; everything it shows arrives through the desktop bridge.
import { useEffect, useState } from "react";
import type { Lang } from "../api/types";
import { makeT } from "../i18n";
import { desktopBridge, type AjarNotice } from "../lib/desktop";
import AjarToast from "../components/AjarToast";

const readLang = (): Lang => {
  try {
    return window.localStorage.getItem("ajar.lang") === "en" ? "en" : "ro";
  } catch {
    return "ro";
  }
};

export default function ToastWindow() {
  const [notice, setNotice] = useState<AjarNotice | null>(null);
  const bridge = desktopBridge();

  useEffect(() => {
    document.documentElement.classList.add("toast-window");
    return bridge?.onToast((next) => setNotice(next));
  }, [bridge]);

  if (!notice) return null;
  const t = makeT(readLang());
  return (
    <AjarToast
      key={notice.id}
      notice={notice}
      standalone
      labels={{ open: t("common.open"), close: t("common.close"), mascot: "Ajar" }}
      onOpen={() => {
        setNotice(null);
        bridge?.openMain();
      }}
      onClose={() => {
        setNotice(null);
        bridge?.toastClosed();
      }}
    />
  );
}
