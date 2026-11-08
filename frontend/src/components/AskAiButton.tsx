// "Ask AI about this". On a computer it opens the Ask page; on a phone the chat is not available,
// so the same button explains that the conversation with Ajar lives in the desktop version.
import { useState } from "react";
import { useIsMobile } from "../lib/useIsMobile";
import { href } from "../router";
import { useApp } from "../state/AppState";
import Dialog from "./Dialog";
import { IconAsk } from "./Icons";

export default function AskAiButton({ question }: { question: string }) {
  const { t } = useApp();
  const isMobile = useIsMobile();
  const [open, setOpen] = useState(false);

  if (!isMobile) {
    return (
      <a className="button" href={href({ name: "ask", query: question })} title={t("dashboard.askAi")}>
        <IconAsk />
        {t("dashboard.askAi")}
      </a>
    );
  }

  return (
    <>
      <button type="button" className="button" onClick={() => setOpen(true)}>
        <IconAsk />
        {t("dashboard.askAi")}
      </button>
      {open && (
        <Dialog
          title={t("mobile.chatTitle")}
          icon={<IconAsk />}
          onCancel={() => setOpen(false)}
          actions={
            <button type="button" className="button primary" data-autofocus onClick={() => setOpen(false)}>
              {t("mobile.chatOk")}
            </button>
          }
        >
          <p className="dialog-body">{t("mobile.chatBody")}</p>
        </Dialog>
      )}
    </>
  );
}
