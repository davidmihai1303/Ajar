// Phone header: the Ajar logo (the real wordmark), the inbox bell and the language switch.
import { useApp } from "../state/AppState";
import { useInbox } from "../state/Inbox";
import { IconBell } from "./Icons";
import LanguageToggle from "./LanguageToggle";

export default function MobileHeader() {
  const { t } = useApp();
  const { unread } = useInbox();

  return (
    <header className="mobile-header" role="banner">
      <a href="#/dashboard" className="mobile-brand">
        <img src="/ajar-logo.svg" alt="Ajar" className="mobile-logo" width="101" height="48" />
      </a>
      <div className="row" style={{ gap: 8 }}>
        <a
          href="#/inbox"
          className="mobile-bell"
          aria-label={unread > 0 ? `${t("nav.inbox")} · ${t("inbox.unreadCount", { count: unread })}` : t("nav.inbox")}
        >
          <IconBell />
          {unread > 0 && <span className="inbox-badge">{unread}</span>}
        </a>
        <LanguageToggle />
      </div>
    </header>
  );
}
