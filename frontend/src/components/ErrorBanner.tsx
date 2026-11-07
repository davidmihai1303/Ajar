// Global message slot: agent unreachable, scan failed, demo data, unreadable file.
import type { ReactNode } from "react";

export default function ErrorBanner({ tone = "error", children, action }: { tone?: "error" | "info"; children: ReactNode; action?: ReactNode }) {
  return (
    <div className={`banner banner-${tone}`} role={tone === "error" ? "alert" : "status"}>
      <span className="banner-mark" aria-hidden="true">
        {tone === "error" ? "!" : "i"}
      </span>
      <span className="grow">{children}</span>
      {action}
    </div>
  );
}
