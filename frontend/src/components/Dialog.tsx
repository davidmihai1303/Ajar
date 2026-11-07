// Modal with a blurred backdrop. While it is open, Ajar walks over to stand beside it
// (AppState counts open dialogs; AjarDock animates to the "dialog" placement).
import { useEffect, useRef, type ReactNode } from "react";
import { useApp } from "../state/AppState";

interface Props {
  title: string;
  icon?: ReactNode;
  children: ReactNode;
  onCancel: () => void;
  actions: ReactNode;
  role?: "dialog" | "alertdialog";
}

export default function Dialog({ title, icon, children, onCancel, actions, role = "dialog" }: Props) {
  const { openDialog } = useApp();
  const panel = useRef<HTMLDivElement>(null);
  const cancel = useRef(onCancel);
  cancel.current = onCancel;

  useEffect(() => openDialog(), [openDialog]);

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    // The safe choice (cancel) gets focus, so confirming is never the default action.
    panel.current?.querySelector<HTMLElement>("[data-autofocus]")?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") cancel.current();
      if (event.key === "Tab" && panel.current) {
        const focusable = panel.current.querySelectorAll<HTMLElement>("button, a[href], input, textarea, select");
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      previous?.focus();
    };
  }, []);

  return (
    <div className="overlay">
      <div ref={panel} className="dialog" role={role} aria-modal="true" aria-labelledby="dialog-title">
        {icon && <div className="dialog-icon">{icon}</div>}
        <h2 id="dialog-title" className="serif dialog-title">
          {title}
        </h2>
        {children}
        <div className="dialog-actions">{actions}</div>
      </div>
    </div>
  );
}
