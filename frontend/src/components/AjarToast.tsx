// Notification popup: the text on the left, Ajar on the right with all his animations.
// Ajar starts calm and then reacts to the news (the door opens, or the lock drops in).
import { useEffect, useRef, useState } from "react";
import type { AjarNotice } from "../lib/desktop";
import { mascotState } from "../lib/scan";
import AjarMascot, { type AjarState } from "./AjarMascot";

const SHOW_MS = 9000;

interface Props {
  notice: AjarNotice;
  labels: { open: string; close: string; mascot: string };
  onOpen: () => void;
  onClose: () => void;
  standalone?: boolean;
}

export default function AjarToast({ notice, labels, onOpen, onClose, standalone = false }: Props) {
  const [state, setState] = useState<AjarState>("shut");
  const [hovered, setHovered] = useState(false);
  const close = useRef(onClose);
  close.current = onClose;

  useEffect(() => {
    setState("shut");
    const react = window.setTimeout(() => setState(mascotState(notice.level)), 450);
    return () => window.clearTimeout(react);
  }, [notice.id, notice.level]);

  useEffect(() => {
    if (hovered) return;
    const timer = window.setTimeout(() => close.current(), SHOW_MS);
    return () => window.clearTimeout(timer);
  }, [notice.id, hovered]);

  return (
    <div
      className={`ajar-toast level-${notice.level}${standalone ? " standalone" : ""}`}
      role="status"
      aria-live="polite"
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <div className="ajar-toast-text">
        <strong className="ajar-toast-title">{notice.title}</strong>
        <p className="ajar-toast-body">{notice.body}</p>
        <button type="button" className="link-button ajar-toast-open" onClick={onOpen}>
          {labels.open}
        </button>
      </div>
      <div className="ajar-toast-mascot">
        <AjarMascot state={state} label={labels.mascot} />
      </div>
      <button type="button" className="ajar-toast-close" onClick={onClose} aria-label={labels.close}>
        ×
      </button>
    </div>
  );
}
