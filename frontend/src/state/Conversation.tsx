// The Ask conversation lives here, not in the Ask page, so it survives moving between pages:
// leaving Ask neither clears the messages nor cancels an answer that is still being written.
// It belongs to one scan (opening another scan starts over) and is kept in memory only.
import { createContext, useContext, useEffect, useRef, useState, type Dispatch, type MutableRefObject,
  type ReactNode, type SetStateAction } from "react";
import { useApp } from "./AppState";

export interface ChatMessage {
  question: string;
  answer?: string;
  muted?: boolean;
  retry?: boolean;
}

interface Conversation {
  messages: ChatMessage[];
  setMessages: Dispatch<SetStateAction<ChatMessage[]>>;
  /** Index of the message whose answer is being written, or null. */
  sending: number | null;
  setSending: Dispatch<SetStateAction<number | null>>;
  /** The request in flight; aborted only when the scan changes or the assistant is turned off. */
  active: MutableRefObject<AbortController | null>;
}

const Ctx = createContext<Conversation | null>(null);

export function useConversation(): Conversation {
  const value = useContext(Ctx);
  if (!value) throw new Error("useConversation outside ConversationProvider");
  return value;
}

export function ConversationProvider({ children }: { children: ReactNode }) {
  const { scan, aiConsent } = useApp();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [sending, setSending] = useState<number | null>(null);
  const active = useRef<AbortController | null>(null);

  const stop = () => {
    active.current?.abort();
    active.current = null;
    setSending(null);
  };

  // A conversation belongs to one scan: start over when another scan is opened.
  const scanId = scan?.id ?? null;
  const shownScan = useRef<string | null>(scanId);
  useEffect(() => {
    if (shownScan.current === scanId) return;
    shownScan.current = scanId;
    stop();
    setMessages([]);
  }, [scanId]);

  // Turning the assistant off (here or in another browser tab) discards a pending reply.
  useEffect(() => {
    if (aiConsent !== true && active.current) stop();
  }, [aiConsent]);

  // Leaving the app altogether cancels the request.
  useEffect(() => () => active.current?.abort(), []);

  return <Ctx.Provider value={{ messages, setMessages, sending, setSending, active }}>{children}</Ctx.Provider>;
}
