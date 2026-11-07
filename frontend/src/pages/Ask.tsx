// Optional local Q&A grounded only in the current scan.
import { useEffect, useRef, useState, type FormEvent } from "react";
import { api } from "../api/client";
import { formatDate } from "../i18n";
import { useApp } from "../state/AppState";
import ErrorBanner from "../components/ErrorBanner";
import { IconSend } from "../components/Icons";
import PermissionDialog from "../components/PermissionDialog";

interface Message {
  from: "user" | "ajar";
  text: string;
  muted?: boolean;
}

const SUGGESTIONS = ["ask.s1", "ask.s2", "ask.s3"];

export default function Ask() {
  const { t, lang, scan, aiConsent, setAiConsent } = useApp();
  const [messages, setMessages] = useState<Message[]>([]);
  const [question, setQuestion] = useState("");
  const [error, setError] = useState(false);
  const [busy, setBusy] = useState(false);
  const [askConsent, setAskConsent] = useState(false);
  const [pending, setPending] = useState<string | null>(null);
  const active = useRef<AbortController | null>(null);
  useEffect(() => () => active.current?.abort(), []);
  useEffect(() => {
    if (aiConsent !== true && active.current) {
      active.current.abort();
      active.current = null;
      setBusy(false);
    }
  }, [aiConsent]);

  const turnOff = () => {
    active.current?.abort();
    active.current = null;
    setBusy(false);
    setPending(null);
    setAskConsent(false);
    setAiConsent(false);
  };

  const send = async (text: string, consented = false) => {
    if (!scan || active.current || (aiConsent === false && !consented)) return;
    const trimmed = text.trim();
    if (!trimmed) {
      setError(true);
      return;
    }
    if (aiConsent !== true && !consented) {
      setPending(trimmed);
      setAskConsent(true);
      return;
    }
    const controller = new AbortController();
    active.current = controller;
    setQuestion("");
    setMessages((list) => [...list, { from: "user", text: trimmed }]);
    setBusy(true);
    try {
      const answer = await api.ask(scan.id, trimmed, lang, controller.signal);
      if (controller.signal.aborted) return;
      if (!answer.available) {
        setMessages((list) => [...list, { from: "ajar", text: t("ask.off"), muted: true }]);
      } else if (!answer.can_answer || !answer.answer) {
        setMessages((list) => [...list, { from: "ajar", text: t("ask.cannotAnswer"), muted: true }]);
      } else {
        setMessages((list) => [...list, { from: "ajar", text: answer.answer as string }]);
      }
    } catch {
      if (controller.signal.aborted) return;
      setMessages((list) => [...list, { from: "ajar", text: t("ask.off"), muted: true }]);
    } finally {
      if (active.current === controller) {
        active.current = null;
        setBusy(false);
      }
    }
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    void send(question);
  };

  return (
    <div className="page ask">
      <div>
        <h1 className="serif h1">{t("ask.title")}</h1>
        {scan && <p className="muted">{t("ask.about", { date: formatDate(scan.created_at, lang), ssid: scan.ssid ?? t("network.unknownName") })}</p>}
      </div>

      {!scan && <p className="muted">{t("common.noScan")}</p>}
      {aiConsent === true && (
        <button type="button" className="button self-start" onClick={turnOff}>{t("ask.turnOff")}</button>
      )}
      {aiConsent === false && (
        <ErrorBanner
          tone="info"
          action={
            <button type="button" className="link-button" onClick={() => setAskConsent(true)}>
              {t("ask.turnOn")}
            </button>
          }
        >
          {t("ask.declined")}
        </ErrorBanner>
      )}

      <div className="chat" aria-live="polite">
        {messages.map((message, index) =>
          message.from === "user" ? (
            <p key={index} className="bubble-user">
              {message.text}
            </p>
          ) : (
            <p key={index} className={`bubble-ajar${message.muted ? " muted" : ""}`}>
              {message.text}
            </p>
          ),
        )}
        {busy && <p className="bubble-ajar muted">{t("ask.thinking")}</p>}
      </div>

      <form className="composer-wrap" onSubmit={submit}>
        <div className="row">
          {SUGGESTIONS.map((key) => (
            <button key={key} type="button" className="pill" onClick={() => void send(t(key))} disabled={!scan || busy || aiConsent === false}>
              {t(key)}
            </button>
          ))}
        </div>
        <div className="ask-input">
          <label htmlFor="ask-question" className="visually-hidden">
            {t("ask.label")}
          </label>
          <textarea
            id="ask-question"
            disabled={!scan || aiConsent === false}
            rows={2}
            value={question}
            placeholder={t("ask.placeholder")}
            onChange={(event) => {
              setQuestion(event.target.value);
              setError(false);
            }}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                void send(question);
              }
            }}
            aria-invalid={error}
            aria-describedby={error ? "ask-error" : undefined}
          />
          <button type="submit" className="icon-button primary" aria-label={t("ask.send")} disabled={!scan || busy || aiConsent === false}>
            <IconSend />
          </button>
        </div>
        {error && (
          <p id="ask-error" className="field-error">
            {t("ask.empty")}
          </p>
        )}
        <p className="muted center">{t("ask.grounded")}</p>
      </form>

      {askConsent && (
        <PermissionDialog
          kind="ai"
          onCancel={turnOff}
          onAccept={() => {
            setAskConsent(false);
            setAiConsent(true);
            if (pending) {
              // Consent is saved; send the question that was waiting for it.
              void send(pending, true);
              setPending(null);
            }
          }}
        />
      )}
    </div>
  );
}
