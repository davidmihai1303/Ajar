// Optional Q&A grounded only in the current scan. Asks for consent before anything leaves the computer.
import { useState, type FormEvent } from "react";
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
  const [off, setOff] = useState(false);

  const send = async (text: string, consented = false) => {
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
    if (!scan) return;
    setQuestion("");
    setMessages((list) => [...list, { from: "user", text: trimmed }]);
    setBusy(true);
    try {
      const answer = await api.ask(scan.id, trimmed, lang);
      if (!answer.available) {
        setOff(true);
        setMessages((list) => [...list, { from: "ajar", text: t("ask.off"), muted: true }]);
      } else if (!answer.can_answer || !answer.answer) {
        setMessages((list) => [...list, { from: "ajar", text: t("ask.cannotAnswer"), muted: true }]);
      } else {
        setMessages((list) => [...list, { from: "ajar", text: answer.answer as string }]);
      }
    } catch {
      setOff(true);
      setMessages((list) => [...list, { from: "ajar", text: t("ask.off"), muted: true }]);
    } finally {
      setBusy(false);
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
      {off && messages.length === 0 && <ErrorBanner tone="info">{t("ask.off")}</ErrorBanner>}

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
            <button key={key} type="button" className="pill" onClick={() => void send(t(key))} disabled={!scan || busy}>
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
          <button type="submit" className="icon-button primary" aria-label={t("ask.send")} disabled={!scan || busy}>
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
          onCancel={() => {
            setAskConsent(false);
            setPending(null);
            setAiConsent(false);
          }}
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
