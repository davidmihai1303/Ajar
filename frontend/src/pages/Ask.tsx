// Optional local Q&A grounded only in the current scan.
import { Fragment, useEffect, useRef, useState, type FormEvent } from "react";
import { api } from "../api/client";
import type { ModelStatus } from "../api/types";
import { formatDate } from "../i18n";
import { useRoute } from "../router";
import { useApp } from "../state/AppState";
import ErrorBanner from "../components/ErrorBanner";
import { IconSend } from "../components/Icons";
import PermissionDialog from "../components/PermissionDialog";

interface Message {
  question: string;
  answer?: string;
  muted?: boolean;
  retry?: boolean;
}

const SUGGESTIONS = ["ask.s1", "ask.s2", "ask.s3"];

export default function Ask() {
  const { t, lang, scan, aiConsent, setAiConsent } = useApp();
  const [messages, setMessages] = useState<Message[]>([]);
  const [question, setQuestion] = useState("");
  const [error, setError] = useState(false);
  const [sending, setSending] = useState<number | null>(null);
  const busy = sending !== null;
  const [askConsent, setAskConsent] = useState(false);
  const [pending, setPending] = useState<string | null>(null);
  const hasEvidence = !!scan && scan.findings_available && scan.score !== null && !scan.error;
  const [status, setStatus] = useState<ModelStatus | null>(null);
  const [unloadFailed, setUnloadFailed] = useState(false);
  const active = useRef<AbortController | null>(null);
  useEffect(() => () => active.current?.abort(), []);
  useEffect(() => {
    if (aiConsent !== true && active.current) {
      active.current.abort();
      active.current = null;
      setSending(null);
    }
  }, [aiConsent]);

  useEffect(() => {
    if (aiConsent !== true || !hasEvidence) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    async function refresh() {
      try {
        const info = await api.modelStatus(controller.signal);
        if (!controller.signal.aborted) setStatus(info);
      } catch { /* The question itself handles a disconnected API. */ }
      if (busy && !controller.signal.aborted) timer = setTimeout(refresh, 750);
    }
    void refresh();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [aiConsent, hasEvidence, busy]);

  const unload = async () => {
    try {
      await api.unloadModel();
      setUnloadFailed(false);
    } catch { setUnloadFailed(true); }
  };

  const turnOff = () => {
    active.current?.abort();
    active.current = null;
    setSending(null);
    setPending(null);
    setAskConsent(false);
    setAiConsent(false);
    if (aiConsent === true) void unload();
  };

  const send = async (text: string, consented = false, retryIndex?: number) => {
    if (!scan || !hasEvidence || active.current || (aiConsent === false && !consented)) return;
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
    const index = retryIndex ?? messages.length;
    if (retryIndex === undefined) {
      setQuestion("");
      setMessages(list => [...list, { question: trimmed }]);
    } else {
      setMessages(list => list.map((m, i) => i === index ? { question: trimmed } : m));
    }
    setSending(index);
    const reply = (answer: string, muted: boolean, retry: boolean) => {
      if (!controller.signal.aborted) {
        setMessages(list => list.map((m, i) => i === index ? { ...m, answer, muted, retry } : m));
      }
    };
    try {
      const answer = await api.ask(scan.id, trimmed, lang, controller.signal);
      if (controller.signal.aborted) return;
      let message = answer.answer ?? t(answer.available ? "ask.cannotAnswer" : "ask.off");
      if (!answer.available) {
        const info = await api.modelStatus(controller.signal).catch(() => null);
        if (info?.reason) message = t("ask.failure." + info.reason);
      }
      reply(message, !answer.can_answer, !answer.available);
    } catch {
      reply(t("ask.off"), true, true);
    } finally {
      if (active.current === controller) {
        active.current = null;
        setSending(null);
      }
    }
  };

  const route = useRoute();
  const initialQueryHandled = useRef<string | null>(null);

  useEffect(() => {
    if (route.name === "ask" && route.query && initialQueryHandled.current !== route.query) {
      initialQueryHandled.current = route.query;
      const initialText = route.query;
      setQuestion(initialText);
      const timer = window.setTimeout(() => {
        if (aiConsent === true) {
          void send(initialText, true);
        } else {
          setPending(initialText);
          setAskConsent(true);
        }
      }, 50);
      return () => {
        window.clearTimeout(timer);
      };
    }
  }, [route, aiConsent]);

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
      {scan && !hasEvidence && <p className="muted">{t("ask.noEvidence")}</p>}
      {aiConsent === true && status && !status.available && !status.state && <p className="muted">{t("ask.modelOffline")}</p>}
      {aiConsent === false && unloadFailed && <p role="status">{t("ask.unloadFailed")} <button type="button" onClick={() => void unload()}>{t("common.retry")}</button></p>}
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
        {messages.map((message, index) => (
          <Fragment key={index}>
            <p className="bubble-user">{message.question}</p>
            {message.answer && <p className={`bubble-ajar${message.muted ? " muted" : ""}`}>
              {message.answer}{" "}
              {message.retry && aiConsent === true && <button type="button" className="link-button"
                disabled={busy} onClick={() => void send(message.question, false, index)}>{t("common.retry")}</button>}
            </p>}
            {sending === index && <p className="bubble-ajar muted">
              {t(status?.state === "starting" ? "ask.starting" : "ask.thinking")}
            </p>}
          </Fragment>
        ))}
      </div>

      <form className="composer-wrap" onSubmit={submit}>
        <div className="row">
          {SUGGESTIONS.map((key) => (
            <button key={key} type="button" className="pill" onClick={() => void send(t(key))} disabled={!hasEvidence || busy || aiConsent === false}>
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
            disabled={!hasEvidence || aiConsent === false}
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
          <button type="submit" className="icon-button primary" aria-label={t("ask.send")} disabled={!hasEvidence || busy || aiConsent === false}>
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
              const toSend = pending;
              setPending(null);
              window.setTimeout(() => {
                void send(toSend, true);
              }, 50);
            }
          }}
        />
      )}
    </div>
  );
}
