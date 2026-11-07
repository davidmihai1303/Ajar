// RO / EN switch. Everything the user sees is available in both languages.
import { useApp } from "../state/AppState";

export default function LanguageToggle() {
  const { lang, setLang, t } = useApp();
  return (
    <div className="segmented" role="group" aria-label={t("lang.label")}>
      {(["ro", "en"] as const).map((code) => (
        <button key={code} type="button" className={lang === code ? "on" : ""} aria-pressed={lang === code} onClick={() => setLang(code)}>
          {code.toUpperCase()}
        </button>
      ))}
    </div>
  );
}
