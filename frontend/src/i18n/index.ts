// Tiny i18n helper: t(key, vars) using ro.json / en.json, language kept in app state.
import en from "./en.json";
import ro from "./ro.json";
import type { Lang } from "../api/types";

type Dict = Record<string, string>;
const DICTS: Record<Lang, Dict> = { ro, en };

export type TFunction = (key: string, vars?: Record<string, string | number>) => string;

export function makeT(lang: Lang): TFunction {
  return (key, vars) => {
    const template = DICTS[lang][key] ?? DICTS.ro[key] ?? key;
    if (!vars) return template;
    return template.replace(/\{(\w+)\}/g, (match, name: string) => (name in vars ? String(vars[name]) : match));
  };
}

export function formatDate(iso: string, lang: Lang, withTime = true): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(lang === "ro" ? "ro-RO" : "en-GB", {
    day: "numeric",
    month: "short",
    ...(withTime ? { hour: "2-digit", minute: "2-digit" } : {}),
  });
}
