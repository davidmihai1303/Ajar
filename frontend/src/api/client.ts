// Typed fetch helpers for /api/* (network, scans, history, explain, ask).
// When the backend can't be reached the app switches to demo data and says so on screen.
import { demoDiff, demoExplanation, demoHistory, demoNetwork, demoScans } from "./demo";
import type { AskResponse, Explanation, HistoryItem, ImportResult, Lang, NetworkInfo, Scan, ScanDiff, ScanRefusal } from "./proposedTypes";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly refusal: ScanRefusal | null = null,
  ) {
    super(message);
  }
}

let demo = false;
export const isDemo = () => demo;

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { headers: { Accept: "application/json" }, ...init });
  const isJson = (response.headers.get("content-type") ?? "").includes("application/json");
  const body = isJson ? await response.json() : null;
  if (!response.ok) {
    const refusal = body && typeof body.reason_ro === "string" ? (body as ScanRefusal) : null;
    throw new ApiError(body?.detail ?? response.statusText, response.status, refusal);
  }
  if (!isJson) throw new ApiError("Not JSON", response.status);
  return body as T;
}

/** Decides once, at start-up, whether a backend answers. */
export async function connect(): Promise<boolean> {
  try {
    await request<HistoryItem[]>("/api/history");
    demo = false;
  } catch {
    demo = true;
  }
  return !demo;
}

const wait = (ms: number) => new Promise((resolve) => window.setTimeout(resolve, ms));

// Demo only: open the app with ?fresh to start from an empty history (welcome screen first).
// The demo history appears after the first scan and disappears again on "delete my history".
let demoHasHistory = !new URLSearchParams(window.location.search).has("fresh");

export const api = {
  network: (): Promise<NetworkInfo> => (demo ? Promise.resolve(demoNetwork) : request("/api/network")),

  history: (): Promise<HistoryItem[]> => (demo ? Promise.resolve(demoHasHistory ? demoHistory() : []) : request("/api/history")),

  scan: (id: string): Promise<Scan> =>
    demo ? Promise.resolve(demoScans.find((scan) => scan.id === id) ?? demoScans[0]) : request(`/api/scans/${encodeURIComponent(id)}`),

  diff: (fromId: string, toId: string): Promise<ScanDiff> =>
    demo
      ? Promise.resolve(demoDiff(fromId, toId))
      : request(`/api/history/diff?from=${encodeURIComponent(fromId)}&to=${encodeURIComponent(toId)}`),

  /** Live scan through the host agent. The backend only runs it with confirm=true. */
  startScan: async (): Promise<Scan> => {
    if (demo) {
      await wait(6000);
      demoHasHistory = true;
      return demoScans[0];
    }
    return request("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ confirm: true }),
    });
  },

  importFiles: async (files: File[]): Promise<ImportResult[]> => {
    if (demo) {
      await wait(800);
      demoHasHistory = true;
      return Promise.all(
        files.map(async (file) => {
          const text = await file.text();
          const readable = text.includes("<nmaprun") && text.trimEnd().endsWith("</nmaprun>");
          return readable
            ? { file: file.name, scan_id: demoScans[0].id, score: demoScans[0].score, error: null }
            : { file: file.name, scan_id: null, score: null, error: "unreadable" };
        }),
      );
    }
    const form = new FormData();
    files.forEach((file) => form.append("files", file));
    return request("/api/scans/import", { method: "POST", body: form });
  },

  deleteHistory: (): Promise<void> => {
    if (demo) {
      demoHasHistory = false;
      return Promise.resolve();
    }
    return request("/api/history", { method: "DELETE" });
  },

  explain: (code: string, lang: Lang): Promise<Explanation> =>
    demo ? Promise.resolve(demoExplanation(code, lang)) : request(`/api/explain/${encodeURIComponent(code)}?lang=${lang}`),

  ask: (scanId: string, question: string, lang: Lang): Promise<AskResponse> =>
    demo
      ? Promise.resolve({ available: false, can_answer: false, answer: null })
      : request("/api/ask", {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          body: JSON.stringify({ scan_id: scanId, question, lang }),
        }),
};
