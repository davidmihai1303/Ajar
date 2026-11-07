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

async function checkedResponse(path: string, init?: RequestInit): Promise<Response> {
  const response = await fetch(path, { headers: { Accept: "application/json" }, ...init });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const detail = body?.detail ?? body;
    const ro = detail?.reason_ro ?? detail?.ro;
    const en = detail?.reason_en ?? detail?.en;
    const refusal = typeof ro === "string" && typeof en === "string" ? { reason_ro: ro, reason_en: en } : null;
    throw new ApiError(typeof detail === "string" ? detail : response.statusText, response.status, refusal);
  }
  return response;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await checkedResponse(path, init);
  if (!response.headers.get("content-type")?.includes("application/json")) throw new ApiError("Not JSON", response.status);
  return response.json();
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
  network: async (): Promise<NetworkInfo> => {
    const info = demo ? demoNetwork : await request<NetworkInfo>("/api/network");
    if (!info.interface || !info.subnet) throw new ApiError("Incomplete network", 502);
    return { interface: info.interface, subnet: info.subnet, gateway: info.gateway || null, ssid: info.ssid || null };
  },

  history: (): Promise<HistoryItem[]> => (demo ? Promise.resolve(demoHasHistory ? demoHistory() : []) : request("/api/history")),

  scan: (id: string): Promise<Scan> =>
    demo ? Promise.resolve(demoScans.find((scan) => scan.id === id) ?? demoScans[0]) : request(`/api/scans/${encodeURIComponent(id)}`),

  diff: (fromId: string, toId: string): Promise<ScanDiff> =>
    demo
      ? Promise.resolve(demoDiff(fromId, toId))
      : request(`/api/history/diff?from=${encodeURIComponent(fromId)}&to=${encodeURIComponent(toId)}`),

  startScan: async (expectedNetwork: NetworkInfo): Promise<Scan> => {
    if (demo) {
      await wait(6000);
      demoHasHistory = true;
      return demoScans[0];
    }
    return request("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ confirm: true, expected_network: expectedNetwork }),
    });
  },

  importFiles: async (files: File[]): Promise<ImportResult[]> => {
    if (demo) throw new ApiError("Import requires the local analysis API", 503);
    const form = new FormData();
    files.forEach((file) => form.append("files", file));
    return request("/api/scans/import", { method: "POST", body: form });
  },

  deleteHistory: async (): Promise<void> => {
    if (demo) {
      demoHasHistory = false;
      return;
    }
    await checkedResponse("/api/history", { method: "DELETE" });
  },

  explain: (code: string, lang: Lang): Promise<Explanation> =>
    demo ? Promise.resolve(demoExplanation(code, lang)) : request(`/api/explain/${encodeURIComponent(code)}?lang=${lang}`),

  ask: (scanId: string, question: string, lang: Lang, signal?: AbortSignal): Promise<AskResponse> =>
    demo
      ? Promise.resolve({ available: false, can_answer: false, answer: null })
      : request("/api/ask", {
          method: "POST",
          signal,
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          body: JSON.stringify({ scan_id: scanId, question, lang }),
        }),
};
