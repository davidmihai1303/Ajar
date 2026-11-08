// Notification inbox. Messages are derived from data the app already has (scan history and the
// changes between two scans of the same network), so nothing new is stored on the server.
// Which messages are read is a per-browser convenience kept in localStorage.
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api } from "../api/client";
import type { Finding, ScanDiff, Severity } from "../api/types";
import { previousComparable } from "../lib/scan";
import { useApp } from "./AppState";

export type InboxKind = "scan" | "scanError" | "newFinding" | "resolved" | "newDevice";

export interface InboxItem {
  id: string;
  kind: InboxKind;
  createdAt: string;
  scanId: string;
  severity?: Severity;
  score?: number | null;
  delta?: number | null;
  ip?: string;
  finding?: Finding;
}

interface InboxValue {
  items: InboxItem[];
  unread: number;
  isRead: (id: string) => boolean;
  setRead: (id: string, read: boolean) => void;
  markAll: (read: boolean) => void;
}

const READ_KEY = "ajar.inbox.read";
const MAX_SCANS = 10;

const loadRead = (): Set<string> => {
  try {
    const raw = window.localStorage.getItem(READ_KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : [];
    return new Set(Array.isArray(parsed) ? parsed.filter((value): value is string => typeof value === "string") : []);
  } catch {
    return new Set();
  }
};

const saveRead = (read: Set<string>) => {
  try {
    window.localStorage.setItem(READ_KEY, JSON.stringify([...read]));
  } catch {
    /* read state lasts for this visit only */
  }
};

const findingId = (scanId: string, kind: string, finding: Finding) =>
  `${scanId}:${kind}:${finding.ip}:${finding.code}:${finding.protocol ?? ""}:${finding.port ?? ""}`;

function diffItems(diff: ScanDiff, createdAt: string): InboxItem[] {
  const scanId = diff.to_id;
  return [
    ...diff.findings_new.map((finding) => ({
      id: findingId(scanId, "new", finding),
      kind: "newFinding" as const,
      createdAt,
      scanId,
      severity: finding.severity,
      ip: finding.ip,
      finding,
    })),
    ...diff.devices_added.map((ip) => ({ id: `${scanId}:device:${ip}`, kind: "newDevice" as const, createdAt, scanId, ip })),
    ...diff.findings_resolved.map((finding) => ({
      id: findingId(scanId, "resolved", finding),
      kind: "resolved" as const,
      createdAt,
      scanId,
      severity: finding.severity,
      ip: finding.ip,
      finding,
    })),
  ];
}

const InboxContext = createContext<InboxValue | null>(null);

export function InboxProvider({ children }: { children: ReactNode }) {
  const { history } = useApp();
  const [read, setReadState] = useState<Set<string>>(loadRead);
  const [diffs, setDiffs] = useState<Record<string, ScanDiff>>({});

  const recent = useMemo(() => history.slice(0, MAX_SCANS), [history]);

  // Changes between each live scan and the previous scan of the same network.
  useEffect(() => {
    let alive = true;
    const pairs = recent
      .map((item) => ({ item, previous: previousComparable(history, item) }))
      .filter((pair) => pair.previous);
    Promise.all(
      pairs.map(({ item, previous }) =>
        api.diff(previous!.id, item.id).then(
          (diff) => [item.id, diff] as const,
          () => null,
        ),
      ),
    ).then((results) => {
      if (!alive) return;
      const next: Record<string, ScanDiff> = {};
      results.forEach((result) => {
        if (result) next[result[0]] = result[1];
      });
      setDiffs(next);
    });
    return () => {
      alive = false;
    };
  }, [recent, history]);

  const items = useMemo(() => {
    const list: InboxItem[] = [];
    recent.forEach((item) => {
      const previous = previousComparable(history, item);
      const diff = diffs[item.id];
      if (diff && diff.from_id === previous?.id) list.push(...diffItems(diff, item.created_at));
      list.push(
        item.error || item.score === null
          ? { id: `${item.id}:scan`, kind: "scanError", createdAt: item.created_at, scanId: item.id }
          : {
              id: `${item.id}:scan`,
              kind: "scan",
              createdAt: item.created_at,
              scanId: item.id,
              score: item.score,
              delta: previous && previous.score !== null ? item.score - previous.score : null,
            },
      );
    });
    return list;
  }, [recent, history, diffs]);

  const update = useCallback((change: (next: Set<string>) => void) => {
    setReadState((current) => {
      const next = new Set(current);
      change(next);
      saveRead(next);
      return next;
    });
  }, []);

  const value = useMemo<InboxValue>(
    () => ({
      items,
      unread: items.filter((item) => !read.has(item.id)).length,
      isRead: (id) => read.has(id),
      setRead: (id, value) => update((next) => (value ? next.add(id) : next.delete(id))),
      markAll: (value) => update((next) => items.forEach((item) => (value ? next.add(item.id) : next.delete(item.id)))),
    }),
    [items, read, update],
  );

  return <InboxContext.Provider value={value}>{children}</InboxContext.Provider>;
}

export function useInbox(): InboxValue {
  const value = useContext(InboxContext);
  if (!value) throw new Error("useInbox must be used inside InboxProvider");
  return value;
}
