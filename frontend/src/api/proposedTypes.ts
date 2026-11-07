// PROPOSED API contract for the UI. Not yet agreed with the analysis (P1) and API (P2) owners.
// `types.ts` and `mock.json` are contract files (AGENTS.md, Git workflow §5), so this lives here
// until P1/P2 approve it; then it moves into `types.ts` and mirrors `api/schemas.py`.
// All MAC addresses arrive already masked from the backend.

export type Severity = "high" | "medium" | "low" | "info";
export type Lang = "ro" | "en";

export interface NetworkInfo {
  ssid: string | null;
  interface: string;
  subnet: string; // CIDR, e.g. 172.20.10.0/28
  gateway: string | null;
}

export interface Port {
  port: number;
  protocol: "tcp" | "udp";
  service: string | null;
  product: string | null;
  version: string | null;
  http_title: string | null;
  tunnel: string | null; // "ssl" when the service runs over TLS
}

export interface Device {
  ip: string;
  mac_masked: string | null;
  vendor: string | null;
  hostname: string | null;
  device_type: string; // router, camera, printer, laptop, phone, tv, iot, nas, server, pc, unknown
  ports: Port[]; // open ports only
}

export interface Finding {
  code: string; // official catalog code, e.g. CAMERA_STREAM_EXPOSED
  severity: Severity;
  points: number;
  ip: string;
  port: number | null; // null for UNKNOWN_DEVICE
  protocol: "tcp" | "udp" | null;
  evidence: string; // raw service / version / title, untrusted text
}

export interface Scan {
  id: string;
  created_at: string; // ISO 8601
  source: "live" | "import";
  file: string;
  ssid: string | null;
  subnet: string | null;
  score: number | null; // null when the file could not be read
  error: string | null;
  devices: Device[];
  findings: Finding[];
}

export interface HistoryItem {
  id: string;
  created_at: string;
  source: "live" | "import";
  file: string;
  ssid: string | null;
  score: number | null;
  device_count: number;
  finding_count: number;
}

export interface PortRef {
  ip: string;
  port: number;
  protocol: "tcp" | "udp";
  service: string | null;
}

export interface ScanDiff {
  from_id: string;
  to_id: string;
  score_before: number | null;
  score_after: number | null;
  devices_added: string[];
  devices_removed: string[];
  ports_opened: PortRef[];
  ports_closed: PortRef[];
  findings_resolved: Finding[];
  findings_new: Finding[];
}

export interface Explanation {
  code: string;
  lang: Lang;
  title: string;
  explanation: string; // max 2 sentences
  steps: string[]; // 1–5 ordered fix steps
}

export interface ImportResult {
  file: string;
  scan_id: string | null;
  score: number | null;
  error: string | null;
}

export interface AskResponse {
  available: boolean; // false when the LLM is off or unreachable
  can_answer: boolean; // false when the scan has no evidence for the question
  answer: string | null;
}

/** Body of a 4xx response when the scope guard refuses a scan. */
export interface ScanRefusal {
  reason_ro: string;
  reason_en: string;
}
