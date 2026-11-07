// Pure helpers over a scan: who is most dangerous, what to fix first, which mascot state to show.
import type { AjarState } from "../components/AjarMascot";
import type { Device, Finding, HistoryItem, Scan, Severity } from "../api/types";

export const SEVERITY_RANK: Record<Severity, number> = { high: 3, medium: 2, low: 1, info: 0 };

export function previousComparable(items: HistoryItem[], current: Scan | HistoryItem): HistoryItem | undefined {
  if (current.source !== "live" || !current.network_id || !current.findings_available || current.score === null) return;
  const index = items.findIndex((item) => item.id === current.id);
  if (index < 0) return;
  return items.slice(index + 1).find((item) => item.source === "live" && item.network_id === current.network_id &&
    item.findings_available && item.score !== null);
}

export function assessment(scan: Scan | null): Severity | "clear" | "unknown" {
  if (!scan || scan.score === null || scan.error || !scan.findings_available) return "unknown";
  let worst: Severity | null = null;
  for (const finding of scan.findings) {
    if (!worst || SEVERITY_RANK[finding.severity] > SEVERITY_RANK[worst]) worst = finding.severity;
  }
  return worst ?? "clear";
}

export function mascotState(level: ReturnType<typeof assessment>): AjarState {
  if (level === "unknown") return "unknown";
  if (level === "clear") return "locked";
  if (level === "high") return "wide";
  return "ajar";
}

const ipNumber = (ip: string) => ip.split(".").reduce((total, part) => total * 256 + Number(part), 0);

export const byIp = (a: { ip: string }, b: { ip: string }) => ipNumber(a.ip) - ipNumber(b.ip);

export const bySeverity = (a: Finding, b: Finding) =>
  SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.points - a.points || (a.port ?? 1e6) - (b.port ?? 1e6) || a.code.localeCompare(b.code);

export interface DeviceRisk {
  device: Device;
  findings: Finding[];
  points: number;
  worst: Severity | null;
}

export function deviceRisks(scan: Scan): DeviceRisk[] {
  return scan.devices.map((device) => {
    const findings = scan.findings.filter((item) => item.ip === device.ip).sort(bySeverity);
    return {
      device,
      findings,
      points: findings.reduce((sum, item) => sum + item.points, 0),
      worst: findings[0]?.severity ?? null,
    };
  });
}

export const byDanger = (a: DeviceRisk, b: DeviceRisk) =>
  b.points - a.points || (b.worst ? SEVERITY_RANK[b.worst] : -1) - (a.worst ? SEVERITY_RANK[a.worst] : -1) || byIp(a.device, b.device);

/** The device that costs the most points, and its worst finding: the jury's "what do I do first?". */
export function fixFirst(scan: Scan): DeviceRisk | null {
  const risky = deviceRisks(scan).filter((risk) => risk.findings.length > 0).sort(byDanger);
  return risky[0] ?? null;
}

export function severityCounts(scan: Scan): Record<Severity, number> {
  const counts: Record<Severity, number> = { high: 0, medium: 0, low: 0, info: 0 };
  scan.findings.forEach((item) => (counts[item.severity] += 1));
  return counts;
}

export const isUnknownDevice = (device: Device) => !device.vendor && !device.hostname;
