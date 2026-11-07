// Pure helpers over a scan: who is most dangerous, what to fix first, which mascot state to show.
import type { AjarState } from "../components/AjarMascot";
import type { Device, Finding, Scan, Severity } from "../api/proposedTypes";

export const SEVERITY_RANK: Record<Severity, number> = { high: 3, medium: 2, low: 1, info: 0 };

export function mascotState(score: number | null | undefined): AjarState {
  if (score === null || score === undefined) return "unknown";
  if (score >= 100) return "locked";
  if (score >= 80) return "shut";
  if (score >= 50) return "ajar";
  return "wide";
}

/** Label key for the score: safe / attention / risky / unknown. */
export function scoreLevel(score: number | null | undefined): "unknown" | "safe" | "attention" | "risky" {
  if (score === null || score === undefined) return "unknown";
  if (score >= 80) return "safe";
  if (score >= 50) return "attention";
  return "risky";
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
