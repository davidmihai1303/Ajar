// One device row: icon, friendly name, vendor, worst severity, points lost.
// Technical details (IP, masked MAC, open ports) open on demand.
import type { DeviceRisk } from "../lib/scan";
import { isUnknownDevice } from "../lib/scan";
import { href } from "../router";
import { useApp } from "../state/AppState";
import { DeviceIcon } from "./Icons";
import { SeverityBadge } from "./ScoreBadge";

export function useDeviceName() {
  const { t } = useApp();
  return (type: string) => {
    const key = `device.type.${type}`;
    const name = t(key);
    return name === key ? t("device.type.unknown") : name;
  };
}

export default function DeviceCard({ risk, open = false }: { risk: DeviceRisk; open?: boolean }) {
  const { t } = useApp();
  const deviceName = useDeviceName();
  const { device, findings, points, worst } = risk;
  const unknown = isUnknownDevice(device);

  return (
    <details className="device-row" open={open}>
      <summary>
        <DeviceIcon type={unknown ? "unknown" : device.device_type} />
        <span className="device-name">
          <span className="strong">
            {unknown ? t("device.unknownTitle") : deviceName(device.device_type)}
            {unknown && <span className="tag">{t("device.unknownTag")}</span>}
          </span>
          <span className="muted">{device.vendor ?? device.hostname ?? t("device.noVendor")}</span>
        </span>
        {worst ? <SeverityBadge severity={worst} /> : <span className="chip sev-ok">✓ {t("device.ok")}</span>}
        <span className="device-points muted">{points > 0 ? `−${points}` : "0"}</span>
      </summary>
      <div className="device-details">
        <span>IP {device.ip}</span>
        <span>MAC {device.mac_masked ?? "—"}</span>
        {device.hostname && <span>{t("device.hostname")} {device.hostname}</span>}
        <span>
          {t("device.ports")}{" "}
          {device.ports.length ? device.ports.map((port) => `${port.port}/${port.service ?? "?"}`).join(", ") : "—"}
        </span>
        <span>{t("device.findings", { count: findings.length })}</span>
        <a href={href({ name: "device", ip: device.ip })} className="push-right">
          {t("common.open")}
        </a>
      </div>
    </details>
  );
}
