// One device, its problems and how to fix them (jury check #3).
import { deviceRisks, isUnknownDevice } from "../lib/scan";
import { href } from "../router";
import { useApp } from "../state/AppState";
import { useDeviceName } from "../components/DeviceCard";
import FindingCard from "../components/FindingCard";
import { DeviceIcon } from "../components/Icons";
import { SeverityBadge } from "../components/ScoreBadge";

export default function DeviceDetail({ ip }: { ip: string }) {
  const { t, scan } = useApp();
  const deviceName = useDeviceName();
  const risk = scan ? deviceRisks(scan).find((item) => item.device.ip === ip) : undefined;

  if (!risk) {
    return (
      <div className="page">
        <a href={href({ name: "devices" })}>‹ {t("nav.devices")}</a>
        <p>{t("device.notFound", { ip })}</p>
      </div>
    );
  }
  const { device, findings, points, worst } = risk;
  const unknown = isUnknownDevice(device);
  const name = unknown ? t("device.unknownTitle") : deviceName(device.device_type);

  return (
    <div className="page">
      <a href={href({ name: "devices" })} className="back">
        ‹ {t("nav.devices")}
      </a>
      <header className="row">
        <DeviceIcon type={unknown ? "unknown" : device.device_type} size={28} />
        <div className="grow">
          <h1 className="serif h1">{name}</h1>
          <p className="muted">
            {[device.vendor, device.hostname, t("device.findings", { count: findings.length })].filter(Boolean).join(" · ")}
          </p>
        </div>
        {worst ? <SeverityBadge severity={worst} /> : <span className="chip sev-ok">✓ {t("device.ok")}</span>}
        <span className="muted">{t("finding.points", { points })}</span>
      </header>

      {findings.length === 0 && <p className="card">{t("device.noFindings")}</p>}
      {findings.map((finding) => (
        <FindingCard key={`${finding.code}-${finding.port}`} finding={finding} deviceName={name} />
      ))}

      <details className="card tech-card">
        <summary className="strong">{t("device.technical")}</summary>
        <div className="row muted tech-facts">
          <span>IP {device.ip}</span>
          <span>MAC {device.mac_masked ?? "—"}</span>
          {device.hostname && (
            <span>
              {t("device.hostname")} {device.hostname}
            </span>
          )}
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>{t("port.port")}</th>
                <th>{t("port.protocol")}</th>
                <th>{t("port.service")}</th>
                <th>{t("port.version")}</th>
                <th>{t("port.title")}</th>
              </tr>
            </thead>
            <tbody>
              {device.ports.map((port) => (
                <tr key={`${port.protocol}-${port.port}`}>
                  <td>{port.port}</td>
                  <td>{port.protocol.toUpperCase()}</td>
                  <td>
                    {port.service ?? "—"}
                    {port.tunnel === "ssl" ? " (ssl)" : ""}
                  </td>
                  <td>{[port.product, port.version].filter(Boolean).join(" ") || "—"}</td>
                  <td>{port.http_title ?? "—"}</td>
                </tr>
              ))}
              {device.ports.length === 0 && (
                <tr>
                  <td colSpan={5}>{t("device.noPorts")}</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}
