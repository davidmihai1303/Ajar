// Everything on the network, riskiest first. Technical details open per row.
import { useState } from "react";
import { byDanger, byIp, deviceRisks, SEVERITY_RANK, type DeviceRisk } from "../lib/scan";
import { useApp } from "../state/AppState";
import DeviceCard from "../components/DeviceCard";

type Sort = "danger" | "ip" | "severity";

const sorters: Record<Sort, (a: DeviceRisk, b: DeviceRisk) => number> = {
  danger: byDanger,
  ip: (a, b) => byIp(a.device, b.device),
  severity: (a, b) => (b.worst ? SEVERITY_RANK[b.worst] : -1) - (a.worst ? SEVERITY_RANK[a.worst] : -1) || byDanger(a, b),
};

export default function Devices() {
  const { t, scan } = useApp();
  const [sort, setSort] = useState<Sort>("danger");
  if (!scan) return null;
  const risks = deviceRisks(scan).sort(sorters[sort]);

  return (
    <div className="page">
      <div className="row spread end">
        <div>
          <h1 className="serif h1">{t("devices.title")}</h1>
          <p className="muted">{t("devices.count", { count: scan.devices.length })}</p>
        </div>
        <div className="segmented" role="group" aria-label={t("devices.sort")}>
          {(["danger", "ip", "severity"] as const).map((key) => (
            <button key={key} type="button" className={sort === key ? "on" : ""} aria-pressed={sort === key} onClick={() => setSort(key)}>
              {t(`devices.sort.${key}`)}
            </button>
          ))}
        </div>
      </div>
      <div className="list-card">
        {risks.map((risk, index) => (
          <DeviceCard key={risk.device.ip} risk={risk} open={index === 0 && sort === "danger" && risk.findings.length > 0} />
        ))}
      </div>
    </div>
  );
}
