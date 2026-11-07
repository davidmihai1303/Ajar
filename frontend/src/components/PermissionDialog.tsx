// Permission and consent dialogs: confirm scan, admin rights, local network, notifications, AI assistant.
import { useEffect, useState, type ReactNode } from "react";
import { useApp } from "../state/AppState";
import Dialog from "./Dialog";
import { IconAsk, IconBell, IconLock, IconShield, IconWifi } from "./Icons";

export type PermissionKind = "consent" | "admin" | "network" | "notify" | "ai";

const ICONS: Record<PermissionKind, ReactNode> = {
  consent: <IconShield />,
  admin: <IconLock />,
  network: <IconWifi size={24} />,
  notify: <IconBell />,
  ai: <IconAsk />,
};

const POINTS: Record<PermissionKind, number> = { consent: 2, admin: 3, network: 3, notify: 2, ai: 3 };
const HAS_NOTE: Record<PermissionKind, boolean> = { consent: false, admin: true, network: true, notify: false, ai: true };

export default function PermissionDialog({ kind, onAccept, onCancel }: { kind: PermissionKind; onAccept: () => void; onCancel: () => void }) {
  const { t, network, setBubble } = useApp();
  // Ajar walks over to the dialog and says why it is asking.
  useEffect(() => {
    setBubble(t(`perm.${kind}.bubble`));
    return () => setBubble(null);
  }, [kind, setBubble, t]);
  const [owned, setOwned] = useState(false);
  const [missing, setMissing] = useState(false);
  const prefix = `perm.${kind}`;

  const accept = () => {
    if (kind === "consent" && !owned) {
      setMissing(true);
      return;
    }
    onAccept();
  };

  return (
    <Dialog
      title={t(`${prefix}.title`)}
      icon={ICONS[kind]}
      onCancel={onCancel}
      actions={
        <>
          <button type="button" className="button" data-autofocus onClick={onCancel}>
            {t(`${prefix}.cancel`)}
          </button>
          <button type="button" className="button primary" onClick={accept}>
            {t(`${prefix}.accept`)}
          </button>
        </>
      }
    >
      <p className="dialog-body">{t(`${prefix}.body`)}</p>

      {kind === "consent" && (
        <dl className="facts">
          <dt>{t("network.wifi")}</dt>
          <dd className="strong">{network?.ssid ?? t("network.unknownName")}</dd>
          <dt>{t("network.subnet")}</dt>
          <dd>{network?.subnet ?? "—"}</dd>
          <dt>{t("network.gateway")}</dt>
          <dd>{network?.gateway ?? "—"}</dd>
        </dl>
      )}

      <ul className="checklist">
        {Array.from({ length: POINTS[kind] }, (_, index) => (
          <li key={index}>
            <span aria-hidden="true">✓</span>
            <span>{t(`${prefix}.point${index + 1}`)}</span>
          </li>
        ))}
      </ul>

      {kind === "consent" && (
        <>
          <label className="check">
            <input
              type="checkbox"
              checked={owned}
              onChange={(event) => {
                setOwned(event.target.checked);
                setMissing(false);
              }}
            />
            <span>{t("perm.consent.owner")}</span>
          </label>
          {missing && (
            <p className="field-error" role="alert">
              {t("perm.consent.ownerMissing")}
            </p>
          )}
        </>
      )}

      {HAS_NOTE[kind] && <p className="muted">{t(`${prefix}.note`)}</p>}
    </Dialog>
  );
}
