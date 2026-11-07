// Consent before a live scan: shows the detected network, requires "this network is mine",
// Cancel has default focus so confirming is never the default action.
import PermissionDialog from "./PermissionDialog";

export default function ConfirmScanDialog({ onConfirm, onCancel }: { onConfirm: () => void; onCancel: () => void }) {
  return <PermissionDialog kind="consent" onAccept={onConfirm} onCancel={onCancel} />;
}
