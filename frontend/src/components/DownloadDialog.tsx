// "Download Ajar for Ubuntu": the desktop app files built on this computer, with how to install.
import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { DesktopDownload } from "../lib/desktop";
import { useApp } from "../state/AppState";
import Dialog from "./Dialog";
import { IconDownload } from "./Icons";

const thisArch = (): DesktopDownload["arch"] => (/aarch64|arm64|armv8/i.test(navigator.userAgent) ? "arm64" : "x64");
const megabytes = (bytes: number) => `${Math.round(bytes / 1024 / 1024)} MB`;

export default function DownloadDialog({ onClose }: { onClose: () => void }) {
  const { t } = useApp();
  const [files, setFiles] = useState<DesktopDownload[] | null>(null);
  const arch = thisArch();

  useEffect(() => {
    let alive = true;
    api.downloads().then((list) => alive && setFiles(list));
    return () => {
      alive = false;
    };
  }, []);

  // The .deb for this computer first: it installs Ajar in the app menu and sets up its sandbox.
  const ordered = [...(files ?? [])].sort(
    (a, b) => Number(b.arch === arch) - Number(a.arch === arch) || Number(b.kind === "deb") - Number(a.kind === "deb"),
  );
  const deb = ordered.find((file) => file.kind === "deb");
  const appImage = ordered.find((file) => file.kind === "appimage");

  return (
    <Dialog
      title={t("download.title")}
      icon={<IconDownload />}
      onCancel={onClose}
      actions={
        <button type="button" className="button" data-autofocus onClick={onClose}>
          {t("common.close")}
        </button>
      }
    >
      <p className="dialog-body">{t("download.intro")}</p>
      {files === null ? (
        <p className="muted">{t("common.loading")}</p>
      ) : files.length === 0 ? (
        <p className="banner banner-info">{t("download.none")} <code>desktop/build.sh</code></p>
      ) : (
        <>
          <ul className="download-list">
            {ordered.map((file, index) => (
              <li key={file.name}>
                <a className={`button${index === 0 ? " primary" : ""}`} href={`/downloads/${encodeURIComponent(file.name)}`} download={file.name}>
                  <IconDownload size={16} />
                  {t(file.kind === "deb" ? "download.deb" : "download.appimage", { arch: file.arch === "arm64" ? "ARM64" : "x86-64" })}
                </a>
                <span className="muted">
                  {megabytes(file.size)}
                  {file.arch === arch ? ` · ${t("download.thisComputer")}` : ""}
                </span>
              </li>
            ))}
          </ul>
          <ol className="steps download-steps">
            {deb && (
              <li>
                {t("download.stepDeb")} <code>sudo apt install ./{deb.name}</code>
              </li>
            )}
            {appImage && (
              <li>
                {t("download.stepAppImage")} <code>chmod +x {appImage.name} && ./{appImage.name}</code>
              </li>
            )}
            <li>{t("download.stepTray")}</li>
          </ol>
        </>
      )}
    </Dialog>
  );
}
