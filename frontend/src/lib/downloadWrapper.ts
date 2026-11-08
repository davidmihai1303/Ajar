/**
 * Direct download for the Ajar Linux executable.
 * Downloads the self-contained Ajar Linux application launcher.
 */
export function downloadAjarLinux(): void {
  const link = document.createElement("a");
  link.href = "/Ajar";
  link.setAttribute("download", "Ajar");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

export const downloadDesktopWrapper = downloadAjarLinux;
