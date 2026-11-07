/**
 * Direct download for the NetCheck Desktop Companion Wrapper installer.
 * Downloads the self-contained NetCheck_Desktop_Setup.bat file.
 */
export function downloadDesktopWrapper(): void {
  const link = document.createElement("a");
  link.href = "/NetCheck_Desktop_Setup.bat";
  link.setAttribute("download", "NetCheck_Desktop_Setup.bat");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}
