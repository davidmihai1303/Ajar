// The only bridge between the Ajar web UI and the desktop app. The page gets a few functions,
// never Node.js or Electron itself (contextIsolation + sandbox).
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("ajarDesktop", {
  isDesktop: true,
  notify: (notice) => ipcRenderer.send("ajar:notify", notice),
  setLang: (lang) => ipcRenderer.send("ajar:lang", lang),
});
