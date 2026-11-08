// Ajar desktop app for Ubuntu (Electron).
//
// It is a shell around the Ajar web app that already runs on this computer (Docker, 127.0.0.1:8001):
// - the main window shows that app; closing it keeps Ajar running in the tray;
// - a tray icon opens the window, shows a test notification, toggles "start at login" and quits;
// - notifications are normal system notifications, with Ajar's picture as their icon;
// - on first start it adds itself to "start at login", so it is in the tray after every login.
// It never runs scans or nmap itself, and it only loads pages from the local Ajar app.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { app, BrowserWindow, Menu, Notification, Tray, ipcMain, nativeImage, net, session, shell } = require("electron");

const APP_URL = new URL(process.env.AJAR_URL || "http://127.0.0.1:8001/");
const LOCAL_HOSTS = new Set(["127.0.0.1", "localhost"]);
if (!LOCAL_HOSTS.has(APP_URL.hostname) || !["http:", "https:"].includes(APP_URL.protocol)) {
  throw new Error("AJAR_URL must point to the Ajar app on this computer (127.0.0.1 or localhost).");
}
const ORIGIN = APP_URL.origin;
const START_HIDDEN = process.argv.includes("--hidden");

const TEXT = {
  ro: {
    open: "Deschide Ajar",
    test: "Arată o notificare de test",
    login: "Pornește odată cu calculatorul",
    quit: "Ieșire",
    testTitle: "Ajar: notificare de test",
    testBody: "Așa te anunț când o scanare găsește ceva nou. Apasă pe notificare ca să vezi detaliile.",
    trayTitle: "Ajar rămâne în bara de sistem",
    trayBody: "Am închis fereastra, dar te anunț în continuare. Mă găsești la iconița Ajar.",
  },
  en: {
    open: "Open Ajar",
    test: "Show a test notification",
    login: "Start when the computer starts",
    quit: "Quit",
    testTitle: "Ajar: test notification",
    testBody: "This is how I tell you when a scan finds something new. Click the notification to see the details.",
    trayTitle: "Ajar stays in the tray",
    trayBody: "I closed the window, but I keep watching. You can find me at the Ajar icon.",
  },
};

let mainWindow = null;
const shownNotifications = new Set(); // kept referenced so a click still reaches us
let tray = null;
let quitting = false;
let lang = "ro";
let retryTimer = null;

const asset = (name) => path.join(__dirname, "assets", name);
const text = () => TEXT[lang] ?? TEXT.ro;
const settingsFile = () => path.join(app.getPath("userData"), "settings.json");

function readSettings() {
  try {
    return JSON.parse(fs.readFileSync(settingsFile(), "utf8"));
  } catch {
    return {};
  }
}

function writeSettings(values) {
  try {
    fs.mkdirSync(path.dirname(settingsFile()), { recursive: true });
    fs.writeFileSync(settingsFile(), JSON.stringify({ ...readSettings(), ...values }));
  } catch {
    /* settings are a convenience */
  }
}

// ---- start at login (freedesktop autostart: ~/.config/autostart/ajar.desktop)

const autostartFile = () => path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config"), "autostart", "ajar.desktop");
const launchCommand = () => process.env.APPIMAGE || process.execPath;

function autostartEnabled() {
  return fs.existsSync(autostartFile());
}

function setAutostart(enabled) {
  writeSettings({ autostartChosen: true });
  try {
    if (!enabled) return fs.rmSync(autostartFile(), { force: true });
    fs.mkdirSync(path.dirname(autostartFile()), { recursive: true });
    const exec = `"${launchCommand().replace(/(["\\$`])/g, "\\$1")}" --hidden`;
    fs.writeFileSync(
      autostartFile(),
      ["[Desktop Entry]", "Type=Application", "Name=Ajar", "Comment=Local network security checker",
        `Exec=${exec}`, "Icon=ajar", "Terminal=false", "X-GNOME-Autostart-enabled=true", ""].join("\n"),
    );
  } catch {
    /* the tray menu shows the real state */
  }
}

// ---- main window

function isLocalUrl(value) {
  try {
    return new URL(value).origin === ORIGIN;
  } catch {
    return false;
  }
}

function lockDown(win) {
  // Only the local Ajar app may be shown inside; any other link opens in the normal browser.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//.test(url) && !isLocalUrl(url)) void shell.openExternal(url);
    return { action: "deny" };
  });
  win.webContents.on("will-navigate", (event, url) => {
    if (!isLocalUrl(url) && !url.startsWith("file://")) event.preventDefault();
  });
}

async function appReachable() {
  try {
    const response = await net.fetch(new URL("/api/history", ORIGIN).toString(), { cache: "no-store" });
    return response.status < 500;
  } catch {
    return false;
  }
}

async function loadApp() {
  clearTimeout(retryTimer);
  if (!mainWindow) return;
  if (await appReachable()) {
    await mainWindow.loadURL(APP_URL.toString()).catch(() => undefined);
  } else {
    await mainWindow.loadFile(path.join(__dirname, "offline.html")).catch(() => undefined);
    retryTimer = setTimeout(loadApp, 3000);
  }
}

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 860,
    minWidth: 900,
    minHeight: 600,
    show: false,
    title: "Ajar",
    icon: asset("icon.png"),
    backgroundColor: "#faf8f5",
    autoHideMenuBar: true,
    // backgroundThrottling off: the window usually sits hidden in the tray and still watches for scans.
    webPreferences: { preload: path.join(__dirname, "preload.js"), contextIsolation: true, sandbox: true, nodeIntegration: false, backgroundThrottling: false },
  });
  lockDown(mainWindow);
  mainWindow.webContents.on("did-fail-load", (_event, _code, _description, url, isMainFrame) => {
    if (isMainFrame && isLocalUrl(url)) void loadApp();
  });
  mainWindow.once("ready-to-show", () => {
    if (!START_HIDDEN) mainWindow.show();
  });
  mainWindow.on("close", (event) => {
    if (quitting) return;
    event.preventDefault();
    mainWindow.hide();
    if (!readSettings().trayHintShown) {
      writeSettings({ trayHintShown: true });
      showNotification({ title: text().trayTitle, body: text().trayBody });
    }
  });
  void loadApp();
}

function showMain() {
  if (!mainWindow) createMainWindow();
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show();
  mainWindow.focus();
}

// ---- notifications: normal system notifications; Ajar's picture is the icon

function showNotification({ title, body }) {
  if (!Notification.isSupported()) return;
  const notification = new Notification({ title, body, icon: nativeImage.createFromPath(asset("icon.png")) });
  const forget = () => shownNotifications.delete(notification);
  shownNotifications.add(notification);
  notification.on("click", () => {
    forget();
    showMain();
  });
  notification.on("close", forget);
  notification.show();
}

// Notices come from the Ajar page; accept only plain, short text from our own pages.
function cleanNotice(raw) {
  if (!raw || typeof raw !== "object") return null;
  const clip = (value, max) => (typeof value === "string" ? value.slice(0, max) : "");
  const notice = {
    title: clip(raw.title, 160),
    body: clip(raw.body, 600),
  };
  return notice.title || notice.body ? notice : null;
}

const fromOurPage = (event) => isLocalUrl(event.senderFrame?.url ?? "");

ipcMain.on("ajar:notify", (event, raw) => {
  if (!fromOurPage(event)) return;
  const notice = cleanNotice(raw);
  if (notice) showNotification(notice);
});
ipcMain.on("ajar:lang", (event, value) => {
  if (!fromOurPage(event) || (value !== "ro" && value !== "en") || value === lang) return;
  lang = value;
  writeSettings({ lang });
  buildTrayMenu();
});

// ---- tray

function trayImage() {
  const image = nativeImage.createFromPath(asset("tray.png"));
  return image.isEmpty() ? nativeImage.createFromPath(asset("icon.png")).resize({ width: 24, height: 24 }) : image;
}

function buildTrayMenu() {
  if (!tray) return;
  const t = text();
  tray.setToolTip("Ajar");
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: t.open, click: showMain },
      { label: t.test, click: () => showNotification({ title: t.testTitle, body: t.testBody }) },
      { type: "separator" },
      { label: t.login, type: "checkbox", checked: autostartEnabled(), click: (item) => setAutostart(item.checked) },
      { type: "separator" },
      { label: t.quit, click: () => { quitting = true; app.quit(); } },
    ]),
  );
}

function createTray() {
  tray = new Tray(trayImage());
  tray.on("click", showMain);
  buildTrayMenu();
}

// ---- start

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", showMain);
  app.whenReady().then(() => {
    // Ajar's pages need no camera, microphone, location or OS notifications.
    session.defaultSession.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
    lang = readSettings().lang === "en" ? "en" : "ro";
    if (app.isPackaged && !readSettings().autostartChosen) setAutostart(true);
    createTray();
    createMainWindow();
  });
  app.on("before-quit", () => {
    quitting = true;
  });
  app.on("window-all-closed", () => {
    /* stay in the tray */
  });
}
