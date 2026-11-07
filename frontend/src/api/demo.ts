// Demo data, used only when the backend is not reachable (the UI says so in a banner).
// Values follow the catalog rules so the screens show realistic findings and scores.
import type { Device, Explanation, Finding, HistoryItem, Lang, NetworkInfo, Scan, ScanDiff } from "./types";

export const demoNetwork: NetworkInfo = {
  ssid: "RSH-07",
  interface: "wlan0",
  subnet: "172.20.10.0/28",
  gateway: "172.20.10.1",
};

const router: Device = {
  ip: "172.20.10.1",
  mac_masked: "50:C7:BF:xx:xx:xx",
  vendor: "TP-Link",
  hostname: "gateway",
  device_type: "router",
  ports: [
    { port: 53, protocol: "tcp", service: "domain", product: "dnsmasq", version: "2.80", http_title: null, tunnel: null },
    { port: 80, protocol: "tcp", service: "http", product: null, version: null, http_title: "TP-Link Router Login", tunnel: null },
    { port: 443, protocol: "tcp", service: "http", product: null, version: null, http_title: "TP-Link Router Login", tunnel: "ssl" },
    { port: 1900, protocol: "udp", service: "upnp", product: "MiniUPnP", version: "1.8", http_title: null, tunnel: null },
  ],
};
const camera: Device = {
  ip: "172.20.10.5",
  mac_masked: "A4:14:37:xx:xx:xx",
  vendor: "Hikvision",
  hostname: "ipcam-living",
  device_type: "camera",
  ports: [
    { port: 80, protocol: "tcp", service: "http", product: "Hikvision IP camera httpd", version: null, http_title: "Web Login", tunnel: null },
    { port: 554, protocol: "tcp", service: "rtsp", product: "Hikvision 7513 rtspd", version: null, http_title: null, tunnel: null },
    { port: 8000, protocol: "tcp", service: "http", product: null, version: null, http_title: null, tunnel: null },
  ],
};
const hub: Device = {
  ip: "172.20.10.6",
  mac_masked: "24:0A:C4:xx:xx:xx",
  vendor: "Espressif",
  hostname: null,
  device_type: "iot",
  ports: [{ port: 1883, protocol: "tcp", service: "mqtt", product: "Mosquitto", version: null, http_title: null, tunnel: null }],
};
const unknown: Device = {
  ip: "172.20.10.9",
  mac_masked: null,
  vendor: null,
  hostname: null,
  device_type: "unknown",
  ports: [{ port: 8080, protocol: "tcp", service: "http-proxy", product: null, version: null, http_title: null, tunnel: null }],
};
const tv: Device = {
  ip: "172.20.10.7",
  mac_masked: "8C:79:F5:xx:xx:xx",
  vendor: "Samsung",
  hostname: "living-tv",
  device_type: "tv",
  ports: [
    { port: 8008, protocol: "tcp", service: "http", product: null, version: null, http_title: null, tunnel: null },
    { port: 8009, protocol: "tcp", service: "ajp13", product: null, version: null, http_title: null, tunnel: null },
  ],
};
const laptop: Device = {
  ip: "172.20.10.2",
  mac_masked: "F0:18:98:xx:xx:xx",
  vendor: "Apple",
  hostname: "laptop-maria",
  device_type: "laptop",
  ports: [],
};
const oldServer: Device = {
  ip: "172.20.10.3",
  mac_masked: "00:1B:21:xx:xx:xx",
  vendor: "Intel",
  hostname: "server-vechi",
  device_type: "server",
  ports: [{ port: 23, protocol: "tcp", service: "telnet", product: "BusyBox telnetd", version: null, http_title: null, tunnel: null }],
};

const f = (code: string, severity: Finding["severity"], points: number, ip: string, port: number | null, protocol: Finding["protocol"], evidence: string): Finding => ({
  code,
  severity,
  points,
  ip,
  port,
  protocol,
  evidence,
});

const routerFindings = [
  f("HTTP_ADMIN_CLEARTEXT", "medium", 10, "172.20.10.1", 80, "tcp", 'http · title "TP-Link Router Login" · no ssl'),
  f("UPNP_EXPOSED", "medium", 10, "172.20.10.1", 1900, "udp", "upnp · MiniUPnP 1.8"),
];
const hubFinding = f("MQTT_EXPOSED", "medium", 10, "172.20.10.6", 1883, "tcp", "mqtt · Mosquitto");
const unknownFinding = f("UNKNOWN_DEVICE", "low", 5, "172.20.10.9", null, null, "no vendor · no hostname · 1 open port");
const cameraFindings = [
  f("CAMERA_STREAM_EXPOSED", "high", 20, "172.20.10.5", 554, "tcp", "rtsp · Hikvision 7513 rtspd"),
  f("HTTP_ADMIN_CLEARTEXT", "medium", 10, "172.20.10.5", 80, "tcp", 'http · title "Web Login" · no ssl'),
];
const telnetFinding = f("TELNET_OPEN", "high", 20, "172.20.10.3", 23, "tcp", "telnet · BusyBox telnetd");

const score = (findings: Finding[]) => Math.max(0, 100 - findings.reduce((sum, item) => sum + item.points, 0));

const build = (id: string, created_at: string, source: Scan["source"], file: string, devices: Device[], findings: Finding[]): Scan => ({
  id,
  created_at,
  source,
  file,
  network_id: source === "live" ? "demo-hotspot" : null,
  findings_available: true,
  ssid: "RSH-07",
  subnet: "172.20.10.0/28",
  score: score(findings),
  error: null,
  devices,
  findings,
});

export const demoScans: Scan[] = [
  build("demo-4", "2026-11-07T14:32:00", "live", "scan_2026-11-07_1432.xml", [router, laptop, camera, hub, tv, unknown], [...routerFindings, ...cameraFindings, hubFinding, unknownFinding]),
  build("demo-3", "2026-11-06T18:05:00", "live", "scan_2026-11-06_1805.xml", [router, laptop, hub, tv, unknown], [...routerFindings, hubFinding, unknownFinding]),
  build("demo-2", "2026-11-04T11:20:00", "import", "lab_after.xml", [{ ...router, ports: router.ports.filter((p) => p.port === 53) }, laptop, { ...oldServer, ports: [] }], []),
  build("demo-1", "2026-11-03T10:02:00", "import", "lab_before.xml", [router, laptop, oldServer], [...routerFindings, telnetFinding]),
];

export const demoHistory = (): HistoryItem[] =>
  demoScans.map((scan) => ({
    id: scan.id,
    created_at: scan.created_at,
    source: scan.source,
    file: scan.file,
    findings_available: scan.findings_available, network_id: scan.network_id, subnet: scan.subnet, error: scan.error,
    ssid: scan.ssid,
    score: scan.score,
    device_count: scan.devices.length,
    finding_count: scan.findings.length,
  }));

const portKey = (ip: string, port: { port: number; protocol: string }) => `${ip}/${port.protocol}/${port.port}`;
const findingKey = (item: Finding) => `${item.ip}/${item.port ?? ""}/${item.code}`;

/** Compares two scans by IP, the same way history/diff.py is specified to. */
export function demoDiff(fromId: string, toId: string): ScanDiff {
  const from = demoScans.find((scan) => scan.id === fromId)!;
  const to = demoScans.find((scan) => scan.id === toId)!;
  const ips = (scan: Scan) => new Set(scan.devices.map((device) => device.ip));
  const ports = (scan: Scan) =>
    new Map(scan.devices.flatMap((device) => device.ports.map((port) => [portKey(device.ip, port), { ip: device.ip, port: port.port, protocol: port.protocol, service: port.service }] as const)));
  const findings = (scan: Scan) => new Map(scan.findings.map((item) => [findingKey(item), item] as const));
  const [fromIps, toIps] = [ips(from), ips(to)];
  const [fromPorts, toPorts] = [ports(from), ports(to)];
  const [fromFindings, toFindings] = [findings(from), findings(to)];
  return {
    from_id: fromId,
    to_id: toId,
    score_before: from.score,
    score_after: to.score,
    devices_added: [...toIps].filter((ip) => !fromIps.has(ip)),
    devices_removed: [...fromIps].filter((ip) => !toIps.has(ip)),
    ports_opened: [...toPorts].filter(([key]) => !fromPorts.has(key)).map(([, value]) => value),
    ports_closed: [...fromPorts].filter(([key]) => !toPorts.has(key)).map(([, value]) => value),
    findings_resolved: [...fromFindings].filter(([key]) => !toFindings.has(key)).map(([, value]) => value),
    findings_new: [...toFindings].filter(([key]) => !fromFindings.has(key)).map(([, value]) => value),
  };
}

type Text = Omit<Explanation, "code" | "lang">;
const TEXTS: Record<string, Record<Lang, Text>> = {
  CAMERA_STREAM_EXPOSED: {
    ro: {
      title: "Serviciul video al camerei este accesibil în rețea",
      explanation: "Scanarea a găsit serviciul prin care camera transmite imagini. Nu a verificat dacă accesul la imagini cere o parolă.",
      steps: ["Deschide setările camerei.", "Verifică cine poate vedea fluxul video.", "Dacă folosești fluxul, cere o parolă pentru acces. Altfel, dezactivează-l."],
    },
    en: {
      title: "The camera’s video service is reachable on the network",
      explanation: "The scan found the service the camera uses to stream video. It did not check whether viewing the stream requires a password.",
      steps: ["Open the camera settings.", "Check who can view the stream.", "If you use the stream, require a password. Otherwise, turn it off."],
    },
  },
  HTTP_ADMIN_CLEARTEXT: {
    ro: {
      title: "Pagina de setări se deschide fără criptare",
      explanation: "Pagina de setări folosește HTTP. Dacă introduci o parolă aici, cineva din rețea ar putea să o citească.",
      steps: ["Intră în setările dispozitivului.", "Activează HTTPS.", "Oprește accesul prin HTTP simplu."],
    },
    en: {
      title: "The settings page is not encrypted",
      explanation: "The settings page uses plain HTTP. If you enter a password here, someone on the network could read it.",
      steps: ["Open the device settings.", "Turn on HTTPS.", "Turn off plain HTTP access."],
    },
  },
  UPNP_EXPOSED: {
    ro: {
      title: "Routerul poate deschide singur uși spre internet",
      explanation: "Funcția UPnP lasă aplicațiile să deschidă porturi fără să te întrebe. Un program rău intenționat ar putea folosi asta.",
      steps: ["Intră în setările routerului.", "Caută opțiunea UPnP.", "Dezactiveaz-o și salvează."],
    },
    en: {
      title: "The router can open doors to the internet by itself",
      explanation: "UPnP lets apps open ports without asking you. A malicious program could use that.",
      steps: ["Open the router settings.", "Find the UPnP option.", "Turn it off and save."],
    },
  },
  MQTT_EXPOSED: {
    ro: {
      title: "Serviciul de mesaje al hubului este accesibil în rețea",
      explanation: "Scanarea a găsit MQTT, serviciul prin care dispozitivele inteligente schimbă mesaje. Nu a verificat cine poate trimite comenzi.",
      steps: ["Deschide setările MQTT ale hubului.", "Verifică ce dispozitive au voie să trimită mesaje.", "Dacă accesul anonim este permis, dezactivează-l."],
    },
    en: {
      title: "The hub’s messaging service is reachable on the network",
      explanation: "The scan found MQTT, the service smart devices use to exchange messages. It did not check who can send commands.",
      steps: ["Open the hub’s MQTT settings.", "Check which devices can send messages.", "If anonymous access is allowed, turn it off."],
    },
  },
  UNKNOWN_DEVICE: {
    ro: {
      title: "Un dispozitiv pe care nu îl recunosc",
      explanation: "Nu are producător cunoscut și nici nume, dar are o ușă deschisă. Verifică dacă e al tău.",
      steps: ["Uită-te în lista de dispozitive conectate a routerului.", "Dacă nu îl recunoști, schimbă parola Wi-Fi-ului."],
    },
    en: {
      title: "A device I don't recognise",
      explanation: "It has no known maker and no name, but it has an open door. Check that it's yours.",
      steps: ["Look at the router's list of connected devices.", "If you don't recognise it, change your Wi-Fi password."],
    },
  },
  TELNET_OPEN: {
    ro: {
      title: "Conectare de la distanță fără criptare",
      explanation: "Telnet trimite parolele în clar prin rețea. Oricine ascultă le poate citi.",
      steps: ["Intră în setările dispozitivului.", "Oprește Telnet.", "Dacă ai nevoie de acces de la distanță, folosește SSH."],
    },
    en: {
      title: "Remote login without encryption",
      explanation: "Telnet sends passwords in plain text. Anyone listening can read them.",
      steps: ["Open the device settings.", "Turn off Telnet.", "If you need remote access, use SSH instead."],
    },
  },
};

export function demoExplanation(code: string, lang: Lang): Explanation {
  const text = TEXTS[code]?.[lang] ?? {
    title: code,
    explanation: lang === "ro" ? "Explicația pentru această problemă nu e disponibilă în modul demonstrativ." : "This explanation isn't available in demo mode.",
    steps: [],
  };
  return { code, lang, ...text };
}
