// Recognised references per catalog code: CIS Controls v8 safeguards and the OWASP IoT Top 10 (2018).
// Display only. These never change findings, severities or scores (those come from analysis/catalog.py).
export interface Reference {
  id: string; // e.g. "CIS 4.8", "OWASP IoT I2"
  name: string; // official English title of the safeguard or category
}

const CIS = {
  "1.1": "Establish and Maintain Detailed Enterprise Asset Inventory",
  "1.2": "Address Unauthorized Assets",
  "2.2": "Ensure Authorized Software is Currently Supported",
  "3.3": "Configure Data Access Control Lists",
  "3.10": "Encrypt Sensitive Data in Transit",
  "4.2": "Establish and Maintain a Secure Configuration Process for Network Infrastructure",
  "4.4": "Implement and Manage a Firewall on Servers",
  "4.5": "Implement and Manage a Firewall on End-User Devices",
  "4.7": "Manage Default Accounts on Enterprise Assets and Software",
  "4.8": "Uninstall or Disable Unnecessary Services on Enterprise Assets and Software",
  "7.4": "Perform Automated Application Patch Management",
} as const;

const OWASP_IOT = {
  I1: "Weak, Guessable, or Hardcoded Passwords",
  I2: "Insecure Network Services",
  I3: "Insecure Ecosystem Interfaces",
  I4: "Lack of Secure Update Mechanism",
  I5: "Use of Insecure or Outdated Components",
  I6: "Insufficient Privacy Protection",
  I7: "Insecure Data Transfer and Storage",
  I8: "Lack of Device Management",
  I9: "Insecure Default Settings",
} as const;

type CisId = keyof typeof CIS;
type IotId = keyof typeof OWASP_IOT;

const MAP: Record<string, { cis: CisId[]; iot: IotId[] }> = {
  TELNET_OPEN: { cis: ["4.8", "3.10"], iot: ["I2", "I7"] },
  RDP_EXPOSED: { cis: ["4.8", "4.5"], iot: ["I2"] },
  VNC_EXPOSED: { cis: ["4.8", "4.5"], iot: ["I2"] },
  DB_EXPOSED: { cis: ["4.4", "3.3"], iot: ["I2"] },
  CAMERA_STREAM_EXPOSED: { cis: ["4.8", "3.3"], iot: ["I2", "I6"] },
  OUTDATED_SERVICE: { cis: ["7.4", "2.2"], iot: ["I5", "I4"] },
  FTP_CLEARTEXT: { cis: ["3.10", "4.8"], iot: ["I7", "I2"] },
  HTTP_ADMIN_CLEARTEXT: { cis: ["3.10"], iot: ["I3", "I7"] },
  SMB_EXPOSED: { cis: ["4.8", "3.3"], iot: ["I2"] },
  MQTT_EXPOSED: { cis: ["4.8", "3.10"], iot: ["I3", "I2"] },
  UPNP_EXPOSED: { cis: ["4.2", "4.8"], iot: ["I9", "I2"] },
  SNMP_EXPOSED: { cis: ["4.2", "4.7"], iot: ["I9", "I8"] },
  PRINTER_RAW_EXPOSED: { cis: ["4.8"], iot: ["I2"] },
  UNKNOWN_DEVICE: { cis: ["1.1", "1.2"], iot: ["I8"] },
  SSH_OPEN: { cis: ["4.8"], iot: ["I1"] },
};

export function referencesFor(code: string): Reference[] {
  const entry = MAP[code];
  if (!entry) return [];
  return [
    ...entry.cis.map((id) => ({ id: `CIS ${id}`, name: CIS[id] })),
    ...entry.iot.map((id) => ({ id: `OWASP IoT ${id}`, name: OWASP_IOT[id] })),
  ];
}
