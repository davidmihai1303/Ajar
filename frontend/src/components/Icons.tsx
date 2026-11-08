// Outline icons (1.5 px stroke). Decorative: always paired with a text label.
import type { ReactNode } from "react";

const Svg = ({ children, size = 20 }: { children: ReactNode; size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    {children}
  </svg>
);

export const IconDashboard = () => (
  <Svg>
    <rect x="3" y="3" width="7" height="9" rx="1" />
    <rect x="14" y="3" width="7" height="5" rx="1" />
    <rect x="14" y="12" width="7" height="9" rx="1" />
    <rect x="3" y="16" width="7" height="5" rx="1" />
  </Svg>
);
export const IconDevices = () => (
  <Svg>
    <rect x="2" y="4" width="14" height="10" rx="2" />
    <path d="M6 18h6" />
    <rect x="18" y="8" width="4" height="12" rx="1" />
  </Svg>
);
export const IconHistory = () => (
  <Svg>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 7v5l3 2" />
  </Svg>
);
export const IconAsk = () => (
  <Svg>
    <path d="M21 12a8 8 0 0 1-11.6 7.1L4 20l1-4.6A8 8 0 1 1 21 12z" />
  </Svg>
);
export const IconPlus = () => (
  <Svg>
    <path d="M12 5v14M5 12h14" />
  </Svg>
);
export const IconWifi = ({ size }: { size?: number }) => (
  <Svg size={size}>
    <path d="M2 9a15 15 0 0 1 20 0" />
    <path d="M5 12.5a10 10 0 0 1 14 0" />
    <path d="M8.5 16a5 5 0 0 1 7 0" />
    <path d="M12 19.5h.01" />
  </Svg>
);
export const IconUpload = () => (
  <Svg size={26}>
    <path d="M12 16V4M7 9l5-5 5 5" />
    <path d="M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3" />
  </Svg>
);
export const IconBell = () => (
  <Svg>
    <path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9" />
    <path d="M10.3 21a1.9 1.9 0 0 0 3.4 0" />
  </Svg>
);
export const IconShield = () => (
  <Svg size={24}>
    <path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z" />
    <path d="m9 12 2 2 4-4" />
  </Svg>
);
export const IconShieldX = () => (
  <Svg size={26}>
    <path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z" />
    <path d="m9.5 9.5 5 5M14.5 9.5l-5 5" />
  </Svg>
);
export const IconLock = () => (
  <Svg size={24}>
    <rect x="4" y="10" width="16" height="11" rx="2" />
    <path d="M8 10V7a4 4 0 0 1 8 0v3" />
  </Svg>
);
export const IconTerminal = () => (
  <Svg size={26}>
    <rect x="3" y="4" width="18" height="16" rx="2" />
    <path d="m7 9 3 3-3 3M13 15h4" />
  </Svg>
);
export const IconTrash = () => (
  <Svg size={24}>
    <path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3" />
  </Svg>
);
export const IconChevron = ({ open }: { open?: boolean }) => (
  <Svg size={18}>
    <path d={open ? "m6 15 6-6 6 6" : "m6 9 6 6 6-6"} />
  </Svg>
);
export const IconSidebar = () => (
  <Svg>
    <rect x="3" y="4" width="18" height="16" rx="2" />
    <path d="M9 4v16" />
  </Svg>
);
export const IconSend = () => (
  <Svg>
    <path d="M12 19V5M5 12l7-7 7 7" />
  </Svg>
);
export const IconAlert = () => (
  <Svg>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 8v5M12 16.5h.01" />
  </Svg>
);

export const IconRefresh = ({ size = 20 }: { size?: number }) => (
  <Svg size={size}>
    <path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
    <path d="M3 3v5h5" />
    <path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16" />
    <path d="M21 21v-5h-5" />
  </Svg>
);

export const IconDownload = ({ size = 20 }: { size?: number }) => (
  <Svg size={size}>
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
    <polyline points="7 10 12 15 17 10" />
    <line x1="12" y1="15" x2="12" y2="3" />
  </Svg>
);

const DEVICE_PATHS: Record<string, ReactNode> = {
  camera: (
    <>
      <rect x="3" y="7" width="13" height="10" rx="2" />
      <path d="m16 11 5-3v8l-5-3" />
    </>
  ),
  router: (
    <>
      <rect x="3" y="13" width="18" height="7" rx="2" />
      <path d="M7 13V9M17 13V9M7 16.5h.01" />
    </>
  ),
  iot: (
    <>
      <path d="M3 11 12 4l9 7v9H3z" />
      <path d="M10 20v-5h4v5" />
    </>
  ),
  tv: (
    <>
      <rect x="2" y="4" width="20" height="13" rx="2" />
      <path d="M8 21h8" />
    </>
  ),
  laptop: (
    <>
      <rect x="4" y="5" width="16" height="11" rx="2" />
      <path d="M2 19h20" />
    </>
  ),
  phone: (
    <>
      <rect x="7" y="2" width="10" height="20" rx="2" />
      <path d="M11 18h2" />
    </>
  ),
  printer: (
    <>
      <path d="M6 9V3h12v6" />
      <rect x="3" y="9" width="18" height="8" rx="2" />
      <path d="M6 14h12v7H6z" />
    </>
  ),
  server: (
    <>
      <rect x="3" y="3" width="18" height="8" rx="2" />
      <rect x="3" y="13" width="18" height="8" rx="2" />
      <path d="M7 7h.01M7 17h.01" />
    </>
  ),
};
DEVICE_PATHS.nas = DEVICE_PATHS.server;
DEVICE_PATHS.pc = DEVICE_PATHS.laptop;

export function DeviceIcon({ type, size = 22 }: { type: string; size?: number }) {
  const paths = DEVICE_PATHS[type];
  return (
    <span className="device-icon" style={{ width: size + 18, height: size + 18 }}>
      {paths ? <Svg size={size}>{paths}</Svg> : <span aria-hidden="true" style={{ fontWeight: 600 }}>?</span>}
    </span>
  );
}
