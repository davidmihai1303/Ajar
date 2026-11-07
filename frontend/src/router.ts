// Minimal hash router: #/dashboard, #/devices, #/devices/<ip>, #/scan, #/history, #/ask.
import { useEffect, useState } from "react";

export type Route =
  | { name: "home" }
  | { name: "dashboard" }
  | { name: "devices" }
  | { name: "device"; ip: string }
  | { name: "scan" }
  | { name: "history" }
  | { name: "ask" };

export function parseRoute(hash: string): Route {
  const parts = hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  switch (parts[0]) {
    case "dashboard":
      return { name: "dashboard" };
    case "devices":
      return parts[1] ? { name: "device", ip: decodeURIComponent(parts[1]) } : { name: "devices" };
    case "scan":
      return { name: "scan" };
    case "history":
      return { name: "history" };
    case "ask":
      return { name: "ask" };
    default:
      return { name: "home" };
  }
}

export const href = (route: Route): string => {
  if (route.name === "device") return `#/devices/${encodeURIComponent(route.ip)}`;
  if (route.name === "home") return "#/";
  return `#/${route.name}`;
};

export const navigate = (route: Route) => {
  window.location.hash = href(route);
};

export function useRoute(): Route {
  const [route, setRoute] = useState(() => parseRoute(window.location.hash));
  useEffect(() => {
    const onChange = () => setRoute(parseRoute(window.location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}
