// Minimal hash router: #/dashboard, #/devices, #/devices/<ip>, #/scan, #/history, #/ask, #/report, #/widget, #/inbox.
import { useEffect, useState } from "react";

export type Route =
  | { name: "home" }
  | { name: "dashboard" }
  | { name: "devices" }
  | { name: "device"; ip: string }
  | { name: "scan" }
  | { name: "history" }
  | { name: "ask"; query?: string }
  | { name: "report" }
  | { name: "widget" }
  | { name: "inbox" };

export function parseRoute(hash: string): Route {
  const [pathPart, queryPart] = hash.replace(/^#\/?/, "").split("?");
  const parts = pathPart.split("/").filter(Boolean);
  const search = new URLSearchParams(queryPart || "");
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
      return { name: "ask", query: search.get("q") ?? undefined };
    case "report":
      return { name: "report" };
    case "widget":
      return { name: "widget" };
    case "inbox":
      return { name: "inbox" };
    default:
      return { name: "home" };
  }
}

export const href = (route: Route): string => {
  if (route.name === "device") return `#/devices/${encodeURIComponent(route.ip)}`;
  if (route.name === "home") return "#/";
  if (route.name === "ask" && "query" in route && route.query) {
    return `#/ask?q=${encodeURIComponent(route.query)}`;
  }
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
