// Minimal hash router: #/dashboard, #/devices, #/devices/<ip>, #/scan, #/history, #/ask, #/report, #/widget, #/inbox, #/toast (desktop app popup).
import { useEffect, useState } from "react";

export type Route =
  | { name: "home" }
  | { name: "dashboard" }
  | { name: "devices" }
  | { name: "device"; ip: string }
  | { name: "scan" }
  | { name: "history" }
  | { name: "ask"; query?: string; draft?: string }
  | { name: "report" }
  | { name: "widget" }
  | { name: "toast" }
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
      return { name: "ask", query: search.get("q") ?? undefined, draft: search.get("draft") ?? undefined };
    case "report":
      return { name: "report" };
    case "widget":
      return { name: "widget" };
    case "toast":
      return { name: "toast" };
    case "inbox":
      return { name: "inbox" };
    default:
      return { name: "home" };
  }
}

export const href = (route: Route): string => {
  if (route.name === "device") return `#/devices/${encodeURIComponent(route.ip)}`;
  if (route.name === "home") return "#/";
  if (route.name === "ask" && route.query) return `#/ask?q=${encodeURIComponent(route.query)}`;
  // A draft is only written into the chat box; the user reads it and sends it.
  if (route.name === "ask" && route.draft) return `#/ask?draft=${encodeURIComponent(route.draft)}`;
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
