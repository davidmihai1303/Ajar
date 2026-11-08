import { useEffect, useState } from "react";

/**
 * Returns true if the client is on a mobile viewport or mobile device.
 */
export function useIsMobile(breakpoint = 768): boolean {
  const [isMobile, setIsMobile] = useState(() => {
    if (typeof window === "undefined") return false;
    const isSmall = window.innerWidth <= breakpoint;
    const isMobileUA = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(
      navigator.userAgent
    );
    const hasParam =
      window.location.search.toLowerCase().includes("mobile") ||
      window.location.hash.toLowerCase().includes("mobile");
    return isSmall || isMobileUA || hasParam;
  });

  useEffect(() => {
    const check = () => {
      const isSmall = window.innerWidth <= breakpoint;
      const isMobileUA = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(
        navigator.userAgent
      );
      const hasParam =
        window.location.search.toLowerCase().includes("mobile") ||
        window.location.hash.toLowerCase().includes("mobile");
      setIsMobile(isSmall || isMobileUA || hasParam);
    };
    window.addEventListener("resize", check);
    window.addEventListener("hashchange", check);
    return () => {
      window.removeEventListener("resize", check);
      window.removeEventListener("hashchange", check);
    };
  }, [breakpoint]);

  return isMobile;
}

