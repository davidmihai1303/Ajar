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
    return isSmall || isMobileUA;
  });

  useEffect(() => {
    const check = () => {
      const isSmall = window.innerWidth <= breakpoint;
      const isMobileUA = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(
        navigator.userAgent
      );
      setIsMobile(isSmall || isMobileUA);
    };
    window.addEventListener("resize", check);
    return () => window.removeEventListener("resize", check);
  }, [breakpoint]);

  return isMobile;
}
