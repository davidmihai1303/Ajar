"""Outdated-version list and version parsing (FR-06).

Specific outdated list:
1. vsftpd 2.3.4 (known backdoor)
2. OpenSSH below 7.4 (parse versions like 8.4p1 Debian 5+deb11u3)
3. Apache httpd <= 2.2.x
4. Microsoft IIS <= 7.5
5. Samba <= 3.x
"""
from __future__ import annotations

import re
from typing import Optional, Tuple


def parse_version_tuple(version_str: str) -> Optional[Tuple[int, ...]]:
    """Parse major, minor, patch from version strings like '8.4p1 Debian 5+deb11u3' -> (8, 4)."""
    if not version_str:
        return None
    m = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", version_str.strip())
    if not m:
        return None
    parts = [int(p) for p in m.groups() if p is not None]
    return tuple(parts)


def check_outdated_service(service_name: str, product: str, version: str) -> Optional[str]:
    """Check if service version is on the official outdated list.

    Returns evidence string if outdated, or None.
    """
    p_lower = (product or "").lower()
    v_str = (version or "").strip()
    s_lower = (service_name or "").lower()

    if not v_str and not p_lower:
        return None

    # 1. vsftpd 2.3.4
    if "vsftpd" in p_lower or (s_lower == "ftp" and "vsftpd" in p_lower):
        if v_str == "2.3.4" or "2.3.4" in v_str:
            return f"vsftpd {v_str} (known backdoor)"

    # 2. OpenSSH below 7.4
    if "openssh" in p_lower or (s_lower == "ssh" and "openssh" in p_lower):
        vt = parse_version_tuple(v_str)
        if vt:
            major = vt[0]
            minor = vt[1] if len(vt) > 1 else 0
            if (major, minor) < (7, 4):
                return f"OpenSSH {v_str} is below 7.4"

    # 3. Apache httpd <= 2.2.x
    if "apache" in p_lower and ("http" in s_lower or "httpd" in p_lower):
        vt = parse_version_tuple(v_str)
        if vt:
            major = vt[0]
            minor = vt[1] if len(vt) > 1 else 0
            if (major, minor) <= (2, 2):
                return f"Apache httpd {v_str} <= 2.2.x"

    # 4. Microsoft IIS <= 7.5
    if "iis" in p_lower or "microsoft iis" in p_lower:
        vt = parse_version_tuple(v_str)
        if vt:
            major = vt[0]
            minor = vt[1] if len(vt) > 1 else 0
            if (major, minor) <= (7, 5):
                return f"Microsoft IIS {v_str} <= 7.5"

    # 5. Samba <= 3.x
    if "samba" in p_lower or s_lower in {"microsoft-ds", "netbios-ssn"} and "samba" in p_lower:
        vt = parse_version_tuple(v_str)
        if vt:
            major = vt[0]
            if major <= 3:
                return f"Samba {v_str} <= 3.x"

    return None
