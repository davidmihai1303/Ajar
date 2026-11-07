"""Outdated list (vsftpd 2.3.4, OpenSSH<7.4, Apache<=2.2, IIS<=7.5, Samba<=3) + robust version parsing ('8.4p1 Debian…')."""
import re
from typing import Optional, Tuple


def parse_major_minor(version_str: str) -> Optional[Tuple[int, int]]:
    """Extract (major, minor) integers from version string like '8.4p1 Debian 5+deb11u3'."""
    if not version_str:
        return None
    match = re.search(r"(\d+)(?:\.(\d+))?", version_str)
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2)) if match.group(2) is not None else 0
    return major, minor


def is_outdated_service(service_name: str, product: str, version: str) -> bool:
    """Check if the given software version is in the official outdated catalog list.

    Catalog rules:
    - vsftpd 2.3.4
    - OpenSSH < 7.4
    - Apache httpd <= 2.2.x
    - Microsoft IIS <= 7.5
    - Samba <= 3.x
    """
    prod_lower = (product or "").strip().lower()
    ver_clean = (version or "").strip()

    if not prod_lower or not ver_clean:
        return False

    # 1. vsftpd 2.3.4
    if "vsftpd" in prod_lower:
        if ver_clean == "2.3.4" or re.search(r"\b2\.3\.4\b", ver_clean):
            return True

    # 2. OpenSSH < 7.4
    if "openssh" in prod_lower:
        parsed = parse_major_minor(ver_clean)
        if parsed is not None and parsed < (7, 4):
            return True

    # 3. Apache httpd <= 2.2.x (exclude Apache Tomcat / Coyote / etc.)
    if "apache httpd" in prod_lower or prod_lower == "apache":
        parsed = parse_major_minor(ver_clean)
        if parsed is not None and parsed <= (2, 2):
            return True

    # 4. Microsoft IIS <= 7.5
    if "iis" in prod_lower or "microsoft-iis" in prod_lower:
        parsed = parse_major_minor(ver_clean)
        if parsed is not None and parsed <= (7, 5):
            return True

    # 5. Samba <= 3.x
    if "samba" in prod_lower or "smbd" in prod_lower:
        parsed = parse_major_minor(ver_clean)
        if parsed is not None and parsed[0] <= 3:
            return True

    return False
