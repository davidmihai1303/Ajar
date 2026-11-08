"""Settings from environment variables only (NFR-01: no secrets in code)."""

import os
import re

# A host name (ajar.local, raspberrypi.local) or an IPv4 address. No wildcards, ports or paths.
_HOST = re.compile(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")


def parse_allowed_hosts(raw: str) -> tuple[str, ...]:
    """'ajar.local, 172.20.10.5' -> ('ajar.local', '172.20.10.5'). Refuses '*' and anything that is not a host.

    These are EXTRA names the web app answers to, on top of 127.0.0.1 and localhost. They only matter
    when the server also listens on the network (NETCHECK_BIND_HOST, LAN test mode). There is no login
    in that mode: anyone on the same Wi-Fi who uses one of these names can open the app.
    """
    hosts: list[str] = []
    for entry in (raw or "").split(","):
        host = entry.strip().lower().rstrip(".")
        if not host:
            continue
        if not _HOST.fullmatch(host):
            raise ValueError(f"NETCHECK_ALLOWED_HOSTS: '{entry.strip()}' is not a host name or IPv4 address")
        if host not in hosts:
            hosts.append(host)
    return tuple(hosts)


DB_PATH: str = os.environ.get("NETCHECK_DB", "data/netcheck.sqlite")
SCANS_DIR: str = os.environ.get("NETCHECK_SCANS_DIR", "/var/lib/netcheck/scans")
AGENT_URL: str = os.environ.get("NETCHECK_AGENT_URL", "http://127.0.0.1:8765")
DEFAULT_LANG: str = os.environ.get("NETCHECK_LANG", "ro")
LLM_BASE_URL: str = os.environ.get("LLM_BASE_URL", "")
LLM_API_KEY: str = os.environ.get("LLM_API_KEY", "")
LLM_MODEL: str = os.environ.get("LLM_MODEL", "")
MAX_XML_BYTES: int = int(os.environ.get("NETCHECK_MAX_XML_BYTES", str(20 * 1024 * 1024)))
LLM_TIMEOUT: float = float(os.environ.get("LLM_TIMEOUT", "60"))
# The Ask assistant shows the model's own written answer, built from the scan facts. On by default;
# set LLM_FREE_ANSWERS=0 to show only verified scan records (free text is not checked, brief NFR-06).
LLM_FREE_ANSWERS: bool = os.environ.get("LLM_FREE_ANSWERS", "1").strip().lower() not in ("0", "false", "no", "off")
QWEN_RUNTIME_DIR: str = os.environ.get("AJAR_QWEN_RUNTIME", "")
# LAN test mode (off by default): extra host names the web app accepts, e.g. "raspberrypi.local,172.20.10.5".
ALLOWED_HOSTS: tuple[str, ...] = parse_allowed_hosts(os.environ.get("NETCHECK_ALLOWED_HOSTS", ""))
