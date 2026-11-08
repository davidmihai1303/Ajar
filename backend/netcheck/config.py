"""Settings from environment variables only (NFR-01: no secrets in code)."""

import os

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
# replies naming evidence the scan does not show are discarded (NFR-06). LLM_FREE_ANSWERS=0 shows only verified scan records.
LLM_FREE_ANSWERS: bool = os.environ.get("LLM_FREE_ANSWERS", "1").strip().lower() not in ("0", "false", "no", "off")
# Built Ajar desktop app files (AppImage / .deb) offered for download; read-only, optional.
DOWNLOADS_DIR: str = os.environ.get("NETCHECK_DOWNLOADS_DIR", "/data/downloads")
QWEN_RUNTIME_DIR: str = os.environ.get("AJAR_QWEN_RUNTIME", "")
