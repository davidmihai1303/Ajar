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
# Opt-in: the Ask assistant shows the model's own written answer (not only scan records). Off by default:
# free text is not verified against the scan (brief NFR-06), so keep it off for the jury unless agreed.
LLM_FREE_ANSWERS: bool = os.environ.get("LLM_FREE_ANSWERS", "").strip().lower() in ("1", "true", "yes", "on")
QWEN_RUNTIME_DIR: str = os.environ.get("AJAR_QWEN_RUNTIME", "")
