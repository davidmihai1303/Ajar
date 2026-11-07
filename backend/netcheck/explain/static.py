"""Built-in, bilingual guidance for each catalog finding."""
from functools import lru_cache
from importlib.resources import files

import yaml


@lru_cache(maxsize=2)
def catalog(lang: str) -> dict:
    if lang not in {"ro", "en"}:
        raise ValueError("unsupported language")
    path = files("netcheck.explain").joinpath("texts", lang + ".yaml")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def guidance(code: str, lang: str, device_type: str = "") -> dict:
    entries = catalog(lang)
    return entries.get(f"{code}.{device_type}", entries[code])
