import pytest

from netcheck import config


@pytest.fixture(autouse=True)
def record_only_answers(monkeypatch):
    """Tests default to record-based Ask answers; free-answer tests turn LLM_FREE_ANSWERS on."""
    monkeypatch.setattr(config, "LLM_FREE_ANSWERS", False)
