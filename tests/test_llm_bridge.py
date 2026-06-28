"""Hermetic tests for the Claude Max LLM bridge (``scanner.llm_bridge``).

No network calls and no repo-fixture mutation: env is monkeypatched, the
``anthropic`` SDK is replaced with a fake client, and ``urllib`` is
monkeypatched to either return a canned body or raise.
"""

from __future__ import annotations

import sys
import types

import pytest

from scanner import llm_bridge
from scanner.llm_bridge import (
    LLMResult,
    bridge_config,
    bridge_health,
    complete,
    complete_json,
    extract_json_object,
    is_enabled,
    looks_structurally_truncated,
)


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test from a clean env so defaults are exercised."""
    for var in (
        "EU_AI_ACT_SCANNER_LLM",
        "EU_AI_ACT_SCANNER_LLM_BASE_URL",
        "EU_AI_ACT_SCANNER_LLM_API_KEY",
        "EU_AI_ACT_SCANNER_LLM_MODEL",
    ):
        monkeypatch.delenv(var, raising=False)


# ─── is_enabled ──────────────────────────────────────────────────────────


def test_is_enabled_false_by_default() -> None:
    assert is_enabled() is False


@pytest.mark.parametrize("value", ["true", "TRUE", "1", "yes", "Yes"])
def test_is_enabled_true_for_affirmative_values(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("EU_AI_ACT_SCANNER_LLM", value)
    assert is_enabled() is True


@pytest.mark.parametrize("value", ["false", "0", "no", "", "maybe"])
def test_is_enabled_false_for_negative_values(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("EU_AI_ACT_SCANNER_LLM", value)
    assert is_enabled() is False


# ─── extract_json_object — 3 strategies + garbage ────────────────────────


def test_extract_json_object_direct() -> None:
    assert extract_json_object('{"score": 0.9, "ok": true}') == {"score": 0.9, "ok": True}


def test_extract_json_object_fenced() -> None:
    text = 'Here is the result:\n```json\n{"verdict": "high-risk"}\n```\nDone.'
    assert extract_json_object(text) == {"verdict": "high-risk"}


def test_extract_json_object_fenced_untagged() -> None:
    text = "```\n{\"a\": 1}\n```"
    assert extract_json_object(text) == {"a": 1}


def test_extract_json_object_braced_in_prose() -> None:
    text = 'The model concluded {"risk": "limited", "confidence": 0.7} after review.'
    assert extract_json_object(text) == {"risk": "limited", "confidence": 0.7}


def test_extract_json_object_braced_picks_answer_after_example() -> None:
    # An example placeholder span precedes the real answer; the later span wins.
    text = 'For example {"x": 1}. The real answer is {"verdict": "prohibited"}.'
    assert extract_json_object(text) == {"verdict": "prohibited"}


def test_extract_json_object_strips_trailing_commas() -> None:
    assert extract_json_object('{"a": 1, "b": 2,}') == {"a": 1, "b": 2}


def test_extract_json_object_garbage_returns_none() -> None:
    assert extract_json_object("this is just prose with no json at all") is None


def test_extract_json_object_empty_returns_none() -> None:
    assert extract_json_object("") is None


def test_extract_json_object_non_dict_json_returns_none() -> None:
    # A bare JSON array is valid JSON but not an object — extractor wants a dict.
    assert extract_json_object("[1, 2, 3]") is None


# ─── looks_structurally_truncated ────────────────────────────────────────


def test_looks_structurally_truncated_true_mid_clause() -> None:
    assert looks_structurally_truncated("Applying that test to the") is True


def test_looks_structurally_truncated_false_complete_sentence() -> None:
    assert looks_structurally_truncated("This is complete.") is False


def test_looks_structurally_truncated_false_for_terminal_variants() -> None:
    assert looks_structurally_truncated("Is it high-risk?") is False
    assert looks_structurally_truncated("Absolutely not!") is False
    assert looks_structurally_truncated("It continues…") is False


def test_looks_structurally_truncated_peels_closing_wrappers() -> None:
    # Terminator hidden behind a closing paren/quote is still a complete end.
    assert looks_structurally_truncated('It is high-risk (see Annex IV.)') is False
    assert looks_structurally_truncated('The verdict is "prohibited."') is False


def test_looks_structurally_truncated_empty_is_false() -> None:
    assert looks_structurally_truncated("") is False
    assert looks_structurally_truncated("   \n  ") is False


def test_looks_structurally_truncated_trailing_comma_is_truncated() -> None:
    assert looks_structurally_truncated("First the risk, then the obligations,") is True


# ─── bridge_config — never leaks the key ─────────────────────────────────


def test_bridge_config_defaults() -> None:
    cfg = bridge_config()
    assert cfg == {
        "base_url": "http://127.0.0.1:8000",
        "model": "claude-haiku-4-5-20251001",
        "api_key_source": "default",
        "enabled": False,
    }


def test_bridge_config_reports_env_source_without_leaking_key(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "sk-super-secret-value-DO-NOT-LEAK"
    monkeypatch.setenv("EU_AI_ACT_SCANNER_LLM_API_KEY", secret)
    monkeypatch.setenv("EU_AI_ACT_SCANNER_LLM", "true")
    monkeypatch.setenv("EU_AI_ACT_SCANNER_LLM_BASE_URL", "https://wrapper.antifragile-ai.net/")
    cfg = bridge_config()
    assert cfg["api_key_source"] == "env"
    assert cfg["enabled"] is True
    # base_url is normalized (trailing slash stripped).
    assert cfg["base_url"] == "https://wrapper.antifragile-ai.net"
    # The secret must never appear anywhere in the config dict.
    assert secret not in repr(cfg)
    for value in cfg.values():
        assert value != secret


# ─── complete / complete_json with a fake anthropic client ───────────────


class _FakeTextBlock:
    """Mimics anthropic's content block (has a ``.text`` attribute)."""

    def __init__(self, text: str) -> None:
        self.text = text


class _FakeResponse:
    def __init__(self, text: str) -> None:
        self.content = [_FakeTextBlock(text)]


class _FakeMessages:
    def __init__(self, text: str, recorder: dict) -> None:
        self._text = text
        self._recorder = recorder

    def create(self, **kwargs: object) -> _FakeResponse:
        self._recorder.update(kwargs)
        return _FakeResponse(self._text)


class _FakeClient:
    def __init__(self, *, base_url: str, api_key: str, text: str, recorder: dict) -> None:
        recorder["base_url"] = base_url
        recorder["api_key"] = api_key
        self.messages = _FakeMessages(text, recorder)


def _install_fake_anthropic(
    monkeypatch: pytest.MonkeyPatch,
    *,
    text: str,
    recorder: dict,
) -> None:
    """Inject a fake ``anthropic`` module exposing ``Anthropic``."""

    fake_module = types.ModuleType("anthropic")

    def _factory(*, base_url: str, api_key: str) -> _FakeClient:
        return _FakeClient(base_url=base_url, api_key=api_key, text=text, recorder=recorder)

    fake_module.Anthropic = _factory  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", fake_module)


def test_complete_returns_text_when_client_monkeypatched(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict = {}
    _install_fake_anthropic(monkeypatch, text="The system is high-risk.", recorder=recorder)
    monkeypatch.setenv("EU_AI_ACT_SCANNER_LLM_API_KEY", "env-key")

    result = complete("You are an auditor.", "Classify this.", max_tokens=123)

    assert isinstance(result, LLMResult)
    assert result.error is None
    assert result.text == "The system is high-risk."
    assert result.truncated is False
    assert result.model == "claude-haiku-4-5-20251001"
    # The bridge routed through the wrapper base_url + env key.
    assert recorder["base_url"] == "http://127.0.0.1:8000"
    assert recorder["api_key"] == "env-key"
    assert recorder["max_tokens"] == 123
    assert recorder["system"] == "You are an auditor."


def test_complete_sets_truncated_on_mid_clause_text(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict = {}
    _install_fake_anthropic(monkeypatch, text="Applying that test to the", recorder=recorder)
    result = complete("sys", "usr")
    assert result.error is None
    assert result.truncated is True


def test_complete_uses_default_api_key_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict = {}
    _install_fake_anthropic(monkeypatch, text="ok.", recorder=recorder)
    complete("sys", "usr")
    assert recorder["api_key"] == "not-needed"


def test_complete_model_override(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict = {}
    _install_fake_anthropic(monkeypatch, text="done.", recorder=recorder)
    result = complete("sys", "usr", model="claude-sonnet-4-5")
    assert result.model == "claude-sonnet-4-5"
    assert recorder["model"] == "claude-sonnet-4-5"


def test_complete_graceful_when_sdk_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force the ImportError branch even if anthropic happens to be installed.
    monkeypatch.setitem(sys.modules, "anthropic", None)
    result = complete("sys", "usr")
    assert result.error is not None
    assert "anthropic" in result.error.lower()
    assert result.text == ""


def test_complete_graceful_on_client_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_module = types.ModuleType("anthropic")

    def _boom(*, base_url: str, api_key: str) -> object:
        raise RuntimeError("connection refused")

    fake_module.Anthropic = _boom  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", fake_module)

    result = complete("sys", "usr")
    assert result.error is not None
    assert "LLM call failed" in result.error
    assert result.text == ""


def test_complete_json_extracts_object(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict = {}
    payload = '```json\n{"score": 0.4, "reasoning": "partial coverage"}\n```'
    _install_fake_anthropic(monkeypatch, text=payload, recorder=recorder)

    parsed, result = complete_json("sys", "usr")

    assert parsed == {"score": 0.4, "reasoning": "partial coverage"}
    assert result.error is None
    assert result.raw_json == parsed


def test_complete_json_none_on_garbage(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder: dict = {}
    _install_fake_anthropic(monkeypatch, text="no json here at all.", recorder=recorder)
    parsed, result = complete_json("sys", "usr")
    assert parsed is None
    assert result.error is None
    assert result.raw_json is None


def test_complete_json_propagates_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "anthropic", None)
    parsed, result = complete_json("sys", "usr")
    assert parsed is None
    assert result.error is not None


# ─── bridge_health — hermetic urllib monkeypatch ─────────────────────────


class _FakeHTTPResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeHTTPResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def test_bridge_health_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_urlopen(url: str, timeout: float = 0.0) -> _FakeHTTPResponse:
        assert url == "http://127.0.0.1:8000/health"
        return _FakeHTTPResponse(b'{"status": "ok", "claude_max": true}')

    monkeypatch.setattr(llm_bridge.urllib.request, "urlopen", _fake_urlopen)

    health = bridge_health()
    assert health == {"reachable": True, "status": "ok", "claude_max": True}


def test_bridge_health_reachable_missing_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_urlopen(url: str, timeout: float = 0.0) -> _FakeHTTPResponse:
        return _FakeHTTPResponse(b"{}")

    monkeypatch.setattr(llm_bridge.urllib.request, "urlopen", _fake_urlopen)

    health = bridge_health()
    assert health == {"reachable": True, "status": None, "claude_max": False}


def test_bridge_health_unreachable_on_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(url: str, timeout: float = 0.0) -> object:
        raise OSError("connection refused")

    monkeypatch.setattr(llm_bridge.urllib.request, "urlopen", _boom)

    health = bridge_health()
    assert health == {"reachable": False, "status": None, "claude_max": False}


def test_bridge_health_unreachable_on_bad_body(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_urlopen(url: str, timeout: float = 0.0) -> _FakeHTTPResponse:
        return _FakeHTTPResponse(b"not json")

    monkeypatch.setattr(llm_bridge.urllib.request, "urlopen", _fake_urlopen)

    health = bridge_health()
    assert health["reachable"] is False


def test_bridge_health_service_name_implies_claude_max(monkeypatch: pytest.MonkeyPatch) -> None:
    """The live wrapper carries no ``claude_max`` flag on /health but names itself
    ``claude-code-openai-wrapper`` — that service signal must be reported truthfully."""
    def _fake_urlopen(url: str, timeout: float = 0.0) -> _FakeHTTPResponse:
        return _FakeHTTPResponse(b'{"status": "healthy", "service": "claude-code-openai-wrapper"}')

    monkeypatch.setattr(llm_bridge.urllib.request, "urlopen", _fake_urlopen)

    health = bridge_health()
    assert health == {"reachable": True, "status": "healthy", "claude_max": True}


def test_extract_json_object_multi_fence_last_wins() -> None:
    """REGRESSION: when an LLM ships a worked-example fence BEFORE the real answer
    fence, the extractor must return the later (real) one — not the example."""
    text = (
        "Here is the format you should use:\n"
        '```json\n{"title": "example", "content": "PLACEHOLDER"}\n```\n'
        "And here is my actual answer:\n"
        '```json\n{"title": "REAL", "content": "the real fix"}\n```\n'
    )
    obj = extract_json_object(text)
    assert obj == {"title": "REAL", "content": "the real fix"}
