"""Regression: scan_project(deep=True) must call semantic_audit_project correctly."""
from pathlib import Path

from scanner.orchestrator import scan_project

FIXTURE = Path(__file__).parent / "fixtures" / "sample_project"


def test_deep_scan_does_not_raise_and_populates_semantic_audit(monkeypatch):
    monkeypatch.setattr("scanner.llm_bridge.is_enabled", lambda: False)
    result = scan_project(FIXTURE, deep=True)
    assert result.semantic_audit is not None
    assert result.semantic_audit["error"] == "LLM bridge is disabled"


def test_deep_scan_markdown_includes_semantic_audit_section(monkeypatch):
    from scanner.cli import _format_markdown
    monkeypatch.setattr("scanner.llm_bridge.is_enabled", lambda: False)
    result = scan_project(FIXTURE, deep=True)
    md = _format_markdown(result)
    assert "## Semantic audit (Claude Code / Codex)" in md
    assert "LLM bridge is disabled" in md

