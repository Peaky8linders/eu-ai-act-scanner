"""Regression: scan_project(deep=True) must call semantic_audit_project correctly."""
from pathlib import Path

from scanner.orchestrator import scan_project

FIXTURE = Path(__file__).parent / "fixtures" / "sample_project"


def test_deep_scan_does_not_raise_and_populates_semantic_audit(monkeypatch):
    monkeypatch.setattr("scanner.llm_bridge.is_enabled", lambda: False)
    result = scan_project(FIXTURE, deep=True)
    assert result.semantic_audit is not None
    assert result.semantic_audit["error"] == "LLM bridge is disabled"
