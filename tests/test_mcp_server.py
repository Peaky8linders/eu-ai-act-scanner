"""Tests for scanner.mcp_server plain tool functions.

These tests deliberately avoid importing the ``mcp`` SDK so the suite runs
without the optional ``[mcp]`` extra. A single SDK-wiring test is guarded by
``pytest.importorskip("mcp")`` and is skipped when the SDK is absent.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import scanner.kb as kb
from scanner.mcp_server import (
    build_server,
    tool_get_article,
    tool_incident_corpus_stats,
    tool_incidents_for_article,
    tool_incidents_for_dimension,
    tool_incidents_for_threat,
    tool_list_dimensions,
    tool_scan_project,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_PROJECT = str(Path(__file__).parent / "fixtures" / "sample_project")


def _json_serializable(obj: object) -> None:
    """Assert obj can round-trip through json.dumps without raising."""
    json.dumps(obj)  # raises TypeError if not serializable


# ---------------------------------------------------------------------------
# tool_scan_project
# ---------------------------------------------------------------------------


def test_scan_project_returns_expected_keys() -> None:
    result = tool_scan_project(SAMPLE_PROJECT)
    assert isinstance(result, dict)
    assert "compliance_scores" in result
    assert "overall_compliance_pct" in result
    assert "incident_grounding" in result


def test_scan_project_json_serializable() -> None:
    result = tool_scan_project(SAMPLE_PROJECT)
    _json_serializable(result)


def test_scan_project_with_name() -> None:
    result = tool_scan_project(SAMPLE_PROJECT, project_name="test-proj")
    assert isinstance(result, dict)
    assert "overall_compliance_pct" in result


# ---------------------------------------------------------------------------
# tool_list_dimensions
# ---------------------------------------------------------------------------


def test_list_dimensions_non_empty() -> None:
    dims = tool_list_dimensions()
    assert isinstance(dims, list)
    assert len(dims) > 0


def test_list_dimensions_count_matches_kb() -> None:
    dims = tool_list_dimensions()
    assert len(dims) == len(kb.DIMENSIONS)


def test_list_dimensions_entry_schema() -> None:
    for entry in tool_list_dimensions():
        assert "id" in entry
        assert "label" in entry
        assert "article" in entry
        assert "description" in entry


def test_list_dimensions_json_serializable() -> None:
    _json_serializable(tool_list_dimensions())


# ---------------------------------------------------------------------------
# tool_get_article
# ---------------------------------------------------------------------------


def test_get_article_known_returns_dimensions_and_incidents() -> None:
    result = tool_get_article("art15")
    assert isinstance(result, dict)
    assert result["article"] == "art15"
    assert len(result["dimensions"]) > 0
    assert len(result["incidents"]) > 0
    assert "error" not in result


def test_get_article_unknown_returns_error_and_empty_lists() -> None:
    result = tool_get_article("art999")
    assert "error" in result
    assert result["dimensions"] == []
    assert result["incidents"] == []


def test_get_article_json_serializable() -> None:
    _json_serializable(tool_get_article("art15"))
    _json_serializable(tool_get_article("art999"))


# ---------------------------------------------------------------------------
# tool_incidents_for_dimension
# ---------------------------------------------------------------------------


def test_incidents_for_dimension_security_with_limit() -> None:
    results = tool_incidents_for_dimension("security", limit=3)
    assert isinstance(results, list)
    assert len(results) <= 3


def test_incidents_for_dimension_entry_schema() -> None:
    results = tool_incidents_for_dimension("security", limit=3)
    for entry in results:
        assert "id" in entry
        assert "owasp_llm" in entry
        assert "mitre_atlas" in entry


def test_incidents_for_dimension_unknown_returns_empty() -> None:
    results = tool_incidents_for_dimension("__nonexistent_dim__", limit=5)
    assert results == []


def test_incidents_for_dimension_json_serializable() -> None:
    _json_serializable(tool_incidents_for_dimension("security", limit=3))


# ---------------------------------------------------------------------------
# tool_incidents_for_threat
# ---------------------------------------------------------------------------


def test_incidents_for_threat_prompt_injection_non_empty() -> None:
    results = tool_incidents_for_threat("prompt_injection")
    assert isinstance(results, list)
    assert len(results) > 0


def test_incidents_for_threat_json_serializable() -> None:
    _json_serializable(tool_incidents_for_threat("prompt_injection"))


# ---------------------------------------------------------------------------
# tool_incidents_for_article
# ---------------------------------------------------------------------------


def test_incidents_for_article_art15_non_empty() -> None:
    results = tool_incidents_for_article("art15")
    assert isinstance(results, list)
    assert len(results) > 0


def test_incidents_for_article_json_serializable() -> None:
    _json_serializable(tool_incidents_for_article("art15"))


# ---------------------------------------------------------------------------
# tool_incident_corpus_stats
# ---------------------------------------------------------------------------


def test_incident_corpus_stats_count_positive() -> None:
    stats = tool_incident_corpus_stats()
    assert isinstance(stats, dict)
    assert stats["count"] > 0


def test_incident_corpus_stats_license() -> None:
    stats = tool_incident_corpus_stats()
    assert stats["license"] == "CC-BY-4.0"


def test_incident_corpus_stats_json_serializable() -> None:
    _json_serializable(tool_incident_corpus_stats())


# ---------------------------------------------------------------------------
# .mcp.json manifest
# ---------------------------------------------------------------------------


def test_mcp_json_parses_and_has_command() -> None:
    mcp_json_path = Path(__file__).parent.parent / ".mcp.json"
    with mcp_json_path.open(encoding="utf-8") as fh:
        manifest = json.load(fh)
    cmd = manifest["mcpServers"]["eu-ai-act-scanner"]["command"]
    assert cmd == "eu-ai-act-scan-mcp"


# ---------------------------------------------------------------------------
# SDK wiring (skipped when mcp is not installed)
# ---------------------------------------------------------------------------


def test_build_server_returns_fastmcp_instance() -> None:
    pytest.importorskip("mcp")
    server = build_server()
    assert server is not None
    # FastMCP instances carry a `name` attribute set in their constructor.
    assert hasattr(server, "name")
    assert server.name == "eu-ai-act-scanner"
