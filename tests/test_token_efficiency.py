"""Token-efficiency contract for agent-facing outputs.

Follows Anthropic's tool-design guidance: a small set of consolidated tools,
concise responses by default with an opt-in ``response_format="detailed"``,
no duplicated payloads (a file written to disk is not echoed back), and
truncated lists that say how to get more. Budgets are generous upper bounds
measured on the sample fixture (tokens estimated as characters / 4).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

import scanner.mcp_server as m

SAMPLE = Path(__file__).resolve().parent / "fixtures" / "sample_project"
NON_AI = Path(__file__).resolve().parent / "fixtures" / "non_ai_project"


def _tok(obj: object) -> int:
    return len(json.dumps(obj, default=str)) // 4


# ---------------------------------------------------------------------------
# Tool surface
# ---------------------------------------------------------------------------

EXPECTED_TOOLS = {
    "scan_project",
    "founder_triage",
    "project_cross_framework",
    "ingest_security_reports",
    "export_sarif",
    "generate_dossier",
    "generate_visual_graph",
    "remediation_loop",
    "regulatory_applicability",
    "list_dimensions",
    "get_article",
    "incidents",
    "agentic_taxonomy",
}


def _registered_tools() -> list[dict]:
    pytest.importorskip("mcp")
    server = m.build_server()
    tools = asyncio.run(server.list_tools())
    return [t.model_dump(by_alias=True, exclude_none=True, mode="json") for t in tools]


def test_mcp_registers_the_consolidated_tool_set() -> None:
    assert {t["name"] for t in _registered_tools()} == EXPECTED_TOOLS


def test_tool_definitions_fit_a_small_budget() -> None:
    tools = _registered_tools()
    assert _tok(tools) <= 2500, _tok(tools)  # was ~3,120 for 17 tools
    for tool in tools:
        assert len(tool.get("description", "")) <= 520, tool["name"]


def test_heavy_tools_offer_response_format() -> None:
    by_name = {t["name"]: t for t in _registered_tools()}
    for name in ("scan_project", "founder_triage", "project_cross_framework", "ingest_security_reports",
                 "generate_dossier", "remediation_loop", "incidents"):
        props = by_name[name]["inputSchema"]["properties"]
        assert "response_format" in props, name


# ---------------------------------------------------------------------------
# Concise by default (MCP), detailed on request
# ---------------------------------------------------------------------------


def test_scan_project_concise_is_small_and_actionable() -> None:
    out = m.tool_scan_project(str(SAMPLE), response_format="concise")
    assert _tok(out) <= 1500, _tok(out)
    assert out["is_ai_system"] is True
    assert "overall_compliance_pct" in out
    assert out["top_gaps"] and all("where" in g and "title" in g for g in out["top_gaps"])
    assert "components" not in out
    assert "response_format='detailed'" in out["more"]


def test_scan_project_detailed_keeps_the_full_result() -> None:
    out = m.tool_scan_project(str(SAMPLE), response_format="detailed")
    assert "components" in out and "file_findings" in out


def test_scan_project_concise_non_ai_explains_scope_without_score() -> None:
    out = m.tool_scan_project(str(NON_AI), response_format="concise")
    assert out["is_ai_system"] is False
    assert out["scope_note"]
    assert "overall_compliance_pct" not in out


def test_founder_triage_concise_returns_the_brief_not_both() -> None:
    out = m.tool_founder_triage(str(SAMPLE), response_format="concise")
    assert _tok(out) <= 1500, _tok(out)
    assert "# Founder AI Compliance Brief" in out["brief_markdown"]
    assert "ship_now" not in out  # structured buckets only in detailed


def test_cross_framework_concise_summarises_frameworks_and_levers() -> None:
    out = m.tool_project_cross_framework(str(SAMPLE), response_format="concise")
    assert _tok(out) <= 1500, _tok(out)
    assert out["frameworks"] and all({"framework", "coverage_pct"} <= set(f) for f in out["frameworks"])
    assert len(out["top_levers"]) <= 3


def test_export_sarif_does_not_echo_the_written_document(tmp_path: Path) -> None:
    out = m.tool_export_sarif(str(SAMPLE), output_path=str(tmp_path / "r.sarif"), response_format="concise")
    assert out["status"] == "success"
    assert "sarif" not in out
    assert _tok(out) <= 400, _tok(out)
    assert json.loads((tmp_path / "r.sarif").read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_dossier_and_graph_return_receipts_not_payloads(tmp_path: Path) -> None:
    dossier = m.tool_generate_dossier(str(SAMPLE), output_path=str(tmp_path / "d.json"), response_format="concise")
    assert _tok(dossier) <= 500 and dossier["integrity_hash"] and "file_manifest" not in dossier
    graph = m.tool_generate_visual_graph(str(SAMPLE), output_path=str(tmp_path / "g.html"), response_format="concise")
    assert _tok(graph) <= 500 and "graph_summary" not in graph


def test_remediation_loop_concise_omits_file_contents() -> None:
    out = m.tool_remediation_loop(str(SAMPLE), response_format="concise")
    assert out["proposals"] and all("content" not in p for p in out["proposals"])
    assert _tok(out) <= 1200, _tok(out)


# ---------------------------------------------------------------------------
# One incidents tool with forgiving keys and helpful errors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", ["security", "art15", "Art. 15", "Article 15", "prompt_injection"])
def test_incidents_resolves_dimension_article_and_threat(key: str) -> None:
    out = m.tool_incidents(key, limit=2)
    assert out["incidents"], out
    assert out["resolved_as"] in {"dimension", "article", "threat"}


def test_incidents_concise_entries_are_compact() -> None:
    concise = m.tool_incidents("security", limit=3, response_format="concise")
    detailed = m.tool_incidents("security", limit=3, response_format="detailed")
    assert _tok(concise) < _tok(detailed)
    assert {"id", "title"} <= set(concise["incidents"][0])


def test_incidents_without_key_returns_corpus_stats_and_unknown_key_helps() -> None:
    stats = m.tool_incidents()
    assert stats["count"] > 0 and stats["license"] == "CC-BY-4.0"
    unknown = m.tool_incidents("not-a-thing")
    assert unknown["incidents"] == [] and "e.g." in unknown["error"]


# ---------------------------------------------------------------------------
# Through the MCP layer: concise by default, compact text, real isError
# ---------------------------------------------------------------------------


def _call(name: str, args: dict):
    pytest.importorskip("mcp")
    server = m.build_server()
    return asyncio.run(server.call_tool(name, args))


def _text(result) -> str:
    return "".join(getattr(c, "text", "") for c in result.content)


def test_mcp_scan_project_defaults_to_concise_compact_json() -> None:
    result = _call("scan_project", {"path": str(SAMPLE)})
    text = _text(result)
    assert not result.is_error
    assert "\n  " not in text  # no pretty-print indentation
    data = json.loads(text)
    assert "top_gaps" in data and "components" not in data
    assert not getattr(result, "structuredContent", None)


def test_mcp_founder_triage_returns_the_markdown_brief() -> None:
    text = _text(_call("founder_triage", {"path": str(SAMPLE)}))
    assert text.startswith("# Founder AI Compliance Brief")


def test_mcp_errors_are_tool_errors_that_keep_the_guidance() -> None:
    pytest.importorskip("mcp")
    from mcp.server.mcpserver.exceptions import ToolError, UnexpectedToolError

    with pytest.raises(ToolError) as excinfo:
        _call("incidents", {"key": "not-a-thing"})
    # A plain exception would surface as a generic UnexpectedToolError and drop
    # the guidance; a ToolError reaches the model as an isError result verbatim.
    assert not isinstance(excinfo.value, UnexpectedToolError)
    assert "e.g." in str(excinfo.value)


def test_mcp_scan_cache_survives_paging_but_not_edits(tmp_path: Path) -> None:
    import shutil

    project = tmp_path / "p"
    shutil.copytree(SAMPLE, project)
    first = m.tool_scan_project(str(project), response_format="concise", limit=1)
    page2 = m.tool_scan_project(str(project), response_format="concise", limit=1, offset=1)
    assert first["gap_count"] == page2["gap_count"]
    assert first["top_gaps"] != page2["top_gaps"]
    (project / "new_module.py").write_text("import anthropic\n", encoding="utf-8")
    after = m.tool_scan_project(str(project), response_format="concise")
    assert after["files_scanned"] == first["files_scanned"] + 1  # the edit invalidated the cache


def test_scan_project_offset_past_the_end_says_so() -> None:
    out = m.tool_scan_project(str(SAMPLE), response_format="concise", offset=500)
    assert out["top_gaps"] == []
    assert "No gaps at offset 500" in out["more"]


def test_scan_project_area_filter_accepts_articles_and_rejects_junk() -> None:
    by_article = m.tool_scan_project(str(SAMPLE), response_format="concise", area="Art. 15")
    assert set(by_article["filtered_to_areas"]) >= {"security"}
    junk = m.tool_scan_project(str(SAMPLE), response_format="concise", area="not-an-area")
    assert "error" in junk and "list_dimensions" in junk["error"]
