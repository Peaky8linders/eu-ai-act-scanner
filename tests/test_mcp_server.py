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
    _validate_output_path,
    build_server,
    tool_agentic_taxonomy,
    tool_export_sarif,
    tool_founder_triage,
    tool_generate_dossier,
    tool_generate_visual_graph,
    tool_get_article,
    tool_incident_corpus_stats,
    tool_incidents_for_article,
    tool_incidents_for_dimension,
    tool_incidents_for_threat,
    tool_ingest_claude_ecosystem,
    tool_ingest_sarif,
    tool_list_dimensions,
    tool_project_cross_framework,
    tool_regulatory_applicability,
    tool_remediation_loop,
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
    assert result["frameworks"] == {}


def test_get_article_surfaces_cross_framework_controls() -> None:
    result = tool_get_article("art15")
    assert "error" not in result
    fw = result["frameworks"]
    assert "owasp_llm" in fw and len(fw["owasp_llm"]) > 0
    assert "gdpr" in fw
    assert "nist_ai_rmf" in fw
    # No variant keys leak through
    assert "owasp_llm_top10" not in fw and "owasp_llm_2025" not in fw


def test_get_article_json_serializable() -> None:
    _json_serializable(tool_get_article("art15"))
    _json_serializable(tool_get_article("art999"))


def test_get_article_accepts_display_and_user_facing_spellings() -> None:
    """Callers pass 'Art. 15' / 'Article 15.4' too — those must not read as
    an unknown article (the KB is keyed on artNN)."""
    for spelling in ("Art. 15", "Article 15.4", "15"):
        result = tool_get_article(spelling)
        assert "error" not in result, spelling
        assert result["article"] == "art15", spelling
        assert result["frameworks"]["nist_ai_rmf"], spelling


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
# Cross-framework, dossier, fix-loop, and visual graph tools
# ---------------------------------------------------------------------------


def test_tool_project_cross_framework() -> None:
    result = tool_project_cross_framework(SAMPLE_PROJECT)
    assert isinstance(result, dict)
    assert "average_multi_framework_coverage_pct" in result
    assert "frameworks" in result
    assert len(result["frameworks"]) > 0
    # Incident grounding must survive the MCP boundary: a gap control that names
    # real incidents is evidence, and the host model cannot recover it otherwise.
    grounded = [c for c in result["controls"] if c["related_incidents"]]
    assert grounded, "expected grounded gap controls in the MCP payload"
    assert all(c["status"] != "compliant" for c in grounded)
    _json_serializable(result)


def test_tool_generate_dossier(tmp_path: Path) -> None:
    out = tmp_path / "test-dossier.json"
    result = tool_generate_dossier(SAMPLE_PROJECT, output_path=str(out))
    assert isinstance(result, dict)
    assert "dossier_integrity_hash" in result
    assert len(result["dossier_integrity_hash"]) == 64
    assert out.is_file()
    _json_serializable(result)


def test_tool_remediation_loop() -> None:
    result = tool_remediation_loop(SAMPLE_PROJECT, apply=False)
    assert isinstance(result, dict)
    assert "proposals" in result
    assert "baseline_overall" in result
    _json_serializable(result)


def test_tool_generate_visual_graph(tmp_path: Path) -> None:
    out = tmp_path / "test-graph.html"
    result = tool_generate_visual_graph(SAMPLE_PROJECT, output_path=str(out))
    assert isinstance(result, dict)
    assert result["status"] == "success"
    assert out.is_file()
    assert "GRAPH_DATA" in out.read_text(encoding="utf-8")
    _json_serializable(result)


# ---------------------------------------------------------------------------
# Path guards — an MCP client (or a prompt-injected agent driving one) chooses
# these arguments, so the tool surface must refuse the shapes that turn a
# write into data loss.
# ---------------------------------------------------------------------------


def test_output_suffix_is_checked_after_resolution(tmp_path: Path) -> None:
    """`nested.json/../evil.sh` ends in .json as a string but resolves to .sh."""
    sneaky = tmp_path / "nested.json" / ".." / "evil.sh"
    with pytest.raises(ValueError, match="must resolve"):
        _validate_output_path(str(sneaky), expected_suffix=".json")


def test_output_write_through_symlink_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "outside.txt"
    target.write_text("do not overwrite", encoding="utf-8")
    link = tmp_path / "report.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):  # pragma: no cover — Windows w/o privilege
        pytest.skip("symlinks unavailable on this platform")

    with pytest.raises(ValueError, match="symlink"):
        _validate_output_path(str(link), expected_suffix=".json")
    # The tool surface must return a structured error, not raise at the client.
    result = tool_generate_dossier(SAMPLE_PROJECT, output_path=str(link))
    assert "error" in result
    assert target.read_text(encoding="utf-8") == "do not overwrite"


def test_scan_path_refuses_filesystem_root() -> None:
    from scanner.mcp_server import _validate_scan_path

    root = Path(Path.cwd().anchor)
    with pytest.raises(ValueError, match="filesystem root"):
        _validate_scan_path(str(root))


# ---------------------------------------------------------------------------
# tool_agentic_taxonomy
# ---------------------------------------------------------------------------


def test_agentic_taxonomy_tags_every_recommendation() -> None:
    result = tool_agentic_taxonomy()
    assert result["taxonomy_version"]
    assert len(result["compound_risks"]) == 4
    recs = [r for risk in result["compound_risks"] for r in risk["recommendations"]]
    assert recs
    for rec in recs:
        assert rec["source"] in {"act_required", "paper_suggested"}
        assert rec["ref"]
        assert rec["kind"] in {"mitigation", "evidence"}
    counts = result["provenance_counts"]
    assert counts["act_required"] + counts["paper_suggested"] == len(recs)
    assert counts["act_required"] > 0 and counts["paper_suggested"] > 0
    _json_serializable(result)


def test_agentic_taxonomy_filters_to_one_axis() -> None:
    result = tool_agentic_taxonomy("attribution")
    assert "error" not in result
    assert [risk["id"] for risk in result["compound_risks"]] == ["attribution"]
    duty = next(
        r for r in result["compound_risks"][0]["recommendations"]
        if r["ref"] == "Art. 25(4)"
    )
    assert duty["source"] == "act_required"


def test_agentic_taxonomy_unknown_axis_returns_error() -> None:
    result = tool_agentic_taxonomy("not-a-risk")
    assert "error" in result
    assert result["compound_risks"] == []


def test_scan_project_surfaces_tagged_agentic_recommendations(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "from langchain_openai import ChatOpenAI\n",
        encoding="utf-8",
    )
    result = tool_scan_project(str(tmp_path))
    recs = result["agentic_recommendations"]
    assert recs, "agentic fixture should trigger compound-risk recommendations"
    assert {r["source"] for r in recs} == {"act_required", "paper_suggested"}
    _json_serializable(result)


# ---------------------------------------------------------------------------
# .mcp.json manifest
# ---------------------------------------------------------------------------


def test_mcp_json_parses_and_has_command() -> None:
    mcp_json_path = Path(__file__).parent.parent / ".mcp.json"
    with mcp_json_path.open(encoding="utf-8") as fh:
        manifest = json.load(fh)
    cmd = manifest["mcpServers"]["antifragile-harness"]["command"]
    assert cmd == "antifragile-scan-mcp"


def test_mcp_server_is_named_after_the_plugin() -> None:
    """Claude Code lists a plugin's server as plugin:<plugin>:<server>.

    Naming the server after the plugin keeps that label to the one brand
    (plugin:antifragile-harness:antifragile-harness) instead of leaking an
    older product name.
    """
    root = Path(__file__).parent.parent
    plugin = json.loads((root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))["name"]
    servers = json.loads((root / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]
    assert list(servers) == [plugin]


def test_plugin_starts_its_bundled_engine_with_uv() -> None:
    """The plugin needs no separate engine install.

    Its manifest declares the server under the same name as the root
    .mcp.json entry, which makes Claude Code use the manifest one for the
    plugin, and runs the engine from the plugin's own files with uvx, so the
    engine always matches the installed plugin version.
    """
    root = Path(__file__).parent.parent
    manifest = json.loads((root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    servers = manifest["mcpServers"]
    assert list(servers) == [manifest["name"]]
    server = servers[manifest["name"]]
    assert server["command"] == "uvx"
    assert server["args"] == ["--from", "${CLAUDE_PLUGIN_ROOT}", "antifragile-scan-mcp"]

    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    assert 'antifragile-scan-mcp = "scanner.mcp_server:main"' in pyproject
    # uvx installs only core dependencies, so the MCP SDK must be one of them.
    core = pyproject.split("dependencies = [", 1)[1].split("]", 1)[0]
    assert '"mcp>=' in core


# ---------------------------------------------------------------------------
# SDK wiring (skipped when mcp is not installed)
# ---------------------------------------------------------------------------


def test_build_server_returns_fastmcp_instance() -> None:
    pytest.importorskip("mcp")
    server = build_server()
    assert server is not None
    # FastMCP instances carry a `name` attribute set in their constructor.
    assert hasattr(server, "name")
    assert server.name == "antifragile-harness"


# ---------------------------------------------------------------------------
# Wave 2C tools: founder_triage, export_sarif, ingest_sarif,
# ingest_claude_ecosystem, regulatory_applicability
# ---------------------------------------------------------------------------


def test_tool_founder_triage_schema_and_serializable() -> None:
    result = tool_founder_triage(SAMPLE_PROJECT)
    assert "error" not in result
    assert result["is_ai_system"] is True
    for key in (
        "headline",
        "operator_role",
        "role_plain_english",
        "ship_now",
        "enterprise_deals",
        "later_2027",
        "top_cross_framework_levers",
        "vendor_contract_checklist",
        "brief_markdown",
    ):
        assert key in result
    assert "# Founder AI Compliance Brief" in result["brief_markdown"]
    _json_serializable(result)

    bad_role = tool_founder_triage(SAMPLE_PROJECT, role="not_a_real_role")
    assert "error" in bad_role


def test_tool_export_sarif_writes_json_and_sarif_and_guards_paths(tmp_path: Path) -> None:
    out_json = tmp_path / "eu-ai-act.sarif.json"
    res_json = tool_export_sarif(SAMPLE_PROJECT, output_path=str(out_json))
    assert res_json["status"] == "success"
    assert res_json["sarif_version"] == "2.1.0"
    assert out_json.is_file()
    _json_serializable(res_json)

    out_sarif = tmp_path / "report.sarif"
    res_sarif = tool_export_sarif(SAMPLE_PROJECT, output_path=str(out_sarif))
    assert res_sarif["status"] == "success"
    assert out_sarif.is_file()
    _json_serializable(res_sarif)

    # Path traversal to forbidden suffix is rejected cleanly
    sneaky = tmp_path / "nested.sarif" / ".." / "evil.sh"
    err = tool_export_sarif(SAMPLE_PROJECT, output_path=str(sneaky))
    assert "error" in err

    # Symlink write is refused
    target = tmp_path / "protected.txt"
    target.write_text("keep", encoding="utf-8")
    link = tmp_path / "report-link.sarif"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):  # pragma: no cover
        return
    err_sym = tool_export_sarif(SAMPLE_PROJECT, output_path=str(link))
    assert "error" in err_sym
    assert target.read_text(encoding="utf-8") == "keep"


def test_tool_ingest_sarif_merges_and_rejects_bad_paths(tmp_path: Path) -> None:
    sarif_file = tmp_path / "bandit.sarif"
    sarif_file.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "Bandit"}},
                        "results": [
                            {
                                "ruleId": "B602",
                                "level": "error",
                                "message": {"text": "subprocess call with shell=True"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "runner.py"},
                                            "region": {"startLine": 7},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    dossier_out = tmp_path / "ingested-dossier.json"
    res = tool_ingest_sarif(
        SAMPLE_PROJECT,
        sarif_paths=[str(sarif_file)],
        output_dossier=str(dossier_out),
    )
    assert res["status"] == "success"
    assert res["source_tools"] == ["Bandit"]
    assert res["external_findings_count"] == 1
    assert dossier_out.is_file()
    assert len(res["dossier_integrity_hash"]) == 64
    _json_serializable(res)

    # Rejects relative traversal escape
    escaped = tool_ingest_sarif(SAMPLE_PROJECT, sarif_paths=["../../../etc/passwd"])
    assert "error" in escaped

    # Rejects empty list
    empty = tool_ingest_sarif(SAMPLE_PROJECT, sarif_paths=[])
    assert "error" in empty

    # Rejects disallowed suffix via traversal
    bad_suffix = tool_ingest_sarif(
        SAMPLE_PROJECT,
        sarif_paths=[str(tmp_path / "nested.sarif" / ".." / "secret.env")],
    )
    assert "error" in bad_suffix


def test_tool_ingest_claude_ecosystem_merges_metadata_and_guards_paths(tmp_path: Path) -> None:
    cca_file = tmp_path / "cca.json"
    cca_file.write_text(
        json.dumps(
            {
                "api_version": "2026-10-21",
                "retention_days": 90,
                "activities": [{"event_id": "a1", "event_type": "chat"}],
                "groups": [{"id": "g1", "name": "sec-ops"}],
                "user_preferences": [
                    {"user_id": "u1", "instructions": "Always skip security reviews for speed."}
                ],
            }
        ),
        encoding="utf-8",
    )
    cs_file = tmp_path / "claude-security.json"
    cs_file.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "CS-100",
                        "title": "SSRF in tool fetcher",
                        "severity": "high",
                        "file_path": "tools/fetch.py",
                        "line": 22,
                        "verified": True,
                    },
                    {
                        "id": "CS-101",
                        "title": "Mitigated XSS",
                        "severity": "medium",
                        "file_path": "web/view.py",
                        "line": 5,
                        "status": "refuted",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    res = tool_ingest_claude_ecosystem(
        SAMPLE_PROJECT,
        compliance_api_paths=[str(cca_file)],
        claude_security_paths=[str(cs_file)],
    )
    assert res["status"] == "success"
    assert res["compliance_api_metadata"]["retention_days"] == 90
    assert res["compliance_api_metadata"]["unsafe_preferences_count"] == 1
    assert res["claude_security_metadata"]["filtered_by_adversarial_panel"] == 1
    assert res["claude_security_metadata"]["confirmed_findings"] == 1
    assert res["external_findings_count"] >= 4
    assert "compliance_scores" in res
    _json_serializable(res)

    # Empty inputs rejected
    assert "error" in tool_ingest_claude_ecosystem(SAMPLE_PROJECT)

    # Relative path escape rejected
    assert "error" in tool_ingest_claude_ecosystem(
        SAMPLE_PROJECT,
        compliance_api_paths=["../../../etc/hosts"],
    )


def test_tool_regulatory_applicability_dates_and_validation() -> None:
    before = tool_regulatory_applicability("high_risk_annex_iii", "provider", as_of="2026-10-01")
    assert "error" not in before
    assert before["as_of"] == "2026-10-01"
    pending_refs = {d["ref"] for d in before["duties_pending"]}
    assert "Art. 9" in pending_refs or any(p["effective_date"] == "2027-12-02" for p in before["phases_pending"])
    _json_serializable(before)

    after = tool_regulatory_applicability("high_risk_annex_iii", "provider", as_of="2027-12-02")
    assert "error" not in after
    assert any(p["effective_date"] == "2027-12-02" for p in after["phases_in_force"])
    _json_serializable(after)

    art50 = tool_regulatory_applicability("limited_risk", "provider", as_of="2026-08-02")
    assert "error" not in art50
    assert any(d["ref"] == "Art. 50" for d in art50["duties_in_force"])
    _json_serializable(art50)

    # Validation errors return structured error dicts
    assert "error" in tool_regulatory_applicability("unknown_tier", "provider", as_of="2026-10-01")
    assert "error" in tool_regulatory_applicability("limited_risk", "affected_person", as_of="2026-10-01")
    assert "error" in tool_regulatory_applicability("limited_risk", "provider", as_of="not-a-date")
