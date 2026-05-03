"""End-to-end scanner tests against the fixture AI project."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner import ScanResult, scan_project
from scanner.analyzers import ANALYZER_REGISTRY, AnalyzerContext, run_all_analyzers
from scanner.kb import ARTICLE_TO_DIMENSIONS, DIMENSIONS, dimensions_for_article

FIXTURE = Path(__file__).parent / "fixtures" / "sample_project"


# ─── KB sanity ──────────────────────────────────────────────────────────


def test_kb_has_expected_dimensions():
    # 19 baseline dimensions + 4 agent-aware dimensions added in v0.3
    # (agent_inventory, tool_governance, regulatory_perimeter, runtime_drift)
    assert len(DIMENSIONS) == 23


def test_every_article_maps_to_known_dimensions():
    for article, dim_ids in ARTICLE_TO_DIMENSIONS.items():
        for d in dim_ids:
            assert d in DIMENSIONS, f"{article} maps to unknown dimension {d}"


def test_dimensions_for_article_returns_full_objects():
    dims = dimensions_for_article("art15")
    assert len(dims) >= 3
    labels = {d.label for d in dims}
    assert "Accuracy & Security" in labels


def test_dimensions_for_article_unknown_returns_empty():
    assert dimensions_for_article("art999") == []


# ─── Analyzer registry ──────────────────────────────────────────────────


def test_analyzer_registry_has_expected_analyzers():
    # 14 baseline analyzers + 7 added in v0.3 (lethal_trifecta, cloud_deployment,
    # model_typology, agent_inventory, privilege_minimization, runtime_drift,
    # regulatory_perimeter)
    assert len(ANALYZER_REGISTRY) == 21


def test_every_analyzer_is_callable():
    ctx = AnalyzerContext(files={}, file_list=[], binary_files={}, languages={})
    for name, fn in ANALYZER_REGISTRY.items():
        result = fn(ctx)
        assert result.analyzer_id == name, f"{name} returned mismatched id"


def test_analyzers_tolerate_empty_project():
    ctx = AnalyzerContext(files={}, file_list=[], binary_files={}, languages={})
    results = run_all_analyzers(ctx)
    assert len(results) == 21
    for r in results:
        assert 0.0 <= r.score <= 100.0


# ─── End-to-end ──────────────────────────────────────────────────────────


def test_scan_fixture_project_produces_result():
    result = scan_project(FIXTURE)
    assert isinstance(result, ScanResult)
    assert result.total_files > 0
    assert result.scanner_version != ""


def test_scan_fixture_detects_ai_framework():
    result = scan_project(FIXTURE)
    types = {c.component_type for c in result.components}
    # The fixture imports torch + transformers — ai_frameworks should find them
    assert "ai_frameworks" in types


def test_scan_fixture_detects_human_oversight():
    """The fixture has `human_review` and `confidence_threshold` — analyzer should see them."""
    result = scan_project(FIXTURE)
    types = {c.component_type for c in result.components}
    assert "human_oversight" in types


def test_compliance_scores_are_nonnegative():
    """Regression guard — scores were previously allowed to go negative."""
    result = scan_project(FIXTURE)
    for dim, score in result.compliance_scores.items():
        assert 0.0 <= score <= 100.0, f"{dim} score out of range: {score}"


def test_scan_nonexistent_path_raises():
    with pytest.raises(ValueError):
        scan_project("/this/path/does/not/exist/xyz123")


def test_scan_rejects_non_directory(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("hello")
    with pytest.raises(ValueError):
        scan_project(f)


# ─── CLI ────────────────────────────────────────────────────────────────


def test_cli_scan_emits_valid_json(capsys):
    from scanner.cli import main
    exit_code = main([str(FIXTURE), "--json"])
    assert exit_code == 0
    import json as _json
    out = capsys.readouterr().out
    parsed = _json.loads(out)
    assert "compliance_scores" in parsed
    assert "scanner_version" in parsed


def test_cli_markdown_includes_project_name(capsys):
    from scanner.cli import main
    exit_code = main([str(FIXTURE), "--markdown"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "# EU AI Act Scan" in out
    assert "sample_project" in out


def test_cli_article_filter_limits_output(capsys):
    from scanner.cli import main
    exit_code = main([str(FIXTURE), "--article", "art15"])
    assert exit_code == 0
    import json as _json
    payload = _json.loads(capsys.readouterr().out)
    assert payload["article"] == "art15"
    # Every returned dimension must be one of art15's mapped dims
    allowed = set(dim.id for dim in dimensions_for_article("art15"))
    for dim in payload.get("compliance_scores", {}):
        assert dim in allowed


def test_cli_article_unknown_reports_error(capsys):
    from scanner.cli import main
    exit_code = main([str(FIXTURE), "--article", "art999"])
    # The CLI exits 0 but payload contains an error field — this is the UX choice
    # so Claude Code commands can parse a consistent JSON shape.
    assert exit_code == 0
    import json as _json
    payload = _json.loads(capsys.readouterr().out)
    assert "error" in payload
