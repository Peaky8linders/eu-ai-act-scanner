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


# ─── AI-system scope gate (Art. 3(1)) ────────────────────────────────────

NON_AI_FIXTURE = Path(__file__).parent / "fixtures" / "non_ai_project"


def test_ai_fixture_is_in_scope():
    """The sample project imports torch/transformers — it IS an AI system, so
    scoring applies and the scope flag is set."""
    result = scan_project(FIXTURE)
    assert result.is_ai_system is True
    assert result.ai_system_signals, "an in-scope project must record its AI signals"
    assert result.compliance_scores, "an AI system must be scored"
    assert result.scope_note == ""


def test_non_ai_project_is_out_of_scope():
    """A plain arithmetic library is not an AI system. Scoring must be skipped —
    not reported as 0% and not gameable up to ~60% by writing boilerplate."""
    result = scan_project(NON_AI_FIXTURE)
    assert result.is_ai_system is False
    assert result.ai_system_signals == []
    # No misleading compliance percentage / per-dimension scores.
    assert result.compliance_scores == {}
    assert result.overall_compliance_pct == 0.0
    # A human-readable explanation is surfaced instead of a number.
    assert result.scope_note
    assert "AI system" in result.scope_note


def test_out_of_scope_suppresses_compliance_framed_output():
    """An out-of-scope scan must not present compliance-framed risk indicators,
    recommendations, or incident grounding (all keyed off scoring)."""
    result = scan_project(NON_AI_FIXTURE)
    assert result.risk_indicators == []
    assert result.incident_grounding == {}


def test_detect_ai_system_keys_only_on_purpose_built_detectors():
    """detect_ai_system fires on framework / typology / agent-runtime signals,
    and stays silent for a project with none of them."""
    from scanner.analyzers import AnalyzerResult, detect_ai_system

    silent = [
        AnalyzerResult(analyzer_id="ai_frameworks", label="AI Frameworks",
                       metadata={"detected": []}),
        AnalyzerResult(analyzer_id="model_typology", label="Model Typology",
                       metadata={"typology": "none"}),
        AnalyzerResult(analyzer_id="agent_inventory", label="Agent Inventory",
                       metadata={"runtime_signals": []}),
    ]
    is_ai, signals = detect_ai_system(silent)
    assert is_ai is False
    assert signals == []


def test_detect_ai_system_flips_on_any_single_signal():
    """Any one of the three purpose-built signals is sufficient to be in scope."""
    from scanner.analyzers import AnalyzerResult, detect_ai_system

    framework = [AnalyzerResult(analyzer_id="ai_frameworks", label="AI Frameworks",
                                metadata={"detected": ["pytorch"]})]
    is_ai, signals = detect_ai_system(framework)
    assert is_ai is True
    assert "ai_framework:pytorch" in signals

    typology = [AnalyzerResult(analyzer_id="model_typology", label="Model Typology",
                               metadata={"typology": "llm"})]
    is_ai, signals = detect_ai_system(typology)
    assert is_ai is True
    assert "model_typology:llm" in signals

    agent = [AnalyzerResult(analyzer_id="agent_inventory", label="Agent Inventory",
                            metadata={"runtime_signals": ["mcp_client"]})]
    is_ai, signals = detect_ai_system(agent)
    assert is_ai is True
    assert "agent_runtime:mcp_client" in signals


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


def test_cli_article_filter_carries_scope_flag(capsys):
    """The --article JSON payload exposes is_ai_system so a single-article query
    can tell an out-of-scope project from a genuinely 0-scoring one."""
    from scanner.cli import main
    exit_code = main([str(NON_AI_FIXTURE), "--article", "art15"])
    assert exit_code == 0
    import json as _json
    payload = _json.loads(capsys.readouterr().out)
    assert payload["is_ai_system"] is False
    assert payload["compliance_scores"] == {}


def test_cli_markdown_flags_non_ai_as_out_of_scope(capsys):
    """The markdown summary must not show a compliance percentage for a non-AI
    project — it shows an out-of-scope banner instead."""
    from scanner.cli import main
    exit_code = main([str(NON_AI_FIXTURE), "--markdown"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Not an AI system" in out
    # The misleading "Overall compliance: 0.0%" line must be gone.
    assert "Overall compliance" not in out


# ─── lethal_trifecta scoring ─────────────────────────────────────────────


def test_lethal_trifecta_score_stays_within_bounds_with_many_gated_files():
    """A project with many gated (positive) trifecta files and at least one
    ungated (gap) file used to push the `gaps and positives` score branch
    above 100, tripping AnalyzerResult's `le=100.0` validation (found while
    dogfooding the scanner against a large real-world repo). The branch must
    clamp its upper bound like every other branch in this analyzer."""
    from scanner.analyzers.lethal_trifecta import analyze_lethal_trifecta

    gated_file = (
        "import requests\n"
        "from agent import run\n\n"
        "@app.post('/webhook')\n"
        "def handle():\n"
        "    data = request.json\n"
        "    customer = customers.find(data['id'])\n"
        "    if confidence_threshold >= 0.9:\n"
        "        approve()\n"
        "    resend.send(customer)\n"
    )
    ungated_file = (
        "import requests\n"
        "from agent import run\n\n"
        "@app.post('/webhook')\n"
        "def handle():\n"
        "    data = request.json\n"
        "    customer = customers.find(data['id'])\n"
        "    resend.send(customer)\n"
    )
    files = {f"gated_{i}.py": gated_file for i in range(14)}
    files["ungated.py"] = ungated_file

    ctx = AnalyzerContext(files=files, file_list=list(files), languages={"python": len(files)})
    result = analyze_lethal_trifecta(ctx)

    assert 0.0 <= result.score <= 100.0
