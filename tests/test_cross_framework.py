"""Tests for cross-framework projection engine (scanner.cross_framework)."""

from __future__ import annotations

from scanner.cross_framework import (
    CrossFrameworkScanProjection,
    project_scan_to_frameworks,
)
from scanner.data.frameworks import (
    CROSSWALK_CATALOGUE_VERSION,
    DIMENSION_CROSSWALK,
    FRAMEWORK_LABELS,
)
from scanner.models import ScanResult


def test_catalogue_version_and_frameworks_registered() -> None:
    assert "2026" in CROSSWALK_CATALOGUE_VERSION
    assert len(FRAMEWORK_LABELS) >= 10
    assert "nist_ai_rmf" in FRAMEWORK_LABELS
    assert "iso_42001" in FRAMEWORK_LABELS
    assert "gdpr" in FRAMEWORK_LABELS
    assert "owasp_llm" in FRAMEWORK_LABELS
    assert "owasp_agentic" in FRAMEWORK_LABELS


def test_dimension_crosswalk_covers_key_dimensions() -> None:
    assert "data_gov" in DIMENSION_CROSSWALK
    assert "risk_mgmt" in DIMENSION_CROSSWALK
    assert "human_oversight" in DIMENSION_CROSSWALK
    assert "security" in DIMENSION_CROSSWALK
    assert "logging" in DIMENSION_CROSSWALK

    # data_gov maps to GDPR and NIST AI RMF
    data_cw = DIMENSION_CROSSWALK["data_gov"]
    assert "gdpr" in data_cw
    assert "nist_ai_rmf" in data_cw


def test_project_scan_to_frameworks_basic() -> None:
    scan = ScanResult(
        project_name="Test-AI",
        is_ai_system=True,
        compliance_scores={
            "risk_mgmt": 85.0,        # compliant
            "data_gov": 45.0,         # partial
            "human_oversight": 15.0,  # gap
            "security": 90.0,         # compliant
            "logging": 70.0,          # compliant
        },
    )

    proj = project_scan_to_frameworks(scan)
    assert isinstance(proj, CrossFrameworkScanProjection)
    assert proj.project_name == "Test-AI"
    assert proj.total_frameworks_mapped > 0
    assert proj.average_multi_framework_coverage_pct > 0.0

    # Framework summaries exist
    fw_ids = [fw.framework_id for fw in proj.frameworks]
    assert "nist_ai_rmf" in fw_ids
    assert "iso_42001" in fw_ids

    # Controls projected
    assert len(proj.controls) > 0
    statuses = {c.status for c in proj.controls}
    assert "compliant" in statuses
    assert "gap" in statuses


def test_framework_projection_coverage_calculation() -> None:
    scan = ScanResult(
        project_name="Test-AI",
        is_ai_system=True,
        compliance_scores={
            "risk_mgmt": 100.0,
            "security": 100.0,
            "logging": 100.0,
            "human_oversight": 100.0,
            "data_gov": 100.0,
            "transparency": 100.0,
            "adversarial_robustness": 100.0,
            "tool_governance": 100.0,
            "eval_framework": 100.0,
            "fria": 100.0,
        },
    )

    proj = project_scan_to_frameworks(scan, target_framework_ids=["gdpr"])
    assert len(proj.frameworks) == 1
    gdpr_summary = proj.frameworks[0]
    assert gdpr_summary.framework_id == "gdpr"
    assert gdpr_summary.coverage_pct >= 80.0
    assert gdpr_summary.gap == 0


def test_satisfy_once_levers_identified() -> None:
    scan = ScanResult(
        project_name="Test-Agent",
        is_ai_system=True,
        compliance_scores={
            "human_oversight": 10.0,  # gap
            "data_gov": 15.0,         # gap
        },
    )

    proj = project_scan_to_frameworks(scan)
    assert len(proj.satisfy_once_levers) > 0
    lever_dims = [lever.dimension_id for lever in proj.satisfy_once_levers]
    assert "human_oversight" in lever_dims or "data_gov" in lever_dims
    first_lever = proj.satisfy_once_levers[0]
    assert first_lever.framework_count >= 2
    assert "Closing this gap directly satisfies" in first_lever.impact_summary


def test_framework_ids_are_canonical_no_variant_keys() -> None:
    """Variant IDs (owasp_llm_top10/owasp_llm_2025/owasp_agentic_top10) must not
    appear as crosswalk keys — filtering silently dropped them (contract bug)."""
    from scanner.data.frameworks import ARTICLE_FRAMEWORK_CROSSWALK

    variants = {"owasp_llm_top10", "owasp_llm_2025", "owasp_agentic_top10"}
    for dim_id, mapping in DIMENSION_CROSSWALK.items():
        assert not (set(mapping) & variants), f"{dim_id} has variant keys"
    for art, mapping in ARTICLE_FRAMEWORK_CROSSWALK.items():
        assert not (set(mapping) & variants), f"{art} has variant keys"


def test_alias_normalization_maps_variants_to_canonical() -> None:
    from scanner.data.frameworks import normalize_framework_id

    assert normalize_framework_id("owasp_llm_top10") == "owasp_llm"
    assert normalize_framework_id("owasp_llm_2025") == "owasp_llm"
    assert normalize_framework_id("owasp_agentic_top10") == "owasp_agentic"
    assert normalize_framework_id("gdpr") == "gdpr"


def test_target_filter_accepts_canonical_and_alias_ids() -> None:
    scan = ScanResult(
        project_name="Test-Filter",
        is_ai_system=True,
        compliance_scores={"risk_mgmt": 50.0, "security": 50.0},
    )
    for fwid in ("owasp_llm", "owasp_llm_top10", "owasp_llm_2025"):
        proj = project_scan_to_frameworks(scan, target_framework_ids=[fwid])
        assert len(proj.frameworks) == 1, fwid
        assert proj.frameworks[0].framework_id == "owasp_llm", fwid
        assert proj.frameworks[0].total_controls > 0, fwid


def test_article_crosswalk_resolves() -> None:
    from scanner.data.frameworks import get_crosswalk_for_article

    cw = get_crosswalk_for_article("Art. 15")
    assert "owasp_llm" in cw
    assert "gdpr" in cw
    assert "nist_ai_rmf" in cw


def test_every_kb_dimension_maps_somewhere() -> None:
    """No scored dimension may be invisible to the projection (false-assurance
    guard: an unmapped 0%-dimension used to leave avg coverage at 100%)."""
    from scanner.kb import DIMENSIONS

    unmapped = [d for d in DIMENSIONS if d not in DIMENSION_CROSSWALK]
    assert unmapped == [], f"unmapped dimensions: {unmapped}"


def test_projection_reports_unmapped_dimensions() -> None:
    scan = ScanResult(
        project_name="Test-Unmapped",
        is_ai_system=True,
        compliance_scores={"risk_mgmt": 50.0, "__future_dim__": 10.0},
    )
    proj = project_scan_to_frameworks(scan)
    assert "__future_dim__" in proj.unmapped_dimensions
    assert "Unmapped dimensions" in proj.format_markdown()


def test_cross_framework_markdown_rendering() -> None:
    scan = ScanResult(
        project_name="Test-Markdown",
        is_ai_system=True,
        compliance_scores={"risk_mgmt": 75.0, "security": 20.0},
    )
    proj = project_scan_to_frameworks(scan)
    md = proj.format_markdown()
    assert "# Cross-Framework Compliance Projection — Test-Markdown" in md
    assert "| Framework | Coverage | Compliant | Partial | Gap |" in md
    assert "Evidence Harmonization & Reuse" in md
