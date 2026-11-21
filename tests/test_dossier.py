"""Tests for cryptographic compliance release dossier (scanner.dossier)."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from scanner.dossier import ComplianceDossier, generate_dossier
from scanner.models import ArchitectureNode, DiscoveredComponent, FileFinding, ScanResult


def test_dossier_sign_and_seal_integrity() -> None:
    dossier = ComplianceDossier(
        project_name="Test-Seal",
        overall_compliance_pct=72.5,
        dimension_scores={"risk_mgmt": 80.0, "security": 65.0},
    )
    assert dossier.dossier_integrity_hash == ""
    dossier.sign_and_seal()
    hash1 = dossier.dossier_integrity_hash
    assert len(hash1) == 64  # SHA-256 hex string

    # Re-signing without mutations produces the identical digest
    dossier.sign_and_seal()
    assert dossier.dossier_integrity_hash == hash1

    # Mutating a field changes the integrity hash
    dossier.overall_compliance_pct = 75.0
    dossier.sign_and_seal()
    assert dossier.dossier_integrity_hash != hash1


def test_dossier_statutory_metadata() -> None:
    dossier = ComplianceDossier(project_name="Test-Regime")
    assert "2024/1689" in dossier.regulatory_regime["primary_regulation"]
    assert "2026/1744" in dossier.regulatory_regime["amending_legislation"]
    assert "02024R1689-20260727" in dossier.regulatory_regime["eur_lex_celex"]
    assert "EN 18286:2026" in dossier.regulatory_regime["harmonised_standards"]
    assert "Art. 17(1)" in dossier.regulatory_regime["harmonised_standards"]
    assert "Art. 11(1)" in dossier.regulatory_regime["harmonised_standards"]


def test_dossier_dynamic_omnibus_phase_resolution(tmp_path: Path) -> None:
    """Enforcement status resolves dynamically via scanner.data.omnibus.resolve_applicability."""
    (tmp_path / "model.py").write_text("import torch\n", encoding="utf-8")
    scan = ScanResult(
        project_name="Phase-Test",
        is_ai_system=True,
        overall_compliance_pct=65.0,
        compliance_scores={"risk_mgmt": 65.0},
        inferred_roles=["provider"],
    )

    dossier_2026 = generate_dossier(scan, tmp_path, as_of=date(2026, 11, 20))
    status_2026 = dossier_2026.regulatory_regime["enforcement_status"]
    assert dossier_2026.regulatory_regime["as_of_date"] == "2026-11-20"
    assert "Art. 50" in status_2026
    assert "2027-12-02" in status_2026

    dossier_2028 = generate_dossier(scan, tmp_path, as_of=date(2028, 1, 15))
    status_2028 = dossier_2028.regulatory_regime["enforcement_status"]
    assert dossier_2028.regulatory_regime["as_of_date"] == "2028-01-15"
    assert "all Annex III phases in force" in status_2028
    assert status_2028 != status_2026


def test_dossier_surfaces_external_security_sources_and_counts(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text("import openai\n", encoding="utf-8")
    scan = ScanResult(
        project_name="Ext-Dossier",
        is_ai_system=True,
        overall_compliance_pct=55.0,
        compliance_scores={"security": 55.0},
        external_security_sources=["sarif:semgrep", "claude-code-security"],
        architecture=[
            ArchitectureNode(
                id="external_security",
                label="External Security & Compliance Findings",
                type="security",
                compliance_status="gap",
                file_count=1,
                finding_count=3,
            )
        ],
        components=[
            DiscoveredComponent(
                name="SQL injection sink",
                component_type="external_security",
                file_path="agent.py",
                confidence=0.9,
                compliance_dimensions=["security"],
                compliance_impact="gap",
            )
        ],
    )
    dossier = generate_dossier(scan, tmp_path)
    assert dossier.external_security_sources == ["sarif:semgrep", "claude-code-security"]
    assert dossier.external_security_findings_count == 3
    assert len(dossier.dossier_integrity_hash) == 64


def test_generate_dossier_with_manifest(tmp_path: Path) -> None:
    # Create test files
    f1 = tmp_path / "model.py"
    f1.write_text("import torch\nprint('model')\n", encoding="utf-8")
    f2 = tmp_path / "README.md"
    f2.write_text("# Test Project\n", encoding="utf-8")

    scan = ScanResult(
        project_name="Fixture-Project",
        is_ai_system=True,
        overall_compliance_pct=60.0,
        compliance_scores={"risk_mgmt": 60.0, "security": 60.0},
        inferred_roles=["provider"],
        file_findings=[
            FileFinding(file_path="model.py", findings=["torch"], status="compliant"),
            FileFinding(file_path="README.md", findings=["doc"], status="compliant"),
        ],
    )

    dossier = generate_dossier(scan, tmp_path, applied_remediations=["art14_human_oversight"])
    assert dossier.project_name == "Fixture-Project"
    assert dossier.inferred_roles == ["provider"]
    assert len(dossier.dossier_integrity_hash) == 64
    assert len(dossier.file_manifest) == 2
    assert "art14_human_oversight" in dossier.applied_remediations

    # Verify SHA-256 manifest
    paths = {m.relative_path for m in dossier.file_manifest}
    assert "model.py" in paths
    assert "README.md" in paths
    for m in dossier.file_manifest:
        assert len(m.sha256) == 64
        assert m.size_bytes > 0

    # Test export
    out_file = tmp_path / "out-dossier.json"
    exported = dossier.export_json(out_file)
    assert exported.is_file()
    loaded = json.loads(exported.read_text(encoding="utf-8"))
    assert loaded["dossier_integrity_hash"] == dossier.dossier_integrity_hash
    assert loaded["regulatory_regime"]["eur_lex_celex"] == "02024R1689-20260727"
