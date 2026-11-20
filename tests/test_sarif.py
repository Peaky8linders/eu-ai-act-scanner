"""Tests for scanner.sarif — offline SARIF 2.1.0 export and external SAST ingestion."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from scanner.models import DiscoveredComponent, ScanResult
from scanner.sarif import ingest_sarif_files, scan_to_sarif, write_sarif

_URL_RE = re.compile(r"https?://")


def _sample_scan_result() -> ScanResult:
    return ScanResult(
        project_name="acme-ai-agent",
        scan_id="scan12345678",
        scanner_version="0.11.3",
        is_ai_system=True,
        overall_compliance_pct=42.5,
        compliance_scores={
            "security": 20.0,
            "transparency": 15.0,
            "logging": 50.0,
        },
        incident_grounding={
            "security": ["INC-001", "INC-002"],
            "transparency": ["INC-010"],
        },
        components=[
            DiscoveredComponent(
                name="MCP tool description poisoning detected",
                component_type="mcp_toolchain",
                file_path=".mcp.json",
                confidence=0.95,
                compliance_dimensions=["security", "tool_governance"],
                compliance_impact="gap",
                details={
                    "evidence": "Hidden directive in tool description (see https://evil.example/payload)",
                    "line_number": 14,
                    "article_paragraphs": ["Art. 15(4)"],
                },
            ),
            DiscoveredComponent(
                name="Missing structured audit logging",
                component_type="logging_monitoring",
                file_path="src/agent.py",
                confidence=0.70,
                compliance_dimensions=["logging"],
                compliance_impact="gap",
                details={"evidence": "Plain print() used in inference loop"},
            ),
            DiscoveredComponent(
                name="Low-confidence documentation hint",
                component_type="documentation",
                file_path="README.md",
                confidence=0.40,
                compliance_dimensions=["tech_docs"],
                compliance_impact="gap",
                details={},
            ),
            DiscoveredComponent(
                name="Structlog configured",
                component_type="logging_monitoring",
                file_path="src/logger.py",
                confidence=0.90,
                compliance_dimensions=["logging"],
                compliance_impact="positive",
                details={},
            ),
        ],
    )


class TestSarifExport:
    def test_scan_to_sarif_structure_and_properties(self) -> None:
        result = _sample_scan_result()
        sarif = scan_to_sarif(result)

        assert sarif["version"] == "2.1.0"
        assert "$schema" not in sarif
        assert len(sarif["runs"]) == 1

        run = sarif["runs"][0]
        driver = run["tool"]["driver"]
        assert driver["name"] == "eu-ai-act-scanner"
        assert driver["version"] == "0.11.3"
        assert "informationUri" not in driver
        assert len(driver["rules"]) == 3

        results = run["results"]
        # Positive finding is excluded; only the 3 gaps are emitted.
        assert len(results) == 3

        first = results[0]
        assert first["level"] == "error"
        assert first["ruleId"].startswith("eu-ai-act/mcp-toolchain/")
        assert "MCP tool description poisoning" in first["message"]["text"]
        loc = first["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == ".mcp.json"
        assert loc["region"]["startLine"] == 14
        props = first["properties"]
        assert "Art. 15(4)" in props["eu_ai_act_articles"]
        assert "security" in props["dimensions"]
        assert "INC-001" in props["related_incidents"]
        assert props["confidence"] == 0.95

        # Second finding has no line_number — region must be omitted gracefully.
        second = results[1]
        assert second["level"] == "warning"
        second_phys = second["locations"][0]["physicalLocation"]
        assert second_phys["artifactLocation"]["uri"] == "src/agent.py"
        assert "region" not in second_phys

        # Third finding has low confidence -> note level.
        assert results[2]["level"] == "note"

    def test_scan_to_sarif_offline_no_remote_urls(self) -> None:
        result = _sample_scan_result()
        sarif = scan_to_sarif(result)
        serialized = json.dumps(sarif)
        assert not _URL_RE.search(serialized), f"SARIF output leaked remote URL: {serialized}"

    def test_scan_to_sarif_non_ai_system_emits_empty_results(self) -> None:
        non_ai = ScanResult(
            project_name="plain-cli",
            is_ai_system=False,
            components=[
                DiscoveredComponent(
                    name="Unrelated warning",
                    component_type="documentation",
                    file_path="README.md",
                    confidence=0.8,
                    compliance_dimensions=["tech_docs"],
                    compliance_impact="gap",
                )
            ],
        )
        sarif = scan_to_sarif(non_ai, tool_version="1.0.0")
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["tool"]["driver"]["version"] == "1.0.0"
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []
        assert sarif["runs"][0]["properties"]["is_ai_system"] is False

    def test_write_sarif_and_round_trip_ingest(self, tmp_path: Path) -> None:
        result = _sample_scan_result()
        out_path = tmp_path / "reports" / "scan.sarif"
        written = write_sarif(result, out_path)
        assert written == out_path
        assert out_path.is_file()

        findings, tools = ingest_sarif_files([out_path])
        assert tools == ["eu-ai-act-scanner"]
        # 3 gap results were error, warning, note -> note is skipped on ingest, leaving 2 findings.
        assert len(findings) == 2
        assert all(f.category == "external_security_sarif" for f in findings)
        assert all(f.compliance_impact == "gap" for f in findings)
        assert all(f.compliance_dimensions == ["security", "supply_chain"] for f in findings)
        assert all(f.article_paragraphs == ["Art. 15(4)"] for f in findings)
        assert "severity=high" in findings[0].description
        assert findings[0].file_path == ".mcp.json"
        assert "severity=medium" in findings[1].description
        assert findings[1].file_path == "src/agent.py"


class TestSarifIngestion:
    def test_ingest_semgrep_and_bandit_sarif_files(self, tmp_path: Path) -> None:
        semgrep_sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Semgrep OSS",
                            "rules": [
                                {
                                    "id": "python.lang.security.audit.eval-detected",
                                    "defaultConfiguration": {"level": "error"},
                                    "shortDescription": {"text": "Detected dynamic eval() call"},
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "python.lang.security.audit.eval-detected",
                            "level": "error",
                            "message": {"text": "Avoid eval() on LLM output."},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/tools.py"},
                                        "region": {
                                            "startLine": 42,
                                            "snippet": {"text": "eval(llm_response)"},
                                        },
                                    }
                                }
                            ],
                        },
                        {
                            "ruleId": "python.lang.security.audit.eval-detected",
                            "level": "error",
                            "message": {"text": "Suppressed finding should be ignored"},
                            "suppressions": [{"kind": "inSource", "justification": "Test fixture"}],
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "tests/test_eval.py"},
                                        "region": {"startLine": 9},
                                    }
                                }
                            ],
                        },
                        {
                            "ruleId": "python.lang.style.info",
                            "level": "note",
                            "message": {"text": "Informational note should be skipped"},
                        },
                    ],
                }
            ],
        }

        bandit_sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Bandit", "rules": []}},
                    "results": [
                        {
                            "ruleId": "B602",
                            "level": "warning",
                            "message": {"text": "subprocess call with shell=True identified"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "file:///app/runner.py"},
                                        "region": {"startLine": 19},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        p1 = tmp_path / "semgrep.sarif"
        p2 = tmp_path / "bandit.sarif.json"
        p1.write_text(json.dumps(semgrep_sarif), encoding="utf-8")
        p2.write_text(json.dumps(bandit_sarif), encoding="utf-8")

        findings, tools = ingest_sarif_files([p1, p2])
        assert tools == ["Semgrep OSS", "Bandit"]
        assert len(findings) == 2

        f_semgrep, f_bandit = findings
        assert f_semgrep.category == "external_security_sarif"
        assert f_semgrep.confidence == 0.90
        assert "severity=high" in f_semgrep.description
        assert f_semgrep.file_path == "src/tools.py"
        assert "eval(llm_response)" in f_semgrep.evidence_snippet
        assert f_semgrep.article_paragraphs == ["Art. 15(4)"]

        assert f_bandit.category == "external_security_sarif"
        assert f_bandit.confidence == 0.75
        assert "severity=medium" in f_bandit.description
        assert f_bandit.file_path == "app/runner.py"
        assert f_bandit.compliance_dimensions == ["security", "supply_chain"]

    def test_ingest_malformed_sarif_raises_clean_value_error(self, tmp_path: Path) -> None:
        bad_json = tmp_path / "broken.sarif"
        bad_json.write_text("{not valid json", encoding="utf-8")
        with pytest.raises(ValueError, match="broken.sarif"):
            ingest_sarif_files([bad_json])

        wrong_shape = tmp_path / "wrong.sarif"
        wrong_shape.write_text(json.dumps({"version": "2.1.0"}), encoding="utf-8")
        with pytest.raises(ValueError, match="wrong.sarif"):
            ingest_sarif_files([wrong_shape])

        missing = tmp_path / "missing.sarif"
        with pytest.raises(ValueError, match="missing.sarif"):
            ingest_sarif_files([missing])
