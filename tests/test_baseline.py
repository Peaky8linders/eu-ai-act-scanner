"""Tests for scanner.baseline — atomic local baseline saving and diffing."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from scanner.baseline import diff_baseline, format_baseline_diff, save_baseline
from scanner.models import DiscoveredComponent, ScanResult

_URL_RE = re.compile(r"https?://")


def _make_scan(
    *,
    overall: float,
    scores: dict[str, float],
    gaps: list[tuple[str, str, str, float]],
    is_ai_system: bool = True,
) -> ScanResult:
    components = [
        DiscoveredComponent(
            name=title,
            component_type=comp_type,
            file_path=file_path,
            confidence=confidence,
            compliance_dimensions=["security"],
            compliance_impact="gap",
        )
        for comp_type, title, file_path, confidence in gaps
    ]
    return ScanResult(
        project_name="demo-agent",
        scanner_version="0.11.3",
        is_ai_system=is_ai_system,
        overall_compliance_pct=overall,
        compliance_scores=scores,
        components=components,
    )


class TestBaselineSaveAndDiff:
    def test_atomic_save_creates_valid_json_with_no_temp_artifacts(self, tmp_path: Path) -> None:
        baseline_file = tmp_path / ".ai-act" / "baseline.json"
        scan = _make_scan(
            overall=40.0,
            scores={"security": 30.0, "logging": 50.0},
            gaps=[
                ("security_controls", "Hardcoded secret", "src/cfg.py", 0.92),
                ("logging_monitoring", "No correlation IDs", "src/app.py", 0.75),
            ],
        )

        saved = save_baseline(scan, baseline_file)
        assert saved == baseline_file
        assert baseline_file.is_file()

        # No leftover temporary files from atomic write
        siblings = [p.name for p in baseline_file.parent.iterdir()]
        assert siblings == ["baseline.json"]

        data = json.loads(baseline_file.read_text(encoding="utf-8"))
        assert data["overall_score"] == 40.0
        assert data["is_ai_system"] is True
        assert data["dimension_scores"] == {"logging": 50.0, "security": 30.0}
        assert len(data["gaps"]) == 2
        assert {g["title"] for g in data["gaps"]} == {"Hardcoded secret", "No correlation IDs"}

    def test_diff_detects_score_delta_fixed_new_and_unchanged_gaps(self, tmp_path: Path) -> None:
        baseline_file = tmp_path / ".ai-act-baseline.json"
        before = _make_scan(
            overall=40.0,
            scores={"security": 30.0, "logging": 50.0},
            gaps=[
                ("security_controls", "Hardcoded secret", "src/cfg.py", 0.92),
                ("logging_monitoring", "No correlation IDs", "src/app.py", 0.75),
            ],
        )
        save_baseline(before, baseline_file)

        after = _make_scan(
            overall=55.5,
            scores={"security": 65.0, "logging": 50.0, "transparency": 51.5},
            gaps=[
                ("logging_monitoring", "No correlation IDs", "src/app.py", 0.75),
                ("mcp_toolchain", "Unpinned MCP server", ".mcp.json", 0.80),
            ],
        )
        original_confidences = [c.confidence for c in after.components]

        diff = diff_baseline(after, baseline_file)
        # Never mutates scanner confidence scores
        assert [c.confidence for c in after.components] == original_confidences

        assert diff["score_delta"] == 15.5
        assert diff["baseline_overall_score"] == 40.0
        assert diff["current_overall_score"] == 55.5
        assert diff["unchanged_gap_count"] == 1
        assert [g["title"] for g in diff["fixed_gaps"]] == ["Hardcoded secret"]
        assert [g["title"] for g in diff["new_gaps"]] == ["Unpinned MCP server"]
        assert diff["dimension_deltas"] == {
            "logging": 0.0,
            "security": 35.0,
            "transparency": 51.5,
        }

        formatted = format_baseline_diff(diff)
        assert "+15.5 pts" in formatted
        assert "[FIXED] Hardcoded secret" in formatted
        assert "[NEW] Unpinned MCP server" in formatted
        assert "`security`: `+35.0 pts`" in formatted
        assert not _URL_RE.search(formatted)

    def test_diff_missing_or_malformed_baseline_raises_clean_errors(self, tmp_path: Path) -> None:
        scan = _make_scan(overall=50.0, scores={"security": 50.0}, gaps=[])
        with pytest.raises(FileNotFoundError):
            diff_baseline(scan, tmp_path / "does-not-exist.json")

        broken = tmp_path / "broken.json"
        broken.write_text("{bad json", encoding="utf-8")
        with pytest.raises(ValueError, match="broken.json"):
            diff_baseline(scan, broken)

        incomplete = tmp_path / "incomplete.json"
        incomplete.write_text(json.dumps({"schema_version": "1.0"}), encoding="utf-8")
        with pytest.raises(ValueError, match="incomplete.json"):
            diff_baseline(scan, incomplete)
