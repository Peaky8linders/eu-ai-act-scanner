"""Tests for interactive context graph visual generator (scanner.visual_graph)."""

from __future__ import annotations

from pathlib import Path

from scanner.models import ArchitectureNode, FileFinding, ScanResult
from scanner.visual_graph import build_graph_data, generate_visual_graph


def test_build_graph_data_with_architecture() -> None:
    scan = ScanResult(
        project_name="Demo-AI-System",
        is_ai_system=True,
        overall_compliance_pct=55.0,
        compliance_scores={
            "human_oversight": 20.0,
            "security": 80.0,
            "logging": 40.0,
        },
        inferred_roles=["deployer"],
        architecture=[
            ArchitectureNode(
                id="agent_execution",
                label="Agent Execution Runtime",
                type="agent_runtime",
                compliance_status="gap",
                connected_to=["human_oversight"],
                file_count=2,
            ),
            ArchitectureNode(
                id="human_oversight",
                label="Human Oversight Gate",
                type="guardrail",
                compliance_status="gap",
                connected_to=[],
                file_count=1,
            ),
        ],
        file_findings=[
            FileFinding(
                file_path="agent.py",
                gaps=["Missing autonomous tool invocation bounds"],
                compliance_dimensions=["human_oversight"],
                status="gap",
            )
        ],
    )

    data = build_graph_data(scan)
    assert data["project_name"] == "Demo-AI-System"
    assert data["is_ai_system"] is True
    assert data["total_nodes"] >= 2
    assert data["gap_nodes_count"] >= 1

    # Check node details
    nodes_by_id = {n["id"]: n for n in data["nodes"]}
    assert "human_oversight" in nodes_by_id
    ho = nodes_by_id["human_oversight"]
    assert ho["compliance_status"] == "gap"
    assert "Art. 14" in ho["article"]
    assert "Omnibus" in ho["omnibus_timeline"] or "Regulation (EU) 2026/1744" in ho["omnibus_timeline"]

    # Recommended fix is populated
    assert ho["recommended_fix"] is not None
    assert "human_oversight.py" in ho["recommended_fix"]["target_path"]
    assert "approval_gate" in ho["recommended_fix"]["code_snippet"].lower() or "override" in ho["recommended_fix"]["code_snippet"].lower()


def test_generate_visual_graph_html_output(tmp_path: Path) -> None:
    scan = ScanResult(
        project_name="Visual-Test",
        is_ai_system=True,
        overall_compliance_pct=65.0,
        compliance_scores={"risk_mgmt": 70.0, "transparency": 10.0},
    )

    out_file = tmp_path / "context_graph.html"
    html = generate_visual_graph(scan, output_path=out_file)

    assert "<!DOCTYPE html>" in html
    assert "EU AI Act Context Graph" in html
    assert "Visual-Test" in html
    assert "GRAPH_DATA" in html
    assert "tailwindcss.min.js" in html

    assert out_file.is_file()
    saved = out_file.read_text(encoding="utf-8")
    assert saved == html
