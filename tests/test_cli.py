"""CLI contract tests — the surface users actually call.

Focused on behaviours a unit test of the underlying module cannot catch:
argument combinations, exit codes, and which stream a message goes to.
"""

from __future__ import annotations

import json

from scanner.cli import main

FIXTURE = "tests/fixtures/sample_project"


def test_dossier_and_graph_together_write_both(tmp_path) -> None:
    """Both are additive writers — an early return used to drop the second."""
    dossier = tmp_path / "dossier.json"
    graph = tmp_path / "graph.html"
    code = main([FIXTURE, "--dossier", str(dossier), "--graph", str(graph)])
    assert code == 0
    assert dossier.is_file() and dossier.stat().st_size > 0
    assert graph.is_file() and graph.stat().st_size > 0


def test_dossier_alone_suppresses_the_json_dump(tmp_path, capsys) -> None:
    dossier = tmp_path / "dossier.json"
    assert main([FIXTURE, "--dossier", str(dossier)]) == 0
    out = capsys.readouterr().out
    assert "dossier written to" in out
    assert "compliance_scores" not in out  # no ScanResult dump


def test_article_filter_accepts_display_spelling(capsys) -> None:
    assert main([FIXTURE, "--article", "Art. 15"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["dimensions"], "article lookup must resolve 'Art. 15'"
    assert "nist_ai_rmf" in payload["frameworks"]


def test_article_filter_rejects_unknown_article(capsys) -> None:
    assert main([FIXTURE, "--article", "art999"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "error" in payload


def test_cross_framework_flag_emits_projection(capsys) -> None:
    assert main([FIXTURE, "--cross-framework"]) == 0
    payload = json.loads(capsys.readouterr().out)
    projection = payload["cross_framework_projection"]
    assert projection["catalogue_version"]
    assert projection["total_frameworks_mapped"] == 11
    assert projection["unmapped_dimensions"] == []
