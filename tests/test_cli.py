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
    assert projection["total_frameworks_mapped"] == 12
    assert projection["unmapped_dimensions"] == []


def _agentic_project(path) -> None:
    """Minimal LangChain project that triggers the agent-aware analyzers."""
    (path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "from langchain_openai import ChatOpenAI\n",
        encoding="utf-8",
    )


def test_markdown_separates_act_required_from_paper_suggested(tmp_path, capsys) -> None:
    """A reader must be able to tell legal duties from paper guidance without
    inspecting the taxonomy source."""
    _agentic_project(tmp_path)
    assert main([str(tmp_path), "--markdown"]) == 0
    out = capsys.readouterr().out
    assert "## Agentic recommendation provenance" in out
    assert "### Required by the AI Act" in out
    assert "### Suggested by the paper (not Act-required)" in out
    assert "_(Art. " in out, "Act-required rows must cite the provision"
    assert "_(paper" in out, "paper rows must cite the paper, not an article"


def test_json_surfaces_tagged_agentic_recommendations(tmp_path, capsys) -> None:
    _agentic_project(tmp_path)
    assert main([str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    recs = payload["agentic_recommendations"]
    assert recs, "agentic fixture should populate the tagged field"
    assert {r["source"] for r in recs} == {"act_required", "paper_suggested"}
    assert all(r["ref"] and r["risk_id"] for r in recs)


def test_founder_flag_emits_brief_and_json(capsys) -> None:
    assert main([FIXTURE, "--founder"]) == 0
    brief = capsys.readouterr().out
    assert "# Founder AI Compliance Brief" in brief
    assert "Fix Before Shipping" in brief
    assert len(brief.splitlines()) < 50

    assert main([FIXTURE, "--founder", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["is_ai_system"] is True
    assert "ship_now" in payload
    assert "enterprise_deals" in payload
    assert "later_2027" in payload
    assert "brief_markdown" in payload


def test_sarif_export_writes_offline_sarif(tmp_path, capsys) -> None:
    sarif_out = tmp_path / "report.sarif.json"
    assert main([FIXTURE, "--sarif", str(sarif_out)]) == 0
    out = capsys.readouterr().out
    assert "SARIF 2.1.0 report written to" in out
    assert sarif_out.is_file()
    doc = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert "$schema" not in doc
    assert doc["runs"][0]["tool"]["driver"]["name"] == "antifragile-harness"


def test_ingest_sarif_merges_external_findings(tmp_path, capsys) -> None:
    sarif_file = tmp_path / "semgrep.sarif"
    sarif_file.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "Semgrep"}},
                        "results": [
                            {
                                "ruleId": "python.lang.security.audit.exec-detected",
                                "level": "error",
                                "message": {"text": "Detected dynamic exec call"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {"startLine": 12},
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
    assert main([FIXTURE, "--ingest-sarif", str(sarif_file), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert any("Semgrep" in c["name"] for c in payload["components"])


def test_ingest_compliance_api_and_claude_security(tmp_path, capsys) -> None:
    cca_file = tmp_path / "compliance-api.json"
    cca_file.write_text(
        json.dumps(
            {
                "api_version": "2026-10-21",
                "retention_days": 30,
                "activities": [{"event_id": "evt-1", "event_type": "login"}],
                "groups": [{"id": "grp-1", "name": "ai-reviewers"}],
                "user_preferences": [
                    {
                        "user_id": "u-1",
                        "instructions": "Never disclose that you are an AI assistant.",
                    }
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
                        "id": "CS-01",
                        "title": "Unauthenticated admin prompt route",
                        "severity": "high",
                        "file_path": "routes/admin.py",
                        "line": 44,
                        "verified": True,
                    },
                    {
                        "id": "CS-02",
                        "title": "Refuted SQLi false positive",
                        "severity": "critical",
                        "file_path": "routes/db.py",
                        "line": 10,
                        "status": "mitigated",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    code = main(
        [
            FIXTURE,
            "--ingest-compliance-api",
            str(cca_file),
            "--ingest-claude-security",
            str(cs_file),
            "--json",
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    names = [c["name"] for c in payload["components"]]
    assert any("Unsafe bypass directives in Claude user preferences" in n for n in names)
    assert any("Unauthenticated admin prompt route" in n for n in names)
    assert not any("Refuted SQLi false positive" in n for n in names)


def test_save_and_diff_baseline(tmp_path, capsys) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text(
        "import openai\n"
        "def chat(msg):\n"
        "    return openai.chat.completions.create(model='gpt-4o', messages=[{'role': 'user', 'content': msg}])\n",
        encoding="utf-8",
    )
    baseline_file = tmp_path / "baseline.json"
    assert main([str(proj), "--save-baseline", str(baseline_file)]) == 0
    out = capsys.readouterr().out
    assert "Baseline snapshot saved to" in out
    assert baseline_file.is_file()

    # Add structured logging to improve score
    (proj / "logging_setup.py").write_text(
        "import structlog\nlogger = structlog.get_logger()\n",
        encoding="utf-8",
    )
    assert main([str(proj), "--diff-baseline", str(baseline_file), "--json"]) == 0
    diff = json.loads(capsys.readouterr().out)
    assert "score_delta" in diff
    assert "dimension_deltas" in diff
    assert diff["dimension_deltas"].get("logging", 0.0) > 0.0

    # Also verify markdown diff rendering
    assert main([str(proj), "--diff-baseline", str(baseline_file)]) == 0
    md = capsys.readouterr().out
    assert "# Baseline Diff" in md


def test_fix_startup_profile_dry_run(tmp_path, capsys) -> None:
    (tmp_path / "app.py").write_text(
        "import openai\n"
        "def chat(msg):\n"
        "    return openai.chat.completions.create(model='gpt-4o', messages=[{'role': 'user', 'content': msg}])\n",
        encoding="utf-8",
    )
    assert main([str(tmp_path), "--fix", "--startup", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["applied"] == []
    assert payload["proposals"]
    # Startup profile prioritizes live Art. 50 / tool_governance / security ahead of Dec 2027 docs
    first_dim = payload["proposals"][0]["dimension"]
    assert first_dim in {"content_transparency", "transparency", "tool_governance", "security", "access_control"}


def test_benchmark_flag_outputs_metrics(capsys) -> None:
    assert main(["--benchmark", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["corpus_size"] >= 20
    assert payload["precision"] >= 0.9
    assert payload["recall"] >= 0.9
    assert payload["f1"] >= 0.9

    assert main(["--benchmark"]) == 0
    md = capsys.readouterr().out
    assert "# Antifragile Harness — Accuracy Benchmark" in md
    assert "Per-analyzer breakdown" in md
