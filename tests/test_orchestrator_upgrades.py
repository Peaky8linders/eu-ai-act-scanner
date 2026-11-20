"""Tests for Wave 2A orchestrator upgrades.

Covers:
1. `_recover_line_number`: exact match, >=40-char prefix match with ellipsis,
   short-prefix guard, never overwriting analyzer-pinned lines, shared cache.
2. Allowlisted `.claude/` config loading via `_collect_agent_config_files`:
   reads only allowlisted project configs, skips worktrees/state/memory/local,
   enforces size cap + symlink escape check, and never inflates `total_files`.
3. Deduplicated `risk_indicators` with shortened file paths and `(+N more)`.
4. `ArchitectureNode.finding_count` and `emits_gaps=False` -> `"info"`.
5. `line_number` and `matched_pattern` populated on `FileFinding` and `DiscoveredComponent`.
6. `external_findings` + `external_sources` ingestion into `scan_project(...)`.
7. `role` threaded into `ctx.extracted_role` activating `regulatory_perimeter`'s `rp-role-mismatch`.
"""

from __future__ import annotations

import os
from pathlib import Path

from scanner.analyzers._base import AnalyzerResult, Finding
from scanner.orchestrator import (
    _MAX_AGENT_CONFIG_BYTES,
    _collect_agent_config_files,
    _recover_line_number,
    scan_project,
)


def _sample_finding(**overrides) -> Finding:
    base = {
        "id": "f-1",
        "category": "security_controls",
        "title": "Sample gap",
        "description": "Sample description",
        "file_path": "src/app.py",
        "confidence": 0.9,
        "compliance_impact": "gap",
        "compliance_dimensions": ["security"],
        "evidence_snippet": "",
        "matched_pattern": "sample_pat",
    }
    base.update(overrides)
    return Finding(**base)


# ─── 1. _recover_line_number ─────────────────────────────────────────────────


def test_recover_line_number_exact_and_cached():
    files = {
        "src/app.py": (
            "import os\n"
            "    secret_token = 'abc123'\n"
            "print('done')\n"
        )
    }
    cache: dict[str, list[str]] = {}
    f = _sample_finding(evidence_snippet="secret_token = 'abc123'")
    recovered = _recover_line_number(f, files, cache)

    assert recovered.line_number == 2
    assert "src/app.py" in cache
    assert len(cache["src/app.py"]) == 4


def test_recover_line_number_prefix_with_ellipsis_and_short_guard():
    long_line = "    result = execute_untrusted_shell_command(user_prompt_payload, timeout=30, capture_output=True)"
    files = {
        "src/app.py": (
            "import osmnx\n"
            f"{long_line}\n"
        )
    }
    # >= 40-char prefix with trailing '...' recovers line 2.
    truncated_ascii = long_line.strip()[:52] + "..."
    assert _recover_line_number(_sample_finding(evidence_snippet=truncated_ascii), files).line_number == 2

    # >= 40-char prefix with unicode ellipsis '…' recovers line 2.
    truncated_unicode = long_line.strip()[:48] + "…"
    assert _recover_line_number(_sample_finding(evidence_snippet=truncated_unicode), files).line_number == 2

    # Short prefix (< 40 chars) must NOT falsely match 'import osmnx'.
    short = _sample_finding(evidence_snippet="import os")
    assert _recover_line_number(short, files).line_number is None


def test_recover_line_number_never_overwrites_existing_pin():
    files = {"src/app.py": "alpha = 1\nbeta = 2\n"}
    pinned = _sample_finding(line_number=99, evidence_snippet="alpha = 1")
    out = _recover_line_number(pinned, files)
    assert out.line_number == 99


# ─── 2. Allowlisted .claude/ agent_config_files ──────────────────────────────


def test_collect_agent_config_files_allowlist_and_exclusions(tmp_path: Path):
    proj = tmp_path / "repo"
    proj.mkdir()

    # Allowlisted files
    (proj / ".claude" / "hooks").mkdir(parents=True)
    (proj / ".claude" / "commands").mkdir(parents=True)
    (proj / ".claude" / "settings.json").write_text('{"permissions": {"deny": ["Read(.env)"]}}', encoding="utf-8")
    (proj / ".claude" / "hooks" / "guard.json").write_text('{"PreToolUse": []}', encoding="utf-8")
    (proj / ".claude" / "commands" / "security-review.md").write_text("# Security Review\n", encoding="utf-8")
    (proj / ".claude" / "security-scan-instructions.md").write_text("# Scan Instructions\n", encoding="utf-8")
    (proj / ".claude" / "false-positive-filter.md").write_text("# FP Filter\n", encoding="utf-8")
    (proj / ".claude" / "threat-model.md").write_text("# Threat Model\n", encoding="utf-8")

    # Explicitly skipped directories & local settings
    (proj / ".claude" / "settings.local.json").write_text('{"bypassPermissions": true}', encoding="utf-8")
    (proj / ".claude" / "worktrees" / "wt1").mkdir(parents=True)
    (proj / ".claude" / "worktrees" / "wt1" / "settings.json").write_text('{"bypassPermissions": true}', encoding="utf-8")
    (proj / ".claude" / "hooks" / "state").mkdir(parents=True)
    (proj / ".claude" / "hooks" / "state" / "last.json").write_text('{"ts": 1}', encoding="utf-8")
    (proj / ".claude" / "memory").mkdir(parents=True)
    (proj / ".claude" / "memory" / "notes.md").write_text("# Private memory\n", encoding="utf-8")
    (proj / ".claude" / "hooks" / "notes.txt").write_text("not json\n", encoding="utf-8")

    # Oversized file must be skipped
    (proj / ".claude" / "commands" / "huge.md").write_text("x" * (_MAX_AGENT_CONFIG_BYTES + 10), encoding="utf-8")

    collected = _collect_agent_config_files(proj)
    assert set(collected.keys()) == {
        ".claude/settings.json",
        ".claude/hooks/guard.json",
        ".claude/commands/security-review.md",
        ".claude/security-scan-instructions.md",
        ".claude/false-positive-filter.md",
        ".claude/threat-model.md",
    }


def test_collect_agent_config_files_blocks_symlink_escape(tmp_path: Path, monkeypatch):
    proj = tmp_path / "repo"
    (proj / ".claude").mkdir(parents=True)
    outside = tmp_path / "outside_secret.json"
    outside.write_text('{"bypassPermissions": true}', encoding="utf-8")
    link = proj / ".claude" / "settings.json"
    try:
        os.symlink(outside, link)
    except OSError:
        # Windows hosts without Developer Mode disallow os.symlink; simulate
        # a symlink resolving outside the project root so the guard is still verified.
        link.write_text('{"bypassPermissions": true}', encoding="utf-8")
        orig_resolve = Path.resolve

        def _fake_resolve(self: Path, strict: bool = False) -> Path:
            if self.name == "settings.json" and self.parent.name == ".claude":
                return orig_resolve(outside, strict=strict)
            return orig_resolve(self, strict=strict)

        monkeypatch.setattr(Path, "resolve", _fake_resolve)

    collected = _collect_agent_config_files(proj)
    assert ".claude/settings.json" not in collected


def test_scan_project_loads_claude_configs_without_counting_in_total_files(tmp_path: Path):
    proj = tmp_path / "ai_repo"
    proj.mkdir()
    (proj / "agent.py").write_text("import openai\nclient = openai.OpenAI()\n", encoding="utf-8")

    base = scan_project(proj)
    assert base.total_files == 1

    # Add allowlisted .claude/ configs AND excluded .claude/worktrees/
    (proj / ".claude" / "worktrees" / "copy").mkdir(parents=True)
    (proj / ".claude" / "worktrees" / "copy" / "agent.py").write_text("import torch\n", encoding="utf-8")
    (proj / ".claude" / "settings.json").write_text(
        '{"permissions": {"deny": ["Read(.env)"]}, '
        '"enabledPlugins": {"claude-security@claude-plugins-official": true}}',
        encoding="utf-8",
    )
    (proj / ".claude" / "threat-model.md").write_text("# Threat Model\n", encoding="utf-8")

    with_claude = scan_project(proj)
    # Hard invariant: total_files MUST NOT include any .claude/* files!
    assert with_claude.total_files == base.total_files == 1

    # Yet claude_code_security analyzer received the allowlisted configs via ctx.agent_config_files!
    comp_names = {c.name for c in with_claude.components}
    assert "Official Claude Code Security plugin enabled" in comp_names
    assert "Repository threat model documented for AI security review" in comp_names
    assert "Least-privilege Claude Code deny rules configured" in comp_names


# ─── 3. Deduplicated risk_indicators with shortened paths & (+N more) ────────


def _make_clean_ai_project(proj: Path) -> None:
    """Create a well-evidenced AI repo with few built-in gaps so new gaps surface in top-10 risk_indicators."""
    proj.mkdir(parents=True, exist_ok=True)
    (proj / "README.md").write_text(
        "# AI Service\n## Installation\npip install .\n"
        "## API\nCall predict().\n## License\nMIT\n",
        encoding="utf-8",
    )
    (proj / "MODEL_CARD.md").write_text(
        "# Model Card\n## Intended use\nDemo\n## Limitations\nNone\n"
        "## Metrics\n95%\n## Training data\nPublic\n## Evaluation\nHoldout\n",
        encoding="utf-8",
    )
    (proj / "tests").mkdir(exist_ok=True)
    (proj / "tests" / "test_agent.py").write_text(
        "import pytest\ndef test_ok():\n    assert True\n",
        encoding="utf-8",
    )
    (proj / "agent.py").write_text(
        "import structlog\n"
        "import torch\n"
        "import torch.nn as nn\n"
        "from fastapi import Depends\n"
        "from pydantic import BaseModel\n"
        "logger = structlog.get_logger(__name__)\n"
        "def approval_gate(pred, confidence):\n"
        '    """Gate low-confidence outputs for human review."""\n'
        "    return pred if confidence > 0.7 else None\n"
        "raw_query = f'SELECT * FROM users WHERE id = {user_input}'\n",
        encoding="utf-8",
    )


def test_deduplicated_risk_indicators_with_count_and_short_path(tmp_path: Path):
    proj = tmp_path / "multi_gap"
    _make_clean_ai_project(proj)

    ext_gaps = [
        _sample_finding(
            id=f"ext-{i}",
            category="external_sast",
            title="Unsanitized SQL query built from LLM output",
            file_path=f"services/backend/api/v{i}/handler.py",
            compliance_impact="gap",
            compliance_dimensions=["security"],
            line_number=10 + i,
            matched_pattern="sast_sql_injection",
        )
        for i in range(1, 4)
    ]

    res = scan_project(
        proj,
        external_findings=ext_gaps,
        external_sources=["sarif:semgrep"],
    )

    matching = [ri for ri in res.risk_indicators if "Unsanitized SQL query" in ri]
    assert len(matching) == 1, f"Expected deduplicated single entry, got {matching}"
    # Shortened to last 3 path segments + (+2 more)
    assert "api/v1/handler.py" in matching[0]
    assert "services/backend/" not in matching[0]
    assert "(+2 more)" in matching[0]


# ─── 4. External findings integration + line_number/matched_pattern + finding_count ─


def test_external_findings_integration_and_model_fields(tmp_path: Path):
    proj = tmp_path / "ext_app"
    _make_clean_ai_project(proj)

    baseline = scan_project(proj)
    assert baseline.compliance_scores.get("security", 0.0) > 0.0

    ext_finding = Finding(
        id="claude-sec-001",
        category="claude_security",
        title="Prompt-injected SQL query construction",
        description="User-controlled LLM output flows directly into SQL query.",
        file_path="agent.py",
        confidence=0.95,
        compliance_impact="gap",
        compliance_dimensions=["security"],
        evidence_snippet="raw_query = f'SELECT * FROM users WHERE id = {user_input}'",
        matched_pattern="claude_security_sql_injection",
    )

    with_ext = scan_project(
        proj,
        external_findings=[ext_finding],
        external_sources=["claude-code-security"],
    )

    assert with_ext.external_security_sources == ["claude-code-security"]
    assert with_ext.compliance_scores["security"] < baseline.compliance_scores["security"]
    assert with_ext.overall_compliance_pct < baseline.overall_compliance_pct

    # ArchitectureNode carries finding_count
    ext_node = next(n for n in with_ext.architecture if n.id == "external_security")
    assert ext_node.finding_count == 1
    assert ext_node.compliance_status == "gap"

    # Line number recovered from agent.py line 10 & matched_pattern propagated
    comp = next(c for c in with_ext.components if c.name == "Prompt-injected SQL query construction")
    assert comp.line_number == 10
    assert comp.matched_pattern == "claude_security_sql_injection"

    ff = next(f for f in with_ext.file_findings if f.file_path == "agent.py")
    assert "Prompt-injected SQL query construction" in ff.gaps
    assert ff.line_number is not None
    assert ff.matched_pattern != ""


def test_architecture_node_info_status_when_emits_gaps_is_false(tmp_path: Path, monkeypatch):
    proj = tmp_path / "info_node"
    proj.mkdir()
    (proj / "agent.py").write_text("import openai\n", encoding="utf-8")

    import scanner.orchestrator as orch

    orig_run = orch.run_all_analyzers

    def _patched_run(ctx):
        results = orig_run(ctx)
        results.append(
            AnalyzerResult(
                analyzer_id="info_only_probe",
                label="Info Only Probe",
                findings=[
                    _sample_finding(
                        id="info-1",
                        category="info_only_probe",
                        title="Informational signal",
                        file_path="agent.py",
                        compliance_impact="neutral",
                        compliance_dimensions=["tech_docs"],
                    )
                ],
                score=100.0,
                file_count=1,
                metadata={"emits_gaps": False},
            )
        )
        return results

    monkeypatch.setattr(orch, "run_all_analyzers", _patched_run)
    res = scan_project(proj)
    node = next(n for n in res.architecture if n.id == "info_only_probe")
    assert node.compliance_status == "info"
    assert node.finding_count == 1


# ─── 5. role -> ctx.extracted_role -> rp-role-mismatch ───────────────────────


def test_role_threaded_into_extracted_role_triggers_role_mismatch(tmp_path: Path):
    """Declaring role='deployer' on a repo with distributable CLI entry points triggers rp-role-mismatch."""
    proj = tmp_path / "cli_provider"
    _make_clean_ai_project(proj)
    (proj / "pyproject.toml").write_text(
        '[project]\nname = "my-ai-cli"\n\n[project.scripts]\nmy-ai = "agent:main"\n',
        encoding="utf-8",
    )

    # Without explicit role, no role-mismatch finding is emitted.
    no_role = scan_project(proj)
    assert not any(
        "Declared operator role disagrees" in c.name for c in no_role.components
    )

    # Passing role="deployer" threads extracted_role="deployer" into regulatory_perimeter.
    mismatch_res = scan_project(proj, role="deployer")
    assert any(
        "Declared operator role disagrees" in c.name for c in mismatch_res.components
    )
    assert any(
        "Declared operator role disagrees" in ri for ri in mismatch_res.risk_indicators
    )

    # Passing role="provider" agrees with the CLI entry point -> no mismatch.
    provider_res = scan_project(proj, role="provider")
    assert not any(
        "Declared operator role disagrees" in c.name for c in provider_res.components
    )
