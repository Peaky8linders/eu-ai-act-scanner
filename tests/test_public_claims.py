"""Public claims must match the code (pattern ported from legit-ai's
``test_public_claims_match_code.py``).

The README once said "12 frameworks" while listing "EU Digital Omnibus
alignment" (not a framework in the code) and leaving out NIST AI 600-1; the CLI
help named five frameworks and an MCP docstring eight; four files advertised a
17-tool MCP server after it shrank. These tests tie each claim to the code.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from scanner.data.frameworks import CANONICAL_FRAMEWORK_IDS

REPO_ROOT = Path(__file__).resolve().parent.parent

# How each canonical framework is named in prose.
_PROSE_NAME = {
    "nist_ai_rmf": "NIST AI RMF",
    "iso_42001": "ISO/IEC 42001",
    "owasp_llm": "OWASP LLM",
    "owasp_agentic": "OWASP Agentic",
    "mitre_atlas": "MITRE ATLAS",
    "nist_ai_600_1": "NIST AI 600-1",
    "csa_aicm": "CSA AICM",
    "gdpr": "GDPR",
    "soc2": "SOC 2",
    "iso_27002": "ISO 27002",
    "nist_sp_800_53": "NIST SP 800-53",
    "cen_cenelec_jtc21": "EN 18286",
}


def _readme() -> str:
    return (REPO_ROOT / "README.md").read_text(encoding="utf-8")


def test_every_canonical_framework_has_a_prose_name() -> None:
    assert set(_PROSE_NAME) == set(CANONICAL_FRAMEWORK_IDS)


def test_readme_framework_claim_matches_the_catalogue() -> None:
    line = next(ln for ln in _readme().splitlines() if "framework projection, not label soup" in ln)
    count = int(re.search(r"(\d+) frameworks", line).group(1))
    assert count == len(CANONICAL_FRAMEWORK_IDS)
    missing = [name for name in _PROSE_NAME.values() if name not in line]
    assert not missing, f"README framework list omits {missing}"
    assert "Digital Omnibus alignment" not in line  # a regulation, not a projected framework


def test_cli_help_framework_count_matches() -> None:
    cli = (REPO_ROOT / "scanner" / "cli.py").read_text(encoding="utf-8")
    assert f"across {len(CANONICAL_FRAMEWORK_IDS)} frameworks" in cli


def test_advertised_mcp_tool_counts_match_registered_tools() -> None:
    pytest.importorskip("mcp")
    import asyncio

    import scanner.mcp_server as m

    count = len(asyncio.run(m.build_server().list_tools()))
    claims = {
        "README.md": rf"\*\*{count} MCP Tools:\*\*",
        "pyproject.toml": rf"a {count}-tool MCP server",
        ".claude-plugin/plugin.json": rf"{count}-tool MCP server",
    }
    for rel, pattern in claims.items():
        assert re.search(pattern, (REPO_ROOT / rel).read_text(encoding="utf-8")), rel
    mcp_desc = json.loads((REPO_ROOT / ".mcp.json").read_text(encoding="utf-8"))
    assert f"{count} tools" in mcp_desc["mcpServers"]["antifragile-harness"]["description"]
    for rel in ("README.md", "pyproject.toml", ".claude-plugin/plugin.json", ".mcp.json"):
        assert not re.search(r"\b17[- ]tool", (REPO_ROOT / rel).read_text(encoding="utf-8")), rel
