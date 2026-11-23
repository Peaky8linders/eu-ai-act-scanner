"""scripts/check_plugin_mcp.py: the CI check that starts the plugin's MCP server.

These tests cover how it builds the command and judges the tool list. They
start no server; CI's `plugin-mcp` job does that on Linux, macOS and Windows.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_script() -> ModuleType:
    path = REPO_ROOT / "scripts" / "check_plugin_mcp.py"
    spec = importlib.util.spec_from_file_location("check_plugin_mcp", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = _load_script()


def test_command_is_the_manifest_server_with_the_plugin_root_filled_in() -> None:
    command = check.server_command(REPO_ROOT)
    manifest = json.loads((REPO_ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    server = manifest["mcpServers"][manifest["name"]]
    assert command[0] == server["command"] == "uvx"
    assert command[-1] == "antifragile-scan-mcp"
    assert REPO_ROOT.as_posix() in command
    assert not any("${" in part for part in command), command


def test_command_follows_the_root_it_is_given(tmp_path: Path) -> None:
    (tmp_path / ".claude-plugin").mkdir()
    (tmp_path / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({
            "name": "demo",
            "mcpServers": {"demo": {"command": "uvx", "args": ["--from", "${CLAUDE_PLUGIN_ROOT}", "srv"]}},
        }),
        encoding="utf-8",
    )
    assert check.server_command(tmp_path) == ["uvx", "--from", tmp_path.as_posix(), "srv"]


def test_expected_tool_count_comes_from_the_readme_claim() -> None:
    assert check.claimed_tool_count(REPO_ROOT) >= len(check.REQUIRED_TOOLS)


def test_tool_list_is_judged_against_the_claim() -> None:
    good = ["founder_triage", "scan_project", "incidents"]
    assert check.check_tools(good, expected=3) == []

    problems = check.check_tools(["scan_project", "incidents", "get_article"], expected=3)
    assert problems == ["missing tools: ['founder_triage']"]

    assert check.check_tools(good, expected=13) == ["3 tools listed, README claims 13"]
