"""This repository's own GitHub Actions workflows.

Each workflow must parse and state its token permissions explicitly (the
default token is broad), CI must keep gating pushes and pull requests to main
with lint, type checks and tests, and no workflow may publish the engine to
PyPI: it ships inside the Claude Code plugin and runs through uv, and there is
no PyPI package (see tests/test_docs_install.py).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"
_FILES = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))


def _load(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{path.name} is not a YAML mapping"
    return data


def _triggers(workflow: dict) -> dict:
    # PyYAML reads the bare key `on` as the boolean True.
    on = workflow.get("on", workflow.get(True))
    return on if isinstance(on, dict) else {name: None for name in (on if isinstance(on, list) else [on])}


def test_workflows_exist() -> None:
    assert _FILES, "no workflows found; the glob or the folder moved"


@pytest.mark.parametrize("path", _FILES, ids=lambda p: p.name)
def test_workflow_parses_and_declares_permissions(path: Path) -> None:
    workflow = _load(path)
    assert workflow.get("jobs"), f"{path.name} has no jobs"
    assert "permissions" in workflow, f"{path.name} must declare top-level token permissions"


def test_ci_gates_main_with_lint_types_and_tests() -> None:
    ci = _load(WORKFLOWS / "ci.yml")
    triggers = _triggers(ci)
    for event in ("push", "pull_request"):
        assert event in triggers, f"CI no longer runs on {event}"
        assert "main" in (triggers[event] or {}).get("branches", []), f"CI {event} must cover main"
    runs = "\n".join(
        str(step.get("run", "")) for job in ci["jobs"].values() for step in job.get("steps", [])
    )
    for command in ("ruff check", "mypy", "pytest"):
        assert command in runs, f"CI no longer runs {command}"


def test_ci_tests_every_listed_python_and_the_plugin_floor() -> None:
    """CI tests each Python the package lists, from requires-python to the latest release,
    including the minimum the plugin asks uv for."""
    root = WORKFLOWS.parent.parent
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    listed = set(re.findall(r'"Programming Language :: Python :: (3\.\d+)"', pyproject))
    floor = re.search(r'requires-python = ">=(3\.\d+)"', pyproject)
    assert floor is not None
    matrix = {str(v) for v in _load(WORKFLOWS / "ci.yml")["jobs"]["test"]["strategy"]["matrix"]["python-version"]}
    assert listed == matrix, "classifiers and the CI matrix list different Pythons"
    assert floor.group(1) in matrix, "CI must test the requires-python minimum"

    manifest = json.loads((root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    args = manifest["mcpServers"][manifest["name"]]["args"]
    plugin_floor = args[args.index("--python") + 1].removeprefix(">=")
    assert plugin_floor in matrix, "CI must test the Python the plugin asks uv for"


def test_ci_starts_the_plugin_mcp_server_on_every_os() -> None:
    """The plugin's uvx-started server is checked on each OS with a cold uv cache."""
    job = _load(WORKFLOWS / "ci.yml")["jobs"]["plugin-mcp"]
    assert set(job["strategy"]["matrix"]["os"]) == {"ubuntu-latest", "macos-latest", "windows-latest"}
    steps = job["steps"]
    setup_uv = next(step for step in steps if str(step.get("uses", "")).startswith("astral-sh/setup-uv@"))
    assert setup_uv.get("with", {}).get("enable-cache") is False, "a warm cache would hide first-start time"
    assert any("scripts/check_plugin_mcp.py" in str(step.get("run", "")) for step in steps)


@pytest.mark.parametrize("path", _FILES, ids=lambda p: p.name)
def test_no_workflow_publishes_to_pypi(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for marker in ("pypa/gh-action-pypi-publish", "twine upload", "uv publish"):
        assert marker not in text, f"{path.name} publishes to PyPI ({marker}); the engine ships with the plugin"
