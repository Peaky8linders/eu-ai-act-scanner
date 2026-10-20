"""Scanning must not depend on where the project happens to live.

The file walker matched excluded directory names against the **absolute** path,
so a checkout under `.freebuff/`, a project under `build/` or anything beneath a
`.venv/` (e.g. a tox/venv-managed checkout) produced a zero-file, out-of-scope
report. Exclusions are now matched against the path *relative to the scan root*:
ancestors are irrelevant, directories inside the project are still skipped.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from scanner.dossier import generate_dossier
from scanner.models import ScanResult
from scanner.orchestrator import scan_project

FIXTURE = Path(__file__).parent / "fixtures" / "sample_project"


@pytest.fixture(scope="module")
def baseline_files() -> int:
    """Files the fixture contributes when scanned at its natural path."""
    return scan_project(FIXTURE).total_files


def _copy_fixture(destination: Path) -> Path:
    shutil.copytree(FIXTURE, destination)
    return destination


@pytest.mark.parametrize("ancestor", [".hidden", ".freebuff", "build", "dist", ".venv", ".claude"])
def test_project_under_an_excluded_ancestor_still_scans(
    tmp_path: Path, ancestor: str, baseline_files: int
) -> None:
    """An ancestor's name says nothing about the project being scanned."""
    project = _copy_fixture(tmp_path / ancestor / "my-ai-app")

    result = scan_project(project)

    assert result.total_files == baseline_files
    assert result.is_ai_system is True


def test_scan_root_itself_named_like_an_excluded_dir_still_scans(
    tmp_path: Path, baseline_files: int
) -> None:
    """The root's own name is an ancestor of every file, not a path component."""
    project = _copy_fixture(tmp_path / "build")

    result = scan_project(project)

    assert result.total_files == baseline_files
    assert result.is_ai_system is True


def test_excluded_directories_below_the_root_are_still_skipped(
    tmp_path: Path, baseline_files: int
) -> None:
    """Relative matching must not weaken the exclusions it was written for."""
    project = _copy_fixture(tmp_path / "app")
    excluded = (
        "node_modules/pkg/index.js",
        ".venv/lib/site.py",
        "build/out.py",
        "dist/bundle.js",
        "__pycache__/mod.cpython-312.pyc",
        ".git/config",
        ".claude/settings.json",
    )
    for relative in excluded:
        target = project / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x = 1\n", encoding="utf-8")

    result = scan_project(project)

    assert result.total_files == baseline_files


def test_hidden_files_below_the_root_are_still_scanned(
    tmp_path: Path, baseline_files: int
) -> None:
    """Only excluded *directories* are skipped — a hidden file is still evidence."""
    project = _copy_fixture(tmp_path / "app")
    (project / ".eslintrc.json").write_text('{"env": {"node": true}}\n', encoding="utf-8")

    result = scan_project(project)

    assert result.total_files == baseline_files + 1


def test_dossier_manifest_is_populated_for_a_project_under_a_dot_directory(
    tmp_path: Path,
) -> None:
    """The dossier's fallback file listing had the same absolute-path bug."""
    root = tmp_path / ".hidden" / "app"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "model.py").write_text("import openai\n", encoding="utf-8")
    ignored = root / ".venv" / "lib"
    ignored.mkdir(parents=True)
    (ignored / "site.py").write_text("x = 1\n", encoding="utf-8")

    scan = ScanResult(
        project_name="hidden-app",
        is_ai_system=True,
        compliance_scores={"human_oversight": 10.0},
    )
    dossier = generate_dossier(scan, root)

    paths = [entry.relative_path for entry in dossier.file_manifest]
    assert "pkg/model.py" in paths
    assert not any(path.startswith(".venv/") for path in paths)
