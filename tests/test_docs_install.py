"""Docs guard: no tracked file may tell users to install this project from PyPI.

The scanner ships as a Claude Code plugin plus an MCP server, installed from this
repository. The `eu-ai-act-scanner` name on PyPI belongs to an unrelated project,
so an install instruction pointing there does not just fail — it installs someone
else's code. That mistake lived in two changelog entries and a README section
before it was corrected, which is exactly the kind of copy-paste that comes back.

The only allowed mention is the warning itself ("there is no PyPI package", "the
name on PyPI is an unrelated project", …). Those warnings necessarily spell the
bad command out, so the guard exempts a mention that sits next to one of them.

Scans every file `git ls-files` reports, falling back to a tree walk when git is
unavailable (source archive), and skips files that are not valid UTF-8.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# An install of this project's PyPI name, with the usual flag, quote and extra
# spellings.
_PYPI_INSTALL = re.compile(
    r"(?i)\b(?:pip3?|pipx|uv\s+pip|python\s+-m\s+pip)\s+install\b"
    r"[^\n]*?[\"']?eu-ai-act-scanner(?:-plugin)?\b"
)

# Text that marks a mention as a warning rather than an instruction.
_WARNING_MARKERS = (
    "no pypi package",
    "never published to pypi",
    "unrelated third-party",
    "unrelated project",
    "unrelated third-party project",
    "someone else's package",
)

_CONTEXT_LINES = 3

# Directories a tree walk must not descend into when git is unavailable.
_SKIP_DIRS = {".git", ".venv", "venv", "build", "dist", "__pycache__", ".claude", "node_modules"}


def _tracked_files() -> list[Path]:
    """Files the guard inspects: everything git tracks, else the source tree."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=REPO_ROOT,
            capture_output=True,
            check=True,
            timeout=30,
        ).stdout
        return [REPO_ROOT / name for name in out.decode("utf-8").split("\0") if name]
    except (OSError, subprocess.SubprocessError):
        files: list[Path] = []
        for path in REPO_ROOT.rglob("*"):
            if not path.is_file() or any(part in _SKIP_DIRS for part in path.parts):
                continue
            if any(part.endswith(".egg-info") for part in path.parts):
                continue
            files.append(path)
        return files


def _violations(text: str) -> list[int]:
    """1-based line numbers where the text instructs a PyPI install.

    A mention is exempt when a warning marker sits within ``_CONTEXT_LINES``
    lines — the warning has to quote the command to be useful.
    """
    lines = text.splitlines()
    found: list[int] = []
    for index, line in enumerate(lines):
        if not _PYPI_INSTALL.search(line):
            continue
        window = "\n".join(lines[max(0, index - _CONTEXT_LINES) : index + _CONTEXT_LINES + 1]).lower()
        if any(marker in window for marker in _WARNING_MARKERS):
            continue
        found.append(index + 1)
    return found


def test_no_tracked_file_instructs_a_pypi_install() -> None:
    files = _tracked_files()
    assert len(files) > 30, f"guard scanned only {len(files)} files — file discovery is broken"

    offenders: list[str] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for line_number in _violations(text):
            offenders.append(f"{path.relative_to(REPO_ROOT)}:{line_number}")

    assert not offenders, (
        "tracked files tell users to install from PyPI; this project is the "
        "Claude Code plugin + MCP server, installed from the repository "
        "(use `pip install -e \".[mcp]\"`), and the PyPI name belongs to an "
        "unrelated project:\n  " + "\n  ".join(offenders)
    )


# Assembled rather than written out: this file is tracked, so the guard itself
# would otherwise flag a literal bad command in its own fixtures.
_NAME = "eu-ai-act-" + "scanner"
_BAD = "pip install " + _NAME


def test_guard_flags_instructions_but_not_warnings() -> None:
    """The exemption must be narrow: only a nearby warning makes a mention legal."""
    bare = f"Install with `{_BAD}` and run the CLI.\n"
    assert _violations(bare) == [1]

    warning = (
        f"> **There is no PyPI package.** `{_BAD}` installs\n"
        "> an unrelated third-party project that owns that name.\n"
    )
    assert _violations(warning) == []

    changelog_style = (
        "It was never published to PyPI, and the `eu-ai-act-scanner` name there\n"
        f"belongs to an unrelated third-party project — so `{_BAD}`\n"
        "fetched someone else's package.\n"
    )
    assert _violations(changelog_style) == []

    # The repo-install form is the supported one and never matches; naming the
    # package in prose ("installed from this repository") is not an instruction.
    repo_install = (
        "pip install -e \".[mcp]\"\n"
        "The package installed from this repository is `eu-ai-act-scanner-plugin`.\n"
    )
    assert _violations(repo_install) == []

    # A warning several paragraphs away does not license an instruction.
    far_warning = "There is no PyPI package.\n\n\n\n\n\n" f"Quick start: {_BAD}\n"
    assert _violations(far_warning) == [7]
