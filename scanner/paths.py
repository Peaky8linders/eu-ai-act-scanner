"""Path rules shared by the scanner's file walkers.

Exclusions apply to components **below the scan root**, never to its ancestors.
A project that happens to live under `.hidden/`, `build/`, `.venv/` or a Claude
worktree is still the project the user asked to scan; matching absolute parts
used to disqualify every file in it and produce an empty, zero-file report.
"""

from __future__ import annotations

from pathlib import Path, PurePath

# Directory names never descended into. Matched against individual path parts
# (not substrings) so `dist` doesn't exclude `distributed.py` and `.git`
# doesn't exclude `.gitignore`. Includes agent-workspace dirs (`.claude`,
# `.freebuff`, `worktrees`) — a stale worktree holds a *copy* of the repo and
# would otherwise double-count every finding against deleted code.
EXCLUDED_PATH_PARTS = frozenset({
    "__pycache__", "node_modules", ".git", ".venv", "venv", ".tox",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", "dist", "build",
    ".claude", ".freebuff", ".worktrees", "worktrees",
})


def is_excluded(relative_path: PurePath | Path | str) -> bool:
    """True when any component *below the scan root* is an excluded directory.

    Always pass a path relative to the scan root: an absolute path would also
    match an ancestor (e.g. a checkout under `.freebuff/`) and silently exclude
    the entire project.
    """
    return bool(EXCLUDED_PATH_PARTS & set(PurePath(relative_path).parts))
