#!/usr/bin/env python3
"""Claude Code PreToolUse guard: block secret files and hardcoded credentials.

Opt-in. Copy this file to ``.claude/hooks/sensitive_data_guard.py`` and merge
``hooks/sensitive-data-guard.json`` into ``.claude/settings.json`` (team) or
``.claude/settings.local.json`` (just you).

Claude Code sends the pending tool call as JSON on stdin
(``{"tool_name": ..., "tool_input": {...}}``). Exit code 2 blocks the call and
feeds stderr back to Claude so it can correct course; exit code 0 allows it.

What it blocks:

* ``Write`` / ``Edit`` / ``MultiEdit`` to ``.env`` files (``.env.example``,
  ``.env.sample`` and ``.env.template`` stay allowed), ``*.pem``, ``*.key``,
  ``id_rsa`` and ``id_ed25519``;
* ``Write`` / ``Edit`` / ``MultiEdit`` whose new content holds a live-looking
  credential (OpenAI/Anthropic ``sk-`` keys, AWS ``AKIA`` keys, GitHub, GitLab
  and Slack tokens, PEM private keys);
* ``Bash`` ``git commit`` when the staged diff adds such a credential.

It fails open: malformed input or a missing ``git`` never blocks your work.
Standard library only, nothing leaves the machine.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import PurePath

_BLOCKED_NAME_RE = re.compile(
    r"^\.env(\..+)?$|\.(pem|key|p12|pfx)$|^id_(rsa|dsa|ecdsa|ed25519)$",
    re.IGNORECASE,
)
_ALLOWED_ENV_TEMPLATES = frozenset({".env.example", ".env.sample", ".env.template"})

# Shapes of real credentials. Each needs enough entropy-length that ordinary
# prose and short identifiers do not match.
_SECRET_RES = (
    re.compile(r"\bsk-(?:proj-|ant-(?:api\d+-)?|live-|svcacct-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{16,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
)
_PLACEHOLDER_RE = re.compile(
    r"example|placeholder|dummy|fake|redacted|changeme|change_me|your[_-]|x{8,}|\.\.\.",
    re.IGNORECASE,
)
_GIT_COMMIT_RE = re.compile(r"\bgit\b[^;&|]*\bcommit\b")


def _find_secret(text: str) -> str | None:
    """Return a redacted preview of the first credential-shaped token, if any."""
    for line in text.splitlines():
        for pattern in _SECRET_RES:
            match = pattern.search(line)
            if match and not _PLACEHOLDER_RE.search(line):
                token = match.group(0)
                return f"{token[:6]}…({len(token)} chars)"
    return None


def _new_content(tool_input: dict) -> str:
    parts: list[str] = []
    for key in ("content", "new_string"):
        value = tool_input.get(key)
        if isinstance(value, str):
            parts.append(value)
    edits = tool_input.get("edits")
    if isinstance(edits, list):
        for edit in edits:
            if isinstance(edit, dict) and isinstance(edit.get("new_string"), str):
                parts.append(edit["new_string"])
    return "\n".join(parts)


def _check_file_write(tool_input: dict) -> str | None:
    file_path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
    name = PurePath(str(file_path).replace("\\", "/")).name
    if name and name.lower() not in _ALLOWED_ENV_TEMPLATES and _BLOCKED_NAME_RE.search(name):
        return (
            f"BLOCKED: refusing to write secret file `{name}`. Put non-secret "
            "templates in .env.example and load live credentials from environment "
            "variables or a secrets manager."
        )
    found = _find_secret(_new_content(tool_input))
    if found:
        return (
            f"BLOCKED: the new content contains a hardcoded credential ({found}). "
            "Read it from an environment variable instead, and rotate the key if it is real."
        )
    return None


def _check_git_commit(command: str) -> str | None:
    if not _GIT_COMMIT_RE.search(command):
        return None
    try:
        diff = subprocess.run(
            ["git", "diff", "--cached", "--diff-filter=ACM", "-U0"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    added = "\n".join(
        line[1:] for line in diff.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )
    found = _find_secret(added)
    if found:
        return (
            f"BLOCKED: the staged diff adds a hardcoded credential ({found}). "
            "Unstage it, load the value from the environment, and rotate the key if it is real."
        )
    return None


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (ValueError, OSError):
        return 0
    if not isinstance(payload, dict):
        return 0
    tool_name = str(payload.get("tool_name", ""))
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return 0

    reason: str | None = None
    if tool_name in {"Write", "Edit", "MultiEdit", "NotebookEdit"}:
        reason = _check_file_write(tool_input)
    elif tool_name == "Bash":
        reason = _check_git_commit(str(tool_input.get("command", "")))

    if reason:
        print(reason, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
