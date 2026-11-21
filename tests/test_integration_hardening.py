"""Regression tests for the Claude ecosystem integrations, as the real tools emit them.

Each test pins an output shape documented by Anthropic and checks the scanner
handles it:

* ``claude-security@claude-plugins-official`` writes ``CLAUDE-SECURITY-RESULTS.jsonl``
  (one finding per line, ``title``/``file``/``line``/``severity`` in upper case);
* ``anthropics/claude-code-security-review`` writes ``{"findings": [...]}``,
  with findings keyed by ``category`` and carrying no ``title``;
* the Claude Compliance API pages groups and user_preferences with
  ``next_page``, pages sessions with ``next_page`` only, and pages activities
  with ``has_more`` + ``last_id``.

Also covers the Claude Code plugin packaging contract, the secret-guard hook's
staging commands, SARIF severity keywords and the ``--founder --diff-baseline``
CLI combination.
"""

from __future__ import annotations

import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest

from scanner.claude_ecosystem import (
    ingest_claude_security_report,
    ingest_compliance_api_export,
)
from scanner.models import DiscoveredComponent
from scanner.sarif import _component_sarif_level

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCH_SCRIPT = REPO_ROOT / "scripts" / "fetch_claude_compliance.py"
HOOK_SCRIPT = REPO_ROOT / "hooks" / "sensitive_data_guard.py"
SAMPLE = REPO_ROOT / "tests" / "fixtures" / "sample_project"

# Built by concatenation so this file never holds a credential-shaped literal.
FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPL3"


def _load_fetch_module() -> Any:
    spec = importlib.util.spec_from_file_location("fetch_claude_compliance_h", FETCH_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# claude-security / security-review report ingestion
# ---------------------------------------------------------------------------


def test_ingests_claude_security_plugin_jsonl(tmp_path: Path) -> None:
    report = tmp_path / "CLAUDE-SECURITY-RESULTS.jsonl"
    rows = [
        {
            "id": "F1", "title": "SQL injection in user search", "file": "app/db.py",
            "line": 42, "description": "User input concatenated into SQL.",
            "exploit_scenario": "GET /search?q=' OR 1=1--", "category": "sql_injection",
            "severity": "CRITICAL", "confidence": "high", "cwe_id": "CWE-89",
            "recommendation": "Use parameterized queries.",
        },
        {
            "id": "F2", "title": "Verbose error page", "file": "app/api.py", "line": 10,
            "description": "Debug mode on.", "category": "info_disclosure",
            "severity": "LOW", "confidence": "medium", "recommendation": "Disable debug.",
        },
    ]
    report.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    findings, meta = ingest_claude_security_report([report])

    assert [f.title for f in findings] == [
        "[claude-security] SQL injection in user search",
        "[claude-security] Verbose error page",
    ]
    assert findings[0].severity == "critical"
    assert (findings[0].file_path, findings[0].line_number) == ("app/db.py", 42)
    assert meta["severity_counts"]["critical"] == 1
    assert meta["severity_counts"]["low"] == 1


def test_malformed_jsonl_still_raises(tmp_path: Path) -> None:
    report = tmp_path / "broken.jsonl"
    report.write_text('{"title": "ok"}\n{not json\n', encoding="utf-8")
    with pytest.raises(ValueError, match="Malformed JSON"):
        ingest_claude_security_report([report])


def test_security_review_action_findings_get_category_titles(tmp_path: Path) -> None:
    report = tmp_path / "security-review.json"
    report.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "file": "app/auth.py", "line": 7, "severity": "HIGH",
                        "category": "hardcoded_secret",
                        "description": "API key hardcoded in source. Rotate it.",
                        "exploit_scenario": "Anyone with repo access can use the key",
                        "recommendation": "Load from env", "confidence": 0.95,
                    }
                ],
                "analysis_summary": {"files_reviewed": 3, "review_completed": True},
            }
        ),
        encoding="utf-8",
    )

    findings, _ = ingest_claude_security_report([report])

    assert len(findings) == 1
    assert findings[0].title == "[claude-security] hardcoded secret: API key hardcoded in source"
    assert "Exploit scenario: Anyone with repo access" in findings[0].description
    assert findings[0].severity == "high"


def test_founder_brief_uses_security_tool_recommendation(tmp_path: Path) -> None:
    from scanner import scan_project
    from scanner.founder_triage import build_founder_triage

    report = tmp_path / "CLAUDE-SECURITY-RESULTS.jsonl"
    report.write_text(
        json.dumps({"id": "F1", "title": "SQL injection in search", "file": "model.py", "line": 3,
                    "severity": "CRITICAL", "description": "Concatenated SQL.",
                    "recommendation": "Use parameterized queries."}) + "\n",
        encoding="utf-8",
    )
    findings, _ = ingest_claude_security_report([report])
    result = scan_project(SAMPLE, external_findings=findings, external_sources=["claude-security"])
    triage = build_founder_triage(result)
    item = next(i for i in triage.ship_now if "SQL injection" in i.title)
    assert item.fix_hint == "Use parameterized queries."


def test_info_severity_is_low_not_medium(tmp_path: Path) -> None:
    report = tmp_path / "r.json"
    report.write_text(
        json.dumps([{"title": "Header hint", "severity": "INFO", "file": "a.py"}]),
        encoding="utf-8",
    )
    findings, meta = ingest_claude_security_report([report])
    assert findings[0].severity == "low"
    assert meta["severity_counts"]["medium"] == 0


# ---------------------------------------------------------------------------
# Claude Compliance API export ingestion
# ---------------------------------------------------------------------------


def test_raw_groups_page_is_not_counted_as_audit_trail(tmp_path: Path) -> None:
    page = tmp_path / "groups.json"
    page.write_text(
        json.dumps(
            {
                "data": [{"id": "grp_1", "name": "Engineering", "created_at": "2026-01-01T00:00:00Z"}],
                "has_more": False,
                "next_page": None,
            }
        ),
        encoding="utf-8",
    )

    findings, meta = ingest_compliance_api_export([page])

    assert meta["counts"]["groups"] == 1
    assert meta["counts"]["activities"] == 0
    ids = {f.id for f in findings}
    assert "cca-activity-audit-trail" not in ids
    assert "cca-org-group-governance" in ids
    # Groups alone say nothing about the activity trail: no retention gap.
    assert "cca-short-log-retention" not in ids


def test_raw_activities_page_still_classified_as_activities(tmp_path: Path) -> None:
    page = tmp_path / "activities.json"
    page.write_text(
        json.dumps(
            {
                "data": [
                    {
                        "id": "act_1", "created_at": "2026-11-01T10:00:00Z",
                        "actor": {"type": "user_actor", "user_id": "u1"},
                        "type": "claude_chat_created",
                    }
                ],
                "has_more": False, "first_id": "act_1", "last_id": "act_1",
            }
        ),
        encoding="utf-8",
    )
    findings, meta = ingest_compliance_api_export([page])
    assert meta["counts"]["activities"] == 1
    assert "cca-activity-audit-trail" in {f.id for f in findings}


def test_preferences_only_export_raises_no_empty_trail_gap(tmp_path: Path) -> None:
    page = tmp_path / "prefs.json"
    page.write_text(
        json.dumps(
            {"data": [{"user_id": "u1", "preferences": {"instructions": "Be concise."}}],
             "has_more": False, "next_page": None}
        ),
        encoding="utf-8",
    )
    findings, _ = ingest_compliance_api_export([page])
    ids = {f.id for f in findings}
    assert "cca-short-log-retention" not in ids
    assert "cca-user-preferences-audited" in ids


def test_snapshot_with_empty_activities_still_flags_empty_trail(tmp_path: Path) -> None:
    snap = tmp_path / "snapshot.json"
    snap.write_text(
        json.dumps({"activities": [], "groups": [{"id": "g", "name": "Eng"}]}), encoding="utf-8"
    )
    findings, _ = ingest_compliance_api_export([snap])
    assert "cca-short-log-retention" in {f.id for f in findings}


# ---------------------------------------------------------------------------
# scripts/fetch_claude_compliance.py pagination
# ---------------------------------------------------------------------------

BASE = "https://api.anthropic.com/v1/compliance"


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        # activities: cursor paging via last_id -> after_id
        ({"data": [], "has_more": True, "last_id": "act_9"}, "after_id=act_9"),
        ({"data": [], "has_more": False, "last_id": "act_9"}, None),
        # groups / user_preferences: page token
        ({"data": [], "has_more": True, "next_page": "tok2"}, "page=tok2"),
        ({"data": [], "has_more": False, "next_page": "tok2"}, None),
        # sessions: next_page only, no has_more
        ({"data": [], "next_page": "tok3"}, "page=tok3"),
        ({"data": [], "next_page": None}, None),
    ],
)
def test_next_page_url_follows_each_pagination_scheme(payload: dict, expected: str | None) -> None:
    fetch = _load_fetch_module()
    url = fetch._next_page_url(f"{BASE}/groups?limit=10", payload)
    if expected is None:
        assert url is None
    else:
        assert url is not None and expected in url and "limit=10" in url


class _FakeResponse(io.BytesIO):
    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _serve(pages: dict[str, dict], seen: list[str]):
    def fake_urlopen(req, timeout=30):  # noqa: ANN001, ARG001
        seen.append(req.full_url)
        for marker, body in pages.items():
            if marker in req.full_url:
                return _FakeResponse(json.dumps(body).encode())
        raise AssertionError(f"unexpected URL {req.full_url}")

    return fake_urlopen


def test_fetch_follows_session_next_page_without_has_more(monkeypatch) -> None:
    fetch = _load_fetch_module()
    seen: list[str] = []
    pages = {
        "page=p2": {"data": [{"id": "m2"}], "next_page": None},
        "messages?limit=": {"data": [{"id": "m1"}], "next_page": "p2"},
    }
    monkeypatch.setattr(fetch.urllib.request, "urlopen", _serve(pages, seen))
    items = fetch._fetch_paginated_endpoint(
        f"{BASE}/apps/sessions/remote/s1/messages?limit=1", "test-key", max_pages=5
    )
    assert [i["id"] for i in items] == ["m1", "m2"]
    assert len(seen) == 2


def test_fetch_page_based_groups_do_not_repeat_first_page(monkeypatch) -> None:
    fetch = _load_fetch_module()
    seen: list[str] = []
    pages = {
        "page=g2": {"data": [{"id": "grp_2"}], "has_more": False, "next_page": None},
        "groups?limit=": {"data": [{"id": "grp_1"}], "has_more": True, "next_page": "g2"},
    }
    monkeypatch.setattr(fetch.urllib.request, "urlopen", _serve(pages, seen))
    items = fetch._fetch_paginated_endpoint(f"{BASE}/groups?limit=1", "test-key", max_pages=5)
    assert [i["id"] for i in items] == ["grp_1", "grp_2"]
    assert "after_id" not in seen[1]


# ---------------------------------------------------------------------------
# Secret-guard hook: staging commands & NotebookEdit
# ---------------------------------------------------------------------------


def _run_guard(payload: dict, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HOOK_SCRIPT)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=60,
        check=False,
    )


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    if shutil.which("git") is None:
        pytest.skip("git not available")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.invalid"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, check=True)
    (tmp_path / "README.md").write_text("hi\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=tmp_path, check=True)
    return tmp_path


def test_guard_blocks_add_then_commit_of_untracked_secret(git_repo: Path) -> None:
    (git_repo / "settings.py").write_text(f'AWS_KEY = "{FAKE_AWS_KEY}"\n', encoding="utf-8")
    proc = _run_guard(
        {"tool_name": "Bash", "tool_input": {"command": "git add -A && git commit -m wip"}},
        cwd=git_repo,
    )
    assert proc.returncode == 2, proc.stderr
    assert "BLOCKED" in proc.stderr


def test_guard_blocks_commit_all_of_modified_tracked_secret(git_repo: Path) -> None:
    (git_repo / "README.md").write_text(f"key {FAKE_AWS_KEY}\n", encoding="utf-8")
    proc = _run_guard(
        {"tool_name": "Bash", "tool_input": {"command": "git commit -am wip"}}, cwd=git_repo
    )
    assert proc.returncode == 2, proc.stderr


def test_guard_allows_plain_commit_with_clean_index(git_repo: Path) -> None:
    # An unstaged secret is not part of a plain `git commit`: do not block it.
    (git_repo / "README.md").write_text(f"key {FAKE_AWS_KEY}\n", encoding="utf-8")
    proc = _run_guard(
        {"tool_name": "Bash", "tool_input": {"command": "git commit -m wip"}}, cwd=git_repo
    )
    assert proc.returncode == 0, proc.stderr


def test_guard_inspects_notebook_edit_source(tmp_path: Path) -> None:
    proc = _run_guard(
        {
            "tool_name": "NotebookEdit",
            "tool_input": {"notebook_path": "nb.ipynb", "new_source": f"key = '{FAKE_AWS_KEY}'"},
        },
        cwd=tmp_path,
    )
    assert proc.returncode == 2


# ---------------------------------------------------------------------------
# SARIF severity keywords
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("No evaluation harness for retrieval quality", "note"),
        ("Pipeline execution order undocumented", "note"),
        ("Use of eval() on model output", "error"),
        ("subprocess call with shell=True", "error"),
    ],
)
def test_sarif_keywords_match_whole_tokens(name: str, expected: str) -> None:
    comp = DiscoveredComponent(
        name=name, component_type="documentation", file_path="a.py",
        confidence=0.4, compliance_impact="gap",
    )
    assert _component_sarif_level(comp) == expected


# ---------------------------------------------------------------------------
# CLI: --founder together with --diff-baseline
# ---------------------------------------------------------------------------


def test_founder_brief_includes_baseline_diff(tmp_path: Path, capsys) -> None:
    from scanner.cli import main

    baseline = tmp_path / "baseline.json"
    assert main([str(SAMPLE), "--save-baseline", str(baseline)]) == 0
    capsys.readouterr()
    assert main([str(SAMPLE), "--founder", "--diff-baseline", str(baseline)]) == 0
    out = capsys.readouterr().out
    assert "# Founder AI Compliance Brief" in out
    assert "# Baseline Diff" in out

    assert main([str(SAMPLE), "--founder", "--json", "--diff-baseline", str(baseline)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["baseline_diff"]["score_delta"] == 0.0


# ---------------------------------------------------------------------------
# Claude Code plugin packaging contract
# ---------------------------------------------------------------------------


def _pyproject_version() -> str:
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def test_plugin_manifest_lives_in_claude_plugin_dir_and_versions_agree() -> None:
    manifest = json.loads((REPO_ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    legacy = json.loads((REPO_ROOT / "plugin.json").read_text(encoding="utf-8"))
    market = json.loads(
        (REPO_ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8")
    )
    version = _pyproject_version()

    assert manifest["name"] == "eu-ai-act-scanner"
    assert not manifest["name"].startswith("claude-")  # reserved prefix
    assert manifest["version"] == legacy["version"] == version
    assert isinstance(manifest["author"], dict) and manifest["author"]["name"]

    entry = next(p for p in market["plugins"] if p["name"] == manifest["name"])
    assert entry["source"] == "./"
    assert entry.get("version", version) == version
    assert market["owner"]["name"]


def test_every_skill_is_a_skill_md_directory() -> None:
    skills_dir = REPO_ROOT / "skills"
    assert not list(skills_dir.glob("*.md")), "flat skills/*.md files are not loaded by Claude Code"
    skill_dirs = [p for p in skills_dir.iterdir() if p.is_dir()]
    assert len(skill_dirs) >= 16
    for d in skill_dirs:
        skill_md = d / "SKILL.md"
        assert skill_md.is_file(), d
        head = skill_md.read_text(encoding="utf-8").split("---")[1]
        assert f"name: {d.name}" in head, d


def test_skill_cross_links_resolve() -> None:
    import re

    link_re = re.compile(r"\]\((\.\./[a-z0-9-]+/SKILL\.md)\)")
    for skill_md in (REPO_ROOT / "skills").glob("*/SKILL.md"):
        for rel in link_re.findall(skill_md.read_text(encoding="utf-8")):
            assert (skill_md.parent / rel).resolve().is_file(), f"{skill_md}: {rel}"


def test_mcp_ingest_accepts_claude_security_jsonl(tmp_path: Path, monkeypatch) -> None:
    from scanner.mcp_server import tool_ingest_claude_ecosystem

    project = tmp_path / "proj"
    shutil.copytree(SAMPLE, project)
    report = project / "CLAUDE-SECURITY-RESULTS.jsonl"
    report.write_text(
        json.dumps({"id": "F1", "title": "SSRF in fetch tool", "file": "model.py", "line": 3,
                    "severity": "HIGH", "description": "Unvalidated URL."}) + "\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    out = tool_ingest_claude_ecosystem(
        path=str(project), claude_security_paths=["CLAUDE-SECURITY-RESULTS.jsonl"]
    )
    assert out.get("status") == "success", out
    assert out["external_findings_count"] == 1
    assert "claude-security" in out["external_sources"]
