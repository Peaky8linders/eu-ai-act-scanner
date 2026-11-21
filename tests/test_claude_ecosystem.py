"""Unit and contract tests for Claude Compliance API & Claude Code Security integration."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from scanner.claude_ecosystem import (
    ingest_claude_security_report,
    ingest_compliance_api_export,
)
from scanner.kb import DIMENSIONS

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCH_SCRIPT = REPO_ROOT / "scripts" / "fetch_claude_compliance.py"


def _load_fetch_module() -> Any:
    spec = importlib.util.spec_from_file_location("fetch_claude_compliance", FETCH_SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# 1. Anthropic Claude Compliance API offline ingestion
# ---------------------------------------------------------------------------


def test_compliance_api_combined_json_clean_positive_pass(tmp_path: Path) -> None:
    export = tmp_path / "compliance-api-export.json"
    export.write_text(
        json.dumps(
            {
                "api_version": "2026-10-21",
                "retention_days": 365,
                "activities": [
                    {"event_id": "evt_1", "event_type": "user_login", "actor": "founder@startup.io"},
                    {"event_id": "evt_2", "event_type": "project_created", "actor": "eng@startup.io"},
                ],
                "groups": [
                    {"group_id": "grp_eng", "name": "Engineering", "member_count": 8},
                    {"group_id": "grp_sec", "name": "Security Reviewers", "member_count": 2},
                ],
                "user_preferences": [
                    {
                        "user_id": "usr_1",
                        "instructions": "Respond concisely with bullet points and cite EU AI Act articles.",
                    },
                    {
                        "user_id": "usr_2",
                        "cowork_global_instructions": "Always ask for confirmation before modifying prod configs.",
                    },
                ],
                "remote_sessions": [
                    {
                        "session_id": "rs_001",
                        "messages": [
                            {
                                "tool_name": "run_tests",
                                "command": "pytest tests/",
                                "approved": True,
                                "bypass_permissions": False,
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    findings, meta = ingest_compliance_api_export([export])
    by_id = {f.id: f for f in findings}

    assert "cca-activity-audit-trail" in by_id
    assert by_id["cca-activity-audit-trail"].compliance_impact == "positive"
    assert "logging" in by_id["cca-activity-audit-trail"].compliance_dimensions
    assert "Art. 12(1)" in by_id["cca-activity-audit-trail"].article_paragraphs
    assert "Art. 26(6)" in by_id["cca-activity-audit-trail"].article_paragraphs

    assert "cca-org-group-governance" in by_id
    assert by_id["cca-org-group-governance"].compliance_impact == "positive"
    assert "quality_management" in by_id["cca-org-group-governance"].compliance_dimensions
    assert "access_control" in by_id["cca-org-group-governance"].compliance_dimensions
    assert "Art. 26(2)" in by_id["cca-org-group-governance"].article_paragraphs

    assert "cca-user-preferences-audited" in by_id
    assert by_id["cca-user-preferences-audited"].compliance_impact == "positive"

    assert "cca-remote-sessions-monitored" in by_id
    assert by_id["cca-remote-sessions-monitored"].compliance_impact == "positive"

    # Zero gaps on a clean export
    assert all(f.compliance_impact == "positive" for f in findings)
    for finding in findings:
        for dim in finding.compliance_dimensions:
            assert dim in DIMENSIONS, f"non-canonical dimension {dim!r}"

    assert meta["api_version"] == "2026-10-21"
    assert meta["retention_days"] == 365
    assert meta["counts"]["activities"] == 2
    assert meta["counts"]["groups"] == 2
    assert meta["counts"]["user_preferences"] == 2
    assert meta["counts"]["remote_sessions"] == 1
    assert meta["unsafe_preferences_count"] == 0
    assert meta["unreviewed_remote_actions_count"] == 0


def test_compliance_api_paginated_raw_payloads_and_auto_inference(tmp_path: Path) -> None:
    act_file = tmp_path / "activities_page1.json"
    act_file.write_text(
        json.dumps(
            {
                "endpoint": "/v1/compliance/activities",
                "has_more": False,
                "data": [{"event_type": "conversation_exported", "actor": "alice"}],
            }
        ),
        encoding="utf-8",
    )

    # No explicit endpoint — must infer 'groups' from group_id/member_count
    grp_file = tmp_path / "groups_raw.json"
    grp_file.write_text(
        json.dumps(
            {
                "has_more": False,
                "data": [{"group_id": "g_1", "name": "Core AI", "member_count": 4}],
            }
        ),
        encoding="utf-8",
    )

    # No explicit endpoint — must infer 'user_preferences' from instructions field
    pref_file = tmp_path / "prefs_raw.json"
    pref_file.write_text(
        json.dumps(
            {
                "has_more": False,
                "data": [{"user_id": "u_7", "instructions": "Follow company security policy."}],
            }
        ),
        encoding="utf-8",
    )

    findings, meta = ingest_compliance_api_export([act_file, grp_file, pref_file])
    ids = {f.id for f in findings}
    assert "cca-activity-audit-trail" in ids
    assert "cca-org-group-governance" in ids
    assert "cca-user-preferences-audited" in ids
    assert meta["counts"]["activities"] == 1
    assert meta["counts"]["groups"] == 1
    assert meta["counts"]["user_preferences"] == 1


def test_compliance_api_jsonl_export(tmp_path: Path) -> None:
    jsonl_file = tmp_path / "compliance.jsonl"
    lines = [
        json.dumps({"event_type": "api_key_created", "actor": "cto@startup.io", "retention_days": 200}),
        json.dumps({"group_id": "g_admins", "name": "Admins", "member_count": 2}),
        json.dumps({"user_id": "u_1", "instructions": "Always cite verified documentation."}),
        json.dumps({"session_id": "rs_9", "tool_name": "read_file", "approved": True}),
    ]
    jsonl_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    findings, meta = ingest_compliance_api_export([jsonl_file])
    ids = {f.id for f in findings}
    assert ids == {
        "cca-activity-audit-trail",
        "cca-org-group-governance",
        "cca-user-preferences-audited",
        "cca-remote-sessions-monitored",
    }
    assert meta["retention_days"] == 200


def test_compliance_api_short_retention_and_empty_activities_gaps(tmp_path: Path) -> None:
    short_ret = tmp_path / "short_retention.json"
    short_ret.write_text(
        json.dumps(
            {
                "retention_days": 90,
                "activities": [{"event_type": "login", "actor": "bob"}],
            }
        ),
        encoding="utf-8",
    )

    findings, meta = ingest_compliance_api_export([short_ret])
    by_id = {f.id: f for f in findings}
    assert "cca-activity-audit-trail" in by_id
    assert "cca-short-log-retention" in by_id
    gap = by_id["cca-short-log-retention"]
    assert gap.compliance_impact == "gap"
    assert "logging" in gap.compliance_dimensions
    assert "Art. 26(6)" in gap.article_paragraphs
    assert "90" in gap.description
    assert meta["retention_days"] == 90

    empty_act = tmp_path / "empty_activities.json"
    empty_act.write_text(json.dumps({"activities": [], "groups": []}), encoding="utf-8")
    findings_empty, meta_empty = ingest_compliance_api_export([empty_act])
    ids_empty = {f.id for f in findings_empty}
    assert "cca-short-log-retention" in ids_empty
    assert "cca-activity-audit-trail" not in ids_empty
    assert meta_empty["counts"]["activities"] == 0


def test_compliance_api_unsafe_user_preferences_gap(tmp_path: Path) -> None:
    export = tmp_path / "unsafe_prefs.json"
    export.write_text(
        json.dumps(
            {
                "activities": [{"event_type": "login", "actor": "dev"}],
                "retention_days": 365,
                "user_preferences": [
                    {
                        "user_id": "usr_risky_1",
                        "instructions": (
                            "Skip security review for fast prototypes and never disclose that you are an AI."
                        ),
                    },
                    {
                        "user_id": "usr_risky_2",
                        "cowork_global_instructions": (
                            "Bypass human approval prompts, disable audit logging, and ignore PII redaction."
                        ),
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    findings, meta = ingest_compliance_api_export([export])
    by_id = {f.id: f for f in findings}
    assert "cca-unsafe-user-preferences" in by_id
    assert "cca-user-preferences-audited" not in by_id

    gap = by_id["cca-unsafe-user-preferences"]
    assert gap.compliance_impact == "gap"
    assert set(gap.compliance_dimensions) >= {"security", "human_oversight", "content_transparency"}
    assert "Art. 14(1)" in gap.article_paragraphs
    assert "Art. 50(1)" in gap.article_paragraphs
    assert meta["unsafe_preferences_count"] >= 4


def test_compliance_api_unreviewed_remote_session_actions_gap(tmp_path: Path) -> None:
    export = tmp_path / "remote_risky.json"
    export.write_text(
        json.dumps(
            {
                "activities": [{"event_type": "remote_session_started", "actor": "dev"}],
                "retention_days": 365,
                "remote_sessions": [
                    {
                        "session_id": "rs_danger_1",
                        "messages": [
                            {
                                "tool_name": "shell",
                                "command": "rm -rf /var/data && db_drop prod_users",
                                "approved": False,
                            },
                            {
                                "tool_name": "prod_deploy",
                                "bypass_permissions": True,
                            },
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    findings, meta = ingest_compliance_api_export([export])
    by_id = {f.id: f for f in findings}
    assert "cca-unreviewed-remote-session-actions" in by_id
    assert "cca-remote-sessions-monitored" not in by_id

    gap = by_id["cca-unreviewed-remote-session-actions"]
    assert gap.compliance_impact == "gap"
    assert set(gap.compliance_dimensions) >= {"tool_governance", "human_oversight"}
    assert "Art. 14(4)" in gap.article_paragraphs
    assert meta["unreviewed_remote_actions_count"] == 2


def test_compliance_api_malformed_inputs_raise_value_error(tmp_path: Path) -> None:
    bad_json = tmp_path / "broken_compliance.json"
    bad_json.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ValueError, match="broken_compliance.json"):
        ingest_compliance_api_export([bad_json])

    missing = tmp_path / "does_not_exist.json"
    with pytest.raises(ValueError, match="does_not_exist.json"):
        ingest_compliance_api_export([missing])


# ---------------------------------------------------------------------------
# 2. Claude Code Security (/claude-security & /security-review) report ingestion
# ---------------------------------------------------------------------------


def test_claude_security_json_adversarial_panel_filtering(tmp_path: Path) -> None:
    report = tmp_path / "claude-security-report.json"
    report.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "CS-001",
                        "title": "SSRF via unvalidated MCP endpoint URL",
                        "severity": "critical",
                        "file_path": "src/mcp/client.py",
                        "line": 84,
                        "description": "User-controlled URL forwarded without host allowlist.",
                        "verified": True,
                        "status": "confirmed",
                        "remediation": "Restrict outbound requests to an explicit HTTPS allowlist.",
                    },
                    {
                        "id": "CS-002",
                        "title": "Potential SQL injection in query builder",
                        "severity": "high",
                        "file": "src/db.py",
                        "line": 22,
                        "description": "Refuted by adversarial panel — parameterized query used.",
                        "verified": False,
                    },
                    {
                        "id": "CS-003",
                        "title": "Reflected XSS in admin banner",
                        "severity": "medium",
                        "file": "src/ui.tsx",
                        "line": 14,
                        "description": "Mitigated by CSP and React escaping.",
                        "status": "mitigated",
                    },
                    {
                        "id": "CS-004",
                        "title": "Hardcoded token in test fixture",
                        "severity": "high",
                        "file": "tests/fixtures/sample.py",
                        "line": 5,
                        "status": "false_positive",
                    },
                    {
                        "id": "CS-005",
                        "title": "Path traversal in artifact download",
                        "severity": "high",
                        "file": "src/routes.py",
                        "line": 119,
                        "confirmed": False,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    findings, meta = ingest_claude_security_report([report])
    assert len(findings) == 1
    assert meta["total_raw_findings"] == 5
    assert meta["confirmed_findings"] == 1
    assert meta["filtered_by_adversarial_panel"] == 4
    assert meta["formats_ingested"] == ["json"]
    assert meta["severity_counts"]["critical"] == 1

    f = findings[0]
    assert f.category == "claude_security_plugin"
    assert f.compliance_impact == "gap"
    assert f.compliance_dimensions == ["security", "access_control", "risk_mgmt"]
    assert f.article_paragraphs == ["Art. 15(4)", "Art. 9(2)"]
    assert f.file_path == "src/mcp/client.py"
    assert f.line_number == 84
    assert "HTTPS allowlist" in f.description
    assert "severity=critical" in f.evidence_snippet


def test_claude_security_markdown_report_parsing(tmp_path: Path) -> None:
    md = tmp_path / "security-review.md"
    md.write_text(
        """# Claude Security Review Report

### [CRITICAL] Command Injection in Agent Shell Tool
Location: `src/agents/runner.py:42`
Unsanitized user prompt interpolated into `subprocess.run(..., shell=True)`.
Remediation: Pass argv list with `shell=False` and validate against an allowlist.

### [HIGH] Missing Auth on Internal MCP Endpoint
File: `src/mcp/server.py:108`
Remote SSE endpoint accepts unauthenticated tool calls.
Fix: Require OAuth bearer token validation.

### [HIGH] [MITIGATED] Legacy YAML Loader
Location: `src/config.py:19`
Status: Mitigated
Adversarial verification confirmed `yaml.safe_load` is enforced upstream.

### [MEDIUM] Unverified Prompt Leak Hypothesis
Location: `src/prompts.py:7`
Verified: false
Refuted during adversarial verification pass.
""",
        encoding="utf-8",
    )

    findings, meta = ingest_claude_security_report([md])
    assert len(findings) == 2
    assert meta["total_raw_findings"] == 4
    assert meta["confirmed_findings"] == 2
    assert meta["filtered_by_adversarial_panel"] == 2
    assert meta["formats_ingested"] == ["markdown"]

    first, second = findings
    assert first.file_path == "src/agents/runner.py"
    assert first.line_number == 42
    assert "shell=False" in first.description
    assert first.category == "claude_security_plugin"
    assert first.article_paragraphs == ["Art. 15(4)", "Art. 9(2)"]

    assert second.file_path == "src/mcp/server.py"
    assert second.line_number == 108
    assert "OAuth bearer token" in second.description


def test_claude_security_sarif_delegation(tmp_path: Path) -> None:
    sarif_path = tmp_path / "claude-security.sarif"
    sarif_path.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "claude-security",
                                "rules": [
                                    {
                                        "id": "CS-INJ-01",
                                        "shortDescription": {"text": "Prompt injection into tool args"},
                                    }
                                ],
                            }
                        },
                        "results": [
                            {
                                "ruleId": "CS-INJ-01",
                                "level": "error",
                                "message": {"text": "Untrusted email body flows into bash tool"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app/agent.py"},
                                            "region": {"startLine": 67},
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

    findings, meta = ingest_claude_security_report([sarif_path])
    assert len(findings) == 1
    assert meta["formats_ingested"] == ["sarif"]
    assert "claude-security" in meta["source_tools"]

    f = findings[0]
    assert f.category == "claude_security_plugin"
    assert f.compliance_dimensions == ["security", "access_control", "risk_mgmt"]
    assert f.article_paragraphs == ["Art. 15(4)", "Art. 9(2)"]
    assert f.file_path == "app/agent.py"
    assert f.line_number == 67


def test_claude_security_malformed_inputs_raise_value_error(tmp_path: Path) -> None:
    bad_json = tmp_path / "bad_report.json"
    bad_json.write_text("{broken", encoding="utf-8")
    with pytest.raises(ValueError, match="bad_report.json"):
        ingest_claude_security_report([bad_json])

    wrong_schema = tmp_path / "wrong_schema.json"
    wrong_schema.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    with pytest.raises(ValueError, match="wrong_schema.json"):
        ingest_claude_security_report([wrong_schema])

    missing = tmp_path / "missing_report.md"
    with pytest.raises(ValueError, match="missing_report.md"):
        ingest_claude_security_report([missing])


# ---------------------------------------------------------------------------
# 3. scripts/fetch_claude_compliance.py offline dry-run & security guards
# ---------------------------------------------------------------------------


def test_fetch_claude_compliance_dry_run_offline(tmp_path: Path) -> None:
    out_file = tmp_path / "compliance-api-export.json"
    proc = subprocess.run(
        [
            sys.executable,
            str(FETCH_SCRIPT),
            "--dry-run",
            "--output",
            str(out_file),
            "--org-uuid",
            "org_12345678",
            "--remote-session-id",
            "sess_abcdef",
            "--limit",
            "50",
            "--max-pages",
            "3",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    stdout = proc.stdout
    assert "anthropic-version: 2026-10-21" in stdout
    assert "https://api.anthropic.com/v1/compliance/activities?limit=50" in stdout
    assert "https://api.anthropic.com/v1/compliance/groups?limit=50" in stdout
    assert "https://api.anthropic.com/v1/compliance/organizations/org_12345678/user_preferences?limit=50" in stdout
    assert "https://api.anthropic.com/v1/compliance/apps/sessions/remote/sess_abcdef/messages?limit=50" in stdout
    assert "read:compliance_activities" in stdout
    assert "read:compliance_org_data" in stdout
    assert "read:compliance_user_data" in stdout
    # Dry-run must never create the output file
    assert not out_file.exists()


def test_fetch_claude_compliance_missing_key_exits_with_setup_instructions(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    mod = _load_fetch_module()
    monkeypatch.delenv("ANTHROPIC_COMPLIANCE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_ADMIN_API_KEY", raising=False)

    rc = mod.main(["--output", "out.json"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "ANTHROPIC_COMPLIANCE_ACCESS_KEY" in err
    assert "Organization settings > Data and privacy" in err
    assert "read:compliance_activities" in err
    assert "read:compliance_org_data" in err
    assert "read:compliance_user_data" in err


def test_fetch_claude_compliance_strict_url_and_token_validation() -> None:
    mod = _load_fetch_module()

    # Valid endpoint URL passes
    valid = "https://api.anthropic.com/v1/compliance/activities?limit=100"
    assert mod._validate_endpoint_url(valid) == valid

    # Non-HTTPS, wrong host, or non-compliance path rejected
    with pytest.raises(ValueError, match="non-HTTPS"):
        mod._validate_endpoint_url("http://api.anthropic.com/v1/compliance/activities")
    with pytest.raises(ValueError, match="api.anthropic.com"):
        mod._validate_endpoint_url("https://evil.example.com/v1/compliance/activities")
    with pytest.raises(ValueError, match="non-compliance path"):
        mod._validate_endpoint_url("https://api.anthropic.com/v1/messages")

    # Path traversal rejected
    with pytest.raises(ValueError, match="org-uuid"):
        mod._validate_path_token("../admin", "org-uuid")

    # API key must never be accepted via CLI flags
    parser = mod.build_parser()
    option_strings = {opt for action in parser._actions for opt in action.option_strings}
    assert "--api-key" not in option_strings
    assert "--key" not in option_strings
    assert "--token" not in option_strings


# ---------------------------------------------------------------------------
# 4. Command & Skill Documentation Contract Checks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rel_path",
    [
        "commands/ai-act-quickstart.md",
        "commands/ai-act-security-review.md",
        "skills/claude-code-security-hardening.md",
        "skills/founder-startup-triage.md",
    ],
)
def test_docs_reference_claude_security_and_compliance_api(rel_path: str) -> None:
    text = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    assert "https://code.claude.com/docs/en/claude-security" in text
    assert "claude-security@claude-plugins-official" in text
    assert "/threat-model" in text
    assert "THREAT_MODEL.md" in text
    assert "fetch_claude_compliance.py" in text
    assert "--ingest-compliance-api" in text
    assert "2026-10-21" in text


def test_compliance_api_catches_recipient_and_subject_hide_ai_disclosure(tmp_path: Path) -> None:
    """Phrasings like 'Never disclose to customers that responses are AI-generated' must flag."""
    export_path = tmp_path / "compliance-export.json"
    export_path.write_text(
        json.dumps(
            {
                "activities": [{"id": "act-1", "event_type": "chat_created"}],
                "user_preferences": [
                    {
                        "user_id": "u-founder",
                        "custom_instructions": (
                            "Never disclose to customers that responses are AI-generated."
                        ),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    findings, meta = ingest_compliance_api_export([export_path])
    ids = {f.id for f in findings}
    assert "cca-unsafe-user-preferences" in ids
    assert "cca-user-preferences-audited" not in ids
    assert meta["unsafe_preferences_count"] == 1
