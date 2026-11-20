"""Tests for scanner.founder_triage and reusable founder/Claude Code assets."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from scanner.founder_triage import (
    FounderTriage,
    build_founder_triage,
    format_founder_brief,
)
from scanner.models import DiscoveredComponent, ScanResult

REPO_ROOT = Path(__file__).resolve().parent.parent
_URL_RE = re.compile(r"https?://")


def _startup_scan_result(*, role: str = "deployer", high_risk_vertical: bool = False) -> ScanResult:
    components = [
        DiscoveredComponent(
            name="Missing Art. 50 chatbot AI interaction disclosure",
            component_type="article_50_transparency",
            file_path="src/chat_ui.tsx",
            confidence=0.90,
            compliance_dimensions=["transparency"],
            compliance_impact="gap",
            details={"article_paragraphs": ["Art. 50(1)"], "line_number": 27},
        ),
        DiscoveredComponent(
            name="MCP tool poisoning directive detected",
            component_type="mcp_toolchain",
            file_path=".mcp.json",
            confidence=0.95,
            compliance_dimensions=["security", "tool_governance"],
            compliance_impact="gap",
            details={"article_paragraphs": ["Art. 15(4)"], "line_number": 8},
        ),
        DiscoveredComponent(
            name="Hardcoded OpenAI API key in config",
            component_type="security_controls",
            file_path="src/config.py",
            confidence=0.95,
            compliance_dimensions=["security"],
            compliance_impact="gap",
            details={"severity": "critical"},
        ),
        DiscoveredComponent(
            name="Over-privileged Bash(*) in .claude/settings.json",
            component_type="claude_code_security",
            file_path=".claude/settings.json",
            confidence=0.90,
            compliance_dimensions=["access_control", "tool_governance"],
            compliance_impact="gap",
        ),
        DiscoveredComponent(
            name="Lethal trifecta: private data + untrusted input + outbound send",
            component_type="lethal_trifecta",
            file_path="src/agent.py",
            confidence=0.88,
            compliance_dimensions=["security", "human_oversight"],
            compliance_impact="gap",
        ),
        DiscoveredComponent(
            name="Missing automated PR security review workflow",
            component_type="claude_code_security",
            file_path=".github/workflows/ci.yml",
            confidence=0.75,
            compliance_dimensions=["security", "infra_mlops"],
            compliance_impact="gap",
        ),
        DiscoveredComponent(
            name="Unpinned npx -y MCP server in .mcp.json",
            component_type="mcp_toolchain",
            file_path=".mcp.json",
            confidence=0.80,
            compliance_dimensions=["supply_chain"],
            compliance_impact="gap",
        ),
        DiscoveredComponent(
            name="Missing structured audit logging with correlation IDs",
            component_type="logging_monitoring",
            file_path="src/inference.py",
            confidence=0.75,
            compliance_dimensions=["logging"],
            compliance_impact="gap",
        ),
        DiscoveredComponent(
            name="Missing Annex IV technical documentation and risk register",
            component_type="documentation",
            file_path="docs/",
            confidence=0.70,
            compliance_dimensions=["tech_docs", "risk_mgmt"],
            compliance_impact="gap",
        ),
    ]
    if high_risk_vertical:
        components.append(
            DiscoveredComponent(
                name="Hiring resume screening model",
                component_type="model_typology",
                file_path="src/hiring_ranker.py",
                confidence=0.85,
                compliance_dimensions=["risk_mgmt"],
                compliance_impact="neutral",
            )
        )

    return ScanResult(
        project_name="startup-copilot",
        is_ai_system=True,
        overall_compliance_pct=34.0,
        active_role=role,
        inferred_roles=[role],
        compliance_scores={
            "transparency": 10.0,
            "security": 20.0,
            "logging": 25.0,
            "access_control": 25.0,
            "supply_chain": 20.0,
            "risk_mgmt": 15.0,
            "data_gov": 20.0,
            "tech_docs": 15.0,
            "human_oversight": 20.0,
        },
        components=components,
    )


class TestFounderTriage:
    def test_non_ai_repo_short_circuits_cleanly(self) -> None:
        non_ai = ScanResult(
            project_name="static-blog",
            is_ai_system=False,
            overall_compliance_pct=0.0,
            compliance_scores={},
            components=[],
        )
        triage = build_founder_triage(non_ai)
        assert isinstance(triage, FounderTriage)
        assert triage.is_ai_system is False
        assert "No AI/ML system detected" in triage.headline
        assert triage.operator_role == "out_of_scope"
        assert triage.ship_now == []
        assert triage.enterprise_deals == []
        assert triage.later_2027 == []
        assert triage.top_cross_framework_levers == []
        assert triage.vendor_contract_checklist == []
        assert triage.summary_counts["total_gaps"] == 0
        assert "No AI/ML system detected" in triage.brief_markdown

    def test_ship_now_enterprise_and_later_2027_bucketing(self) -> None:
        result = _startup_scan_result(role="deployer", high_risk_vertical=True)
        triage = build_founder_triage(result)

        assert triage.is_ai_system is True
        assert triage.operator_role == "deployer"
        assert "deployer" in triage.role_plain_english.lower()
        assert "Art. 26/50" in triage.role_plain_english

        ship_titles = [item.title for item in triage.ship_now]
        assert any("Art. 50" in t for t in ship_titles)
        assert any("MCP tool poisoning" in t for t in ship_titles)
        assert any("Hardcoded OpenAI API key" in t for t in ship_titles)
        assert any("Bash(*)" in t for t in ship_titles)
        assert any("Lethal trifecta" in t for t in ship_titles)

        # Verify Art. 50 mentions live 2 Aug 2026 date
        art50_item = next(item for item in triage.ship_now if "Art. 50" in item.title)
        assert "2 Aug 2026" in art50_item.why_it_matters_now
        assert art50_item.line_number == 27

        ent_titles = [item.title for item in triage.enterprise_deals]
        assert any("PR security review" in t for t in ent_titles)
        assert any("Unpinned npx -y" in t for t in ent_titles)
        assert any("structured audit logging" in t for t in ent_titles)

        # Top cross-framework levers and deployer vendor contract checklist
        assert 1 <= len(triage.top_cross_framework_levers) <= 3
        assert len(triage.vendor_contract_checklist) == 3
        assert any("Art. 25(1)" in item for item in triage.vendor_contract_checklist)

        # Later 2027 bucket notes Digital Omnibus 2 Dec 2027 + Annex I 2 Aug 2028 + high-risk vertical
        assert len(triage.later_2027) >= 1
        later_reason = triage.later_2027[0].why_it_matters_now
        assert "2026/1744" in later_reason
        assert "2 Dec 2027" in later_reason
        assert "2 Aug 2028" in later_reason
        assert "Employment / HR" in later_reason

        assert triage.summary_counts["ship_now"] == len(triage.ship_now)
        assert triage.summary_counts["enterprise_deals"] == len(triage.enterprise_deals)
        assert triage.summary_counts["later_2027"] == len(triage.later_2027)
        assert triage.summary_counts["total_gaps"] == (
            len(triage.ship_now) + len(triage.enterprise_deals) + len(triage.later_2027)
        )

    def test_provider_role_omits_deployer_vendor_checklist(self) -> None:
        result = _startup_scan_result(role="provider")
        triage = build_founder_triage(result)
        assert triage.operator_role == "provider"
        assert "provider" in triage.role_plain_english.lower()
        assert triage.vendor_contract_checklist == []

    def test_accepts_precomputed_cross_framework_dict(self) -> None:
        result = _startup_scan_result(role="deployer")
        custom_cf = {
            "satisfy_once_levers": [
                {
                    "dimension_id": "logging",
                    "dimension_label": "Record-Keeping",
                    "frameworks_helped": ["soc2", "gdpr", "owasp_llm"],
                    "controls_closed_count": 7,
                    "impact_summary": "Unlocks SOC 2, GDPR, and OWASP LLM in one PR.",
                }
            ]
        }
        triage = build_founder_triage(result, cross_framework=custom_cf)
        assert len(triage.top_cross_framework_levers) == 1
        assert triage.top_cross_framework_levers[0].control == "Record-Keeping"
        assert len(triage.top_cross_framework_levers[0].frameworks_unlocked) == 3

    def test_format_founder_brief_is_concise_and_strictly_offline(self) -> None:
        result = _startup_scan_result(role="deployer")
        triage = build_founder_triage(result)
        brief = format_founder_brief(triage)

        lines = brief.splitlines()
        assert len(lines) < 50, f"Founder brief exceeded 50 lines ({len(lines)} lines)"
        assert "# Founder AI Compliance Brief" in brief
        assert "Fix Before Shipping" in brief
        assert "Unblock Enterprise Deals" in brief
        assert "2 Dec 2027" in brief
        assert not _URL_RE.search(brief), "Founder brief must not embed remote URLs"

        # Entire JSON model must also stay strictly offline
        payload_json = json.dumps(triage.model_dump())
        assert not _URL_RE.search(payload_json), "FounderTriage JSON must not embed remote URLs"


class TestReusableAssetsContracts:
    def test_sensitive_data_guard_hook_is_valid_json(self) -> None:
        hook_path = REPO_ROOT / "hooks" / "sensitive-data-guard.json"
        data = json.loads(hook_path.read_text(encoding="utf-8"))
        # Claude Code settings use an event-keyed object with matchers, each
        # containing one or more command hooks (not a flat event/command list).
        events = data.get("hooks")
        assert isinstance(events, dict)
        pre_tool_use = events.get("PreToolUse")
        assert isinstance(pre_tool_use, list) and pre_tool_use
        registered = [hook for matcher in pre_tool_use for hook in matcher.get("hooks", [])]
        assert registered
        assert all(hook["type"] == "command" for hook in registered)
        assert all("sensitive_data_guard.py" in hook["command"] for hook in registered)
        assert {"Write", "Edit", "Bash"}.issubset(set(pre_tool_use[0]["matcher"].split("|")))

    def test_contract_playbook_yaml_has_8_positions_and_omnibus_dates(self) -> None:
        playbook_path = REPO_ROOT / "playbooks" / "ai-act-contract-positions.yaml"
        data = yaml.safe_load(playbook_path.read_text(encoding="utf-8"))
        assert isinstance(data, dict)
        positions = data["positions"]
        assert len(positions) == 8
        assert [p["id"] for p in positions] == [f"aiact-0{i}" for i in range(1, 9)]
        assert data["key_dates"]["article_50_transparency"] == "2026-08-02"
        assert data["key_dates"]["annex_iii_high_risk"] == "2027-12-02"
        assert data["key_dates"]["annex_i_safety_components"] == "2028-08-02"
