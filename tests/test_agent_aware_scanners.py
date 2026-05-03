"""Tests for the agent-aware analyzers added in v0.3.

Per Nannini et al. (2026), "AI Agents under EU Law: A Compliance Architecture
for AI Providers". The analyzers cover four compound-risk axes (cascading,
emergent, attribution, temporal) defined in §10.4 of the working paper.
"""

from __future__ import annotations

from scanner.analyzers import AnalyzerContext


def _ctx(files: dict[str, str]) -> AnalyzerContext:
    return AnalyzerContext(
        files=files,
        file_list=list(files.keys()),
        languages={"python": 1},
    )


# ── agent_inventory ─────────────────────────────────────────────────────


def test_agent_inventory_detects_mcp_and_assistants_v2():
    from scanner.analyzers.agent_inventory import analyze_agent_inventory
    ctx = _ctx({
        "agent.py": (
            "from openai import OpenAI\n"
            "client = OpenAI()\n"
            "client.beta.assistants.create(name='helper')\n"
            "client.beta.threads.runs.create(thread_id='t')\n"
            "from mcp import client as mcp_client\n"
        ),
    })
    result = analyze_agent_inventory(ctx)
    ids = {f.id for f in result.findings}
    assert "ai-runtime-detected" in ids
    runtime_signals = result.metadata.get("runtime_signals", [])
    assert "mcp_client" in runtime_signals
    assert "openai_assistants_v2" in runtime_signals
    assert result.metadata["autonomy_axis"] in {"looped", "multi-agent"}


def test_agent_inventory_detects_browser_and_code_interpreter():
    from scanner.analyzers.agent_inventory import analyze_agent_inventory
    ctx = _ctx({
        "agent.py": (
            "from playwright.async_api import async_playwright\n"
            "import browser_use\n"
            "from e2b import Sandbox\n"
        ),
    })
    result = analyze_agent_inventory(ctx)
    signals = result.metadata.get("runtime_signals", [])
    assert "browser_agent" in signals
    assert "code_interpreter" in signals


def test_agent_inventory_categorises_healthcare_high_risk():
    from scanner.analyzers.agent_inventory import analyze_agent_inventory
    ctx = _ctx({
        "clinical.py": (
            "from fhirclient import client\n"
            "import pydicom\n"
            "from openai import OpenAI\n"
        ),
    })
    result = analyze_agent_inventory(ctx)
    cats = result.metadata.get("deployment_categories", [])
    assert "healthcare" in cats
    cat_finding = next(f for f in result.findings if f.id == "ai-category-healthcare")
    assert "MDR" in cat_finding.description or "Annex I(A)" in cat_finding.description


def test_agent_inventory_action_verbs():
    from scanner.analyzers.agent_inventory import analyze_agent_inventory
    ctx = _ctx({
        "tool.py": (
            "import smtplib\n"
            "import subprocess\n"
            "result = subprocess.run(cmd, shell=True)\n"
            "stripe.PaymentIntent.create(amount=100)\n"
        ),
    })
    result = analyze_agent_inventory(ctx)
    verbs = result.metadata.get("action_verbs", [])
    assert "send_email" in verbs
    assert "execute_code" in verbs
    assert "authorize_payment" in verbs


def test_agent_inventory_flags_missing_inventory_artefact():
    from scanner.analyzers.agent_inventory import analyze_agent_inventory
    ctx = _ctx({
        "agent.py": "from langchain.agents import AgentExecutor\n",
    })
    result = analyze_agent_inventory(ctx)
    ids = {f.id for f in result.findings}
    assert "ai-no-inventory-doc" in ids


def test_agent_inventory_recognises_inventory_artefact():
    from scanner.analyzers.agent_inventory import analyze_agent_inventory
    ctx = _ctx({
        "agent.py": "from langchain.agents import AgentExecutor\n",
        "agent-inventory.md": "# Agent Inventory\n",
    })
    result = analyze_agent_inventory(ctx)
    ids = {f.id for f in result.findings}
    assert "ai-inventory-doc" in ids
    assert "ai-no-inventory-doc" not in ids


# ── privilege_minimization ──────────────────────────────────────────────


def test_privilege_minimization_flags_prompt_as_control():
    from scanner.analyzers.privilege_minimization import analyze_privilege_minimization
    ctx = _ctx({
        "agent.py": (
            'from openai import OpenAI\n'
            'SYS = "You are a helper. Do not delete files. Never send emails to admin."\n'
        ),
    })
    result = analyze_privilege_minimization(ctx)
    ids = {f.id for f in result.findings}
    assert "pm-prompt-as-control" in ids


def test_privilege_minimization_flags_open_exec():
    from scanner.analyzers.privilege_minimization import analyze_privilege_minimization
    ctx = _ctx({
        "agent.py": (
            "from openai import OpenAI\n"
            "import subprocess\n"
            "subprocess.run(model_output, shell=True)\n"
        ),
    })
    result = analyze_privilege_minimization(ctx)
    ids = {f.id for f in result.findings}
    assert "pm-open-exec" in ids


def test_privilege_minimization_flags_long_lived_cred():
    from scanner.analyzers.privilege_minimization import analyze_privilege_minimization
    ctx = _ctx({
        "agent.py": (
            "from openai import OpenAI\n"
            "ACCESS_KEY = 'AKIA1234567890ABCDEF1234567890ABCDEF'\n"
        ),
    })
    result = analyze_privilege_minimization(ctx)
    ids = {f.id for f in result.findings}
    assert "pm-long-lived-cred" in ids


def test_privilege_minimization_flags_oauth_overgrant():
    from scanner.analyzers.privilege_minimization import analyze_privilege_minimization
    ctx = _ctx({
        "config.py": (
            "SCOPES = ['https://www.googleapis.com/auth/gmail.send']\n"
        ),
        "agent.py": (
            "from googleapiclient.discovery import build\n"
            "service = build('gmail', 'v1')\n"
        ),
    })
    result = analyze_privilege_minimization(ctx)
    ids = {f.id for f in result.findings}
    assert any(i.startswith("pm-overgrant-gmail-send") for i in ids)


def test_privilege_minimization_recognises_permission_registry():
    from scanner.analyzers.privilege_minimization import analyze_privilege_minimization
    ctx = _ctx({
        "tools-permissions.yaml": "tools:\n  - name: read_email\n    scopes: [read]\n",
    })
    result = analyze_privilege_minimization(ctx)
    ids = {f.id for f in result.findings}
    assert "pm-permission-registry" in ids


# ── runtime_drift ───────────────────────────────────────────────────────


def test_runtime_drift_flags_floating_model():
    from scanner.analyzers.runtime_drift import analyze_runtime_drift
    ctx = _ctx({
        "agent.py": 'response = client.chat.completions.create(model="gpt-4o", messages=[])\n',
    })
    result = analyze_runtime_drift(ctx)
    ids = {f.id for f in result.findings}
    assert "rd-model-floating" in ids
    assert result.metadata["model_floating"] is True
    assert result.metadata["model_pinned"] is False


def test_runtime_drift_recognises_pinned_model():
    from scanner.analyzers.runtime_drift import analyze_runtime_drift
    ctx = _ctx({
        "agent.py": 'response = client.chat.completions.create(model="gpt-4o-2024-08-06", messages=[])\n',
    })
    result = analyze_runtime_drift(ctx)
    ids = {f.id for f in result.findings}
    assert "rd-model-pinned" in ids
    assert result.metadata["model_pinned"] is True


def test_runtime_drift_flags_inline_prompt():
    from scanner.analyzers.runtime_drift import analyze_runtime_drift
    ctx = _ctx({
        "agent.py": (
            'msg = SystemMessage(content="You are a helpful agent that answers questions about EU AI Act compliance and never makes things up")\n'
        ),
    })
    result = analyze_runtime_drift(ctx)
    ids = {f.id for f in result.findings}
    assert "rd-prompt-inline" in ids


def test_runtime_drift_recognises_versioned_prompts():
    from scanner.analyzers.runtime_drift import analyze_runtime_drift
    ctx = _ctx({
        "prompts/system_v3.md": "# System Prompt v3\n",
    })
    result = analyze_runtime_drift(ctx)
    ids = {f.id for f in result.findings}
    assert "rd-prompt-versioned" in ids


def test_runtime_drift_recognises_tool_manifest():
    from scanner.analyzers.runtime_drift import analyze_runtime_drift
    ctx = _ctx({
        "tools-catalog.yaml": "tools: []\n",
    })
    result = analyze_runtime_drift(ctx)
    ids = {f.id for f in result.findings}
    assert "rd-tools-manifest" in ids


def test_runtime_drift_flags_no_substantial_modification_doc():
    from scanner.analyzers.runtime_drift import analyze_runtime_drift
    ctx = _ctx({"agent.py": "x = 1\n"})
    result = analyze_runtime_drift(ctx)
    ids = {f.id for f in result.findings}
    assert "rd-no-sm-procedure" in ids


def test_runtime_drift_recognises_substantial_modification_doc():
    from scanner.analyzers.runtime_drift import analyze_runtime_drift
    ctx = _ctx({
        "docs/governance.md": (
            "# Substantial Modification Procedure\n"
            "Per Art. 3(23), changes to the model snapshot trigger re-conformity review.\n"
        ),
    })
    result = analyze_runtime_drift(ctx)
    ids = {f.id for f in result.findings}
    assert "rd-sm-procedure" in ids


# ── regulatory_perimeter ────────────────────────────────────────────────


def test_regulatory_perimeter_emits_gdpr_for_crm_signal():
    from scanner.analyzers.regulatory_perimeter import analyze_regulatory_perimeter
    ctx = _ctx({"agent.py": "import simple_salesforce\n"})
    result = analyze_regulatory_perimeter(ctx)
    triggered = result.metadata.get("triggered_instruments", [])
    assert "GDPR" in triggered


def test_regulatory_perimeter_emits_data_act_for_iot():
    from scanner.analyzers.regulatory_perimeter import analyze_regulatory_perimeter
    ctx = _ctx({"agent.py": "import paho.mqtt.client\n"})
    result = analyze_regulatory_perimeter(ctx)
    assert "Data Act" in result.metadata["triggered_instruments"]


def test_regulatory_perimeter_emits_cra_for_pyproject_cli():
    from scanner.analyzers.regulatory_perimeter import analyze_regulatory_perimeter
    ctx = _ctx({
        "pyproject.toml": "[project.scripts]\nagent = \"agent.cli:main\"\n",
    })
    result = analyze_regulatory_perimeter(ctx)
    assert "CRA" in result.metadata["triggered_instruments"]


def test_regulatory_perimeter_emits_mdr_for_fhir():
    from scanner.analyzers.regulatory_perimeter import analyze_regulatory_perimeter
    ctx = _ctx({"agent.py": "from fhirclient import client\n"})
    result = analyze_regulatory_perimeter(ctx)
    assert "MDR" in result.metadata["triggered_instruments"]


def test_regulatory_perimeter_emits_nis2_for_ot():
    from scanner.analyzers.regulatory_perimeter import analyze_regulatory_perimeter
    ctx = _ctx({
        "agent.py": "from opcua import Client\nimport pymodbus\n",
    })
    result = analyze_regulatory_perimeter(ctx)
    assert "NIS2" in result.metadata["triggered_instruments"]


def test_regulatory_perimeter_step9_artefact_recognised():
    from scanner.analyzers.regulatory_perimeter import analyze_regulatory_perimeter
    ctx = _ctx({
        "agent.py": "import simple_salesforce\n",
        "adjacent-legislation.md": "# Adjacent legislation\n",
    })
    result = analyze_regulatory_perimeter(ctx)
    ids = {f.id for f in result.findings}
    assert "rp-step9-doc" in ids
    assert "rp-step9-missing" not in ids


def test_regulatory_perimeter_step9_missing_when_triggered():
    from scanner.analyzers.regulatory_perimeter import analyze_regulatory_perimeter
    ctx = _ctx({"agent.py": "import simple_salesforce\n"})
    result = analyze_regulatory_perimeter(ctx)
    ids = {f.id for f in result.findings}
    assert "rp-step9-missing" in ids


def test_regulatory_perimeter_quiet_when_no_triggers():
    from scanner.analyzers.regulatory_perimeter import analyze_regulatory_perimeter
    ctx = _ctx({"plain.py": "print('hello world')\n"})
    result = analyze_regulatory_perimeter(ctx)
    assert result.findings == []
    assert result.metadata["instrument_count"] == 0


# ── KB sanity for the 4 new dimensions ──────────────────────────────────


def test_new_kb_dimensions_exist():
    from scanner.kb import DIMENSIONS
    for new_id in (
        "agent_inventory",
        "tool_governance",
        "regulatory_perimeter",
        "runtime_drift",
    ):
        assert new_id in DIMENSIONS, f"Expected new dimension {new_id!r} not in KB"


# ── Default taxonomy back-fill ──────────────────────────────────────────


def test_default_taxonomy_backfilled_on_gap_findings():
    """The Nannini-aligned analyzers should get compound_risk_type +
    threat_categories on every finding, plus applicable_roles on gaps.
    """
    from scanner.analyzers import run_all_analyzers
    ctx = _ctx({"agent.py": "from langchain.agents import AgentExecutor\n"})
    results = run_all_analyzers(ctx)
    by_id = {r.analyzer_id: r for r in results}

    inv = by_id["agent_inventory"]
    gap = next((f for f in inv.findings if f.compliance_impact == "gap"), None)
    assert gap is not None, "expected at least one gap from agent_inventory"
    assert gap.compound_risk_type == "attribution"
    assert "governance_autonomy" in gap.threat_categories
    assert "provider" in gap.applicable_roles
