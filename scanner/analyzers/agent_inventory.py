"""Agent Inventory Analyzer — detects modern agent runtime patterns and emits a per-tool inventory.

Implements the inventory backbone from Nannini et al. (2026), AI Agents
under EU Law, Conclusion 3 — *"the provider's foundational compliance
task is an exhaustive inventory of the agent's external actions, data
flows, connected systems, and affected persons."* (paper line 2456)

Scope intentionally distinct from `agent_cascade.py` (chain-shape +
validation gates). This analyzer:

- Detects the **modern agent surface** the paper highlights: MCP
  clients, OpenAI Assistants v2 thread/run model, Anthropic tool-use,
  browser-use / Playwright agents, code-interpreter sandboxes, and
  emerging multi-agent stacks (AG2, OpenDevin, MetaGPT) — the things
  `agent_cascade._AGENT_CHAIN_PATTERNS` substring-matches LangChain
  family but never sees.
- Categorises the agent against Table 1's nine deployment categories
  (Customer Service, HR, Coding/DevOps, Finance, Sales/Marketing,
  Research, IT Operations, Healthcare, Personal Assistant) by
  evidence-weighted external-system signal.
- Estimates the **autonomy axis** ∈ {none, single-step, looped,
  multi-agent} which the existing classifier does not surface.

Maps to KB dimensions: agent_inventory, tool_governance, transparency.

References:
- Paper §3 + Table 1 (lines 236-378)
- Paper §6.1 + prEN 18282 (lines 672-773)
- Paper Conclusion 3 (line 2456)
"""

from __future__ import annotations

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    has_file,
    search_files,
)

# ─── Modern agent runtime signals ────────────────────────────────────────────
# Each entry: (regex, signal_name, autonomy_hint).
# autonomy_hint ∈ {"single-step", "looped", "multi-agent"} — best-effort
# guess; the per-system aggregate is computed at the end.

_AGENT_RUNTIME_SIGNALS: list[tuple[str, str, str]] = [
    # MCP clients (Model Context Protocol)
    (r"\bfrom\s+mcp\b", "mcp_client", "looped"),
    (r"\bmcp\.client\b", "mcp_client", "looped"),
    (r"@mcp\.server\.tool\b", "mcp_server_tool", "looped"),
    (r"@mcp\.tool\b", "mcp_server_tool", "looped"),
    # OpenAI Assistants v2
    (r"client\.beta\.assistants\.(create|retrieve|list)", "openai_assistants_v2", "looped"),
    (r"client\.beta\.threads\.(create|runs)", "openai_assistants_v2", "looped"),
    # Anthropic tool-use (separate from raw chat completion)
    (r"messages\.create\([^)]*\btools\s*=", "anthropic_tool_use", "looped"),
    (r"\btool_choice\s*=\s*[\"'{]", "anthropic_tool_use", "looped"),
    (r'"type":\s*"tool_use"', "anthropic_tool_use", "looped"),
    # Browser / Web automation agents
    (r"\bfrom\s+playwright\b", "browser_agent", "looped"),
    (r"\bbrowser_use\b", "browser_agent", "looped"),
    (r"\bfrom\s+selenium\b", "browser_agent", "looped"),
    # Code interpreters / sandboxed execution
    (r'"type":\s*"code_interpreter"', "code_interpreter", "looped"),
    (r"\bfrom\s+e2b\b", "code_interpreter", "looped"),
    (r"\bfrom\s+daytona\b", "code_interpreter", "looped"),
    (r"\bmodal\.Sandbox\b", "code_interpreter", "looped"),
    # Multi-agent orchestrators beyond the LangChain family
    (r"\bautogen_agentchat\b", "autogen_v04", "multi-agent"),
    (r"\bautogen_core\b", "autogen_v04", "multi-agent"),
    (r"\bag2\b", "ag2", "multi-agent"),
    (r"\bopendevin\b", "opendevin", "multi-agent"),
    (r"\bmetagpt\b", "metagpt", "multi-agent"),
    # Older but still-relevant: confirm coverage, lighter weight than agent_cascade
    (r"\blangchain\.agents\b", "langchain_agent", "looped"),
    (r"\blanggraph\b", "langgraph", "multi-agent"),
    (r"\bcrewai\b", "crewai", "multi-agent"),
]

# ─── External-system signals → Table 1 deployment categories ─────────────────
# Each entry is a regex paired with the (category, system_label) it implies.
# Multiple categories per file are allowed; aggregation happens at the end.

_CATEGORY_SIGNALS: list[tuple[str, str, str]] = [
    # Customer Service
    (r"\bsimple_salesforce\b|\bsalesforce_api\b", "customer_service", "Salesforce CRM"),
    (r"\bhubspot\b", "customer_service", "HubSpot CRM"),
    (r"\bzendesk\b|\bfreshdesk\b", "customer_service", "ticketing"),
    # HR / Recruitment
    (r"\bworkday\b", "hr_recruitment", "Workday ATS"),
    (r"\bgreenhouse_io\b|\bgreenhouse\.io\b", "hr_recruitment", "Greenhouse ATS"),
    (r"\bbamboohr\b|\blever\.co\b", "hr_recruitment", "HR/ATS"),
    # Coding / DevOps
    (r"\bgithub\.Github\b|\bPyGithub\b|\bfrom\s+github\b", "coding_devops", "GitHub API"),
    (r"\bgitlab\b", "coding_devops", "GitLab API"),
    (r"\bfrom\s+jenkins\b|\bjenkinsapi\b", "coding_devops", "Jenkins CI"),
    # Finance / Accounting
    (r"\bfrom\s+pyrfc\b|\bsap_business_one\b", "finance_accounting", "SAP ERP"),
    (r"\bquickbooks\b|\bxero\b", "finance_accounting", "accounting"),
    (r"\bplaid\b|\bopenbanking\b", "finance_accounting", "banking API"),
    # Sales / Marketing
    (r"\bmailchimp\b|\bsendgrid\b", "sales_marketing", "email marketing"),
    (r"\btwitter_api|tweepy\b|\bfacebook_business\b", "sales_marketing", "social media API"),
    # Research / Knowledge
    (r"\bgoogle_search\b|\bduckduckgo_search\b|\bfrom\s+serpapi\b", "research_knowledge", "web search"),
    (r"\bscholarly\b|\barxiv\.|\busptov2\b", "research_knowledge", "research DB"),
    # IT Operations
    (r"\bdatadog\b|\bdatadog_api\b", "it_operations", "Datadog monitoring"),
    (r"\bprometheus_client\b|\bnewrelic\b", "it_operations", "monitoring/APM"),
    (r"\bjira\b|\bservicenow\b", "it_operations", "ITSM"),
    (r"\bopcua\b|\bpymodbus\b", "it_operations", "OT / SCADA"),
    # Healthcare / Clinical
    (r"\bfhir\b|\bfhirclient\b", "healthcare", "FHIR / EHR"),
    (r"\bpydicom\b", "healthcare", "DICOM imaging"),
    (r"\bepic_fhir\b|\bcerner_fhir\b", "healthcare", "EHR vendor"),
    # Personal Assistant
    (r"\bgoogleapiclient.*gmail|\boauth.*gmail\b", "personal_assistant", "Gmail"),
    (r"\bO365\b|\bexchangelib\b", "personal_assistant", "Outlook/Exchange"),
    (r"\bgoogleapiclient.*calendar", "personal_assistant", "Google Calendar"),
]

# ─── Action-verb taxonomy (paper line 80) ──────────────────────────────────
# Distinguishes "an LLM that acts on the world" from "an LLM that returns a
# prediction." This is the primary scanner signal per Table 1 §3.

_ACTION_VERB_SIGNALS: dict[str, list[str]] = {
    "send_email": [r"\bsmtplib\b", r"\.send_message\(", r"send_email", r"sendgrid\.send"],
    "write_file": [r"\bopen\s*\([^)]*[\"']w[\"']", r"\.write_text\(", r"\.write\("],
    "execute_code": [r"\bsubprocess\.run\b", r"\bexec\s*\(", r"\beval\s*\(", r"shell\s*=\s*True"],
    "modify_db": [r"\.execute\([\"']INSERT\b", r"\.execute\([\"']UPDATE\b", r"\.execute\([\"']DELETE\b", r"\.delete\(", r"\.update\("],
    "post_content": [r"\.post\([^)]*twitter|\.post\([^)]*facebook", r"\.create_tweet\(", r"slack_sdk.*chat_postMessage"],
    "authorize_payment": [r"\bstripe\.PaymentIntent\.create\b", r"\.charge\(", r"\bcreate_charge\b"],
    "infra_mutation": [r"\bboto3\.client\([\"']ec2[\"']\)", r"\.terminate_instances\(", r"kubectl\.apply\(", r"\bansible_runner\b"],
}


def _autonomy_rank(autonomy: str) -> int:
    return {"none": 0, "single-step": 1, "looped": 2, "multi-agent": 3}.get(autonomy, 0)


def analyze_agent_inventory(ctx: AnalyzerContext) -> AnalyzerResult:
    findings: list[Finding] = []
    evidence_files: set[str] = set()

    # ── 1. Detect modern agent runtime patterns ─────────────────────────
    runtime_hits: dict[str, list[tuple[str, str]]] = {}
    runtime_autonomy: str = "none"
    for pattern, signal_name, autonomy_hint in _AGENT_RUNTIME_SIGNALS:
        matches = search_files(ctx, pattern)
        if matches:
            runtime_hits.setdefault(signal_name, []).extend(matches)
            if _autonomy_rank(autonomy_hint) > _autonomy_rank(runtime_autonomy):
                runtime_autonomy = autonomy_hint

    if runtime_hits:
        first_signal = next(iter(runtime_hits))
        first_match = runtime_hits[first_signal][0]
        evidence_files.add(first_match[0])
        signals_summary = ", ".join(sorted(runtime_hits.keys()))
        findings.append(Finding(
            id="ai-runtime-detected", category="agent_inventory",
            title=f"Agent runtime patterns detected: {signals_summary}",
            description=(
                "The codebase imports agent-runtime libraries beyond raw chat completion. "
                "Per the EU AI Agents paper (Nannini et al. 2026), this triggers an obligation "
                "under Conclusion 3 to inventory external actions, data flows, connected systems, "
                "and affected persons. The current scanner has registered the runtime presence — "
                "the operator must produce the inventory itself."
            ),
            file_path=first_match[0], confidence=0.85,
            compliance_impact="neutral",
            compliance_dimensions=["agent_inventory", "tech_docs"],
            evidence_snippet=first_match[1],
            kb_question_ids=["ai-1", "ai-2"], suggested_answer="partial",
        ))

    # ── 2. Per-category external-system inventory (Table 1) ─────────────
    category_hits: dict[str, list[tuple[str, str, str]]] = {}
    for pattern, category, label in _CATEGORY_SIGNALS:
        matches = search_files(ctx, pattern)
        for path, line in matches:
            category_hits.setdefault(category, []).append((path, line, label))

    if category_hits:
        # Each detected category becomes one finding so the audit wizard can
        # surface the regulatory triggers per Table 5 (the regulatory_perimeter
        # analyzer turns these into per-instrument obligations).
        for category, hits in sorted(category_hits.items()):
            first_path, first_line, first_label = hits[0]
            evidence_files.add(first_path)
            risk_anchor = _CATEGORY_RISK_ANCHOR.get(category, "Art. 50 transparency baseline")
            findings.append(Finding(
                id=f"ai-category-{category}", category="agent_inventory",
                title=f"Deployment category signal: {category.replace('_', ' ').title()}",
                description=(
                    f"External system signal: {first_label}. Risk anchor: {risk_anchor}. "
                    f"Operator must confirm the deployment category and resolve any high-risk "
                    f"Annex III mapping in the audit wizard."
                ),
                file_path=first_path, confidence=0.7,
                compliance_impact="neutral",
                compliance_dimensions=["agent_inventory", "risk_mgmt"],
                evidence_snippet=first_line,
                kb_question_ids=["ai-2", "ai-3"], suggested_answer="partial",
            ))

    # ── 3. Action-verb taxonomy: "agent that acts on the world" ─────────
    action_hits: dict[str, list[tuple[str, str]]] = {}
    for verb, patterns in _ACTION_VERB_SIGNALS.items():
        for pattern in patterns:
            matches = search_files(ctx, pattern)
            if matches:
                action_hits.setdefault(verb, []).extend(matches)

    if action_hits:
        first_verb = next(iter(action_hits))
        first_match = action_hits[first_verb][0]
        evidence_files.add(first_match[0])
        verbs_present = sorted(action_hits.keys())
        findings.append(Finding(
            id="ai-action-verbs", category="agent_inventory",
            title=f"World-acting verbs detected: {', '.join(verbs_present)}",
            description=(
                "Code paths exist that send/write/execute/post/pay/mutate. Per the paper §1 "
                "(line 80), this is what differentiates an agent from a non-agent LLM. Each "
                "verb is an action class that requires a per-action audit trail under Art. 12 "
                "and an authority decision under Art. 14."
            ),
            file_path=first_match[0], confidence=0.8,
            compliance_impact="neutral",
            compliance_dimensions=["agent_inventory", "logging", "human_oversight"],
            evidence_snippet=first_match[1],
            kb_question_ids=["ai-3"], suggested_answer="partial",
        ))

    # ── 4. Inventory-document presence check (the operator artefact) ────
    inventory_doc_paths = (
        has_file(ctx, r"agent[-_]?inventory\.(md|json|ya?ml)$")
        or has_file(ctx, r"tools?[-_]?catalog\.(md|json|ya?ml)$")
        or has_file(ctx, r"action[-_]?inventory\.(md|json|ya?ml)$")
    )
    if inventory_doc_paths:
        findings.append(Finding(
            id="ai-inventory-doc", category="agent_inventory",
            title="Agent inventory artefact detected",
            description=(
                "An agent-inventory document exists. This satisfies Conclusion 3 of the paper "
                "structurally; the audit wizard must confirm completeness against Table 1's "
                "four facets: external actions, data flows, connected systems, affected persons."
            ),
            file_path=inventory_doc_paths[0], confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["agent_inventory", "tech_docs"],
            evidence_snippet="",
            kb_question_ids=["ai-1"], suggested_answer="yes",
        ))
    elif runtime_hits or category_hits or action_hits:
        findings.append(Finding(
            id="ai-no-inventory-doc", category="agent_inventory",
            title="Agent runtime present but no inventory artefact",
            description=(
                "Agent runtime/category/action signals were detected, but no "
                "`agent-inventory.{md,json,yaml}` or `tools-catalog.{md,json,yaml}` "
                "artefact exists in the repo. Per Nannini et al. Conclusion 3, the inventory "
                "is the regulatory map — without it the operator cannot answer the auditor's "
                "Table 5 trigger questions. Add the artefact at the repo root."
            ),
            file_path=next(iter(evidence_files), "(no file)"),
            confidence=0.85,
            compliance_impact="gap",
            compliance_dimensions=["agent_inventory", "tech_docs"],
            evidence_snippet="",
            kb_question_ids=["ai-1"], suggested_answer="no",
        ))

    # ── 5. Score + autonomy axis ────────────────────────────────────────
    autonomy_axis = runtime_autonomy
    if not runtime_hits and (category_hits or action_hits):
        autonomy_axis = "single-step"
    if not runtime_hits and not category_hits and not action_hits:
        autonomy_axis = "none"

    if not findings:
        score = 80.0  # not applicable — no agent surface detected
    else:
        positives = sum(1 for f in findings if f.compliance_impact == "positive")
        gaps = sum(1 for f in findings if f.compliance_impact == "gap")
        if not gaps and positives:
            score = 85.0 + min(positives * 4, 15.0)
        elif gaps and positives:
            score = max(40.0, 65.0 - gaps * 12 + positives * 5)
        elif gaps:
            score = max(15.0, 55.0 - gaps * 12)
        else:
            score = 60.0

    return AnalyzerResult(
        analyzer_id="agent_inventory",
        label="Agent Inventory (4-facet)",
        findings=findings,
        score=round(score, 1),
        file_count=len(evidence_files),
        graph_node_type="agent",
        graph_icon="🛰",
        connected_categories=["agent_cascade", "tool_governance", "regulatory_perimeter"],
        metadata={
            "autonomy_axis": autonomy_axis,
            "runtime_signals": sorted(runtime_hits.keys()),
            "deployment_categories": sorted(category_hits.keys()),
            "action_verbs": sorted(action_hits.keys()),
        },
    )


# Risk anchor map for each Table 1 deployment category — kept terse so the
# Finding description stays under the 200-char evidence-snippet ceiling.
_CATEGORY_RISK_ANCHOR: dict[str, str] = {
    "customer_service": "Art. 50 + GDPR; Annex III if integrated into credit/insurance",
    "hr_recruitment": "Annex III 4(a) HIGH-RISK + GDPR Art. 22 + prEN 18283 bias",
    "coding_devops": "Art. 50 + CRA + prEN 18282 (open-ended code execution)",
    "finance_accounting": "GDPR + Annex III 5(b) if creditworthiness + MiFID II",
    "sales_marketing": "Art. 50 + GDPR profiling + DSA + ePrivacy",
    "research_knowledge": "Art. 50 + DSM Arts. 3-4 (copyright) + Data Act",
    "it_operations": "CRA + NIS2 if essential entity + Annex III 2 if critical infra",
    "healthcare": "Annex I(A) MDR/IVDR HIGH-RISK + GDPR Art. 9 + ISO 13485",
    "personal_assistant": "Art. 50 + GDPR + prEN 18282 read-only example + CRA vertical",
}
