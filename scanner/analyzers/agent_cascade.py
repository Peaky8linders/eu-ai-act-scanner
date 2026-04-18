"""Multi-Agent Cascade Risk Analyzer — detects chained AI agents without validation gates.

When multiple AI models/agents chain outputs without intermediate validation,
errors propagate and amplify (Art. 15(4) resilience requirement).

Maps to: risk_mgmt, human_oversight, decision_governance
"""

from __future__ import annotations

import re

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    search_files,
)

# Patterns indicating multi-agent/multi-model chaining
_AGENT_CHAIN_PATTERNS = [
    r"(langchain|langgraph|crewai|autogen|swarm|magentic)",
    r"agent.*chain|chain.*agent|multi.?agent|agent.*orchestrat",
    r"tool_calls|function_calling|tool_use",
    r"\.invoke\(.*\.invoke\(|\.run\(.*\.run\(",
    r"pipeline|workflow.*step|step.*workflow|dag.*task",
]

_VALIDATION_GATE_PATTERNS = [
    r"validat(e|or|ion).*output|output.*validat",
    r"check.*result|result.*check|verify.*output",
    r"guardrail|safety.*check|content.*filter",
    r"intermediate.*review|review.*before|gate.*check",
    r"assert.*type|isinstance.*check|schema.*valid",
    r"confidence.*check|threshold.*gate|score.*min",
    r"human.*approval|manual.*review|approval.*gate",
]

_MODEL_ROUTING_PATTERNS = [
    r"model.*select|select.*model|route.*model|model.*rout",
    r"fallback.*model|backup.*model|model.*fallback",
    r"model_name|model_id|llm_model|completion_model",
]

_ERROR_PROPAGATION_PATTERNS = [
    r"try.*except.*pass|except.*continue|except.*:.*$",
    r"suppress.*error|ignore.*error|swallow.*exception",
    r"\.get\(.*default|\.get\(.*None\)",
]


def analyze_agent_cascade(ctx: AnalyzerContext) -> AnalyzerResult:
    findings: list[Finding] = []
    evidence_files: set[str] = set()

    # 1. Detect multi-agent/chain frameworks
    agent_framework_files: list[tuple[str, str]] = []
    for pattern in _AGENT_CHAIN_PATTERNS:
        agent_framework_files.extend(search_files(ctx, pattern))

    has_agent_chains = len(agent_framework_files) > 0

    if agent_framework_files:
        evidence_files.add(agent_framework_files[0][0])
        findings.append(Finding(
            id="ac-agent-framework", category="agent_cascade",
            title="Multi-agent or chain framework detected",
            description="Project uses an agent/chain framework that enables multi-model orchestration.",
            file_path=agent_framework_files[0][0], confidence=0.9,
            compliance_impact="neutral",
            compliance_dimensions=["risk_mgmt", "decision_governance"],
            evidence_snippet=agent_framework_files[0][1],
        ))

    # 2. Check for validation gates between chain steps
    validation_matches: list[tuple[str, str]] = []
    for pattern in _VALIDATION_GATE_PATTERNS:
        validation_matches.extend(search_files(ctx, pattern))

    validation_files = {m[0] for m in validation_matches}

    if has_agent_chains and validation_matches:
        # Check if validation exists in agent-chain files specifically
        agent_files = {m[0] for m in agent_framework_files}
        validated_agent_files = agent_files & validation_files
        if validated_agent_files:
            findings.append(Finding(
                id="ac-validation-gate", category="agent_cascade",
                title="Inter-step validation gates detected",
                description="Validation/checking logic found in agent chain files. Outputs are verified between steps.",
                file_path=list(validated_agent_files)[0], confidence=0.8,
                compliance_impact="positive",
                compliance_dimensions=["risk_mgmt", "human_oversight"],
                evidence_snippet=validation_matches[0][1],
                kb_question_ids=["rm-4"], suggested_answer="partial",
            ))
        else:
            findings.append(Finding(
                id="ac-missing-validation", category="agent_cascade",
                title="Agent chains lack inter-step validation",
                description=(
                    "Multi-agent chains detected but no validation gates found in chain files. "
                    "Art. 15(4) requires resilience against errors propagating between components. "
                    "Add output validation between each agent step."
                ),
                file_path=agent_framework_files[0][0], confidence=0.85,
                compliance_impact="gap",
                compliance_dimensions=["risk_mgmt", "human_oversight", "decision_governance"],
                evidence_snippet=agent_framework_files[0][1],
                kb_question_ids=["rm-4", "ho-1"], suggested_answer="no",
            ))
    elif has_agent_chains and not validation_matches:
        findings.append(Finding(
            id="ac-no-validation", category="agent_cascade",
            title="No inter-step validation in multi-agent system",
            description=(
                "Multi-agent framework detected but NO validation gates found anywhere in the codebase. "
                "This is a critical compliance gap: Art. 15(4) requires high-risk AI systems to be resilient "
                "against errors or inconsistencies that may occur within the system or its environment. "
                "Without validation between agent steps, errors cascade uncontrolled."
            ),
            file_path=agent_framework_files[0][0], confidence=0.9,
            compliance_impact="gap",
            compliance_dimensions=["risk_mgmt", "human_oversight", "decision_governance"],
            evidence_snippet=agent_framework_files[0][1],
            kb_question_ids=["rm-4", "ho-1"], suggested_answer="no",
        ))

    # 3. Detect model routing without fitness checks
    routing_matches = []
    for pattern in _MODEL_ROUTING_PATTERNS:
        routing_matches.extend(search_files(ctx, pattern))

    if routing_matches:
        evidence_files.add(routing_matches[0][0])
        # Check if model selection includes fitness/capability checks
        fitness_check = search_files(ctx, r"model.*capabilit|capabilit.*model|model.*fit|suitable.*model")
        if fitness_check:
            findings.append(Finding(
                id="ac-model-fitness", category="agent_cascade",
                title="Model fitness validation detected",
                description="Code checks model capability/suitability before routing tasks.",
                file_path=fitness_check[0][0], confidence=0.75,
                compliance_impact="positive",
                compliance_dimensions=["risk_mgmt", "decision_governance"],
                evidence_snippet=fitness_check[0][1],
            ))
        elif has_agent_chains:
            findings.append(Finding(
                id="ac-no-fitness-check", category="agent_cascade",
                title="Model routing without fitness validation",
                description=(
                    "Models are selected/routed but no capability or fitness check found. "
                    "A model technically authorised may not be appropriate for the task. "
                    "Add model-task fitness validation before inference."
                ),
                file_path=routing_matches[0][0], confidence=0.7,
                compliance_impact="gap",
                compliance_dimensions=["risk_mgmt", "decision_governance"],
                evidence_snippet=routing_matches[0][1],
            ))

    # 4. Detect silent error swallowing in chain contexts
    if has_agent_chains:
        agent_files_set = {m[0] for m in agent_framework_files}
        swallowed_in_agents: list[tuple[str, str]] = []
        for path in agent_files_set:
            content = ctx.files.get(path, "")
            lines = content.split("\n")
            for i, line in enumerate(lines):
                stripped = line.strip()
                if re.match(r"except.*:", stripped):
                    # Check current line and next line for bare pass/continue/...
                    if re.search(r"\b(pass|continue)\b", stripped):
                        swallowed_in_agents.append((path, stripped))
                        break
                    elif i + 1 < len(lines) and re.match(r"\s*(pass|continue|\.\.\.)\s*$", lines[i + 1]):
                        swallowed_in_agents.append((path, f"{stripped} → {lines[i+1].strip()}"))
                        break
        if swallowed_in_agents:
            findings.append(Finding(
                id="ac-silent-failure", category="agent_cascade",
                title="Silent error swallowing in agent chain",
                description=(
                    "Agent chain code silently swallows exceptions (except: pass/continue). "
                    "In multi-agent systems, silent failures mask cascade errors that should "
                    "trigger escalation or halt. Art. 9(4)(b) requires fail-closed behavior."
                ),
                file_path=swallowed_in_agents[0][0], confidence=0.8,
                compliance_impact="gap",
                compliance_dimensions=["risk_mgmt", "human_oversight"],
                evidence_snippet=swallowed_in_agents[0][1],
                kb_question_ids=["rm-4"], suggested_answer="no",
            ))

    # 5. Check for cascade depth limits
    if has_agent_chains:
        depth_limit = search_files(ctx, r"max.?(depth|steps|iterations|hops|recursion)|recursion.?limit")
        if depth_limit:
            findings.append(Finding(
                id="ac-depth-limit", category="agent_cascade",
                title="Agent cascade depth limit detected",
                description="Code limits the maximum depth/steps in agent chains, preventing runaway cascades.",
                file_path=depth_limit[0][0], confidence=0.8,
                compliance_impact="positive",
                compliance_dimensions=["risk_mgmt"],
                evidence_snippet=depth_limit[0][1],
                kb_question_ids=["rm-4"], suggested_answer="partial",
            ))
        else:
            findings.append(Finding(
                id="ac-no-depth-limit", category="agent_cascade",
                title="No cascade depth limit in multi-agent system",
                description=(
                    "Multi-agent chains detected without explicit depth/iteration limits. "
                    "Unbounded agent recursion can cause runaway cascades. "
                    "Add max_depth, max_steps, or recursion_limit controls."
                ),
                file_path=agent_framework_files[0][0], confidence=0.75,
                compliance_impact="gap",
                compliance_dimensions=["risk_mgmt"],
                evidence_snippet=agent_framework_files[0][1],
            ))

    # 6. Check for agent output logging/tracing
    if has_agent_chains:
        tracing = search_files(ctx, r"langsmith|langfuse|arize|phoenix|trace.*agent|agent.*trace|log.*output|output.*log")
        if tracing:
            findings.append(Finding(
                id="ac-agent-tracing", category="agent_cascade",
                title="Agent output tracing/logging detected",
                description="Agent outputs are traced or logged, enabling post-hoc audit of cascade decisions.",
                file_path=tracing[0][0], confidence=0.8,
                compliance_impact="positive",
                compliance_dimensions=["risk_mgmt", "logging"],
                evidence_snippet=tracing[0][1],
                kb_question_ids=["lm-1"], suggested_answer="partial",
            ))

    # Score
    if not findings:
        # No agent chains detected — not applicable, give neutral score
        score = 75.0
    else:
        positive = [f for f in findings if f.compliance_impact == "positive"]
        gaps = [f for f in findings if f.compliance_impact == "gap"]
        if not gaps and positive:
            score = min(85.0 + len(positive) * 5, 100.0)
        elif gaps and positive:
            score = max(30.0, 70.0 - len(gaps) * 15 + len(positive) * 5)
        elif gaps:
            score = max(10.0, 50.0 - len(gaps) * 15)
        else:
            score = 50.0

    return AnalyzerResult(
        analyzer_id="agent_cascade",
        label="Agent Cascade Risk",
        findings=findings,
        score=round(score, 1),
        file_count=len(evidence_files),
        graph_node_type="cascade",
        graph_icon="🔗",
        connected_categories=["ai_frameworks", "human_oversight", "security_controls"],
    )
