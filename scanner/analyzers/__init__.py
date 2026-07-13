"""Specialized code scanner analyzers — pluggable architecture.

Each analyzer performs real static analysis on a specific domain
(AI frameworks, security, testing, agentic-AI risk, etc.) and produces
structured findings that map to EU AI Act compliance dimensions.

Usage:
    from scanner.analyzers import run_all_analyzers, AnalyzerContext
    ctx = AnalyzerContext(files=..., file_list=..., ...)
    results = run_all_analyzers(ctx)
"""

from __future__ import annotations

import statistics
from collections.abc import Callable

from scanner.analyzers._base import AnalyzerContext, AnalyzerResult, Finding
from scanner.analyzers.adversarial_robustness import analyze_adversarial_robustness
from scanner.analyzers.agent_cascade import analyze_agent_cascade
from scanner.analyzers.agent_inventory import analyze_agent_inventory
from scanner.analyzers.ai_frameworks import analyze_ai_frameworks
from scanner.analyzers.article_50_transparency import analyze_article_50_transparency
from scanner.analyzers.cicd_dockerfile import analyze_cicd_dockerfile
from scanner.analyzers.cloud_deployment import analyze_cloud_deployment
from scanner.analyzers.cloudformation_k8s import analyze_cloudformation_k8s
from scanner.analyzers.configuration import analyze_configuration
from scanner.analyzers.data_pipeline import analyze_data_pipeline
from scanner.analyzers.documentation import analyze_documentation
from scanner.analyzers.fairness_testing import analyze_fairness_testing
from scanner.analyzers.human_oversight import analyze_human_oversight
from scanner.analyzers.lethal_trifecta import analyze_lethal_trifecta
from scanner.analyzers.logging_monitoring import analyze_logging_monitoring
from scanner.analyzers.model_typology import analyze_model_typology
from scanner.analyzers.privilege_minimization import analyze_privilege_minimization
from scanner.analyzers.regulatory_perimeter import analyze_regulatory_perimeter
from scanner.analyzers.runtime_drift import analyze_runtime_drift
from scanner.analyzers.security_controls import analyze_security_controls
from scanner.analyzers.terraform import analyze_terraform
from scanner.analyzers.test_suite import analyze_test_suite
from scanner.data.agentic_taxonomy import CompoundRiskType, ThreatCategory
from scanner.data.role_obligations import (
    ROLE_DEPLOYER,
    ROLE_PRODUCT_MANUFACTURER,
    ROLE_PROVIDER,
)
from scanner.incident_grounding import incidents_for_finding

ANALYZER_REGISTRY: dict[str, Callable[[AnalyzerContext], AnalyzerResult]] = {
    "ai_frameworks": analyze_ai_frameworks,
    "data_pipeline": analyze_data_pipeline,
    "human_oversight": analyze_human_oversight,
    "security_controls": analyze_security_controls,
    "fairness_testing": analyze_fairness_testing,
    "test_suite": analyze_test_suite,
    "logging_monitoring": analyze_logging_monitoring,
    "documentation": analyze_documentation,
    "configuration": analyze_configuration,
    "agent_cascade": analyze_agent_cascade,
    "lethal_trifecta": analyze_lethal_trifecta,
    "adversarial_robustness": analyze_adversarial_robustness,
    "terraform": analyze_terraform,
    "cloudformation_k8s": analyze_cloudformation_k8s,
    "cicd_dockerfile": analyze_cicd_dockerfile,
    "cloud_deployment": analyze_cloud_deployment,
    "model_typology": analyze_model_typology,
    "article_50_transparency": analyze_article_50_transparency,
    # Agent-aware analyzers from Nannini et al. (2026) "AI Agents under EU Law"
    "agent_inventory": analyze_agent_inventory,
    "privilege_minimization": analyze_privilege_minimization,
    "runtime_drift": analyze_runtime_drift,
    "regulatory_perimeter": analyze_regulatory_perimeter,
}


# Default agentic-AI taxonomy tags applied to gap findings emitted by the
# Nannini-paper-aligned analyzers when those analyzers don't set the tags
# themselves. Centralising the mapping keeps the taxonomy single-sourced —
# any new analyzer that fits one of these archetypes inherits the tags
# automatically. Compound-risk axes per paper §10.4:
#   - cascading: errors propagate across orchestrated sub-agents
#   - emergent: unsafe collective behaviour from individually safe agents
#   - attribution: multi-provider value chain obscures responsibility
#   - temporal: long-running state drift outside conformity envelope
_PROVIDER_DEPLOYER_MFR = (ROLE_PROVIDER, ROLE_PRODUCT_MANUFACTURER, ROLE_DEPLOYER)

_DEFAULT_TAXONOMY_TAGS: dict[str, dict[str, object]] = {
    "agent_inventory": {
        # Inventory gaps are attribution-class — without the
        # external-action inventory the regulatory perimeter cannot be
        # mapped (paper Conclusion 3, lines 2456-2462).
        "compound_risk_type": CompoundRiskType.attribution.value,
        "threat_categories": [ThreatCategory.governance_autonomy.value],
        "applicable_roles": list(_PROVIDER_DEPLOYER_MFR),
    },
    "privilege_minimization": {
        # Tool-permission over-provisioning + cross-tool propagation are
        # the canonical cascading exemplars (paper §6.1 lines 731-741,
        # OWASP Top-10 Agentic).
        "compound_risk_type": CompoundRiskType.cascading.value,
        "threat_categories": [
            ThreatCategory.tool_misuse_privilege_escalation.value,
            ThreatCategory.autonomous_cyber_exploit.value,
        ],
        "applicable_roles": list(_PROVIDER_DEPLOYER_MFR),
    },
    "regulatory_perimeter": {
        # Missing perimeter classification = NLF role-mismatch territory
        # — attribution risk per §10.4 lines 2230-2232.
        "compound_risk_type": CompoundRiskType.attribution.value,
        "threat_categories": [ThreatCategory.governance_autonomy.value],
        "applicable_roles": list(_PROVIDER_DEPLOYER_MFR),
    },
    "runtime_drift": {
        # Drift detection gaps are the textbook temporal-axis exemplar
        # (paper §6.4 lines 940-958, Rath ASI semantic/coordination/
        # behavioural drift, Art. 3(23) substantial modification).
        "compound_risk_type": CompoundRiskType.temporal.value,
        "threat_categories": [
            ThreatCategory.governance_autonomy.value,
            ThreatCategory.aepd_lethal_trifecta.value,
        ],
        "applicable_roles": list(_PROVIDER_DEPLOYER_MFR),
    },
}


def _apply_default_taxonomy_tags(findings: list[Finding]) -> list[Finding]:
    """Back-fill compound_risk_type / applicable_roles / threat_categories
    on gap findings whose analyzer has a default mapping.

    Non-gap findings (positive / neutral) get the compound_risk_type +
    threat_categories so graph traversal works, but NOT applicable_roles
    — those are an obligation marker that only makes sense on gaps.

    Findings that already carry any of the three fields are left
    untouched — analyzer-level overrides win.
    """
    for f in findings:
        defaults = _DEFAULT_TAXONOMY_TAGS.get(f.category)
        if not defaults:
            continue
        if not f.compound_risk_type:
            f.compound_risk_type = defaults["compound_risk_type"]  # type: ignore[assignment]
        if not f.threat_categories:
            f.threat_categories = list(defaults["threat_categories"])  # type: ignore[arg-type]
        if not f.applicable_roles and f.compliance_impact == "gap":
            f.applicable_roles = list(defaults["applicable_roles"])  # type: ignore[arg-type]
    return findings


def _attach_incident_grounding(findings: list[Finding], limit: int = 3) -> list[Finding]:
    """Ground gap findings in real-world incidents from the vendored corpus.

    For each *gap* finding, crosswalks its threat categories / compliance
    dimensions to the GenAI-incidents corpus and records up to ``limit``
    matching incident IDs in ``related_incidents`` (resolve via
    :mod:`scanner.incident_grounding`). Positive / neutral evidence is left
    untouched — grounding answers "where has this gap bitten people", which
    only makes sense for gaps. Must run *after* :func:`_apply_default_taxonomy_tags`
    so threat-category tags are populated first.
    """
    for f in findings:
        if f.compliance_impact != "gap" or f.related_incidents:
            continue
        matches = incidents_for_finding(f, limit=limit)
        if matches:
            f.related_incidents = [inc.id for inc in matches]
    return findings


def run_all_analyzers(ctx: AnalyzerContext) -> list[AnalyzerResult]:
    """Run all registered analyzers and return their results.

    Findings emitted by analyzers in :data:`_DEFAULT_TAXONOMY_TAGS` are
    automatically tagged with the corresponding compound-risk axis,
    threat categories, and applicable operator roles per paper §10.4.
    Analyzer-level overrides (a Finding that already carries the field)
    win over the defaults, so per-finding precision is preserved.

    Gap findings are then grounded in real-world incidents
    (:func:`_attach_incident_grounding`) so each gap carries the documented
    incidents that exploited its class, and enriched with the operator
    role(s) that owe the implicated obligation
    (:func:`scanner.obligations.enrich_findings`) — back-filled from the
    inferred role profile of the scanned codebase, gap findings only.
    """
    # Lazy import: obligations pulls scanner.grounding/refs which import the
    # scanner package; importing it here (not at module top) sidesteps any
    # partial-initialisation cycle during ``import scanner``.
    from scanner import obligations

    results = [fn(ctx) for fn in ANALYZER_REGISTRY.values()]
    for r in results:
        _apply_default_taxonomy_tags(r.findings)
        _attach_incident_grounding(r.findings)
        obligations.enrich_findings(r.findings, ctx)
    return results


def detect_ai_system(analyzer_results: list[AnalyzerResult]) -> tuple[bool, list[str]]:
    """Decide whether the scanned codebase is an *AI system* under EU AI Act scope.

    The Regulation (2024/1689) governs "AI systems" (Art. 3(1)). A repository
    with no AI/ML/agent signal at all is out of scope, and reporting a
    "compliance %" for it is misleading — it also lets the autonomous fix loop
    game the score by writing boilerplate evidence (``MODEL_CARD.md``, tests,
    ``Dockerfile``) into a project the law does not touch.

    The gate keys on the three *purpose-built* AI detectors. Only
    ``ai_frameworks`` is import-precise; ``model_typology`` and
    ``agent_inventory`` use broader heuristics that can occasionally match
    non-AI code. That imprecision is accepted on purpose — erring toward *in
    scope* is the conservative direction for a compliance gate: a non-AI repo
    incidentally scored is a smaller harm than a real AI system wrongly ruled
    out of scope (a false negative the Regulation would not forgive).

    * ``ai_frameworks`` — an actual ML/LLM framework import was detected via AST
      (``metadata['detected']``: pytorch, tensorflow, sklearn, openai,
      anthropic, langchain, ...). Precise.
    * ``model_typology`` — the typology classifier resolved to something other
      than ``"none"`` (``llm`` / ``classical_ml`` / ``both``). Heuristic: a bare
      ``.fit(`` / ``.predict(`` or an ``nn.Module`` reference is enough, so the
      odd non-AI repo can land here.
    * ``agent_inventory`` — a modern agent-*runtime* signal was detected
      (``metadata['runtime_signals']``: MCP / Assistants v2 / LangGraph /
      CrewAI / Selenium ...). Heuristic: e.g. a Selenium import counts even when
      used only for end-to-end tests.

    The generic action-verb and deployment-category heuristics are deliberately
    *excluded* — ``write_file`` / ``execute_code`` and the external-system
    (CRM / GitHub / Gmail) regexes match ordinary non-AI code far too
    aggressively and would collapse the gate.

    Returns ``(is_ai_system, signals)`` where ``signals`` is a sorted, de-duped
    list of human-readable evidence strings (e.g. ``"ai_framework:pytorch"``,
    ``"model_typology:llm"``). ``signals`` is empty iff ``is_ai_system`` is
    False.
    """
    signals: set[str] = set()
    for ar in analyzer_results:
        if ar.analyzer_id == "ai_frameworks":
            for fw in ar.metadata.get("detected", []):
                signals.add(f"ai_framework:{fw}")
        elif ar.analyzer_id == "model_typology":
            typology = ar.metadata.get("typology", "none")
            if typology and typology != "none":
                signals.add(f"model_typology:{typology}")
        elif ar.analyzer_id == "agent_inventory":
            for sig in ar.metadata.get("runtime_signals", []):
                signals.add(f"agent_runtime:{sig}")
    return bool(signals), sorted(signals)


def compute_dimension_scores(all_findings: list[Finding]) -> dict[str, float]:
    """Compute compliance scores per KB dimension from all findings.

    Score = avg confidence of positive evidence, penalized by gap ratio.
    Result clamped to [0, 100].
    """
    dim_ids: set[str] = set()
    for f in all_findings:
        dim_ids.update(f.compliance_dimensions)

    scores: dict[str, float] = {}
    for dim_id in sorted(dim_ids):
        relevant = [f for f in all_findings if dim_id in f.compliance_dimensions]
        if not relevant:
            scores[dim_id] = 0.0
            continue
        positive = [f for f in relevant if f.compliance_impact == "positive"]
        gaps = [f for f in relevant if f.compliance_impact == "gap"]
        base = statistics.mean(f.confidence for f in positive) * 100 if positive else 0.0
        penalty = len(gaps) / (len(positive) + len(gaps)) * 30 if gaps else 0.0
        scores[dim_id] = min(max(round(base - penalty, 1), 0.0), 100.0)

    return scores


def collect_pre_filled_answers(all_findings: list[Finding]) -> dict[str, str]:
    """Aggregate pre-filled assessment answers from all findings.

    When multiple findings target the same question, 'yes' wins over 'partial'.
    """
    answers: dict[str, str] = {}
    priority = {"yes": 2, "partial": 1, "no": 0}
    for f in all_findings:
        if f.suggested_answer and f.kb_question_ids:
            for qid in f.kb_question_ids:
                existing = answers.get(qid)
                if existing is None or priority.get(f.suggested_answer, 0) > priority.get(existing, 0):
                    answers[qid] = f.suggested_answer
    return answers


__all__ = [
    "ANALYZER_REGISTRY",
    "AnalyzerContext",
    "AnalyzerResult",
    "Finding",
    "run_all_analyzers",
    "compute_dimension_scores",
    "detect_ai_system",
    "collect_pre_filled_answers",
    "_apply_default_taxonomy_tags",
    "_attach_incident_grounding",
    "_DEFAULT_TAXONOMY_TAGS",
]
