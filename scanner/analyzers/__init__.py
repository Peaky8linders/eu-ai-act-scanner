"""Specialized code scanner analyzers — pluggable architecture.

Each analyzer performs real static analysis on a specific domain
(AI frameworks, security, testing, etc.) and produces structured
findings that map to EU AI Act compliance dimensions.

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
from scanner.analyzers.ai_frameworks import analyze_ai_frameworks
from scanner.analyzers.cicd_dockerfile import analyze_cicd_dockerfile
from scanner.analyzers.cloudformation_k8s import analyze_cloudformation_k8s
from scanner.analyzers.configuration import analyze_configuration
from scanner.analyzers.data_pipeline import analyze_data_pipeline
from scanner.analyzers.documentation import analyze_documentation
from scanner.analyzers.fairness_testing import analyze_fairness_testing
from scanner.analyzers.human_oversight import analyze_human_oversight
from scanner.analyzers.logging_monitoring import analyze_logging_monitoring
from scanner.analyzers.security_controls import analyze_security_controls
from scanner.analyzers.terraform import analyze_terraform
from scanner.analyzers.test_suite import analyze_test_suite

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
    "adversarial_robustness": analyze_adversarial_robustness,
    "terraform": analyze_terraform,
    "cloudformation_k8s": analyze_cloudformation_k8s,
    "cicd_dockerfile": analyze_cicd_dockerfile,
}


def run_all_analyzers(ctx: AnalyzerContext) -> list[AnalyzerResult]:
    """Run all registered analyzers and return their results."""
    return [fn(ctx) for fn in ANALYZER_REGISTRY.values()]


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
    "collect_pre_filled_answers",
]
