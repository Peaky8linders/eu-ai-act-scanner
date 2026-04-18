"""Fairness Testing Analyzer — bias detection, protected attributes, fairness metrics.

Maps to: data_gov, risk_mgmt
"""

from __future__ import annotations

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    search_files,
)


def analyze_fairness_testing(ctx: AnalyzerContext) -> AnalyzerResult:
    findings: list[Finding] = []
    evidence_files: set[str] = set()

    # 1. Fairness libraries
    for name, pat in [
        ("AIF360", r"aif360|from\s+aif360"),
        ("Fairlearn", r"fairlearn|from\s+fairlearn"),
        ("aequitas", r"aequitas|from\s+aequitas"),
        ("Themis-ML", r"themis_ml|themis\.ml"),
    ]:
        matches = search_files(ctx, pat)
        if matches:
            evidence_files.add(matches[0][0])
            findings.append(Finding(
                id=f"ft-lib-{name[:8].lower()}", category="fairness_testing",
                title=f"Fairness library: {name}",
                description=f"Bias/fairness assessment library '{name}' detected.",
                file_path=matches[0][0], confidence=0.9,
                compliance_impact="positive",
                compliance_dimensions=["data_gov", "risk_mgmt"],
                evidence_snippet=matches[0][1],
                kb_question_ids=["dg-2"], suggested_answer="yes",
            ))
            break

    # 2. Protected attributes
    attr_matches = search_files(ctx, r"protected.*attr|sensitive.*attr|gender|race|ethnicity|age.*group|disability")
    # Only count in data processing / model code, not docs
    code_matches = [(p, s) for p, s in attr_matches if p.endswith((".py", ".ipynb", ".r", ".R"))]
    if code_matches:
        findings.append(Finding(
            id="ft-protected-attrs", category="fairness_testing",
            title="Protected attribute handling detected",
            description="Code references protected/sensitive attributes (gender, race, age, etc.).",
            file_path=code_matches[0][0], confidence=0.7,
            compliance_impact="neutral",
            compliance_dimensions=["data_gov"],
            evidence_snippet=code_matches[0][1],
        ))

    # 3. Fairness metrics
    metric_patterns = [
        (r"disparate.impact|disparate_impact", "Disparate impact"),
        (r"demographic.parity|statistical.parity", "Demographic/statistical parity"),
        (r"equalized.odds|equal.opportunity", "Equalized odds"),
        (r"calibration.*fairness|predictive.*parity", "Calibration fairness"),
    ]
    for pat, desc in metric_patterns:
        matches = search_files(ctx, pat)
        if matches:
            findings.append(Finding(
                id=f"ft-metric-{desc[:15].replace(' ', '-').lower()}", category="fairness_testing",
                title=f"Fairness metric: {desc}",
                description=f"Fairness metric computation '{desc}' detected.",
                file_path=matches[0][0], confidence=0.85,
                compliance_impact="positive",
                compliance_dimensions=["data_gov", "risk_mgmt"],
                evidence_snippet=matches[0][1],
                kb_question_ids=["dg-2"], suggested_answer="yes",
            ))

    # 4. Bias mitigation
    mitigation_matches = search_files(ctx, r"reweigh|adversarial.*debias|calibrated.*eq|reject.*option|threshold.*optim")
    if mitigation_matches:
        findings.append(Finding(
            id="ft-mitigation", category="fairness_testing",
            title="Bias mitigation technique detected",
            description="Active bias mitigation (reweighing, adversarial debiasing, etc.) found.",
            file_path=mitigation_matches[0][0], confidence=0.85,
            compliance_impact="positive",
            compliance_dimensions=["risk_mgmt"],
            evidence_snippet=mitigation_matches[0][1],
            kb_question_ids=["rm-3"], suggested_answer="yes",
        ))

    # 5. Subgroup analysis
    subgroup_matches = search_files(ctx, r"group.*metric|by.*group|subgroup.*eval|slice.*eval|disaggreg")
    if subgroup_matches:
        findings.append(Finding(
            id="ft-subgroup", category="fairness_testing",
            title="Subgroup/disaggregated evaluation detected",
            description="Model evaluation broken down by demographic groups found.",
            file_path=subgroup_matches[0][0], confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["data_gov"],
            evidence_snippet=subgroup_matches[0][1],
        ))

    # 6. Fairness reports
    report_matches = search_files(ctx, r"fairness.*report|bias.*report|bias.*audit|equity.*report")
    if report_matches:
        findings.append(Finding(
            id="ft-report", category="fairness_testing",
            title="Fairness/bias report generation",
            description="Fairness audit or bias report generation patterns detected.",
            file_path=report_matches[0][0], confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["data_gov", "transparency"],
            evidence_snippet=report_matches[0][1],
        ))

    # 7. Pre/post-processing
    prepost_matches = search_files(ctx, r"resample|oversample|undersample|SMOTE|threshold.*adjust|post.*process.*fair")
    if prepost_matches:
        findings.append(Finding(
            id="ft-prepost", category="fairness_testing",
            title="Pre/post-processing fairness technique",
            description="Data resampling or threshold adjustment for fairness detected.",
            file_path=prepost_matches[0][0], confidence=0.75,
            compliance_impact="positive",
            compliance_dimensions=["data_gov"],
            evidence_snippet=prepost_matches[0][1],
        ))

    positive = [f for f in findings if f.compliance_impact == "positive"]
    gaps = [f for f in findings if f.compliance_impact == "gap"]
    score = 0.0
    if positive:
        from statistics import mean
        score = mean(f.confidence for f in positive) * 100
        if gaps:
            score -= len(gaps) / (len(positive) + len(gaps)) * 30
        score = min(max(round(score, 1), 0), 100)

    return AnalyzerResult(
        analyzer_id="fairness_testing", label="Fairness Testing",
        findings=findings, score=score,
        file_count=len(evidence_files),
        graph_node_type="test", graph_icon="⚖️",
        connected_categories=["data_pipeline", "test_suite"],
    )
