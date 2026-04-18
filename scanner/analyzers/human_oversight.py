"""Human Oversight Analyzer — approval gates, confidence thresholds, HITL, kill switch.

Maps to: human_oversight, decision_governance
"""

from __future__ import annotations

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    search_files,
)


def analyze_human_oversight(ctx: AnalyzerContext) -> AnalyzerResult:
    findings: list[Finding] = []
    evidence_files: set[str] = set()

    # 1. Approval gates
    gate_matches = search_files(ctx, r"approv|human.*review|manual.*review|review.*queue|pending.*approval")
    if gate_matches:
        evidence_files.add(gate_matches[0][0])
        findings.append(Finding(
            id="ho-approval-gate", category="human_oversight",
            title="Approval/review gate detected",
            description="Human approval or review gate pattern found in code.",
            file_path=gate_matches[0][0], confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["human_oversight"],
            evidence_snippet=gate_matches[0][1],
            kb_question_ids=["ho-1"], suggested_answer="partial",
        ))

    # 2. Confidence thresholds
    conf_matches = search_files(ctx, r"confidence\s*[<>]=?\s*[\d.]|threshold.*confidence|if.*score\s*[<>]")
    if conf_matches:
        findings.append(Finding(
            id="ho-confidence-threshold", category="human_oversight",
            title="Confidence threshold check detected",
            description="Code checks confidence/score against a threshold before acting.",
            file_path=conf_matches[0][0], confidence=0.85,
            compliance_impact="positive",
            compliance_dimensions=["human_oversight", "decision_governance"],
            evidence_snippet=conf_matches[0][1],
            kb_question_ids=["dc-1"], suggested_answer="partial",
        ))

    # 3. Escalation paths
    esc_matches = search_files(ctx, r"escalat|route.*human|fallback.*human|human.*fallback|send.*review")
    if esc_matches:
        findings.append(Finding(
            id="ho-escalation", category="human_oversight",
            title="Escalation to human detected",
            description="Code paths that escalate decisions to human reviewers found.",
            file_path=esc_matches[0][0], confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["human_oversight"],
            evidence_snippet=esc_matches[0][1],
            kb_question_ids=["ho-2"], suggested_answer="partial",
        ))

    # 4. HITL frameworks
    for name, pat in [
        ("Label Studio", r"label.studio|labelstudio"),
        ("Prodigy", r"import\s+prodigy|prodigy\."),
        ("Argilla", r"import\s+argilla|from\s+argilla"),
    ]:
        matches = search_files(ctx, pat)
        if matches:
            findings.append(Finding(
                id=f"ho-hitl-{name[:8].lower()}", category="human_oversight",
                title=f"HITL framework: {name}",
                description=f"Human-in-the-loop annotation tool '{name}' detected.",
                file_path=matches[0][0], confidence=0.9,
                compliance_impact="positive",
                compliance_dimensions=["human_oversight", "data_gov"],
                evidence_snippet=matches[0][1],
            ))
            break

    # 5. Override mechanisms
    override_matches = search_files(ctx, r"override|manual.*correct|user.*overrid|admin.*overrid|force.*update")
    if override_matches:
        findings.append(Finding(
            id="ho-override", category="human_oversight",
            title="Manual override mechanism detected",
            description="Code allows humans to override AI decisions.",
            file_path=override_matches[0][0], confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["human_oversight"],
            evidence_snippet=override_matches[0][1],
            kb_question_ids=["ho-4"], suggested_answer="partial",
        ))

    # 6. Decision audit trail
    audit_matches = search_files(ctx, r"audit.*trail|decision.*log|log.*(approv|reject|verdict)|record.*decision")
    if audit_matches:
        findings.append(Finding(
            id="ho-audit-trail", category="human_oversight",
            title="Decision audit trail detected",
            description="Logging of approval/rejection decisions with context found.",
            file_path=audit_matches[0][0], confidence=0.85,
            compliance_impact="positive",
            compliance_dimensions=["human_oversight", "logging"],
            evidence_snippet=audit_matches[0][1],
            kb_question_ids=["dc-4"], suggested_answer="partial",
        ))

    # 7. Kill switch / stop
    kill_matches = search_files(ctx, r"kill.*switch|emergency.*stop|shutdown|disable.*model|circuit.*breaker")
    if kill_matches:
        findings.append(Finding(
            id="ho-kill-switch", category="human_oversight",
            title="Kill switch / emergency stop detected",
            description="Mechanism to halt or disable AI system found.",
            file_path=kill_matches[0][0], confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["human_oversight"],
            evidence_snippet=kill_matches[0][1],
            kb_question_ids=["ho-1"], suggested_answer="yes",
        ))

    if not findings:
        findings.append(Finding(
            id="ho-none", category="human_oversight",
            title="No human oversight mechanisms detected",
            description="No approval gates, confidence checks, escalation, or override patterns found.",
            file_path="", confidence=0.8,
            compliance_impact="gap",
            compliance_dimensions=["human_oversight"],
            kb_question_ids=["ho-1"], suggested_answer="no",
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
        analyzer_id="human_oversight", label="Human Oversight",
        findings=findings, score=score,
        file_count=len(evidence_files),
        graph_node_type="api", graph_icon="👤",
        connected_categories=["ai_frameworks", "logging_monitoring"],
    )
