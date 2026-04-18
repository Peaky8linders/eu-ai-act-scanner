"""Logging & Monitoring Analyzer — structured logging, experiment tracking, observability.

Maps to: logging, decision_governance
"""

from __future__ import annotations

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    search_files,
)


def analyze_logging_monitoring(ctx: AnalyzerContext) -> AnalyzerResult:
    findings: list[Finding] = []
    evidence_files: set[str] = set()

    # 1. Structured logging
    for name, pat in [
        ("structlog", r"import\s+structlog|from\s+structlog"),
        ("python-json-logger", r"pythonjsonlogger|json_log_formatter"),
        ("loguru", r"from\s+loguru|import\s+loguru"),
    ]:
        matches = search_files(ctx, pat)
        if matches:
            evidence_files.add(matches[0][0])
            findings.append(Finding(
                id=f"log-structured-{name}", category="logging_monitoring",
                title=f"Structured logging: {name}",
                description=f"Structured logging library '{name}' detected.",
                file_path=matches[0][0], confidence=0.9,
                compliance_impact="positive",
                compliance_dimensions=["logging"],
                evidence_snippet=matches[0][1],
                kb_question_ids=["lg-1"], suggested_answer="yes",
            ))
            break

    # 2. Experiment tracking
    for name, pat in [
        ("MLflow", r"import\s+mlflow|from\s+mlflow|mlflow\."),
        ("Weights & Biases", r"import\s+wandb|wandb\.init"),
        ("Neptune", r"import\s+neptune|neptune\.init"),
        ("ClearML", r"import\s+clearml|from\s+clearml"),
    ]:
        matches = search_files(ctx, pat)
        if matches:
            evidence_files.add(matches[0][0])
            findings.append(Finding(
                id=f"log-experiment-{name[:8].lower()}", category="logging_monitoring",
                title=f"Experiment tracking: {name}",
                description=f"ML experiment tracking with '{name}' detected.",
                file_path=matches[0][0], confidence=0.9,
                compliance_impact="positive",
                compliance_dimensions=["logging", "tech_docs"],
                evidence_snippet=matches[0][1],
                kb_question_ids=["lg-1", "lg-2"], suggested_answer="yes",
            ))
            break

    # 3. Inference logging
    inference_patterns = search_files(ctx, r"log.*(predict|inference|response)|inference.*log|request.*log.*response")
    if inference_patterns:
        findings.append(Finding(
            id="log-inference", category="logging_monitoring",
            title="Inference/prediction logging detected",
            description="Input/output logging around AI predictions found.",
            file_path=inference_patterns[0][0], confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["logging", "decision_governance"],
            evidence_snippet=inference_patterns[0][1],
            kb_question_ids=["lg-1", "dc-4"], suggested_answer="partial",
        ))

    # 4. Drift detection
    for name, pat in [
        ("NannyML", r"nannyml|nanny_ml"),
        ("Evidently", r"import\s+evidently|from\s+evidently"),
        ("Alibi Detect", r"alibi_detect|alibi\.detect"),
    ]:
        matches = search_files(ctx, pat)
        if matches:
            findings.append(Finding(
                id=f"log-drift-{name[:8].lower()}", category="logging_monitoring",
                title=f"Drift detection: {name}",
                description=f"Model/data drift detection library '{name}' detected.",
                file_path=matches[0][0], confidence=0.9,
                compliance_impact="positive",
                compliance_dimensions=["logging"],
                evidence_snippet=matches[0][1],
                kb_question_ids=["lg-6"], suggested_answer="yes",
            ))
            break

    # 5. Alerting
    alert_matches = search_files(ctx, r"pagerduty|slack.*webhook|sendgrid|smtp|alert.*notify|notification.*send")
    if alert_matches:
        findings.append(Finding(
            id="log-alerting", category="logging_monitoring",
            title="Alerting/notification system detected",
            description="Alerting integration for incident notification found.",
            file_path=alert_matches[0][0], confidence=0.75,
            compliance_impact="positive",
            compliance_dimensions=["logging"],
            evidence_snippet=alert_matches[0][1],
        ))

    # 6. Observability stack
    for name, pat in [
        ("Prometheus", r"prometheus_client|prometheus|prom_"),
        ("Datadog", r"datadog|ddtrace"),
        ("OpenTelemetry", r"opentelemetry|otel"),
        ("StatsD", r"statsd"),
    ]:
        matches = search_files(ctx, pat)
        if matches:
            evidence_files.add(matches[0][0])
            findings.append(Finding(
                id=f"log-observability-{name[:8].lower()}", category="logging_monitoring",
                title=f"Observability: {name}",
                description=f"Metrics/observability stack '{name}' detected.",
                file_path=matches[0][0], confidence=0.85,
                compliance_impact="positive",
                compliance_dimensions=["logging"],
                evidence_snippet=matches[0][1],
            ))
            break

    # 7. Log discipline (print vs structured)
    print_matches = search_files(ctx, r"^\s*print\s*\(")
    # Filter to non-test source files
    print_in_source = [(p, s) for p, s in print_matches if "test" not in p.lower() and "__pycache__" not in p]
    structured = any(f.id.startswith("log-structured") for f in findings)
    if print_in_source and not structured:
        findings.append(Finding(
            id="log-print-instead", category="logging_monitoring",
            title=f"Bare print() used in {len(print_in_source)} source files",
            description="Source code uses print() instead of structured logging — logs will lack context.",
            file_path=print_in_source[0][0], confidence=0.7,
            compliance_impact="gap",
            compliance_dimensions=["logging"],
            evidence_snippet=print_in_source[0][1],
            kb_question_ids=["lg-1"], suggested_answer="partial",
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
        analyzer_id="logging_monitoring", label="Logging & Monitoring",
        findings=findings, score=score,
        file_count=len(evidence_files),
        graph_node_type="infra", graph_icon="📡",
        connected_categories=["ai_frameworks", "data_pipeline", "human_oversight"],
    )
