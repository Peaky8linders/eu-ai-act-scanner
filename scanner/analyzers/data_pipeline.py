"""Data Pipeline Analyzer — versioning, schema validation, quality, lineage, PII.

Maps to: data_gov, logging
"""

from __future__ import annotations

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    has_file,
    search_files,
)


def analyze_data_pipeline(ctx: AnalyzerContext) -> AnalyzerResult:
    findings: list[Finding] = []
    evidence_files: set[str] = set()

    # 1. Data loading
    data_lib_detected = False
    for name, pat in [
        ("pandas", r"import\s+pandas|from\s+pandas"),
        ("polars", r"import\s+polars|from\s+polars"),
        ("SQL", r"sqlalchemy|sqlite3|psycopg|asyncpg|import\s+sql"),
        ("Parquet/Arrow", r"parquet|pyarrow|read_parquet|to_parquet"),
    ]:
        matches = search_files(ctx, pat)
        if matches:
            data_lib_detected = True
            evidence_files.add(matches[0][0])
            findings.append(Finding(
                id=f"dp-load-{name[:8].lower()}", category="data_pipeline",
                title=f"Data loading: {name}",
                description=f"Data handling library '{name}' detected.",
                file_path=matches[0][0], confidence=0.85,
                # Neutral, not positive: importing pandas proves data is handled,
                # not that it is governed under Art. 10.
                compliance_impact="neutral",
                compliance_dimensions=["data_gov"],
                evidence_snippet=matches[0][1],
            ))
            break  # One data loading finding is enough

    # 2. Data versioning
    dvc_files = has_file(ctx, r"\.dvc$|dvc\.yaml|dvc\.lock")
    lakefs_matches = search_files(ctx, r"lakefs|delta.lake|deltaTable")
    if dvc_files:
        findings.append(Finding(
            id="dp-versioning-dvc", category="data_pipeline",
            title="Data versioning with DVC",
            description="DVC (Data Version Control) files found — data lineage tracked.",
            file_path=dvc_files[0], confidence=0.9,
            compliance_impact="positive",
            compliance_dimensions=["data_gov"],
            kb_question_ids=["dg-1"], suggested_answer="yes",
        ))
    elif lakefs_matches:
        findings.append(Finding(
            id="dp-versioning-lakefs", category="data_pipeline",
            title="Data versioning detected (LakeFS/Delta Lake)",
            description="Data versioning system detected.",
            file_path=lakefs_matches[0][0], confidence=0.85,
            compliance_impact="positive",
            compliance_dimensions=["data_gov"],
            kb_question_ids=["dg-1"], suggested_answer="yes",
        ))

    # 3. Schema validation
    for name, pat in [
        ("pandera", r"import\s+pandera|from\s+pandera"),
        ("great_expectations", r"great_expectations|import\s+ge"),
        ("Pydantic data models", r"class\s+\w+Data\w*\(BaseModel\)"),
    ]:
        matches = search_files(ctx, pat)
        if matches:
            findings.append(Finding(
                id=f"dp-schema-{name[:8].lower()}", category="data_pipeline",
                title=f"Schema validation: {name}",
                description=f"Data schema validation with '{name}' detected.",
                file_path=matches[0][0], confidence=0.85,
                compliance_impact="positive",
                compliance_dimensions=["data_gov"],
                evidence_snippet=matches[0][1],
                kb_question_ids=["dg-3"], suggested_answer="yes",
            ))
            break

    # 4. Train/val/test split
    split_matches = search_files(ctx, r"train_test_split|StratifiedKFold|DataLoader.*shuffle|val_split|test_size")
    if split_matches:
        findings.append(Finding(
            id="dp-split", category="data_pipeline",
            title="Train/validation/test split detected",
            description="Data splitting for training and evaluation found.",
            file_path=split_matches[0][0], confidence=0.85,
            compliance_impact="positive",
            compliance_dimensions=["data_gov"],
            evidence_snippet=split_matches[0][1],
            kb_question_ids=["dg-4"], suggested_answer="partial",
        ))

    # 5. Data lineage
    lineage_matches = search_files(ctx, r"mlflow.*log.*dataset|data.*provenance|data.*lineage|data.*card")
    if lineage_matches:
        findings.append(Finding(
            id="dp-lineage", category="data_pipeline",
            title="Data lineage/provenance tracking",
            description="Data lineage or provenance metadata tracking detected.",
            file_path=lineage_matches[0][0], confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["data_gov", "transparency"],
            evidence_snippet=lineage_matches[0][1],
            kb_question_ids=["dg-1"], suggested_answer="yes",
        ))

    # 6. PII handling
    pii_matches = search_files(ctx, r"presidio|anonymiz|pseudonymiz|faker.*generate|hash.*(?:email|name|ssn)")
    if pii_matches:
        findings.append(Finding(
            id="dp-pii", category="data_pipeline",
            title="PII handling/anonymization detected",
            description="Personal data anonymization or pseudonymization patterns found.",
            file_path=pii_matches[0][0], confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["data_gov"],
            evidence_snippet=pii_matches[0][1],
        ))

    # 7. Data quality checks
    quality_matches = search_files(ctx, r"\.isnull\(\)|\.dropna\(|data.*quality|ydata.*profil|assert.*not.*null")
    if quality_matches:
        findings.append(Finding(
            id="dp-quality", category="data_pipeline",
            title="Data quality checks detected",
            description="Null checks, data validation, or profiling patterns found.",
            file_path=quality_matches[0][0], confidence=0.75,
            compliance_impact="positive",
            compliance_dimensions=["data_gov"],
            evidence_snippet=quality_matches[0][1],
            kb_question_ids=["dg-3"], suggested_answer="partial",
        ))

    # 8. Art. 10 gaps — when data libraries are detected without versioning
    # or quality controls, emit explicit gaps rather than letting neutral data
    # imports pass Art. 10 unchecked.
    if data_lib_detected:
        if not any(f.id.startswith(("dp-versioning", "dp-lineage")) for f in findings):
            findings.append(Finding(
                id="dp-no-versioning", category="data_pipeline",
                title="No dataset versioning or lineage tooling detected",
                description=(
                    "Data libraries detected without DVC, LakeFS, or lineage instrumentation. "
                    "Art. 10(2) requires documented data governance covering collection, "
                    "preparation and provenance of training, validation and test sets."
                ),
                file_path=next(iter(sorted(evidence_files)), ""),
                confidence=0.7,
                compliance_impact="gap",
                compliance_dimensions=["data_gov"],
                kb_question_ids=["dg-1"], suggested_answer="no",
                article_paragraphs=["10(2)"],
            ))
        has_quality = bool(quality_matches) or any(f.id.startswith("dp-schema-") for f in findings)
        if not has_quality:
            findings.append(Finding(
                id="dp-no-quality-checks", category="data_pipeline",
                title="No data quality or validation checks detected",
                description=(
                    "Data libraries detected without null checks, schema validation, or "
                    "profiling. Art. 10(3) requires training, validation and testing data sets "
                    "to be relevant, sufficiently representative, and free of errors."
                ),
                file_path=next(iter(sorted(evidence_files)), ""),
                confidence=0.7,
                compliance_impact="gap",
                compliance_dimensions=["data_gov"],
                kb_question_ids=["dg-3"], suggested_answer="no",
                article_paragraphs=["10(3)"],
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
        analyzer_id="data_pipeline", label="Data Pipeline",
        findings=findings, score=score,
        file_count=len(evidence_files),
        graph_node_type="data", graph_icon="📊",
        connected_categories=["ai_frameworks", "fairness_testing", "logging_monitoring"],
    )
