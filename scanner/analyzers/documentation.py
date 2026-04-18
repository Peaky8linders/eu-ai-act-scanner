"""Documentation Analyzer — README, model cards, API docs, architecture docs.

Maps to: tech_docs, transparency

Uses AST for docstring coverage analysis and optional LLM for
README/model card quality assessment (EU_AI_ACT_SCANNER_LLM=true).
"""

from __future__ import annotations

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    get_docstring_coverage,
    has_file,
    llm_assess,
    search_files,
)

_README_SECTIONS = ["install", "usage", "api", "license", "contribut", "getting started", "quick start"]
_MODEL_CARD_SECTIONS = ["intended use", "limitation", "metric", "training data", "ethical", "bias", "evaluation"]


def analyze_documentation(ctx: AnalyzerContext) -> AnalyzerResult:
    findings: list[Finding] = []
    evidence_files: set[str] = set()

    # 1. README completeness
    readme_files = has_file(ctx, r"readme\.md$|readme\.rst$|readme\.txt$|readme$")
    if readme_files:
        content = ctx.files.get(readme_files[0], "").lower()
        present = [s for s in _README_SECTIONS if s in content]
        missing = [s for s in _README_SECTIONS if s not in content]
        evidence_files.add(readme_files[0])
        if len(present) >= 4:
            findings.append(Finding(
                id="doc-readme-complete", category="documentation",
                title=f"README has {len(present)}/{len(_README_SECTIONS)} key sections",
                description=f"Sections found: {', '.join(present)}.",
                file_path=readme_files[0], confidence=0.85,
                compliance_impact="positive",
                compliance_dimensions=["tech_docs"],
                kb_question_ids=["td-1"], suggested_answer="yes",
            ))
        else:
            findings.append(Finding(
                id="doc-readme-incomplete", category="documentation",
                title=f"README missing sections: {', '.join(missing[:3])}",
                description=f"Only {len(present)}/{len(_README_SECTIONS)} key sections found.",
                file_path=readme_files[0], confidence=0.8,
                compliance_impact="gap",
                compliance_dimensions=["tech_docs"],
                kb_question_ids=["td-1"], suggested_answer="partial",
            ))
    else:
        findings.append(Finding(
            id="doc-no-readme", category="documentation",
            title="No README file found",
            description="Project lacks a README — basic documentation missing.",
            file_path="", confidence=0.95,
            compliance_impact="gap",
            compliance_dimensions=["tech_docs", "transparency"],
            kb_question_ids=["td-1"], suggested_answer="no",
        ))

    # 2. Model card detection
    model_card_files = has_file(ctx, r"model.card|model_card|MODEL_CARD")
    hf_yaml = search_files(ctx, r"^---\s*\n.*?model[-_]?name|^---\s*\n.*?license")
    if model_card_files or hf_yaml:
        card_file = model_card_files[0] if model_card_files else (hf_yaml[0][0] if hf_yaml else "")
        evidence_files.add(card_file)
        findings.append(Finding(
            id="doc-model-card", category="documentation",
            title="Model card detected",
            description="Model card documentation found — Art. 11 technical documentation.",
            file_path=card_file, confidence=0.9,
            compliance_impact="positive",
            compliance_dimensions=["tech_docs", "transparency"],
            kb_question_ids=["td-4"], suggested_answer="partial",
        ))

        # 3. Model card completeness
        card_content = ctx.files.get(card_file, "").lower()
        present = [s for s in _MODEL_CARD_SECTIONS if s in card_content]
        if len(present) >= 5:
            findings.append(Finding(
                id="doc-model-card-complete", category="documentation",
                title=f"Model card covers {len(present)}/{len(_MODEL_CARD_SECTIONS)} sections",
                description=f"Sections: {', '.join(present)}.",
                file_path=card_file, confidence=0.85,
                compliance_impact="positive",
                compliance_dimensions=["tech_docs"],
                kb_question_ids=["td-4"], suggested_answer="yes",
            ))

    # 4. API documentation
    api_doc_matches = search_files(ctx, r"openapi|swagger|FastAPI|@app\.(get|post|put|delete)")
    search_files(ctx, r'""".*?(endpoint|route|api|handler)')
    if api_doc_matches:
        findings.append(Finding(
            id="doc-api", category="documentation",
            title="API framework with auto-docs detected",
            description="FastAPI/OpenAPI/Swagger documentation framework found.",
            file_path=api_doc_matches[0][0], confidence=0.85,
            compliance_impact="positive",
            compliance_dimensions=["tech_docs", "transparency"],
            evidence_snippet=api_doc_matches[0][1],
        ))

    # 5. Architecture docs
    arch_files = has_file(ctx, r"architecture|design\.md|system.*diagram|\.drawio|\.mermaid|ARCHITECTURE")
    if arch_files:
        evidence_files.add(arch_files[0])
        findings.append(Finding(
            id="doc-architecture", category="documentation",
            title="Architecture documentation found",
            description=f"Architecture/design doc: {arch_files[0]}.",
            file_path=arch_files[0], confidence=0.85,
            compliance_impact="positive",
            compliance_dimensions=["tech_docs"],
        ))

    # 6. Data sheets
    data_doc_files = has_file(ctx, r"datasheet|data.card|data.sheet|dataset.*readme|DATA_CARD")
    if data_doc_files:
        findings.append(Finding(
            id="doc-datasheet", category="documentation",
            title="Dataset documentation found",
            description=f"Data documentation: {data_doc_files[0]}.",
            file_path=data_doc_files[0], confidence=0.85,
            compliance_impact="positive",
            compliance_dimensions=["data_gov", "transparency"],
        ))

    # 7. Changelog
    changelog_files = has_file(ctx, r"changelog|CHANGES|HISTORY\.md|RELEASES")
    if changelog_files:
        findings.append(Finding(
            id="doc-changelog", category="documentation",
            title="Changelog/release notes found",
            description=f"Version history: {changelog_files[0]}.",
            file_path=changelog_files[0], confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["tech_docs"],
        ))

    # 8. AST-powered docstring coverage
    documented, total = get_docstring_coverage(ctx)
    if total > 0:
        ratio = documented / total
        findings.append(Finding(
            id="doc-docstring-coverage", category="documentation",
            title=f"Docstring coverage: {documented}/{total} public functions ({ratio:.0%})",
            description=f"AST analysis: {ratio:.0%} of public functions have docstrings.",
            file_path="", confidence=0.85,
            compliance_impact="positive" if ratio >= 0.5 else "gap",
            compliance_dimensions=["tech_docs"],
        ))

    # 9. LLM-powered README quality assessment (optional, requires EU_AI_ACT_SCANNER_LLM=true)
    if readme_files:
        readme_content = ctx.files.get(readme_files[0], "")
        if readme_content and len(readme_content) > 50:
            assessment = llm_assess(
                prompt=(
                    "You are an AI compliance documentation reviewer. "
                    "Score this README from 0.0 to 1.0 on how well it documents an AI system "
                    "for EU AI Act compliance (Art. 11/13). "
                    "Consider: intended purpose, limitations, performance metrics, training data, "
                    "deployment instructions, and risk warnings. "
                    "Respond ONLY with JSON: {\"score\": 0.X, \"reasoning\": \"...\", \"findings\": [\"...\"]}"
                ),
                content=readme_content,
            )
            if assessment.error is None:
                impact = "positive" if assessment.score >= 0.6 else "gap"
                findings.append(Finding(
                    id="doc-llm-readme-quality", category="documentation",
                    title=f"LLM README quality: {assessment.score:.0%}",
                    description=f"Semantic analysis: {assessment.reasoning[:150]}",
                    file_path=readme_files[0], confidence=min(assessment.score, 0.9),
                    compliance_impact=impact,
                    compliance_dimensions=["tech_docs", "transparency"],
                    evidence_snippet="; ".join(assessment.findings[:3])[:200] if assessment.findings else "",
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
        analyzer_id="documentation", label="Documentation",
        findings=findings, score=score,
        file_count=len(evidence_files),
        graph_node_type="doc", graph_icon="📋",
        connected_categories=["ai_frameworks", "configuration"],
    )
