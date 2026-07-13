"""Model Typology Analyzer — classify AI systems as LLM / Classical ML / Rule-based.

Distinguishes:
  - llm          : generative AI (OpenAI, Anthropic, LangChain, HuggingFace transformers, RAG, etc.)
  - classical_ml : sklearn / xgboost / PyTorch classifier/regressor trained models
  - both         : dual-mode system — highest governance burden
  - none         : no ML/AI signals at all

Uses only existing KB dimensions:
  - transparency      : LLM systems need Art. 50 disclosure
  - human_oversight   : LLM systems need Art. 14 controls
  - data_gov          : classical ML needs bias + data lineage (Art. 10)
  - tech_docs         : document system type (Art. 11)
  - security          : dual-mode composition risk
  - quality_management: no-ML signal → missing documentation requirement

Metadata exposes ``typology: "llm" | "classical_ml" | "both" | "none"``.
"""

from __future__ import annotations

import re

import structlog

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    get_import_modules,
    has_file,
    parse_python_imports,
    search_files,
)

logger = structlog.get_logger(__name__)

# ─── LLM signals ──────────────────────────────────────────────────────────────

# Top-level module names (matched against AST-extracted imports)
_LLM_MODULES = {
    "openai", "anthropic", "langchain", "langchain_core", "langchain_community",
    "llama_index", "llama_cpp", "mistralai", "cohere", "groq",
    "transformers",          # HuggingFace — tokenizers + AutoModel
    "sentence_transformers",
    "vllm", "tgi",
    "pinecone", "chromadb", "weaviate", "qdrant",  # vector DBs = RAG
    "faiss",                 # facebook AI similarity search
}

# Regex patterns for non-import LLM signals
_LLM_REGEX_PATTERNS = [
    (r"ChatCompletion|messages\.create\s*\(|client\.chat\.completions",
     "OpenAI/Anthropic chat API call"),
    (r"AutoModelFor\w+|AutoTokenizer\.from_pretrained|pipeline\s*\(\s*['\"]",
     "HuggingFace AutoModel / pipeline"),
    (r"LLMChain|ConversationalRetrievalChain|RetrievalQA\b",
     "LangChain chain"),
    (r"llm_index|VectorStoreIndex|SimpleDirectoryReader",
     "LlamaIndex RAG pipeline"),
    (r"model\s*=\s*['\"]gpt-|model\s*=\s*['\"]claude-|model\s*=\s*['\"]mistral",
     "LLM model name literal"),
]

# System-prompt pattern: multi-line string starting with "You are "
_SYSTEM_PROMPT_RE = re.compile(
    r'(?:"""|\'\'\')[\s\S]{0,200}?You are [\w\s]',
    re.MULTILINE,
)

# Prompt template patterns
_PROMPT_TEMPLATE_RE = re.compile(
    r"PromptTemplate|ChatPromptTemplate|SystemMessagePromptTemplate|"
    r"HumanMessagePromptTemplate|f['\"][^'\"]*\{[^}]+\}[^'\"]*['\"]",
    re.IGNORECASE,
)

# Input validation alongside LLM — positive signal
_VALIDATION_RE = re.compile(
    r"InputValidator|sanitize_for_llm|prompt_guard|bleach\.clean|"
    r"html\.escape|re\.sub.*input|validate\w*input",
    re.IGNORECASE,
)

# ─── Classical ML signals ─────────────────────────────────────────────────────

_CML_MODULES = {
    "sklearn", "xgboost", "lightgbm", "catboost",
    "statsmodels",
}

_CML_TORCH_KERAS_WITHOUT_LLM = {
    "torch",       # without transformers = likely a trained classifier / regressor
    "tensorflow",
    "keras",
}

_CML_REGEX_PATTERNS = [
    (r"\.fit\s*\(|\.predict\s*\(|\.fit_transform\s*\(", "fit/predict call"),
    (r"accuracy_score|train_test_split|cross_val_score|GridSearchCV",
     "sklearn metric / CV function"),
    (r"XGBClassifier|XGBRegressor|LGBMClassifier|CatBoostClassifier",
     "gradient-boosting classifier"),
    (r"torch\.nn\.Linear|torch\.nn\.Sequential|nn\.Module",
     "PyTorch custom layer"),
]

_CML_FILE_PATTERNS = [
    r"train\.py$",
    r"train_model\.py$",
    r"\bmodel\.(pkl|joblib)$",
]


def _detect_llm(ctx: AnalyzerContext) -> tuple[bool, list[tuple[str, str]]]:
    """Return (detected, [(file_path, evidence_line), ...])."""
    evidence: list[tuple[str, str]] = []

    # AST-based import check
    ast_modules = get_import_modules(ctx)
    llm_mods_found = ast_modules & _LLM_MODULES
    if llm_mods_found:
        for imp in parse_python_imports(ctx):
            if imp.module.split(".")[0] in _LLM_MODULES:
                evidence.append((imp.file_path, f"import {imp.module}"))
                break

    # Regex patterns
    for pat, _ in _LLM_REGEX_PATTERNS:
        hits = search_files(ctx, pat)
        for path, line in hits:
            evidence.append((path, line))
            break  # one file per pattern

    # System prompt heuristic across all file content
    for path, content in ctx.files.items():
        if _SYSTEM_PROMPT_RE.search(content):
            match = _SYSTEM_PROMPT_RE.search(content)
            snip = match.group(0)[:80].replace("\n", " ") if match else "system prompt"
            evidence.append((path, snip))
            break

    return bool(evidence), evidence


def _detect_classical_ml(ctx: AnalyzerContext, llm_modules: set[str]) -> tuple[bool, list[tuple[str, str]]]:
    """Return (detected, [(file_path, evidence_line), ...])."""
    evidence: list[tuple[str, str]] = []

    # AST module check — classical-only modules
    ast_modules = get_import_modules(ctx)
    cml_mods = ast_modules & _CML_MODULES
    if cml_mods:
        for imp in parse_python_imports(ctx):
            if imp.module.split(".")[0] in _CML_MODULES:
                evidence.append((imp.file_path, f"import {imp.module}"))
                break

    # torch / tensorflow / keras without transformers / llm_modules = classical
    pytorch_or_keras = ast_modules & _CML_TORCH_KERAS_WITHOUT_LLM
    if pytorch_or_keras and not (ast_modules & _LLM_MODULES):
        for imp in parse_python_imports(ctx):
            if imp.module.split(".")[0] in pytorch_or_keras:
                evidence.append((imp.file_path, f"import {imp.module} (no LLM modules)"))
                break

    # Regex patterns
    for pat, _ in _CML_REGEX_PATTERNS:
        hits = search_files(ctx, pat)
        for path, line in hits:
            evidence.append((path, line))
            break

    # Model artifact files
    for fpat in _CML_FILE_PATTERNS:
        matched = has_file(ctx, fpat)
        if matched:
            evidence.append((matched[0], f"model artifact: {matched[0].split('/')[-1]}"))

    return bool(evidence), evidence


def analyze_model_typology(ctx: AnalyzerContext) -> AnalyzerResult:  # noqa: C901
    findings: list[Finding] = []

    ast_modules = get_import_modules(ctx)

    llm_detected, llm_evidence = _detect_llm(ctx)
    cml_detected, cml_evidence = _detect_classical_ml(ctx, ast_modules & _LLM_MODULES)

    # ─── LLM findings ──────────────────────────────────────────────────
    if llm_detected:
        # Representative file + snippet
        rep_file = llm_evidence[0][0] if llm_evidence else ""
        rep_snip = llm_evidence[0][1][:150] if llm_evidence else ""

        findings.append(Finding(
            id="mt-llm-detected",
            category="model_typology",
            title="LLM-based AI system detected",
            description=(
                "Generative AI / LLM signals found (OpenAI, Anthropic, HuggingFace Transformers, "
                "LangChain, vector DB, etc.). Art. 50 transparency obligations likely apply."
            ),
            file_path=rep_file,
            confidence=0.9,
            compliance_impact="positive",
            compliance_dimensions=["tech_docs"],
            evidence_snippet=rep_snip,
            kb_question_ids=["td-1"],
            suggested_answer="partial",
        ))

        # Art. 50 transparency is now handled precisely by the dedicated
        # ``article_50_transparency`` analyzer, which checks whether the AI
        # disclosure / content marking actually EXISTS in the code. model_typology
        # therefore no longer emits a blanket transparency gap for every detected
        # LLM — that double-penalised the ``transparency`` dimension even when the
        # app already discloses the AI interaction.

        # Human oversight gap — LLMs need Art. 14 controls
        findings.append(Finding(
            id="mt-llm-oversight-gap",
            category="model_typology",
            title="LLM detected: Art. 14 human oversight controls required",
            description=(
                "LLM-based systems with significant output impact require human override mechanisms "
                "(Art. 14). Verify escalation paths, confidence thresholds, and override capability."
            ),
            file_path=rep_file,
            confidence=0.8,
            compliance_impact="gap",
            compliance_dimensions=["human_oversight"],
            evidence_snippet=rep_snip,
            kb_question_ids=["ho-1", "ho-2"],
            suggested_answer="partial",
        ))

        # Check for system prompt (additional documentation requirement)
        system_prompt_files = []
        for path, content in ctx.files.items():
            if _SYSTEM_PROMPT_RE.search(content):
                system_prompt_files.append(path)
        if system_prompt_files:
            findings.append(Finding(
                id="mt-llm-system-prompt",
                category="model_typology",
                title="System prompt(s) detected in source",
                description=(
                    "Strings matching 'You are ...' pattern found — system prompts define LLM behavior. "
                    "Document the intended purpose and constraints of each prompt."
                ),
                file_path=system_prompt_files[0],
                confidence=0.75,
                compliance_impact="positive",
                compliance_dimensions=["tech_docs", "transparency"],
                evidence_snippet=f"System prompt in: {', '.join(system_prompt_files[:3])}",
                kb_question_ids=["td-1", "tr-3"],
                suggested_answer="partial",
            ))

        # Positive: input validation alongside LLM
        val_hits = search_files(ctx, _VALIDATION_RE.pattern)
        if val_hits:
            findings.append(Finding(
                id="mt-llm-input-validation",
                category="model_typology",
                title="Input validation present alongside LLM",
                description=(
                    "Input sanitization / prompt guard detected alongside LLM code. "
                    "Good security posture for prompt injection defense (Art. 15)."
                ),
                file_path=val_hits[0][0],
                confidence=0.85,
                compliance_impact="positive",
                compliance_dimensions=["security", "human_oversight"],
                evidence_snippet=val_hits[0][1][:150],
                kb_question_ids=["sc-3", "ho-3"],
                suggested_answer="yes",
            ))

    # ─── Classical ML findings ─────────────────────────────────────────
    if cml_detected:
        rep_file = cml_evidence[0][0] if cml_evidence else ""
        rep_snip = cml_evidence[0][1][:150] if cml_evidence else ""

        findings.append(Finding(
            id="mt-classical-ml-detected",
            category="model_typology",
            title="Classical ML system detected",
            description=(
                "sklearn / xgboost / PyTorch / TensorFlow patterns found — trained model "
                "without LLM-shaped generative API calls. Art. 10 bias + data governance applies."
            ),
            file_path=rep_file,
            confidence=0.88,
            compliance_impact="positive",
            compliance_dimensions=["tech_docs", "data_gov"],
            evidence_snippet=rep_snip,
            kb_question_ids=["td-1", "td-2"],
            suggested_answer="partial",
        ))

        # Classical ML positive: deterministic, easier to audit
        findings.append(Finding(
            id="mt-classical-ml-auditability",
            category="model_typology",
            title="Classical ML: deterministic outputs — favorable auditability",
            description=(
                "Classical ML models produce deterministic outputs that are easier to audit "
                "and explain (LIME/SHAP). Document performance metrics and bias testing (Art. 10, 15)."
            ),
            file_path=rep_file,
            confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["transparency", "data_gov"],
            evidence_snippet=rep_snip,
            kb_question_ids=["tr-3", "dg-2"],
            suggested_answer="partial",
        ))

    # ─── Both (dual-mode) ─────────────────────────────────────────────
    if llm_detected and cml_detected:
        findings.append(Finding(
            id="mt-both-composition-risk",
            category="model_typology",
            title="Dual-mode system (LLM + Classical ML): elevated governance burden",
            description=(
                "Both LLM and classical ML patterns detected in the same codebase. "
                "Dual-mode composition creates compounded risks — each subsystem requires its own "
                "compliance controls and both must be documented together (Art. 9, 11)."
            ),
            file_path="",
            confidence=0.85,
            compliance_impact="gap",
            compliance_dimensions=["security", "risk_mgmt", "tech_docs"],
            evidence_snippet="LLM + classical ML co-present",
            kb_question_ids=["rm-2", "td-4"],
            suggested_answer="partial",
        ))

    # ─── No-ML / rule-based ───────────────────────────────────────────
    if not llm_detected and not cml_detected:
        findings.append(Finding(
            id="mt-no-ml-signals",
            category="model_typology",
            title="No ML/LLM signals detected",
            description=(
                "No AI framework imports, model artifacts, or LLM API calls found. "
                "If this is intentional (rule-based system), document it explicitly so "
                "the EU AI Act risk classification is unambiguous."
            ),
            file_path="",
            confidence=0.7,
            compliance_impact="neutral",
            compliance_dimensions=["tech_docs"],
            evidence_snippet="no ML/LLM imports or patterns",
            kb_question_ids=["td-1"],
            suggested_answer="partial",
        ))

    # Determine typology label
    if llm_detected and cml_detected:
        typology = "both"
    elif llm_detected:
        typology = "llm"
    elif cml_detected:
        typology = "classical_ml"
    else:
        typology = "none"

    # Score
    positive = [f for f in findings if f.compliance_impact == "positive"]
    gaps = [f for f in findings if f.compliance_impact == "gap"]
    score = 0.0
    if positive:
        from statistics import mean
        score = mean(f.confidence for f in positive) * 100
        if gaps:
            score -= len(gaps) / (len(positive) + len(gaps)) * 30
        score = min(max(round(score, 1), 0.0), 100.0)

    evidence_files = {f.file_path for f in findings if f.file_path}

    logger.debug(
        "model_typology_scan_done",
        typology=typology,
        llm=llm_detected,
        classical_ml=cml_detected,
        findings=len(findings),
    )

    return AnalyzerResult(
        analyzer_id="model_typology",
        label="Model Typology",
        findings=findings,
        score=score,
        file_count=len(evidence_files),
        graph_node_type="model",
        graph_icon="🧬",
        connected_categories=["ai_frameworks", "transparency", "human_oversight"],
        metadata={"typology": typology},
    )
