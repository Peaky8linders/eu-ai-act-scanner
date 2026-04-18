"""AI Frameworks Analyzer — detect ML/AI libraries, version pinning, best practices.

Maps to: tech_docs, supply_chain

Uses AST-based import detection for Python files (more accurate than regex),
falls back to regex for non-Python files.
"""

from __future__ import annotations

import re

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    file_content,
    get_import_modules,
    search_files,
)

_FRAMEWORKS = {
    "pytorch": (r"\btorch\b", r"import\s+torch"),
    "tensorflow": (r"\btensorflow\b", r"import\s+tensorflow"),
    "sklearn": (r"\bsklearn\b", r"from\s+sklearn"),
    "huggingface": (r"\btransformers\b", r"from\s+transformers"),
    "openai": (r"\bopenai\b", r"import\s+openai"),
    "anthropic": (r"\banthrop", r"import\s+anthropic"),
    "langchain": (r"\blangchain\b", r"from\s+langchain"),
    "spacy": (r"\bspacy\b", r"import\s+spacy"),
    "fastai": (r"\bfastai\b", r"from\s+fastai"),
    "keras": (r"\bkeras\b", r"import\s+keras"),
}

_DEPRECATED = [
    (r"tf\.compat\.v1", "TensorFlow v1 compat layer"),
    (r"openai\.ChatCompletion", "OpenAI pre-v1 SDK"),
    (r"keras\.backend\.", "Direct Keras backend access"),
]

_UNSAFE_LOAD = [
    (r"torch\.load\s*\(", "torch.load (pickle-based, unsafe)"),
    (r"pickle\.load\s*\(", "pickle.load (arbitrary code execution risk)"),
    (r"joblib\.load\s*\(", "joblib.load (pickle-based)"),
]

_SAFE_LOAD = [
    (r"safetensors", "safetensors (safe serialization)"),
    (r"from_pretrained\s*\(", "from_pretrained (managed loading)"),
    (r"onnx", "ONNX (portable format)"),
]


# AST module name → framework display name
_AST_FRAMEWORK_MAP: dict[str, str] = {
    "torch": "pytorch", "tensorflow": "tensorflow", "sklearn": "sklearn",
    "transformers": "huggingface", "openai": "openai", "anthropic": "anthropic",
    "langchain": "langchain", "spacy": "spacy", "fastai": "fastai", "keras": "keras",
}


def analyze_ai_frameworks(ctx: AnalyzerContext) -> AnalyzerResult:
    findings: list[Finding] = []
    detected_frameworks: list[str] = []
    evidence_files: set[str] = set()

    # 1. Framework detection — AST-first for Python, regex fallback for others
    ast_modules = get_import_modules(ctx)
    ast_detected: set[str] = set()
    for mod, fw_name in _AST_FRAMEWORK_MAP.items():
        if mod in ast_modules:
            ast_detected.add(fw_name)
            detected_frameworks.append(fw_name)
            # Find the file that imports it for evidence
            from scanner.analyzers._base import parse_python_imports
            for imp in parse_python_imports(ctx):
                if imp.module.split(".")[0] == mod:
                    evidence_files.add(imp.file_path)
                    findings.append(Finding(
                        id=f"af-detect-{fw_name}", category="ai_frameworks",
                        title=f"{fw_name.title()} framework detected (AST-verified)",
                        description=f"AI framework '{fw_name}' imported in Python source (AST analysis).",
                        file_path=imp.file_path, confidence=0.95,
                        compliance_impact="positive",
                        compliance_dimensions=["tech_docs"],
                        evidence_snippet=f"import {imp.module}" + (f" ({', '.join(imp.names)})" if imp.names else ""),
                        kb_question_ids=["td-1"], suggested_answer="partial",
                    ))
                    break

    # Regex fallback for non-Python files (JS/TS/Java/etc.)
    for name, patterns in _FRAMEWORKS.items():
        if name in ast_detected:
            continue
        for pat in patterns:
            matches = search_files(ctx, pat)
            # Only match non-Python files (Python already covered by AST)
            non_py = [(p, s) for p, s in matches if not p.endswith(".py")]
            if non_py:
                detected_frameworks.append(name)
                evidence_files.add(non_py[0][0])
                findings.append(Finding(
                    id=f"af-detect-{name}", category="ai_frameworks",
                    title=f"{name.title()} framework detected",
                    description=f"AI framework '{name}' found in project source code.",
                    file_path=non_py[0][0], confidence=0.85,
                    compliance_impact="positive",
                    compliance_dimensions=["tech_docs"],
                    evidence_snippet=non_py[0][1],
                    kb_question_ids=["td-1"], suggested_answer="partial",
                ))
                break

    # 2. Version pinning
    for req_file in ["requirements.txt", "pyproject.toml", "setup.cfg"]:
        content = file_content(ctx, req_file)
        if not content:
            continue
        unpinned = []
        for fw in detected_frameworks:
            # Check if framework dep is pinned (has ==, >=, ~=)
            if re.search(rf"{fw}[^=\n]*$", content, re.MULTILINE | re.IGNORECASE):
                if not re.search(rf"{fw}\s*[=~><]", content, re.IGNORECASE):
                    unpinned.append(fw)
        if unpinned:
            findings.append(Finding(
                id="af-version-unpin", category="ai_frameworks",
                title=f"Unpinned AI dependencies: {', '.join(unpinned)}",
                description="AI framework dependencies without version constraints risk breaking changes.",
                file_path=req_file, confidence=0.8,
                compliance_impact="gap",
                compliance_dimensions=["supply_chain"],
                evidence_snippet=f"Unpinned: {', '.join(unpinned)}",
                kb_question_ids=["sp-1"], suggested_answer="partial",
            ))
        elif detected_frameworks:
            findings.append(Finding(
                id="af-version-pinned", category="ai_frameworks",
                title="AI dependencies properly version-pinned",
                description="All detected AI framework dependencies have version constraints.",
                file_path=req_file, confidence=0.85,
                compliance_impact="positive",
                compliance_dimensions=["supply_chain"],
                kb_question_ids=["sp-1"], suggested_answer="yes",
            ))

    # 3. Deprecated API usage
    for pat, desc in _DEPRECATED:
        matches = search_files(ctx, pat)
        if matches:
            findings.append(Finding(
                id=f"af-deprecated-{desc[:20].replace(' ', '-').lower()}", category="ai_frameworks",
                title=f"Deprecated API: {desc}",
                description=f"Usage of deprecated API pattern detected: {desc}.",
                file_path=matches[0][0], confidence=0.85,
                compliance_impact="gap",
                compliance_dimensions=["tech_docs"],
                evidence_snippet=matches[0][1],
            ))

    # 4. Safe vs unsafe model loading
    for pat, desc in _UNSAFE_LOAD:
        matches = search_files(ctx, pat)
        if matches:
            findings.append(Finding(
                id=f"af-unsafe-{desc[:15].replace(' ', '-').lower()}", category="ai_frameworks",
                title=f"Unsafe model loading: {desc}",
                description="Pickle-based model loading is a security risk (arbitrary code execution).",
                file_path=matches[0][0], confidence=0.9,
                compliance_impact="gap",
                compliance_dimensions=["security"],
                evidence_snippet=matches[0][1],
            ))

    for pat, desc in _SAFE_LOAD:
        matches = search_files(ctx, pat)
        if matches:
            findings.append(Finding(
                id=f"af-safe-{desc[:15].replace(' ', '-').lower()}", category="ai_frameworks",
                title=f"Safe model loading: {desc}",
                description="Secure model serialization pattern detected.",
                file_path=matches[0][0], confidence=0.85,
                compliance_impact="positive",
                compliance_dimensions=["security"],
                evidence_snippet=matches[0][1],
            ))

    # 5. Multi-framework mixing
    if len(detected_frameworks) >= 3:
        findings.append(Finding(
            id="af-multi-framework", category="ai_frameworks",
            title=f"Multi-framework complexity: {len(detected_frameworks)} frameworks",
            description=f"Project uses {len(detected_frameworks)} AI frameworks ({', '.join(detected_frameworks)}). High complexity increases maintenance risk.",
            file_path="", confidence=0.7,
            compliance_impact="gap",
            compliance_dimensions=["risk_mgmt"],
        ))

    # 6. GPU/accelerator
    gpu_matches = search_files(ctx, r"\bcuda\b|\bmps\b|\btpu\b|\.to\(['\"]cuda")
    if gpu_matches:
        findings.append(Finding(
            id="af-gpu", category="ai_frameworks",
            title="GPU/accelerator usage detected",
            description="Code references GPU/TPU accelerators — document hardware requirements.",
            file_path=gpu_matches[0][0], confidence=0.8,
            compliance_impact="neutral",
            compliance_dimensions=["tech_docs"],
            evidence_snippet=gpu_matches[0][1],
        ))

    # 7. ONNX export
    onnx_matches = search_files(ctx, r"onnx\.export|torch\.onnx|onnxruntime")
    if onnx_matches:
        findings.append(Finding(
            id="af-onnx", category="ai_frameworks",
            title="ONNX model portability",
            description="ONNX export/runtime detected — enables cross-platform deployment.",
            file_path=onnx_matches[0][0], confidence=0.85,
            compliance_impact="positive",
            compliance_dimensions=["tech_docs"],
            evidence_snippet=onnx_matches[0][1],
        ))

    # Score
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
        analyzer_id="ai_frameworks", label="AI Frameworks",
        findings=findings, score=score,
        file_count=len(evidence_files),
        graph_node_type="model", graph_icon="🤖",
        connected_categories=["data_pipeline", "test_suite", "configuration"],
        metadata={"detected": detected_frameworks},
    )
