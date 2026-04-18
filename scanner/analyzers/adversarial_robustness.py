"""Adversarial Robustness Analyzer — detects defenses against adversarial attacks.

Checks for adversarial testing frameworks, input validation on model endpoints,
prompt injection guards, model hardening patterns, and robustness testing.

EU AI Act Art. 15(3): High-risk AI systems shall be resilient against attempts
by unauthorised third parties to alter their use, outputs or performance by
exploiting system vulnerabilities.

Art. 15(4): Shall be resilient as regards errors, faults or inconsistencies
that may occur within the system or the environment.

Maps to: security, risk_mgmt
"""

from __future__ import annotations

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    get_import_modules,
    search_files,
)

# ─── Adversarial testing frameworks ──────────────────────────────────
_ADVERSARIAL_FRAMEWORKS = {
    "cleverhans": "CleverHans adversarial ML library",
    "art": "IBM Adversarial Robustness Toolbox (ART)",
    "foolbox": "Foolbox adversarial attack library",
    "textattack": "TextAttack NLP adversarial framework",
    "robustbench": "RobustBench adversarial robustness benchmark",
    "adversarial_robustness_toolbox": "IBM ART (full name)",
    "armory": "DARPA Armory adversarial evaluation",
    "counterfit": "Microsoft Counterfit adversarial ML",
}

# ─── Prompt injection / LLM guard patterns ───────────────────────────
_PROMPT_GUARD_PATTERNS = [
    r"prompt.*inject|inject.*prompt|injection.*detect|detect.*injection",
    r"guardrail|guard.*rail|content.*filter|safety.*filter",
    r"nemo.*guardrails|llama.*guard|rebuff|lakera",
    r"input.*sanitiz|sanitiz.*input|clean.*prompt|prompt.*clean",
    r"system.*prompt.*protect|prompt.*template.*safe",
    r"jailbreak.*detect|detect.*jailbreak",
]

# ─── Input validation on model/inference endpoints ───────────────────
_INPUT_VALIDATION_PATTERNS = [
    r"pydantic.*BaseModel|class\s+\w+.*BaseModel",
    r"@validator|@field_validator|model_validator",
    r"input.*schema|schema.*valid|request.*valid",
    r"max_length|min_length|regex.*pattern|constr\(",
    r"input.*bounds|clip.*input|normalize.*input|clamp\(",
]

# ─── Model hardening patterns ────────────────────────────────────────
_HARDENING_PATTERNS = [
    r"adversarial.*train|train.*adversarial|pgd.*train",
    r"gradient.*mask|gradient.*clip|grad.*norm",
    r"dropout|noise.*inject|gaussian.*noise|data.*augment",
    r"distill|knowledge.*distill|model.*compress",
    r"ensemble|model.*ensemble|voting.*classifier",
    r"differential.*privacy|dp.*sgd|opacus",
]

# ─── Rate limiting / abuse prevention ────────────────────────────────
_RATE_LIMIT_PATTERNS = [
    r"rate.*limit|throttl|slowapi|limiter",
    r"max.*request|request.*limit|quota",
    r"cooldown|backoff|retry.*limit",
    r"captcha|recaptcha|bot.*detect",
]

# ─── Output validation ──────────────────────────────────────────────
_OUTPUT_VALIDATION_PATTERNS = [
    r"output.*valid|valid.*output|response.*check",
    r"output.*filter|filter.*output|post.*process.*output",
    r"confidence.*threshold|min.*confidence|score.*threshold",
    r"hallucination.*detect|factual.*check|ground.*truth",
    r"toxic.*detect|content.*moderat|harmful.*content",
]


def analyze_adversarial_robustness(ctx: AnalyzerContext) -> AnalyzerResult:
    findings: list[Finding] = []
    evidence_files: set[str] = set()

    imported_modules = get_import_modules(ctx)

    # Detect if this is an AI/ML project at all
    ai_modules = {"torch", "tensorflow", "keras", "sklearn", "scikit-learn", "xgboost",
                  "lightgbm", "transformers", "openai", "anthropic", "langchain",
                  "huggingface_hub", "diffusers", "jax", "flax", "paddlepaddle"}
    has_ai_project = bool(ai_modules & imported_modules) or bool(
        search_files(ctx, r"import\s+(torch|tensorflow|keras|sklearn|openai|anthropic|langchain|transformers)")
    )

    # ── 1. Adversarial testing frameworks ─────────────────────────────
    detected_frameworks: list[str] = []
    for module, description in _ADVERSARIAL_FRAMEWORKS.items():
        if module in imported_modules:
            detected_frameworks.append(description)
            # Find the import file
            matches = search_files(ctx, rf"import\s+{module}|from\s+{module}")
            file_path = matches[0][0] if matches else "unknown"
            evidence_files.add(file_path)

    if detected_frameworks:
        findings.append(Finding(
            id="ar-adversarial-framework", category="adversarial_robustness",
            title="Adversarial testing framework detected",
            description=f"Project uses adversarial ML testing: {', '.join(detected_frameworks[:3])}.",
            file_path=list(evidence_files)[0] if evidence_files else "unknown",
            confidence=0.9,
            compliance_impact="positive",
            compliance_dimensions=["security", "risk_mgmt"],
            evidence_snippet=detected_frameworks[0],
            kb_question_ids=["sec-3"], suggested_answer="yes",
        ))
    else:
        # Check for adversarial test patterns even without framework imports
        adv_test_matches = search_files(ctx, r"adversar|robustness.*test|attack.*test|perturbat")
        if adv_test_matches:
            evidence_files.add(adv_test_matches[0][0])
            findings.append(Finding(
                id="ar-adversarial-patterns", category="adversarial_robustness",
                title="Adversarial testing patterns found",
                description="Code references adversarial testing or robustness evaluation.",
                file_path=adv_test_matches[0][0], confidence=0.7,
                compliance_impact="positive",
                compliance_dimensions=["security", "risk_mgmt"],
                evidence_snippet=adv_test_matches[0][1],
                kb_question_ids=["sec-3"], suggested_answer="partial",
            ))
        elif has_ai_project:
            findings.append(Finding(
                id="ar-no-adversarial-testing", category="adversarial_robustness",
                title="No adversarial testing detected",
                description=(
                    "No adversarial testing frameworks or patterns found. "
                    "Art. 15(3) requires high-risk AI systems to be resilient against "
                    "attempts to alter use, outputs or performance by exploiting vulnerabilities. "
                    "Consider adding adversarial robustness testing (e.g. IBM ART, Foolbox, TextAttack)."
                ),
                file_path="project", confidence=0.8,
                compliance_impact="gap",
                compliance_dimensions=["security", "risk_mgmt"],
                evidence_snippet="No adversarial testing framework found in imports",
                kb_question_ids=["sec-3"], suggested_answer="no",
            ))

    # ── 2. Prompt injection guards (LLM-specific) ────────────────────
    has_llm = bool(search_files(ctx, r"openai|anthropic|langchain|llama|transformers|huggingface"))

    if has_llm:
        guard_matches: list[tuple[str, str]] = []
        for pattern in _PROMPT_GUARD_PATTERNS:
            guard_matches.extend(search_files(ctx, pattern))

        if guard_matches:
            evidence_files.add(guard_matches[0][0])
            findings.append(Finding(
                id="ar-prompt-guards", category="adversarial_robustness",
                title="Prompt injection guards detected",
                description="LLM system includes prompt injection detection or content filtering.",
                file_path=guard_matches[0][0], confidence=0.85,
                compliance_impact="positive",
                compliance_dimensions=["security", "risk_mgmt"],
                evidence_snippet=guard_matches[0][1],
                kb_question_ids=["sec-3", "rm-4"], suggested_answer="partial",
            ))
        else:
            findings.append(Finding(
                id="ar-no-prompt-guards", category="adversarial_robustness",
                title="LLM system lacks prompt injection guards",
                description=(
                    "LLM framework detected but no prompt injection defenses found. "
                    "Art. 15(3) requires resilience against exploitation of vulnerabilities. "
                    "Add guardrails (e.g. NeMo Guardrails, Llama Guard, Rebuff, Lakera) "
                    "or implement input sanitization and output filtering."
                ),
                file_path="project", confidence=0.8,
                compliance_impact="gap",
                compliance_dimensions=["security", "risk_mgmt"],
                evidence_snippet="LLM imports found without prompt injection guards",
                kb_question_ids=["sec-3", "rm-4"], suggested_answer="no",
            ))

    # ── 3. Input validation on model endpoints ───────────────────────
    input_val_matches: list[tuple[str, str]] = []
    for pattern in _INPUT_VALIDATION_PATTERNS:
        input_val_matches.extend(search_files(ctx, pattern))

    if input_val_matches:
        # Check specifically for model/inference endpoint validation
        model_endpoint_files = search_files(ctx, r"predict|inference|generate|embed|classify|score")
        model_files = {m[0] for m in model_endpoint_files}
        validated_model_files = model_files & {m[0] for m in input_val_matches}

        if validated_model_files:
            findings.append(Finding(
                id="ar-input-validation-model", category="adversarial_robustness",
                title="Input validation on model endpoints",
                description="Model/inference endpoints have input validation (schema, bounds, or sanitization).",
                file_path=list(validated_model_files)[0], confidence=0.8,
                compliance_impact="positive",
                compliance_dimensions=["security"],
                evidence_snippet=input_val_matches[0][1],
                kb_question_ids=["sec-1"], suggested_answer="partial",
            ))
        else:
            findings.append(Finding(
                id="ar-input-validation-generic", category="adversarial_robustness",
                title="Input validation present (not on model endpoints)",
                description="Input validation found but not co-located with model inference code.",
                file_path=input_val_matches[0][0], confidence=0.6,
                compliance_impact="positive",
                compliance_dimensions=["security"],
                evidence_snippet=input_val_matches[0][1],
            ))
    elif has_ai_project:
        findings.append(Finding(
            id="ar-no-input-validation", category="adversarial_robustness",
            title="No input validation detected",
            description=(
                "No input validation patterns found (Pydantic models, schema validation, bounds checking). "
                "Unvalidated inputs to AI models enable adversarial attacks. "
                "Add request validation at the API boundary."
            ),
            file_path="project", confidence=0.75,
            compliance_impact="gap",
            compliance_dimensions=["security"],
            evidence_snippet="No input validation patterns found",
            kb_question_ids=["sec-1"], suggested_answer="no",
        ))

    # ── 4. Model hardening techniques ────────────────────────────────
    hardening_matches: list[tuple[str, str]] = []
    for pattern in _HARDENING_PATTERNS:
        hardening_matches.extend(search_files(ctx, pattern))

    if hardening_matches:
        evidence_files.add(hardening_matches[0][0])
        techniques = list({m[1][:50] for m in hardening_matches[:5]})
        findings.append(Finding(
            id="ar-model-hardening", category="adversarial_robustness",
            title="Model hardening techniques detected",
            description=f"Hardening patterns found: {'; '.join(techniques[:3])}.",
            file_path=hardening_matches[0][0], confidence=0.75,
            compliance_impact="positive",
            compliance_dimensions=["security", "risk_mgmt"],
            evidence_snippet=hardening_matches[0][1],
            kb_question_ids=["sec-3"], suggested_answer="partial",
        ))

    # ── 5. Rate limiting / abuse prevention ──────────────────────────
    rate_matches: list[tuple[str, str]] = []
    for pattern in _RATE_LIMIT_PATTERNS:
        rate_matches.extend(search_files(ctx, pattern))

    if rate_matches:
        evidence_files.add(rate_matches[0][0])
        findings.append(Finding(
            id="ar-rate-limiting", category="adversarial_robustness",
            title="Rate limiting / abuse prevention detected",
            description="API rate limiting or abuse prevention mechanisms found.",
            file_path=rate_matches[0][0], confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["security"],
            evidence_snippet=rate_matches[0][1],
            kb_question_ids=["sec-1"], suggested_answer="partial",
        ))
    elif has_llm:
        findings.append(Finding(
            id="ar-no-rate-limiting", category="adversarial_robustness",
            title="No rate limiting on AI endpoints",
            description=(
                "AI/LLM endpoints detected without rate limiting. "
                "Unthrottled model endpoints enable denial-of-wallet attacks "
                "and automated adversarial probing. Add rate limiting."
            ),
            file_path="project", confidence=0.7,
            compliance_impact="gap",
            compliance_dimensions=["security"],
            evidence_snippet="No rate limiting patterns found",
        ))

    # ── 6. Output validation / post-processing ───────────────────────
    output_matches: list[tuple[str, str]] = []
    for pattern in _OUTPUT_VALIDATION_PATTERNS:
        output_matches.extend(search_files(ctx, pattern))

    if output_matches:
        evidence_files.add(output_matches[0][0])
        findings.append(Finding(
            id="ar-output-validation", category="adversarial_robustness",
            title="Output validation / post-processing detected",
            description="Model outputs are validated, filtered, or checked before delivery.",
            file_path=output_matches[0][0], confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["security", "risk_mgmt"],
            evidence_snippet=output_matches[0][1],
            kb_question_ids=["sec-3"], suggested_answer="partial",
        ))
    elif has_llm:
        findings.append(Finding(
            id="ar-no-output-validation", category="adversarial_robustness",
            title="No output validation for AI system",
            description=(
                "AI system detected without output validation or content filtering. "
                "Art. 15(4) requires resilience against errors within the system. "
                "Add output validation, confidence thresholds, or content moderation."
            ),
            file_path="project", confidence=0.75,
            compliance_impact="gap",
            compliance_dimensions=["security", "risk_mgmt"],
            evidence_snippet="No output validation patterns found",
            kb_question_ids=["sec-3"], suggested_answer="no",
        ))

    # ── Score calculation ────────────────────────────────────────────
    positive = [f for f in findings if f.compliance_impact == "positive"]
    gaps = [f for f in findings if f.compliance_impact == "gap"]

    if not findings:
        score = 50.0  # No AI patterns detected — neutral
    elif not gaps and positive:
        score = min(80.0 + len(positive) * 5, 100.0)
    elif gaps and positive:
        score = max(20.0, 65.0 - len(gaps) * 12 + len(positive) * 5)
    elif gaps:
        score = max(5.0, 40.0 - len(gaps) * 12)
    else:
        score = 50.0

    return AnalyzerResult(
        analyzer_id="adversarial_robustness",
        label="Adversarial Robustness",
        findings=findings,
        score=round(score, 1),
        file_count=len(evidence_files),
        graph_node_type="shield",
        graph_icon="🛡️",
        connected_categories=["security_controls", "ai_frameworks", "agent_cascade"],
    )
