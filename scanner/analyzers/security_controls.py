"""Security Controls Analyzer — auth, secrets, input validation, RBAC, API security.

Maps to: security, access_control

Uses AST for Pydantic model detection and decorator analysis.
"""

from __future__ import annotations

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    any_file_contains,
    has_file,
    parse_python_classes,
    search_files,
)


def analyze_security_controls(ctx: AnalyzerContext) -> AnalyzerResult:
    findings: list[Finding] = []
    evidence_files: set[str] = set()

    # 1. Authentication
    auth_patterns = [
        (r"from\s+fastapi.*Depends|Depends\s*\(", "FastAPI dependency injection (auth middleware)"),
        (r"jwt\.|jose\.|PyJWT|python-jose", "JWT token handling"),
        (r"OAuth|oauth2|authlib", "OAuth/OAuth2 flow"),
        (r"@login_required|@authenticated", "Auth decorator"),
    ]
    for pat, desc in auth_patterns:
        matches = search_files(ctx, pat)
        if matches:
            evidence_files.add(matches[0][0])
            findings.append(Finding(
                id=f"sec-auth-{desc[:15].replace(' ', '-').lower()}", category="security_controls",
                title=f"Authentication: {desc}",
                description=f"Authentication mechanism detected: {desc}.",
                file_path=matches[0][0], confidence=0.85,
                compliance_impact="positive",
                compliance_dimensions=["security", "access_control"],
                evidence_snippet=matches[0][1],
                kb_question_ids=["ac-1"], suggested_answer="partial",
            ))
            break

    # 2. Secrets management
    vault_matches = search_files(ctx, r"vault|aws.*secrets.*manager|SecretStr|dotenv|environ\.get")
    gitignore_has_env = False
    for gi in has_file(ctx, r"\.gitignore$"):
        content = ctx.files.get(gi, "")
        if ".env" in content:
            gitignore_has_env = True
    env_files = has_file(ctx, r"\.env$")
    if vault_matches and gitignore_has_env:
        findings.append(Finding(
            id="sec-secrets-managed", category="security_controls",
            title="Secrets management in place",
            description="Environment variables or vault used for secrets, .env excluded from git.",
            file_path=vault_matches[0][0], confidence=0.85,
            compliance_impact="positive",
            compliance_dimensions=["security"],
            evidence_snippet=vault_matches[0][1],
            kb_question_ids=["ac-2"], suggested_answer="yes",
        ))
    elif env_files and not gitignore_has_env:
        findings.append(Finding(
            id="sec-secrets-exposed", category="security_controls",
            title=".env file not in .gitignore",
            description="Environment file found but not excluded from version control — secrets may be committed.",
            file_path=env_files[0], confidence=0.9,
            compliance_impact="gap",
            compliance_dimensions=["security"],
            kb_question_ids=["ac-2"], suggested_answer="no",
        ))

    # 3. Input validation — AST-powered Pydantic model detection
    pydantic_classes = [c for c in parse_python_classes(ctx) if "BaseModel" in c.bases]
    if pydantic_classes:
        evidence_files.add(pydantic_classes[0].file_path)
        findings.append(Finding(
            id="sec-input-validation", category="security_controls",
            title=f"Input validation: {len(pydantic_classes)} Pydantic models (AST-verified)",
            description=f"AST analysis found {len(pydantic_classes)} Pydantic BaseModel classes for request validation.",
            file_path=pydantic_classes[0].file_path, confidence=0.9,
            compliance_impact="positive",
            compliance_dimensions=["security"],
            evidence_snippet=f"class {pydantic_classes[0].name}(BaseModel)",
        ))

    # 4. RBAC
    rbac_matches = search_files(ctx, r"rbac|role.*based|permission|@requires_role|has_permission")
    if rbac_matches:
        findings.append(Finding(
            id="sec-rbac", category="security_controls",
            title="Role-based access control detected",
            description="RBAC patterns found in source code.",
            file_path=rbac_matches[0][0], confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["access_control"],
            evidence_snippet=rbac_matches[0][1],
            kb_question_ids=["ac-1"], suggested_answer="yes",
        ))

    # 5. Rate limiting
    rate_matches = search_files(ctx, r"slowapi|ratelimit|rate.limit|throttle|RateLimiter")
    if rate_matches:
        findings.append(Finding(
            id="sec-rate-limit", category="security_controls",
            title="Rate limiting configured",
            description="Rate limiting middleware or decorator detected.",
            file_path=rate_matches[0][0], confidence=0.85,
            compliance_impact="positive",
            compliance_dimensions=["security"],
            evidence_snippet=rate_matches[0][1],
        ))

    # 6. TLS/HTTPS
    tls_matches = search_files(ctx, r"ssl_context|certfile|https://|TLSv|ssl\.create_default_context")
    if tls_matches:
        findings.append(Finding(
            id="sec-tls", category="security_controls",
            title="TLS/HTTPS configuration detected",
            description="TLS or HTTPS references found in server configuration.",
            file_path=tls_matches[0][0], confidence=0.7,
            compliance_impact="positive",
            compliance_dimensions=["security"],
            evidence_snippet=tls_matches[0][1],
        ))

    # 7. Dependency scanning
    dep_scan_files = any_file_contains(ctx, [
        ".safety", "safety.yml", ".snyk", "dependabot.yml", "dependabot.yaml",
        "pip-audit", "bandit.yml", ".bandit",
    ])
    if dep_scan_files:
        findings.append(Finding(
            id="sec-dep-scan", category="security_controls",
            title="Dependency vulnerability scanning configured",
            description=f"Security scanning config found: {', '.join(dep_scan_files)}.",
            file_path=dep_scan_files[0], confidence=0.9,
            compliance_impact="positive",
            compliance_dimensions=["supply_chain"],
            kb_question_ids=["sp-2"], suggested_answer="yes",
        ))

    # 8. Hardcoded secrets
    secret_patterns = [
        (r"""['"](?:sk-|pk_|AKIA|ghp_|gho_|glpat-)[A-Za-z0-9]{10,}['"]""", "Potential API key literal"),
        (r"""password\s*=\s*['"][^'"]{8,}['"]""", "Hardcoded password"),
        (r"""(?:api_key|secret_key|access_token)\s*=\s*['"][^'"]{8,}['"]""", "Hardcoded secret"),
    ]
    for pat, desc in secret_patterns:
        matches = search_files(ctx, pat)
        # Filter out test files and example configs
        real_matches = [(p, s) for p, s in matches if "test" not in p.lower() and "example" not in p.lower()]
        if real_matches:
            findings.append(Finding(
                id=f"sec-hardcoded-{desc[:15].replace(' ', '-').lower()}", category="security_controls",
                title=f"Potential hardcoded secret: {desc}",
                description="Pattern matching a hardcoded secret found in source (not test/example).",
                file_path=real_matches[0][0], confidence=0.7,
                compliance_impact="gap",
                compliance_dimensions=["security"],
                evidence_snippet="[redacted — potential secret]",
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
        analyzer_id="security_controls", label="Security Controls",
        findings=findings, score=score,
        file_count=len(evidence_files),
        graph_node_type="security", graph_icon="🔒",
        connected_categories=["configuration", "test_suite"],
    )
