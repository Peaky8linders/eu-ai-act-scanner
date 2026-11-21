"""Security Controls Analyzer — auth, secrets, input validation, RBAC, API security.

Maps to: security, access_control

Uses AST for Pydantic model detection and decorator analysis.
"""

from __future__ import annotations

import ast
import re

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    _cached_ast,
    any_file_contains,
    has_file,
    parse_python_classes,
    product_files,
    search_files,
    search_files_with_lines,
)

# `timeout = 5` is as valid as `timeout=5`, so the separator is not literal.
_TIMEOUT_KWARG_RE = re.compile(r"\btimeout\s*=")
_REQUESTS_CALL_PATTERN = r"requests\.(get|post|put|delete)\("
_UNSAFE_DESER_MODULES = frozenset({"marshal", "dill"})
_UNSAFE_DESER_FUNCS = frozenset({"load", "loads"})


def _find_unsafe_deserialization(ctx: AnalyzerContext) -> list[tuple[str, int, str, str]]:
    """AST-based detector for ``marshal.load(s)`` / ``dill.load(s)`` in Python product code."""
    hits: list[tuple[str, int, str, str]] = []
    for path, content in product_files(ctx):
        if not path.endswith(".py"):
            continue
        tree = _cached_ast(ctx, path, content)
        if tree is None:
            continue
        # Track aliases: `import dill as d` or `from marshal import loads as mloads`
        module_aliases: dict[str, str] = {}
        direct_aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top in _UNSAFE_DESER_MODULES:
                        module_aliases[alias.asname or top] = top
            elif isinstance(node, ast.ImportFrom) and node.module:
                top = node.module.split(".")[0]
                if top in _UNSAFE_DESER_MODULES:
                    for alias in node.names:
                        if alias.name in _UNSAFE_DESER_FUNCS:
                            direct_aliases[alias.asname or alias.name] = f"{top}.{alias.name}"

        lines = content.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call_label = ""
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                mod = module_aliases.get(node.func.value.id)
                if mod and node.func.attr in _UNSAFE_DESER_FUNCS:
                    call_label = f"{mod}.{node.func.attr}"
            elif isinstance(node.func, ast.Name):
                call_label = direct_aliases.get(node.func.id, "")
            if call_label:
                ln = node.lineno
                snippet = lines[ln - 1].strip()[:200] if 0 < ln <= len(lines) else call_label
                hits.append((path, ln, snippet, f"ast.Call:{call_label}"))
                if len(hits) >= 3:
                    return hits
    return hits


def _call_window_has_timeout(content: str, start_line: int) -> bool:
    """Check whether the call starting at 1-indexed ``start_line`` specifies ``timeout=``."""
    lines = content.splitlines()
    idx = start_line - 1
    if idx < 0 or idx >= len(lines):
        return False
    # Check the call line plus up to 10 continuation lines until closing paren.
    chunk_lines: list[str] = []
    depth = 0
    started = False
    for line in lines[idx : idx + 11]:
        chunk_lines.append(line)
        for ch in line:
            if ch == "(":
                depth += 1
                started = True
            elif ch == ")":
                depth -= 1
        if started and depth <= 0:
            break
    return bool(_TIMEOUT_KWARG_RE.search("\n".join(chunk_lines)))


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

    # 8. Hardcoded secrets — line-aware (up to 3 sites per pattern, redacted snippet).
    secret_patterns = [
        (r"""['"](?:sk-|pk_|AKIA|ghp_|gho_|glpat-)[A-Za-z0-9]{10,}['"]""", "Potential API key literal"),
        (r"""password\s*=\s*['"][^'"]{8,}['"]""", "Hardcoded password"),
        (r"""(?:api_key|secret_key|access_token)\s*=\s*['"][^'"]{8,}['"]""", "Hardcoded secret"),
    ]
    for pat, desc in secret_patterns:
        line_matches = search_files_with_lines(ctx, pat)
        real_matches = [
            m for m in line_matches
            if "test" not in m[0].lower() and "example" not in m[0].lower()
        ]
        for path, line_no, _matched, pattern in real_matches[:3]:
            findings.append(Finding(
                id=f"sec-hardcoded-{desc[:15].replace(' ', '-').lower()}-{line_no}",
                category="security_controls",
                title=f"Potential hardcoded secret: {desc}",
                description=(
                    f"Pattern `{pattern}` matched at {path}:{line_no} (not test/example). "
                    "Verify the literal is not a production credential."
                ),
                file_path=path, confidence=0.7,
                compliance_impact="gap",
                compliance_dimensions=["security"],
                evidence_snippet="[redacted — potential secret literal at this line]",
                line_number=line_no,
                matched_pattern=pattern,
                article_paragraphs=["Art. 15(3)"],
            ))

    # 9. Unsafe deserialization (code-gated AST check for marshal/dill load(s)).
    for path, line_no, snippet, matched_pat in _find_unsafe_deserialization(ctx):
        findings.append(Finding(
            id=f"sec-unsafe-deserialization-{line_no}",
            category="security_controls",
            title=f"Unsafe deserialization ({matched_pat.split(':', 1)[-1]})",
            description=(
                f"Untrusted deserialization via `{matched_pat.split(':', 1)[-1]}` at "
                f"{path}:{line_no} allows arbitrary code execution on attacker-controlled "
                "payloads. Use safe formats (JSON, safetensors, ONNX). Art. 15(3)-(4)."
            ),
            file_path=path,
            confidence=0.85,
            compliance_impact="gap",
            compliance_dimensions=["security"],
            evidence_snippet=snippet,
            kb_question_ids=["sc-3"],
            suggested_answer="no",
            line_number=line_no,
            matched_pattern=matched_pat,
            article_paragraphs=["Art. 15(3)", "Art. 15(4)"],
        ))

    # 10. Outbound HTTP requests missing explicit timeout= (2-step non-backtracking).
    # Single-regex negative lookaheads between backtrackable `[^)]*` segments are
    # no-ops that falsely flag compliant `requests.get(url, timeout=5)` calls.
    # Step 1 finds the call line; Step 2 checks the call's argument window for `timeout=`.
    timeout_gaps = 0
    for path, line_no, text, pattern in search_files_with_lines(
        ctx, _REQUESTS_CALL_PATTERN, max_matches_per_file=5
    ):
        if not path.endswith(".py") or "test" in path.lower():
            continue
        stripped = text.lstrip()
        if stripped.startswith("#") or "search_files" in text or "_PATTERNS" in text:
            continue
        content = ctx.files.get(path, "")
        if _call_window_has_timeout(content, line_no):
            continue
        findings.append(Finding(
            id=f"sec-http-timeout-missing-{line_no}",
            category="security_controls",
            title="HTTP request missing explicit timeout=",
            description=(
                f"Outbound HTTP call at {path}:{line_no} omits an explicit `timeout=` "
                "argument. Unbounded blocking network calls can exhaust worker threads "
                "and cause cascading availability failures (Art. 15(4) resilience)."
            ),
            file_path=path,
            confidence=0.8,
            compliance_impact="gap",
            compliance_dimensions=["security", "risk_mgmt"],
            evidence_snippet=text,
            suggested_answer="no",
            line_number=line_no,
            matched_pattern=pattern,
            article_paragraphs=["Art. 15(4)"],
        ))
        timeout_gaps += 1
        if timeout_gaps >= 3:
            break

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
