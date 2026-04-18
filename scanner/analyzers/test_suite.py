"""Test Suite Analyzer — test framework, coverage, ML-specific tests, CI integration.

Maps to: risk_mgmt, quality_management

Uses AST to count actual test functions and compute test-to-source ratio.
"""

from __future__ import annotations

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    any_file_contains,
    has_file,
    parse_python_functions,
    search_files,
)


def analyze_test_suite(ctx: AnalyzerContext) -> AnalyzerResult:
    findings: list[Finding] = []
    evidence_files: set[str] = set()

    # 1. Test framework detection
    frameworks_found = []
    for name, pat in [
        ("pytest", r"import\s+pytest|from\s+pytest|@pytest\."),
        ("unittest", r"import\s+unittest|unittest\.TestCase"),
        ("hypothesis", r"from\s+hypothesis|@given\("),
        ("doctest", r"import\s+doctest|>>>"),
    ]:
        matches = search_files(ctx, pat)
        if matches:
            frameworks_found.append(name)
            evidence_files.add(matches[0][0])
            findings.append(Finding(
                id=f"ts-framework-{name}", category="test_suite",
                title=f"Test framework: {name}",
                description=f"Testing framework '{name}' detected in project.",
                file_path=matches[0][0], confidence=0.9,
                compliance_impact="positive",
                compliance_dimensions=["risk_mgmt", "quality_management"],
                evidence_snippet=matches[0][1],
                kb_question_ids=["rm-3"], suggested_answer="yes",
            ))

    # 2. Test file ratio
    test_files = has_file(ctx, r"test[_s]?[/\\]|_test\.py$|test_\w+\.py$")
    source_files = [p for p in ctx.file_list if p.endswith(".py") and "test" not in p.lower()]
    if source_files:
        ratio = len(test_files) / len(source_files) if source_files else 0
        if ratio >= 0.3:
            findings.append(Finding(
                id="ts-ratio-good", category="test_suite",
                title=f"Good test coverage ratio: {len(test_files)} test / {len(source_files)} source files",
                description=f"Test-to-source ratio of {ratio:.0%} indicates healthy test coverage.",
                file_path=test_files[0] if test_files else "", confidence=0.75,
                compliance_impact="positive",
                compliance_dimensions=["quality_management"],
                kb_question_ids=["qm-5"], suggested_answer="partial",
            ))
        elif test_files:
            findings.append(Finding(
                id="ts-ratio-low", category="test_suite",
                title=f"Low test ratio: {len(test_files)} test / {len(source_files)} source files",
                description=f"Test-to-source ratio of {ratio:.0%} suggests insufficient test coverage.",
                file_path=test_files[0], confidence=0.7,
                compliance_impact="gap",
                compliance_dimensions=["quality_management"],
            ))
        else:
            findings.append(Finding(
                id="ts-no-tests", category="test_suite",
                title="No test files detected",
                description="No test files found in the project — testing is required for compliance.",
                file_path="", confidence=0.9,
                compliance_impact="gap",
                compliance_dimensions=["risk_mgmt", "quality_management"],
                kb_question_ids=["rm-3"], suggested_answer="no",
            ))

    # 2b. AST-powered test function count (more accurate than file count)
    all_fns = parse_python_functions(ctx)
    test_fns = [f for f in all_fns if f.is_test]
    non_test_fns = [f for f in all_fns if not f.is_test and not f.name.startswith("_")]
    if test_fns:
        fn_ratio = len(test_fns) / (len(non_test_fns) + len(test_fns)) if non_test_fns else 1.0
        findings.append(Finding(
            id="ts-ast-count", category="test_suite",
            title=f"AST: {len(test_fns)} test functions, {len(non_test_fns)} source functions",
            description=f"Test function ratio: {fn_ratio:.0%} (AST-verified, not just file count).",
            file_path=test_fns[0].file_path, confidence=0.9,
            compliance_impact="positive" if fn_ratio >= 0.2 else "gap",
            compliance_dimensions=["quality_management"],
        ))

    # 3. ML-specific tests
    ml_test_patterns = [
        (r"drift|data_drift|model_drift|concept_drift", "Data/model drift testing"),
        (r"accuracy.*assert|assert.*accuracy|performance.*regress", "Model performance regression tests"),
        (r"prediction.*distribut|output.*distribut", "Prediction distribution tests"),
    ]
    for pat, desc in ml_test_patterns:
        matches = search_files(ctx, pat)
        test_matches = [(p, s) for p, s in matches if "test" in p.lower()]
        if test_matches:
            findings.append(Finding(
                id=f"ts-ml-{desc[:15].replace(' ', '-').lower()}", category="test_suite",
                title=f"ML-specific test: {desc}",
                description=f"Machine learning testing pattern detected: {desc}.",
                file_path=test_matches[0][0], confidence=0.8,
                compliance_impact="positive",
                compliance_dimensions=["risk_mgmt"],
                evidence_snippet=test_matches[0][1],
            ))

    # 4. Integration tests
    integ_matches = search_files(ctx, r"TestClient|httpx\.Client|requests\.(get|post)|app\.test_client")
    integ_in_tests = [(p, s) for p, s in integ_matches if "test" in p.lower()]
    if integ_in_tests:
        findings.append(Finding(
            id="ts-integration", category="test_suite",
            title="Integration/API tests detected",
            description="Tests making HTTP requests to the application detected.",
            file_path=integ_in_tests[0][0], confidence=0.85,
            compliance_impact="positive",
            compliance_dimensions=["quality_management"],
            evidence_snippet=integ_in_tests[0][1],
        ))

    # 5. Test infrastructure
    infra_files = any_file_contains(ctx, ["conftest.py", "fixtures.py", "factories.py"])
    if infra_files:
        findings.append(Finding(
            id="ts-infrastructure", category="test_suite",
            title="Test infrastructure (fixtures/factories)",
            description=f"Test infrastructure files: {', '.join(infra_files)}.",
            file_path=infra_files[0], confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["quality_management"],
        ))

    # 6. CI test runner
    ci_test_patterns = search_files(ctx, r"pytest|python\s+-m\s+pytest|npm\s+test|jest|mocha")
    ci_files = [(p, s) for p, s in ci_test_patterns
                if any(ci in p.lower() for ci in [".github", "gitlab-ci", "jenkins", "circle", ".yml", ".yaml"])]
    if ci_files:
        findings.append(Finding(
            id="ts-ci-runner", category="test_suite",
            title="Tests integrated in CI pipeline",
            description="Test execution commands found in CI configuration.",
            file_path=ci_files[0][0], confidence=0.9,
            compliance_impact="positive",
            compliance_dimensions=["quality_management"],
            evidence_snippet=ci_files[0][1],
            kb_question_ids=["qm-5"], suggested_answer="yes",
        ))

    # 7. Benchmark tests
    bench_matches = search_files(ctx, r"@pytest\.mark\.benchmark|benchmark|perf_counter|timeit|locust|k6")
    bench_in_tests = [(p, s) for p, s in bench_matches if "test" in p.lower() or "bench" in p.lower()]
    if bench_in_tests:
        findings.append(Finding(
            id="ts-benchmark", category="test_suite",
            title="Performance/benchmark tests detected",
            description="Benchmark or performance testing patterns found.",
            file_path=bench_in_tests[0][0], confidence=0.75,
            compliance_impact="positive",
            compliance_dimensions=["risk_mgmt"],
            evidence_snippet=bench_in_tests[0][1],
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
        analyzer_id="test_suite", label="Test Suite",
        findings=findings, score=score,
        file_count=len(evidence_files) + len(test_files),
        graph_node_type="test", graph_icon="🧪",
        connected_categories=["ai_frameworks", "security_controls", "data_pipeline"],
        metadata={"frameworks": frameworks_found, "test_file_count": len(test_files)},
    )
