"""Targeted unit & precision/recall tests for Wave 1A scanner parity upgrades."""

from __future__ import annotations

import warnings

from scanner.analyzers import (
    ANALYZER_REGISTRY,
    AnalyzerContext,
    Finding,
    _execute_analyzer,
    collect_pre_filled_answers,
    compute_dimension_scores,
)
from scanner.analyzers._base import (
    _cached_ast,
    is_non_product_path,
    parse_python_classes,
    parse_python_functions,
    product_files,
    search_code_files,
    search_files,
    search_files_with_lines,
)
from scanner.benchmark import run_scanner_benchmark


def _ctx(files: dict[str, str], **kwargs) -> AnalyzerContext:
    return AnalyzerContext(files=files, file_list=sorted(files.keys()), **kwargs)


# ─── _base.py: AST cache, SyntaxWarning suppression, docstring bug, fixture gate ─


def test_ast_cache_reuses_parsed_tree_and_suppresses_syntax_warning():
    # Non-raw regex string in scanned user code triggers SyntaxWarning on Python 3.12.
    bad_escape_src = 'PATTERN = "\\s+\\d+"\ndef stub(): ...\n'
    ctx = _ctx({"app.py": bad_escape_src})
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        t1 = _cached_ast(ctx, "app.py", bad_escape_src)
        t2 = _cached_ast(ctx, "app.py", bad_escape_src)
    assert t1 is not None
    assert t1 is t2
    assert not [w for w in caught if issubclass(w.category, SyntaxWarning)]


def test_ellipsis_body_not_counted_as_docstring():
    ctx = _ctx({
        "proto.py": (
            "class Proto:\n"
            "    ...\n"
            "    def method(self): ...\n\n"
            "class Documented:\n"
            '    """Real class docstring."""\n'
            "    def real_fn(self):\n"
            '        """Real function docstring."""\n'
            "        return 1\n"
        ),
    })
    fns = {f.name: f.has_docstring for f in parse_python_functions(ctx)}
    cls = {c.name: c.has_docstring for c in parse_python_classes(ctx)}
    assert fns["method"] is False
    assert fns["real_fn"] is True
    assert cls["Proto"] is False
    assert cls["Documented"] is True


def test_is_non_product_path_and_search_helpers_fixture_gate():
    assert is_non_product_path("tests/fixtures/iac/k8s_bad.yaml") is True
    assert is_non_product_path("test_app.py") is True
    assert is_non_product_path("src/components/App.spec.tsx") is True
    assert is_non_product_path("src/client.py") is False
    assert is_non_product_path("docs/governance.md") is False

    ctx = _ctx({
        "src/app.py": "TOKEN_MARKER = 'prod'\n",
        "tests/fixtures/fake.py": "TOKEN_MARKER = 'fixture'\n",
    })
    assert [p for p, _ in product_files(ctx)] == ["src/app.py"]
    assert [p for p, _ in search_files(ctx, "TOKEN_MARKER")] == ["src/app.py"]
    assert len(search_files(ctx, "TOKEN_MARKER", include_non_product=True)) == 2
    assert [p for p, _ in search_code_files(ctx, "TOKEN_MARKER")] == ["src/app.py"]
    line_hits = search_files_with_lines(ctx, "TOKEN_MARKER")
    assert len(line_hits) == 1
    assert line_hits[0][0] == "src/app.py"
    assert line_hits[0][1] == 1


# ─── data_pipeline.py ────────────────────────────────────────────────────


def test_data_pipeline_pandas_only_is_neutral_without_art10_gaps():
    """Art. 10 governs training data: pandas alone (no training) raises no Art. 10 gap."""
    from scanner.analyzers.data_pipeline import analyze_data_pipeline

    res = analyze_data_pipeline(_ctx({"ingest.py": "import pandas as pd\ndf = pd.read_csv('a.csv')\n"}))
    by_id = {f.id: f for f in res.findings}
    assert by_id["dp-load-pandas"].compliance_impact == "neutral"
    assert "dp-no-versioning" not in by_id


def test_data_pipeline_training_without_governance_emits_art10_gaps():
    from scanner.analyzers.data_pipeline import analyze_data_pipeline

    res = analyze_data_pipeline(_ctx({"train.py": (
        "import pandas as pd\nfrom sklearn.linear_model import LogisticRegression\n"
        "df = pd.read_csv('a.csv')\nmodel = LogisticRegression().fit(df[['x']], df['y'])\n"
    )}))
    by_id = {f.id: f for f in res.findings}
    assert by_id["dp-no-versioning"].kb_question_ids == ["dg-1"]
    assert "dp-no-quality-checks" in by_id
    assert by_id["dp-no-quality-checks"].kb_question_ids == ["dg-3"]
    # Coverage ratio: neutral + 2 gaps -> data_gov scores 0.0%, never 100%!
    dims = compute_dimension_scores(res.findings)
    assert dims["data_gov"] == 0.0


# ─── human_oversight.py ──────────────────────────────────────────────────


def test_human_oversight_ignores_fastapi_shutdown_and_downgrades_kill_switch_to_partial():
    from scanner.analyzers.human_oversight import analyze_human_oversight

    fastapi_res = analyze_human_oversight(_ctx({
        "main.py": '@app.on_event("shutdown")\nasync def shutdown():\n    await db.close()\n',
    }))
    ids = {f.id for f in fastapi_res.findings}
    assert "ho-kill-switch" not in ids
    assert "ho-none" in ids

    real_res = analyze_human_oversight(_ctx({
        "safety.py": "def model_shutdown():\n    halt_inference()\n",
    }))
    ks = next(f for f in real_res.findings if f.id == "ho-kill-switch")
    assert ks.suggested_answer == "partial"


# ─── agent_cascade.py ────────────────────────────────────────────────────


def test_agent_cascade_unbounded_loop_swarm_lg1_and_narrow_except():
    from scanner.analyzers.agent_cascade import analyze_agent_cascade

    res = analyze_agent_cascade(_ctx({
        "swarm.py": (
            "import crewai\n"
            "import langsmith\n\n"
            "def run_loop(agent, state):\n"
            "    try:\n"
            "        while True:\n"
            "            state = agent.invoke(state)\n"
            "    except ValueError:\n"
            "        pass\n"
        ),
    }))
    by_id = {f.id: f for f in res.findings}
    assert "ac-unbounded-subagent-loop" in by_id
    assert "ac-mas-emergence-no-monitor" in by_id
    assert by_id["ac-agent-tracing"].kb_question_ids == ["lg-1"]
    # Narrow `except ValueError: pass` must NOT trigger silent failure!
    assert "ac-silent-failure" not in by_id


def test_agent_cascade_prose_mentions_do_not_trigger_modern_patterns():
    from scanner.analyzers.agent_cascade import analyze_agent_cascade

    res = analyze_agent_cascade(_ctx({
        "README.md": "We compared crewai, autogen_core, browser_use, and e2b.\n",
        "src/plain.py": "x = 1\n",
    }))
    assert res.findings == []


# ─── IaC fixture exclusion & Art. 10(2)/15 residency citation fix ────────


def test_iac_analyzers_exclude_test_fixtures_and_fix_art10_residency_citation():
    from scanner.analyzers.cicd_dockerfile import analyze_cicd_dockerfile
    from scanner.analyzers.cloud_deployment import analyze_cloud_deployment
    from scanner.analyzers.cloudformation_k8s import analyze_cloudformation_k8s
    from scanner.analyzers.terraform import analyze_terraform

    tf_bad = (
        'provider "aws" {\n  region = "us-east-1"\n}\n'
        'resource "aws_sagemaker_endpoint" "m" {}\n'
    )
    assert analyze_terraform(_ctx({"tests/fixtures/bad.tf": tf_bad})).findings == []

    tf_prod = analyze_terraform(_ctx({"infra/main.tf": tf_bad}))
    region_gap = next(f for f in tf_prod.findings if f.id == "tf-region-non-eu-us-east-1")
    assert "Art. 10(5)" not in region_gap.article_paragraphs
    assert "Art. 10(2)" in region_gap.article_paragraphs

    k8s_bad = (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\n"
        "spec:\n  template:\n    spec:\n      containers:\n        - name: c\n          image: x:1\n"
    )
    assert analyze_cloudformation_k8s(_ctx({"tests/fixtures/k8s.yaml": k8s_bad})).findings == []
    assert analyze_cicd_dockerfile(_ctx({"tests/fixtures/Dockerfile": "FROM python:latest\n"})).findings == []

    # Cloud deployment multi-cloud description no longer cites Art. 10(5).
    cd_res = analyze_cloud_deployment(_ctx({
        "aws.py": "import boto3\n",
        "gcp.py": "import vertexai\n",
    }))
    mc = next(f for f in cd_res.findings if f.id == "cd-multi-cloud")
    assert "Art. 10(5)" not in mc.description
    assert "Art. 10(2)" in mc.description


# ─── test_suite.py include_non_product=True ──────────────────────────────


def test_test_suite_still_detects_pytest_under_tests_dir():
    from scanner.analyzers.test_suite import analyze_test_suite

    res = analyze_test_suite(_ctx({
        "src/app.py": "def run():\n    return 1\n",
        "tests/test_app.py": "import pytest\n\ndef test_run():\n    assert True\n",
    }))
    ids = {f.id for f in res.findings}
    assert "ts-framework-pytest" in ids
    assert "ts-no-tests" not in ids


# ─── lethal_trifecta.py multi-file emission (cap 25) + clamp ─────────────


def test_lethal_trifecta_emits_up_to_25_ungated_findings():
    from scanner.analyzers.lethal_trifecta import analyze_lethal_trifecta

    ungated = (
        "import openai\n"
        "@app.post('/hook')\n"
        "def h():\n"
        "    d = request.json\n"
        "    c = customers.find(d['id'])\n"
        "    resend.send(c)\n"
    )
    files = {f"src/agent_{i}.py": ungated for i in range(30)}
    res = analyze_lethal_trifecta(_ctx(files))
    gaps = [f for f in res.findings if f.id == "lt-trifecta-violation"]
    assert len(gaps) == 25
    assert res.file_count == 30
    assert 0.0 <= res.score <= 100.0


# ─── security_controls.py line numbers, marshal/dill AST, 2-step timeout ─


def test_security_controls_line_numbers_deserialization_and_timeout():
    from scanner.analyzers.security_controls import analyze_security_controls

    res = analyze_security_controls(_ctx({
        "cfg.py": (
            "# line 1\n"
            "# line 2\n"
            'API_KEY = "sk-abcdef1234567890"\n'
        ),
        "loader.py": (
            "import marshal\n"
            "# dill.loads(comment_only)\n"
            "def parse(b):\n"
            "    return marshal.loads(b)\n"
        ),
        "http_bad.py": (
            "def call(url):\n"
            "    return requests.get(url)\n"
        ),
        "http_good.py": (
            "def call_ok(url):\n"
            "    return requests.post(url, timeout=10)\n"
        ),
    }))
    secret = next(f for f in res.findings if f.id.startswith("sec-hardcoded-"))
    assert secret.line_number == 3
    assert secret.matched_pattern != ""
    assert secret.article_paragraphs == ["Art. 15(3)"]

    deser = next(f for f in res.findings if f.id.startswith("sec-unsafe-deserialization-"))
    assert deser.line_number == 4
    assert deser.file_path == "loader.py"

    timeout_gaps = [f for f in res.findings if f.id.startswith("sec-http-timeout-missing-")]
    assert len(timeout_gaps) == 1
    assert timeout_gaps[0].file_path == "http_bad.py"
    assert timeout_gaps[0].line_number == 2


def test_security_controls_ignore_synthetic_benchmark_examples():
    from pathlib import Path

    from scanner.analyzers.security_controls import analyze_security_controls

    benchmark = Path(__file__).parent.parent / "scanner" / "benchmark.py"
    source = benchmark.read_text(encoding="utf-8")
    res = analyze_security_controls(_ctx({"scanner/benchmark.py": source}))
    assert not any(
        f.id.startswith("sec-hardcoded-") or f.id.startswith("sec-http-timeout-missing-")
        for f in res.findings
    )


# ─── ai_frameworks.py, adversarial_robustness.py, regulatory_perimeter.py ─


def test_ai_frameworks_populates_line_number_and_matched_pattern():
    from scanner.analyzers.ai_frameworks import analyze_ai_frameworks

    res = analyze_ai_frameworks(_ctx({
        "model.py": "# header\nimport torch\n",
    }))
    f = next(f for f in res.findings if f.id == "af-detect-pytorch")
    assert f.line_number == 2
    assert f.matched_pattern == "ast.Import:torch"


def test_adversarial_robustness_uses_canonical_sc_kb_ids():
    from scanner.analyzers.adversarial_robustness import analyze_adversarial_robustness

    # An HTTP endpoint makes the endpoint-only checks (input validation: sc-1) apply.
    res = analyze_adversarial_robustness(_ctx({
        "llm.py": (
            "import openai\nfrom fastapi import FastAPI\napp = FastAPI()\nclient = openai.OpenAI()\n\n"
            "@app.post('/ask')\ndef ask(q: str):\n    return client.responses.create(model='m', input=q)\n"
        ),
    }))
    all_qids = [qid for f in res.findings for qid in f.kb_question_ids]
    assert not any(q.startswith("sec-") for q in all_qids)
    assert "sc-3" in all_qids
    assert "sc-1" in all_qids


def test_regulatory_perimeter_role_mismatch_keys_on_content_not_bare_manifest():
    from scanner.analyzers.regulatory_perimeter import analyze_regulatory_perimeter

    # Plain pyproject.toml without [project.scripts] + deployer -> NO mismatch!
    no_mismatch = analyze_regulatory_perimeter(_ctx(
        {"pyproject.toml": '[project]\nname = "internal-app"\n'},
        extracted_role="deployer",
    ))
    assert "rp-role-mismatch" not in {f.id for f in no_mismatch.findings}

    # CLI entry point + deployer -> mismatch gap!
    mismatch = analyze_regulatory_perimeter(_ctx(
        {"pyproject.toml": '[project.scripts]\nmycli = "pkg:main"\n'},
        extracted_role="deployer",
    ))
    assert "rp-role-mismatch" in {f.id for f in mismatch.findings}


def test_all_analyzer_connected_categories_exist_in_registry():
    ctx = _ctx({})
    for aid, fn in ANALYZER_REGISTRY.items():
        res = fn(ctx)
        for target in res.connected_categories:
            assert target in ANALYZER_REGISTRY, (
                f"Analyzer {aid!r} has dangling connected_category {target!r}"
            )


# ─── analyzers/__init__.py fail-soft, coverage-ratio, disagreement-safe ──


def test_execute_analyzer_fail_soft_isolation(monkeypatch):
    def _boom(_ctx):
        raise RuntimeError("hostile input")

    monkeypatch.setitem(ANALYZER_REGISTRY, "test_suite", _boom)
    res = _execute_analyzer("test_suite", _ctx({}))
    assert res.analyzer_id == "test_suite"
    assert res.findings == []
    assert res.metadata["status"] == "error"
    assert "hostile input" in res.metadata["error"]


def test_compute_dimension_scores_coverage_ratio_and_skips_neutral_only():
    findings = [
        Finding(
            id="neutral-only", category="c", title="t", description="d",
            file_path="a.py", confidence=0.7, compliance_impact="neutral",
            compliance_dimensions=["infra_mlops"],
        ),
        Finding(
            id="pos-only", category="c", title="t", description="d",
            file_path="a.py", confidence=0.8, compliance_impact="positive",
            compliance_dimensions=["security"],
        ),
        Finding(
            id="gap-only", category="c", title="t", description="d",
            file_path="a.py", confidence=0.9, compliance_impact="gap",
            compliance_dimensions=["data_gov"],
        ),
    ]
    scores = compute_dimension_scores(findings)
    assert "infra_mlops" not in scores
    assert scores["security"] == 100.0
    assert scores["data_gov"] == 0.0


def test_collect_pre_filled_answers_disagreement_resolves_to_partial():
    findings = [
        Finding(
            id="f1", category="c1", title="t", description="d",
            file_path="a.py", confidence=0.8, compliance_impact="positive",
            kb_question_ids=["ho-1"], suggested_answer="yes",
        ),
        Finding(
            id="f2", category="c2", title="t", description="d",
            file_path="a.py", confidence=0.8, compliance_impact="gap",
            kb_question_ids=["ho-1"], suggested_answer="no",
        ),
    ]
    answers = collect_pre_filled_answers(findings)
    assert answers["ho-1"] == "partial"


# ─── scanner/benchmark.py ────────────────────────────────────────────────


def test_scanner_benchmark_is_deterministic_with_perfect_precision_and_recall():
    r1 = run_scanner_benchmark()
    r2 = run_scanner_benchmark()
    assert r1.corpus_size >= 25
    assert r1.inputs_digest == r2.inputs_digest
    assert r1.reproducible is True
    assert r1.false_positives == 0, f"Benchmark FPs: {r1.per_analyzer}"
    assert r1.false_negatives == 0, f"Benchmark FNs: {r1.per_analyzer}"
    assert r1.precision == 1.0
    assert r1.recall == 1.0
    assert r1.f1 == 1.0
