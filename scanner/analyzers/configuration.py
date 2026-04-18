"""Configuration Analyzer — Docker, K8s, CI/CD, env management, reproducibility.

Maps to: quality_management, infra_mlops
"""

from __future__ import annotations

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    any_file_contains,
    has_file,
    search_files,
)


def analyze_configuration(ctx: AnalyzerContext) -> AnalyzerResult:
    findings: list[Finding] = []
    evidence_files: set[str] = set()

    # 1. Containerization
    dockerfiles = has_file(ctx, r"Dockerfile|dockerfile")
    compose_files = has_file(ctx, r"docker-compose|compose\.ya?ml")
    if dockerfiles:
        evidence_files.add(dockerfiles[0])
        content = ctx.files.get(dockerfiles[0], "")
        multi_stage = "FROM" in content and content.count("FROM") >= 2
        findings.append(Finding(
            id="cfg-docker", category="configuration",
            title=f"Dockerfile detected{' (multi-stage)' if multi_stage else ''}",
            description="Containerization with Docker enables reproducible deployments.",
            file_path=dockerfiles[0], confidence=0.9,
            compliance_impact="positive",
            compliance_dimensions=["infra_mlops", "quality_management"],
            kb_question_ids=["im-1"], suggested_answer="partial",
        ))
    if compose_files:
        findings.append(Finding(
            id="cfg-compose", category="configuration",
            title="Docker Compose detected",
            description="Multi-service orchestration with Docker Compose.",
            file_path=compose_files[0], confidence=0.85,
            compliance_impact="positive",
            compliance_dimensions=["infra_mlops"],
        ))

    # 2. Orchestration
    k8s_files = has_file(ctx, r"\.ya?ml$")
    k8s_content = [(p, ctx.files.get(p, "")) for p in k8s_files if "kind:" in ctx.files.get(p, "") and "apiVersion:" in ctx.files.get(p, "")]
    has_file(ctx, r"Chart\.ya?ml|values\.ya?ml|templates/")
    terraform_files = has_file(ctx, r"\.tf$|terraform")
    if k8s_content:
        findings.append(Finding(
            id="cfg-k8s", category="configuration",
            title="Kubernetes manifests detected",
            description="K8s deployment configuration found.",
            file_path=k8s_content[0][0], confidence=0.9,
            compliance_impact="positive",
            compliance_dimensions=["infra_mlops"],
            kb_question_ids=["im-1"], suggested_answer="yes",
        ))
    if terraform_files:
        findings.append(Finding(
            id="cfg-terraform", category="configuration",
            title="Terraform IaC detected",
            description="Infrastructure as Code with Terraform.",
            file_path=terraform_files[0], confidence=0.9,
            compliance_impact="positive",
            compliance_dimensions=["infra_mlops"],
        ))

    # 3. CI/CD pipeline
    ci_files = any_file_contains(ctx, [
        ".github/workflows", "gitlab-ci.yml", ".gitlab-ci.yml",
        "Jenkinsfile", ".circleci/config.yml", "bitbucket-pipelines.yml",
    ])
    gh_workflow_files = has_file(ctx, r"\.github/workflows/.*\.ya?ml$")
    if ci_files or gh_workflow_files:
        ci_path = ci_files[0] if ci_files else gh_workflow_files[0]
        evidence_files.add(ci_path)
        findings.append(Finding(
            id="cfg-cicd", category="configuration",
            title="CI/CD pipeline configured",
            description=f"Continuous integration/deployment config: {ci_path}.",
            file_path=ci_path, confidence=0.9,
            compliance_impact="positive",
            compliance_dimensions=["quality_management", "infra_mlops"],
            kb_question_ids=["im-3"], suggested_answer="yes",
        ))

    # 4. Environment management
    env_example = any_file_contains(ctx, [".env.example", ".env.sample", ".env.template"])
    config_schema = search_files(ctx, r"class\s+\w*Settings\w*\(BaseSettings\)|pydantic_settings|environ\.get")
    if env_example:
        findings.append(Finding(
            id="cfg-env-example", category="configuration",
            title="Environment template (.env.example) found",
            description="Environment variable documentation exists for reproducibility.",
            file_path=env_example[0], confidence=0.85,
            compliance_impact="positive",
            compliance_dimensions=["quality_management"],
        ))
    if config_schema:
        findings.append(Finding(
            id="cfg-config-schema", category="configuration",
            title="Configuration schema validation",
            description="Typed configuration with validation (pydantic-settings) detected.",
            file_path=config_schema[0][0], confidence=0.85,
            compliance_impact="positive",
            compliance_dimensions=["quality_management"],
            evidence_snippet=config_schema[0][1],
        ))

    # 5. Reproducibility
    lock_files = any_file_contains(ctx, [
        "poetry.lock", "Pipfile.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    ])
    search_files(ctx, r"--hash=sha256:")
    seed_matches = search_files(ctx, r"random.*seed|np\.random\.seed|torch\.manual_seed|set_seed|SEED\s*=")
    if lock_files:
        findings.append(Finding(
            id="cfg-lockfile", category="configuration",
            title=f"Dependency lock file: {lock_files[0]}",
            description="Lock file ensures reproducible dependency installation.",
            file_path=lock_files[0], confidence=0.85,
            compliance_impact="positive",
            compliance_dimensions=["quality_management"],
        ))
    if seed_matches:
        findings.append(Finding(
            id="cfg-seed", category="configuration",
            title="Random seed setting for reproducibility",
            description="Code sets random seeds for reproducible results.",
            file_path=seed_matches[0][0], confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["quality_management"],
            evidence_snippet=seed_matches[0][1],
        ))

    # 6. Model serving
    serving_matches = search_files(ctx, r"uvicorn|gunicorn|flask.*run|triton|torchserve|bentoml|seldon")
    health_matches = search_files(ctx, r"/health|healthcheck|health_check|readiness.*probe|liveness.*probe")
    if serving_matches:
        findings.append(Finding(
            id="cfg-serving", category="configuration",
            title="Model/API serving framework detected",
            description="Application server for model serving configured.",
            file_path=serving_matches[0][0], confidence=0.85,
            compliance_impact="positive",
            compliance_dimensions=["infra_mlops"],
            evidence_snippet=serving_matches[0][1],
        ))
    if health_matches:
        findings.append(Finding(
            id="cfg-healthcheck", category="configuration",
            title="Health check endpoint configured",
            description="Readiness/liveness probe for deployment monitoring.",
            file_path=health_matches[0][0], confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["infra_mlops"],
            evidence_snippet=health_matches[0][1],
        ))

    # 7. Canary/A/B testing
    canary_matches = search_files(ctx, r"feature.*flag|canary|a/b.*test|gradual.*rollout|experiment.*config|unleash|launchdarkly")
    if canary_matches:
        findings.append(Finding(
            id="cfg-canary", category="configuration",
            title="Feature flags / canary deployment detected",
            description="Gradual rollout or A/B testing infrastructure found.",
            file_path=canary_matches[0][0], confidence=0.75,
            compliance_impact="positive",
            compliance_dimensions=["quality_management"],
            evidence_snippet=canary_matches[0][1],
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
        analyzer_id="configuration", label="Configuration",
        findings=findings, score=score,
        file_count=len(evidence_files),
        graph_node_type="config", graph_icon="⚙️",
        connected_categories=["security_controls", "documentation", "ai_frameworks"],
    )
