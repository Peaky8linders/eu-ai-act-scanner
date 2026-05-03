"""Cloud Deployment Analyzer — detect AWS / GCP / Azure deployment signals.

Detects cloud platform usage across IaC files, imports, and config files.
Maps to: infrastructure_security (infra_mlops), governance (quality_management),
         data residency (data_gov).

Uses existing KB dimensions only (no kb.py changes):
  - infra_mlops  : cloud infra + IaC coverage
  - security     : IAM / access controls
  - data_gov     : region / residency
  - quality_management : multi-cloud portability / governance posture

Metadata exposes ``clouds_detected: list[str]`` for downstream UI pivoting.
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
    search_files,
)

logger = structlog.get_logger(__name__)

# ─── AWS signals ─────────────────────────────────────────────────────────────

_AWS_IMPORT_PREFIXES = ("boto3", "aws_cdk", "aws_lambda_powertools")
_AWS_FILES = [
    r"serverless\.yml$",
    r"serverless\.yaml$",
    r"samconfig\.toml$",
    r"Dockerfile\.lambda$",
    r"ecs-task-definition\.json$",
]
_AWS_TF_RESOURCE = re.compile(r'resource\s+"aws_', re.IGNORECASE)
_AWS_CFN_MARKER = re.compile(r"AWSTemplateFormatVersion|AWS::", re.IGNORECASE)
_AWS_IAM_PATTERN = re.compile(
    r'resource\s+"aws_iam_|"Action"\s*:\s*\[|"Effect"\s*:\s*"Allow"',
    re.IGNORECASE,
)

# ─── GCP signals ─────────────────────────────────────────────────────────────

_GCP_IMPORT_PREFIXES = ("google.cloud", "google_cloud", "firebase_admin", "vertexai")
_GCP_FILES = [
    r"app\.yaml$",
    r"cloudbuild\.ya?ml$",
    r"Dockerfile\.cloudrun$",
]
_GCP_TF_RESOURCE = re.compile(r'resource\s+"google_', re.IGNORECASE)
_GCP_VERTEX_IMPORT = re.compile(
    r"from\s+google\.cloud\s+import\s+aiplatform|import\s+vertexai|"
    r"from\s+vertexai|google-cloud-aiplatform",
    re.IGNORECASE,
)
_GCP_FIREBASE_IMPORT = re.compile(r"import\s+firebase_admin|from\s+firebase_admin", re.IGNORECASE)

# ─── Azure signals ────────────────────────────────────────────────────────────

_AZURE_IMPORT_PREFIXES = ("azure",)
_AZURE_FILES = [
    r"azuredeploy\.json$",
    r"azure-pipelines\.ya?ml$",
    r"\.bicep$",
    r"function\.json$",
]
_AZURE_TF_RESOURCE = re.compile(r'resource\s+"azurerm_', re.IGNORECASE)
_AZURE_IAM_PATTERN = re.compile(
    r'resource\s+"azurerm_role_assignment|azurerm_key_vault',
    re.IGNORECASE,
)

# ─── Docker / container signals (multi-cloud / on-prem) ───────────────────

_DOCKER_FILES = [r"docker-compose\.ya?ml$", r"^Dockerfile$", r"/Dockerfile$"]


def _first_match(ctx: AnalyzerContext, pattern: str) -> tuple[str, str] | None:
    """Return (file_path, matched_line) for the first file matching pattern."""
    results = search_files(ctx, pattern)
    return results[0] if results else None


def _snippet(path: str, extra: str = "") -> str:
    """Build a short evidence snippet from path + optional context."""
    combined = f"{path}: {extra}" if extra else path
    return combined[:200]


def analyze_cloud_deployment(ctx: AnalyzerContext) -> AnalyzerResult:  # noqa: C901
    findings: list[Finding] = []
    clouds_detected: list[str] = []
    has_iac: dict[str, bool] = {"aws": False, "gcp": False, "azure": False}
    has_iam: dict[str, bool] = {"aws": False, "azure": False}

    top_modules = get_import_modules(ctx)

    # ─── AWS detection ──────────────────────────────────────────────────
    aws_import_file: str | None = None
    for mod in _AWS_IMPORT_PREFIXES:
        # top-level match (boto3) or prefix match for multi-segment modules
        if mod in top_modules or any(m.startswith(mod.split(".")[0]) for m in top_modules):
            # Find representative file
            hits = search_files(ctx, rf"\b{re.escape(mod.split('.')[0])}\b")
            if hits:
                aws_import_file = hits[0][0]
                snip = hits[0][1]
                findings.append(Finding(
                    id=f"cd-aws-import-{mod.replace('.', '-')}",
                    category="cloud_deployment",
                    title=f"AWS SDK import detected ({mod})",
                    description=f"Python import of '{mod}' found — project interacts with AWS APIs.",
                    file_path=aws_import_file,
                    confidence=0.9,
                    compliance_impact="neutral",
                    compliance_dimensions=["infra_mlops", "supply_chain"],
                    evidence_snippet=_snippet(aws_import_file, snip),
                ))
                break

    # AWS IaC files
    for pat in _AWS_FILES:
        matched = has_file(ctx, pat)
        if matched:
            has_iac["aws"] = True
            slug = pat[:20].replace(r"\.", "").replace("$", "").replace("/", "-")
            findings.append(Finding(
                id=f"cd-aws-iac-{slug}",
                category="cloud_deployment",
                title=f"AWS IaC config file detected ({matched[0].split('/')[-1]})",
                description="AWS-specific infrastructure configuration file found (serverless/SAM/ECS).",
                file_path=matched[0],
                confidence=0.95,
                compliance_impact="positive",
                compliance_dimensions=["infra_mlops", "quality_management"],
                evidence_snippet=_snippet(matched[0]),
            ))
            break

    # AWS Terraform resources
    tf_files = [(p, c) for p, c in ctx.files.items() if p.endswith(".tf")]
    for path, content in tf_files:
        if _AWS_TF_RESOURCE.search(content):
            has_iac["aws"] = True
            line = _AWS_TF_RESOURCE.search(content)
            snip = line.group(0)[:80] if line else ""
            findings.append(Finding(
                id="cd-aws-tf-resource",
                category="cloud_deployment",
                title="AWS Terraform resources detected",
                description="Terraform HCL with aws_* resource blocks found — AWS infra-as-code.",
                file_path=path,
                confidence=0.95,
                compliance_impact="positive",
                compliance_dimensions=["infra_mlops", "quality_management"],
                evidence_snippet=_snippet(path, snip),
            ))
            if _AWS_IAM_PATTERN.search(content):
                has_iam["aws"] = True
            break

    # AWS CloudFormation
    for path, content in ctx.files.items():
        if path.endswith((".yml", ".yaml", ".json")) and _AWS_CFN_MARKER.search(content):
            has_iac["aws"] = True
            findings.append(Finding(
                id="cd-aws-cfn",
                category="cloud_deployment",
                title="AWS CloudFormation template detected",
                description="CloudFormation template with AWS:: resources found.",
                file_path=path,
                confidence=0.9,
                compliance_impact="positive",
                compliance_dimensions=["infra_mlops", "quality_management"],
                evidence_snippet=_snippet(path, "AWSTemplateFormatVersion / AWS:: resources"),
            ))
            break

    if aws_import_file or has_iac["aws"]:
        clouds_detected.append("aws")
        # Gap: SDK present but no IaC
        if aws_import_file and not has_iac["aws"]:
            findings.append(Finding(
                id="cd-aws-no-iac",
                category="cloud_deployment",
                title="AWS SDK used but no IaC found",
                description=(
                    "boto3/aws_cdk imports detected but no Terraform/SAM/Serverless/CFN files. "
                    "Undeclared infra is a governance gap — Art. 9 risk management requires "
                    "documented deployment topology."
                ),
                file_path=aws_import_file,
                confidence=0.8,
                compliance_impact="gap",
                compliance_dimensions=["infra_mlops", "quality_management"],
                evidence_snippet=_snippet(aws_import_file, "AWS SDK without IaC"),
            ))
        # Positive: IAM policies present
        if has_iam["aws"]:
            findings.append(Finding(
                id="cd-aws-iam-controls",
                category="cloud_deployment",
                title="AWS IAM access controls in IaC",
                description="aws_iam_* resources or IAM policy documents found in Terraform — access control governance.",
                file_path=tf_files[0][0] if tf_files else "",
                confidence=0.9,
                compliance_impact="positive",
                compliance_dimensions=["security", "infra_mlops"],
                evidence_snippet="aws_iam_* resource block",
            ))

    # ─── GCP detection ──────────────────────────────────────────────────
    gcp_import_file: str | None = None
    for mod_prefix in _GCP_IMPORT_PREFIXES:
        top = mod_prefix.split(".")[0]
        if top in top_modules or any(m == top for m in top_modules):
            hits = search_files(ctx, rf"\b{re.escape(top)}\b")
            if hits:
                gcp_import_file = hits[0][0]
                snip = hits[0][1]
                findings.append(Finding(
                    id=f"cd-gcp-import-{top}",
                    category="cloud_deployment",
                    title=f"GCP SDK import detected ({mod_prefix})",
                    description=f"Python import of '{mod_prefix}' found — project uses Google Cloud APIs.",
                    file_path=gcp_import_file,
                    confidence=0.9,
                    compliance_impact="neutral",
                    compliance_dimensions=["infra_mlops", "supply_chain"],
                    evidence_snippet=_snippet(gcp_import_file, snip),
                ))
                break

    # GCP-specific import patterns (regex for non-top-level)
    if not gcp_import_file:
        hit = _first_match(ctx, r"google\.cloud\.|vertexai\.|firebase_admin\.")
        if hit:
            gcp_import_file = hit[0]
            findings.append(Finding(
                id="cd-gcp-import-regex",
                category="cloud_deployment",
                title="GCP SDK usage detected",
                description="google.cloud / vertexai / firebase_admin usage found.",
                file_path=hit[0],
                confidence=0.85,
                compliance_impact="neutral",
                compliance_dimensions=["infra_mlops", "supply_chain"],
                evidence_snippet=_snippet(hit[0], hit[1]),
            ))

    for pat in _GCP_FILES:
        matched = has_file(ctx, pat)
        if matched:
            has_iac["gcp"] = True
            slug = pat[:20].replace(r"\.", "").replace("$", "")
            findings.append(Finding(
                id=f"cd-gcp-iac-{slug}",
                category="cloud_deployment",
                title=f"GCP IaC config file detected ({matched[0].split('/')[-1]})",
                description="GCP-specific infrastructure file found (App Engine / Cloud Build / Cloud Run).",
                file_path=matched[0],
                confidence=0.95,
                compliance_impact="positive",
                compliance_dimensions=["infra_mlops", "quality_management"],
                evidence_snippet=_snippet(matched[0]),
            ))
            break

    for path, content in tf_files:
        if _GCP_TF_RESOURCE.search(content):
            has_iac["gcp"] = True
            line = _GCP_TF_RESOURCE.search(content)
            snip = line.group(0)[:80] if line else ""
            findings.append(Finding(
                id="cd-gcp-tf-resource",
                category="cloud_deployment",
                title="GCP Terraform resources detected",
                description="Terraform HCL with google_* resource blocks found.",
                file_path=path,
                confidence=0.95,
                compliance_impact="positive",
                compliance_dimensions=["infra_mlops", "quality_management"],
                evidence_snippet=_snippet(path, snip),
            ))
            break

    if gcp_import_file or has_iac["gcp"]:
        clouds_detected.append("gcp")
        if gcp_import_file and not has_iac["gcp"]:
            findings.append(Finding(
                id="cd-gcp-no-iac",
                category="cloud_deployment",
                title="GCP SDK used but no IaC found",
                description=(
                    "google.cloud / vertexai imports detected but no Cloud Build / App Engine / "
                    "Terraform google_* files. Undeclared infra is a governance gap."
                ),
                file_path=gcp_import_file,
                confidence=0.8,
                compliance_impact="gap",
                compliance_dimensions=["infra_mlops", "quality_management"],
                evidence_snippet=_snippet(gcp_import_file, "GCP SDK without IaC"),
            ))

    # ─── Azure detection ─────────────────────────────────────────────────
    azure_import_file: str | None = None
    if "azure" in top_modules or any(m.startswith("azure") for m in top_modules):
        hits = search_files(ctx, r"\bazure\b")
        if hits:
            azure_import_file = hits[0][0]
            snip = hits[0][1]
            findings.append(Finding(
                id="cd-azure-import",
                category="cloud_deployment",
                title="Azure SDK import detected",
                description="Python import of 'azure.*' found — project uses Azure APIs.",
                file_path=azure_import_file,
                confidence=0.9,
                compliance_impact="neutral",
                compliance_dimensions=["infra_mlops", "supply_chain"],
                evidence_snippet=_snippet(azure_import_file, snip),
            ))

    for pat in _AZURE_FILES:
        matched = has_file(ctx, pat)
        if matched:
            has_iac["azure"] = True
            slug = pat[:20].replace(r"\.", "").replace("$", "")
            findings.append(Finding(
                id=f"cd-azure-iac-{slug}",
                category="cloud_deployment",
                title=f"Azure IaC config file detected ({matched[0].split('/')[-1]})",
                description="Azure-specific infrastructure file found (ARM / Bicep / Azure Pipelines).",
                file_path=matched[0],
                confidence=0.95,
                compliance_impact="positive",
                compliance_dimensions=["infra_mlops", "quality_management"],
                evidence_snippet=_snippet(matched[0]),
            ))
            break

    for path, content in tf_files:
        if _AZURE_TF_RESOURCE.search(content):
            has_iac["azure"] = True
            line = _AZURE_TF_RESOURCE.search(content)
            snip = line.group(0)[:80] if line else ""
            findings.append(Finding(
                id="cd-azure-tf-resource",
                category="cloud_deployment",
                title="Azure Terraform resources detected",
                description="Terraform HCL with azurerm_* resource blocks found.",
                file_path=path,
                confidence=0.95,
                compliance_impact="positive",
                compliance_dimensions=["infra_mlops", "quality_management"],
                evidence_snippet=_snippet(path, snip),
            ))
            if _AZURE_IAM_PATTERN.search(content):
                has_iam["azure"] = True
            break

    if azure_import_file or has_iac["azure"]:
        clouds_detected.append("azure")
        if azure_import_file and not has_iac["azure"]:
            findings.append(Finding(
                id="cd-azure-no-iac",
                category="cloud_deployment",
                title="Azure SDK used but no IaC found",
                description=(
                    "azure.* imports detected but no azuredeploy.json / Bicep / "
                    "azurerm_* Terraform files. Undeclared infra is a governance gap."
                ),
                file_path=azure_import_file,
                confidence=0.8,
                compliance_impact="gap",
                compliance_dimensions=["infra_mlops", "quality_management"],
                evidence_snippet=_snippet(azure_import_file, "Azure SDK without IaC"),
            ))
        if has_iam["azure"]:
            findings.append(Finding(
                id="cd-azure-iam-controls",
                category="cloud_deployment",
                title="Azure IAM / Key Vault access controls in IaC",
                description="azurerm_role_assignment / azurerm_key_vault found — access control governance.",
                file_path=tf_files[0][0] if tf_files else "",
                confidence=0.9,
                compliance_impact="positive",
                compliance_dimensions=["security", "infra_mlops"],
                evidence_snippet="azurerm_role_assignment / azurerm_key_vault resource block",
            ))

    # ─── Multi-cloud / container-only ────────────────────────────────────
    if len(clouds_detected) >= 2:
        clouds_detected.append("multi")
        findings.append(Finding(
            id="cd-multi-cloud",
            category="cloud_deployment",
            title=f"Multi-cloud deployment detected ({', '.join(c for c in clouds_detected if c != 'multi')})",
            description=(
                "Multiple cloud platforms detected — good portability posture. "
                "Ensure data residency and cross-cloud IAM policies are documented (Art. 10(5), Art. 15)."
            ),
            file_path="",
            confidence=0.85,
            compliance_impact="positive",
            compliance_dimensions=["quality_management", "infra_mlops", "data_gov"],
            evidence_snippet=f"clouds: {', '.join(c for c in clouds_detected if c != 'multi')}",
        ))
    elif not clouds_detected:
        # Check for container-only (Docker with no cloud target)
        docker_matches = has_file(ctx, r"docker-compose\.ya?ml$") or has_file(ctx, r"(^|/)Dockerfile$")
        if docker_matches:
            path = docker_matches[0] if isinstance(docker_matches, list) else docker_matches
            findings.append(Finding(
                id="cd-container-only",
                category="cloud_deployment",
                title="Container deployment (no cloud-specific IaC)",
                description=(
                    "Docker / docker-compose found but no AWS/GCP/Azure-specific files. "
                    "On-prem or cloud-agnostic deployment — document the target environment."
                ),
                file_path=path,
                confidence=0.7,
                compliance_impact="neutral",
                compliance_dimensions=["infra_mlops", "quality_management"],
                evidence_snippet=_snippet(path, "container without cloud IaC"),
            ))
        else:
            clouds_detected.append("none")
            findings.append(Finding(
                id="cd-no-cloud-signals",
                category="cloud_deployment",
                title="No cloud deployment signals detected",
                description=(
                    "No AWS/GCP/Azure SDK imports or IaC files found. "
                    "If this system is deployed to cloud, add IaC to satisfy Art. 9 deployment documentation."
                ),
                file_path="",
                confidence=0.6,
                compliance_impact="neutral",
                compliance_dimensions=["infra_mlops"],
                evidence_snippet="no cloud SDK imports or IaC files",
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
        score = min(max(round(score, 1), 0.0), 100.0)

    evidence_files = {f.file_path for f in findings if f.file_path}

    logger.debug(
        "cloud_deployment_scan_done",
        clouds=clouds_detected,
        findings=len(findings),
        has_iac=has_iac,
    )

    return AnalyzerResult(
        analyzer_id="cloud_deployment",
        label="Cloud Deployment",
        findings=findings,
        score=score,
        file_count=len(evidence_files),
        graph_node_type="infrastructure",
        graph_icon="☁",
        connected_categories=["terraform", "cloudformation_k8s", "cicd_dockerfile", "configuration"],
        metadata={"clouds_detected": clouds_detected},
    )
