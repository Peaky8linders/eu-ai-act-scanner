"""Terraform IaC analyzer — EU AI Act controls expressed in HCL.

Detects AWS/Azure/GCP resources related to AI workloads and flags missing
compliance controls: CloudTrail for Art. 12 logging, KMS for Art. 15 security,
S3 Object Lock for Art. 11 tamper-proof docs, EU region for Art. 10(5) residency,
mandatory risk-tier tag for Art. 49 inventory, guardrails for Art. 14/50,
drift monitors for Art. 72 post-market.

No external HCL parser dependency — regex-based detection of resource blocks
matches the zero-dep posture of sibling analyzers.
"""
from __future__ import annotations

import re

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
)

_AI_RESOURCE_RE = re.compile(
    r'resource\s+"(aws_sagemaker_[a-z_]+|aws_bedrock_[a-z_]+|'
    r'google_vertex_ai_[a-z_]+|azurerm_machine_learning_[a-z_]+|'
    r'azurerm_cognitive_[a-z_]+)"\s+"([a-z0-9_]+)"',
    re.MULTILINE,
)
_TF_EXT_RE = re.compile(r"\.tf$", re.IGNORECASE)


def _tf_files(ctx: AnalyzerContext) -> list[tuple[str, str]]:
    return [(p, c) for p, c in ctx.files.items() if _TF_EXT_RE.search(p)]


def _finding(
    *, id: str, title: str, description: str, file_path: str, confidence: float,
    impact: str, dims: list[str], articles: list[str],
    kb_q: list[str] | None = None, answer: str | None = None,
) -> Finding:
    return Finding(
        id=id, category="terraform", title=title, description=description,
        file_path=file_path, confidence=confidence, compliance_impact=impact,
        compliance_dimensions=dims, article_paragraphs=articles,
        iac_artifact_type="terraform",
        kb_question_ids=kb_q or [],
        suggested_answer=answer,
    )


def analyze_terraform(ctx: AnalyzerContext) -> AnalyzerResult:
    findings: list[Finding] = []
    tf_files = _tf_files(ctx)
    if not tf_files:
        return AnalyzerResult(
            analyzer_id="terraform", label="Terraform IaC", findings=[],
            score=0.0, file_count=0,
        )

    # Aggregate content for cross-file-in-this-analyzer reasoning
    ai_resource_files: list[str] = []
    has_cloudtrail = False
    has_kms = False
    has_risk_tier_tag = False
    provider_region_lines: list[tuple[str, str]] = []

    for path, content in tf_files:
        if _AI_RESOURCE_RE.search(content):
            ai_resource_files.append(path)
        if re.search(r'resource\s+"aws_cloudtrail"', content):
            has_cloudtrail = True
            findings.append(_finding(
                id="tf-cloudtrail-present", title="CloudTrail configured",
                description="aws_cloudtrail resource logs API activity for audit.",
                file_path=path, confidence=1.0, impact="positive",
                dims=["logging"], articles=["Art. 12(1)"],
            ))
        if re.search(r'resource\s+"aws_kms_key"|resource\s+"google_kms_crypto_key"|'
                     r'resource\s+"azurerm_key_vault_key"', content):
            has_kms = True
            findings.append(_finding(
                id="tf-kms-present", title="KMS key defined",
                description="Managed encryption key available for AI data/artifacts.",
                file_path=path, confidence=1.0, impact="positive",
                dims=["security"], articles=["Art. 15(1)"],
            ))
        if re.search(r"object_lock_enabled\s*=\s*true", content):
            findings.append(_finding(
                id="tf-s3-object-lock", title="S3 Object Lock enabled",
                description="Tamper-proof retention for model docs / audit artifacts.",
                file_path=path, confidence=1.0, impact="positive",
                dims=["tech_docs", "quality_management"],
                articles=["Art. 11(1)", "Art. 18(1)"],
            ))
        if re.search(r'resource\s+"aws_bedrock_guardrail"|'
                     r'azurerm_cognitive_account.*content_filter|'
                     r'google_vertex_ai_.*safety_setting', content):
            findings.append(_finding(
                id="tf-guardrail-present", title="Content safety guardrail configured",
                description="Bedrock / Vertex / Azure AI content guardrail present.",
                file_path=path, confidence=0.9, impact="positive",
                dims=["human_oversight", "content_transparency"],
                articles=["Art. 14(4)", "Art. 50(2)"],
            ))
        if re.search(r'resource\s+"aws_sagemaker_model_quality_job_definition"|'
                     r'resource\s+"aws_sagemaker_data_quality_job_definition"',
                     content):
            findings.append(_finding(
                id="tf-drift-monitor", title="Model quality / drift monitor configured",
                description="Post-market monitoring job definition present.",
                file_path=path, confidence=1.0, impact="positive",
                dims=["risk_mgmt", "logging"], articles=["Art. 72(1)"],
            ))
        if re.search(r'ai-act-risk-tier\s*=\s*"(high|limited|minimal|prohibited)"',
                     content):
            has_risk_tier_tag = True
            findings.append(_finding(
                id="tf-risk-tier-tag", title="ai-act-risk-tier tag present",
                description="Inventory-phase tagging enables Art. 49 registration.",
                file_path=path, confidence=1.0, impact="positive",
                dims=["risk_mgmt"], articles=["Art. 49(1)"],
            ))
        for m in re.finditer(
            r'provider\s+"aws"\s*{[^}]*?region\s*=\s*"([a-z0-9-]+)"',
            content, re.DOTALL,
        ):
            provider_region_lines.append((path, m.group(1)))

    # Gap findings — only emit when AI resources exist
    if ai_resource_files:
        first_ai_file = ai_resource_files[0]
        if not has_cloudtrail:
            findings.append(_finding(
                id="tf-cloudtrail-missing", title="CloudTrail not configured",
                description="AI resources present but no aws_cloudtrail — "
                            "Art. 12 requires automatic logging.",
                file_path=first_ai_file, confidence=1.0, impact="gap",
                dims=["logging"], articles=["Art. 12(1)"],
            ))
        if not has_kms:
            findings.append(_finding(
                id="tf-kms-missing", title="No KMS / CMK defined",
                description="AI resources present but no customer-managed encryption "
                            "key — Art. 15(1) cybersecurity baseline.",
                file_path=first_ai_file, confidence=0.9, impact="gap",
                dims=["security"], articles=["Art. 15(1)"],
            ))
        if not has_risk_tier_tag:
            findings.append(_finding(
                id="tf-risk-tier-missing", title="ai-act-risk-tier tag missing",
                description="AI resources lack risk-tier tag — blocks Art. 49 inventory.",
                file_path=first_ai_file, confidence=0.8, impact="gap",
                dims=["risk_mgmt"], articles=["Art. 49(1)"],
            ))
        # Region check: any non-EU region next to AI resources → gap
        for path, region in provider_region_lines:
            if not region.startswith("eu-"):
                findings.append(_finding(
                    id=f"tf-region-non-eu-{region}",
                    title=f"Provider region is not EU ({region})",
                    description="Risk-tier high data may fall under Art. 10(5) residency.",
                    file_path=path, confidence=0.7, impact="gap",
                    dims=["data_gov"], articles=["Art. 10(5)"],
                ))
            else:
                findings.append(_finding(
                    id=f"tf-region-eu-{region}",
                    title=f"Provider region is EU ({region})",
                    description="AI workload stays within EU boundary.",
                    file_path=path, confidence=1.0, impact="positive",
                    dims=["data_gov"], articles=["Art. 10(5)"],
                ))

    return AnalyzerResult(
        analyzer_id="terraform", label="Terraform IaC",
        findings=findings,
        score=0.0,  # Aggregate scoring done at compute_dimension_scores level.
        file_count=len(tf_files),
        graph_node_type="infrastructure",
        graph_icon="terraform",
    )
