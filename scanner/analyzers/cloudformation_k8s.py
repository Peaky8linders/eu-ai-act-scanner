"""CloudFormation + Kubernetes IaC analyzer.

CFN detected by AWSTemplateFormatVersion; K8s by apiVersion + kind.
Uses yaml.safe_load from the stdlib-adjacent PyYAML dependency (already
indirectly required via FastAPI's deps).

Covers:
- CFN: CloudTrail presence, S3 ObjectLockEnabled, risk-tier tag.
- K8s: NetworkPolicy presence, SecurityContext runAsNonRoot, readiness/liveness probes,
       ResourceQuota / LimitRange, risk-tier label.
"""
from __future__ import annotations

import yaml

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
)


class _CfnSafeLoader(yaml.SafeLoader):
    """SafeLoader subclass that tolerates CloudFormation intrinsic tags.

    CFN templates use tags like `!Ref`, `!Sub`, `!GetAtt`, `!Join` that
    the standard SafeLoader rejects. We register a multi-constructor so
    every `!Foo` tag becomes a plain string/dict we can ignore — we only
    care about the resource structure, not the intrinsic values.
    """


def _cfn_tag_constructor(loader, tag_suffix, node):  # noqa: ARG001
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return None


_CfnSafeLoader.add_multi_constructor("!", _cfn_tag_constructor)


def _parse_yaml_documents(content: str) -> list[dict]:
    """Parse multi-document YAML safely; return list of dict documents.

    Uses a CFN-tolerant SafeLoader so templates containing intrinsic
    function tags (!Ref, !Sub, etc.) still parse. K8s manifests do not
    use custom tags, so this is strictly additive for that case.
    """
    try:
        docs = list(yaml.load_all(content, Loader=_CfnSafeLoader))
    except yaml.YAMLError:
        return []
    return [d for d in docs if isinstance(d, dict)]


def _is_cfn(doc: dict) -> bool:
    return "AWSTemplateFormatVersion" in doc or "Resources" in doc


def _is_k8s(doc: dict) -> bool:
    return "apiVersion" in doc and "kind" in doc


def _finding(
    *, id: str, title: str, description: str, file_path: str, confidence: float,
    impact: str, dims: list[str], articles: list[str], artifact: str,
) -> Finding:
    return Finding(
        id=id, category="cloudformation_k8s", title=title,
        description=description, file_path=file_path, confidence=confidence,
        compliance_impact=impact, compliance_dimensions=dims,
        article_paragraphs=articles,
        iac_artifact_type=artifact,  # "cloudformation" or "kubernetes"
    )


def _analyze_cfn(docs: list[dict], path: str) -> list[Finding]:
    findings: list[Finding] = []
    resources = docs[0].get("Resources", {}) if docs else {}
    types = {r.get("Type") for r in resources.values() if isinstance(r, dict)}
    ai_types = {t for t in types
                if t and (t.startswith("AWS::SageMaker::") or t.startswith("AWS::Bedrock::"))}
    has_cloudtrail = "AWS::CloudTrail::Trail" in types
    object_locked_bucket = any(
        r.get("Type") == "AWS::S3::Bucket"
        and isinstance(r.get("Properties"), dict)
        and r["Properties"].get("ObjectLockEnabled") is True
        for r in resources.values() if isinstance(r, dict)
    )
    has_risk_tier_tag = False
    for r in resources.values():
        if not isinstance(r, dict):
            continue
        tags = r.get("Properties", {}).get("Tags", [])
        if not isinstance(tags, list):
            continue
        for tag in tags:
            if isinstance(tag, dict) and tag.get("Key") == "ai-act-risk-tier":
                has_risk_tier_tag = True

    if has_cloudtrail:
        findings.append(_finding(
            id="cfn-cloudtrail-present", title="CloudTrail Trail declared",
            description="AWS::CloudTrail::Trail resource present — Art. 12 logging.",
            file_path=path, confidence=1.0, impact="positive",
            dims=["logging"], articles=["Art. 12(1)"],
            artifact="cloudformation",
        ))
    elif ai_types:
        findings.append(_finding(
            id="cfn-cloudtrail-missing", title="CloudTrail not declared",
            description="AI resources present but no AWS::CloudTrail::Trail — Art. 12.",
            file_path=path, confidence=1.0, impact="gap",
            dims=["logging"], articles=["Art. 12(1)"],
            artifact="cloudformation",
        ))
    if object_locked_bucket:
        findings.append(_finding(
            id="cfn-s3-object-lock", title="S3 Bucket with ObjectLockEnabled",
            description="Tamper-proof bucket for model documentation.",
            file_path=path, confidence=1.0, impact="positive",
            dims=["tech_docs"], articles=["Art. 11(1)"],
            artifact="cloudformation",
        ))
    if has_risk_tier_tag:
        findings.append(_finding(
            id="cfn-risk-tier-tag", title="ai-act-risk-tier tag present",
            description="Resource tagged for Art. 49 inventory.",
            file_path=path, confidence=1.0, impact="positive",
            dims=["risk_mgmt"], articles=["Art. 49(1)"],
            artifact="cloudformation",
        ))
    elif ai_types:
        findings.append(_finding(
            id="cfn-risk-tier-missing", title="ai-act-risk-tier tag missing",
            description="AI resources lack risk-tier tag — blocks Art. 49 inventory.",
            file_path=path, confidence=0.8, impact="gap",
            dims=["risk_mgmt"], articles=["Art. 49(1)"],
            artifact="cloudformation",
        ))
    return findings


def _analyze_k8s_docs(docs: list[dict], path: str) -> list[Finding]:
    findings: list[Finding] = []
    has_network_policy = any(d.get("kind") == "NetworkPolicy" for d in docs)
    has_resource_quota = any(d.get("kind") in ("ResourceQuota", "LimitRange") for d in docs)
    deployments = [d for d in docs if d.get("kind") in ("Deployment", "StatefulSet", "DaemonSet")]

    # Resource-level checks on each Deployment
    for d in deployments:
        meta = d.get("metadata") or {}
        labels = meta.get("labels") or {}
        name = meta.get("name", "unknown")
        spec = (d.get("spec") or {}).get("template", {}).get("spec", {})
        sec_ctx = spec.get("securityContext", {}) or {}
        containers = spec.get("containers", []) or []

        if labels.get("ai-act.eu/risk-tier"):
            findings.append(_finding(
                id=f"k8s-risk-tier-label-{name}",
                title=f"ai-act.eu/risk-tier label on {name}",
                description="Deployment tagged for Art. 49 inventory.",
                file_path=path, confidence=1.0, impact="positive",
                dims=["risk_mgmt"], articles=["Art. 49(1)"],
                artifact="kubernetes",
            ))

        if sec_ctx.get("runAsNonRoot") is True:
            findings.append(_finding(
                id=f"k8s-non-root-{name}",
                title=f"runAsNonRoot on {name}",
                description="Pod runs as non-root — Art. 15 cybersecurity baseline.",
                file_path=path, confidence=1.0, impact="positive",
                dims=["security"], articles=["Art. 15(1)"],
                artifact="kubernetes",
            ))
        else:
            findings.append(_finding(
                id=f"k8s-security-context-non-root-missing-{name}",
                title=f"runAsNonRoot not set on {name}",
                description="Pod may run as root — Art. 15(1) cybersecurity risk.",
                file_path=path, confidence=0.7, impact="gap",
                dims=["security"], articles=["Art. 15(1)"],
                artifact="kubernetes",
            ))

        probe_present = any(
            c.get("livenessProbe") and c.get("readinessProbe") for c in containers
        )
        if probe_present:
            findings.append(_finding(
                id=f"k8s-probes-{name}",
                title=f"Liveness + readiness probes on {name}",
                description="Health probes improve Art. 15 robustness / availability.",
                file_path=path, confidence=1.0, impact="positive",
                dims=["quality_management"], articles=["Art. 15(4)"],
                artifact="kubernetes",
            ))
        else:
            findings.append(_finding(
                id=f"k8s-probes-missing-{name}",
                title=f"Missing liveness/readiness probes on {name}",
                description="Inference pod lacks health probes — Art. 15 robustness gap.",
                file_path=path, confidence=0.7, impact="gap",
                dims=["quality_management"], articles=["Art. 15(4)"],
                artifact="kubernetes",
            ))

    if deployments and has_network_policy:
        findings.append(_finding(
            id="k8s-networkpolicy-present", title="NetworkPolicy defined",
            description="Namespace-level egress/ingress control — Art. 15 security.",
            file_path=path, confidence=1.0, impact="positive",
            dims=["security"], articles=["Art. 15(1)"],
            artifact="kubernetes",
        ))
    elif deployments and not has_network_policy:
        findings.append(_finding(
            id="k8s-networkpolicy-missing", title="No NetworkPolicy defined",
            description="Unrestricted pod networking — Art. 15 cybersecurity gap.",
            file_path=path, confidence=0.8, impact="gap",
            dims=["security"], articles=["Art. 15(1)"],
            artifact="kubernetes",
        ))
    if deployments and has_resource_quota:
        findings.append(_finding(
            id="k8s-resource-quota-present", title="ResourceQuota / LimitRange defined",
            description="Namespace resource limits enforce operational hygiene.",
            file_path=path, confidence=1.0, impact="positive",
            dims=["quality_management"], articles=["Art. 15(4)"],
            artifact="kubernetes",
        ))
    return findings


def analyze_cloudformation_k8s(ctx: AnalyzerContext) -> AnalyzerResult:
    findings: list[Finding] = []
    yaml_files = [
        (p, c) for p, c in ctx.files.items()
        if p.endswith((".yml", ".yaml", ".json"))
    ]
    file_count = 0
    for path, content in yaml_files:
        docs = _parse_yaml_documents(content) if not path.endswith(".json") else []
        if not docs:
            continue
        if any(_is_cfn(d) for d in docs):
            findings.extend(_analyze_cfn(docs, path))
            file_count += 1
        if any(_is_k8s(d) for d in docs):
            findings.extend(_analyze_k8s_docs([d for d in docs if _is_k8s(d)], path))
            file_count += 1
    return AnalyzerResult(
        analyzer_id="cloudformation_k8s",
        label="CloudFormation + Kubernetes IaC",
        findings=findings, score=0.0, file_count=file_count,
        graph_node_type="infrastructure", graph_icon="yaml",
    )
