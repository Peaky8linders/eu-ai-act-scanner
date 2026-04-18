"""CI/CD + Dockerfile IaC analyzer.

- GitHub Actions workflows under .github/workflows/*.yml
- Dockerfile (any filename starting with 'Dockerfile')
- docker-compose*.yml

Checks:
- GH Actions: adversarial tests, fairness step, model card step, explicit permissions.
- Dockerfile: USER non-root, base image pinned by digest.
- Compose: read-only model volume mounts.
"""
from __future__ import annotations

import re

import yaml

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
)


def _finding(
    *, id: str, title: str, description: str, file_path: str, confidence: float,
    impact: str, dims: list[str], articles: list[str], artifact: str,
) -> Finding:
    return Finding(
        id=id, category="cicd_dockerfile", title=title, description=description,
        file_path=file_path, confidence=confidence, compliance_impact=impact,
        compliance_dimensions=dims, article_paragraphs=articles,
        iac_artifact_type=artifact,
    )


def _analyze_gh_actions(path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        doc = yaml.safe_load(content) or {}
    except yaml.YAMLError:
        return []

    # Flatten all step run/name entries
    step_texts: list[str] = []
    for job in (doc.get("jobs") or {}).values():
        for step in (job or {}).get("steps") or []:
            if not isinstance(step, dict):
                continue
            step_texts.append(str(step.get("run", "")))
            step_texts.append(str(step.get("name", "")))
    blob = "\n".join(step_texts).lower()

    if re.search(r"adversarial|red[\s_-]?team|pyrit|prompt[\s_-]?injection", blob):
        findings.append(_finding(
            id="gha-adversarial-present", title="Adversarial test suite in CI",
            description="Workflow runs adversarial / prompt-injection tests.",
            file_path=path, confidence=0.9, impact="positive",
            dims=["quality_management", "security"],
            articles=["Art. 15(4)"], artifact="github_actions",
        ))
    else:
        findings.append(_finding(
            id="gha-adversarial-missing", title="No adversarial test step detected",
            description="Art. 15 robustness recommends adversarial testing in CI.",
            file_path=path, confidence=0.6, impact="gap",
            dims=["quality_management", "security"],
            articles=["Art. 15(4)"], artifact="github_actions",
        ))
    if re.search(r"fairness|bias[\s_-]?audit|aif360|fairlearn|disparate", blob):
        findings.append(_finding(
            id="gha-fairness-present", title="Fairness / bias audit step",
            description="CI runs a fairness / bias audit before deploy.",
            file_path=path, confidence=0.9, impact="positive",
            dims=["data_gov"], articles=["Art. 10(3)"], artifact="github_actions",
        ))
    if re.search(r"model[\s_-]?card|spdx|annex[\s_-]?iv", blob):
        findings.append(_finding(
            id="gha-model-card-present", title="Model card / SPDX step in CI",
            description="Workflow generates model card or Annex IV artifact.",
            file_path=path, confidence=0.9, impact="positive",
            dims=["tech_docs"], articles=["Art. 11(1)"], artifact="github_actions",
        ))
    if doc.get("permissions") or any("permissions" in (j or {})
                                     for j in (doc.get("jobs") or {}).values()):
        findings.append(_finding(
            id="gha-permissions-explicit", title="Explicit permissions: key",
            description="Workflow declares least-privilege permissions explicitly.",
            file_path=path, confidence=1.0, impact="positive",
            dims=["security"], articles=["Art. 15(1)"], artifact="github_actions",
        ))
    else:
        findings.append(_finding(
            id="gha-permissions-missing", title="No explicit permissions: key",
            description="Workflow runs with default token permissions — Art. 15 risk.",
            file_path=path, confidence=0.8, impact="gap",
            dims=["security"], articles=["Art. 15(1)"], artifact="github_actions",
        ))
    return findings


def _analyze_dockerfile(path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()

    user_lines = [ln for ln in lines if ln.strip().startswith("USER ")]
    if user_lines and not any("USER root" in ln or "USER 0" in ln for ln in user_lines):
        findings.append(_finding(
            id="dockerfile-user-nonroot", title="USER directive (non-root)",
            description="Dockerfile sets USER to non-root — Art. 15 cybersecurity.",
            file_path=path, confidence=1.0, impact="positive",
            dims=["security"], articles=["Art. 15(1)"], artifact="dockerfile",
        ))
    else:
        findings.append(_finding(
            id="dockerfile-user-missing", title="Missing USER directive",
            description="Container runs as root — Art. 15 cybersecurity gap.",
            file_path=path, confidence=0.9, impact="gap",
            dims=["security"], articles=["Art. 15(1)"], artifact="dockerfile",
        ))

    from_lines = [ln for ln in lines if ln.strip().upper().startswith("FROM ")]
    if any("@sha256:" in ln for ln in from_lines):
        findings.append(_finding(
            id="dockerfile-pinned-digest", title="Base image pinned by digest",
            description="FROM uses @sha256: digest — supply chain hardened.",
            file_path=path, confidence=1.0, impact="positive",
            dims=["security", "quality_management"],
            articles=["Art. 15(1)"], artifact="dockerfile",
        ))
    elif any(":latest" in ln for ln in from_lines):
        findings.append(_finding(
            id="dockerfile-unpinned-latest", title="Base image uses :latest tag",
            description="Unpinned base image — Art. 15 supply chain risk.",
            file_path=path, confidence=1.0, impact="gap",
            dims=["security", "quality_management"],
            articles=["Art. 15(1)"], artifact="dockerfile",
        ))
    elif from_lines:
        findings.append(_finding(
            id="dockerfile-unpinned-tag", title="Base image not pinned by digest",
            description="FROM uses a tag but not a digest — pin via @sha256:.",
            file_path=path, confidence=0.7, impact="gap",
            dims=["security", "quality_management"],
            articles=["Art. 15(1)"], artifact="dockerfile",
        ))
    return findings


def _analyze_compose(path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    if re.search(r":ro(\s|$|\")", content) or "read_only: true" in content:
        findings.append(_finding(
            id="compose-readonly-volume", title="Read-only volume mount",
            description="docker-compose mounts model/data volumes :ro.",
            file_path=path, confidence=0.9, impact="positive",
            dims=["security"], articles=["Art. 15(1)"], artifact="compose",
        ))
    return findings


def _is_gh_actions_workflow(path: str) -> bool:
    """True if path is a GH Actions workflow (handles any path prefix)."""
    # Normalize backslashes for Windows paths.
    p = path.replace("\\", "/")
    if not p.endswith((".yml", ".yaml")):
        return False
    return ".github/workflows/" in p or p.startswith(".github/workflows/")


def _is_dockerfile(path: str) -> bool:
    """True if the basename starts with 'Dockerfile' (case-insensitive)."""
    basename = path.replace("\\", "/").rsplit("/", 1)[-1]
    return basename.lower().startswith("dockerfile")


_COMPOSE_RE = re.compile(r"(^|/)docker-compose[^/]*\.ya?ml$", re.IGNORECASE)


def _is_compose(path: str) -> bool:
    """True for docker-compose*.yml / .yaml at any depth."""
    return _COMPOSE_RE.search(path.replace("\\", "/")) is not None


def analyze_cicd_dockerfile(ctx: AnalyzerContext) -> AnalyzerResult:
    findings: list[Finding] = []
    file_count = 0
    for path, content in ctx.files.items():
        if _is_gh_actions_workflow(path):
            findings.extend(_analyze_gh_actions(path, content))
            file_count += 1
        elif _is_dockerfile(path):
            findings.extend(_analyze_dockerfile(path, content))
            file_count += 1
        elif _is_compose(path):
            findings.extend(_analyze_compose(path, content))
            file_count += 1
    return AnalyzerResult(
        analyzer_id="cicd_dockerfile",
        label="CI/CD + Dockerfile IaC",
        findings=findings, score=0.0, file_count=file_count,
        graph_node_type="infrastructure", graph_icon="pipeline",
    )
