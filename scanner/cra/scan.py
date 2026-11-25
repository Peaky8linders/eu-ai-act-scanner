"""CRA readiness scan: Regulation (EU) 2024/2847, first slice.

Separate from the EU AI Act scan. It shares the file walker and the scope
signals in ``scanner.analyzers.regulatory_perimeter`` and nothing else: no
dimension, no KB question and no score is touched.

What it does:

1. **Scope.** ``assess_cra_scope`` decides whether the repository looks like a
   product with digital elements. If not, the report is empty: no findings and
   never a score.
2. **Two checks**, each with a stable id, a citation and either the file that
   is the evidence or the name of the artefact that is missing:

   * ``cra-cvd-policy``: a coordinated vulnerability disclosure policy with a
     contact for reports (Annex I Part II(5) and (6));
   * ``cra-sbom``: a machine-readable software bill of materials, CycloneDX or
     SPDX (Annex I Part II(1)).

Both duties apply from 11 December 2027; Art. 14 reporting applies from
11 September 2026 (Art. 71(2)). The scan reports evidence. It never says a
product is compliant or certified, and it has no numeric result by design.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from scanner.analyzers._base import AnalyzerContext, is_non_product_path, search_code_files
from scanner.analyzers.regulatory_perimeter import (
    CRA_SIGNAL_LABELS,
    CraScopeAssessment,
    assess_cra_scope,
)
from scanner.cra.clock import FULL_APPLICATION_FROM, REGULATION

CVD_CHECK_ID = "cra-cvd-policy"
SBOM_CHECK_ID = "cra-sbom"

DISCLAIMER = (
    "Evidence found in a repository, not a legal assessment. This report does not say that a "
    "product meets the Cyber Resilience Act, and it gives no score. Use it with counsel."
)

LIVE_NOW = [
    "Reporting applies since 11 September 2026 (CRA Art. 14, Art. 71(2)). A manufacturer notifies "
    "an actively exploited vulnerability in the product, or a severe incident affecting its "
    "security: an early warning within 24 hours of becoming aware and a notification within "
    "72 hours (Art. 14(2)(a)-(b), 14(4)(a)-(b)).",
    "Final report: no later than 14 days after a corrective or mitigating measure is available "
    "for a vulnerability (Art. 14(2)(c)); within one month after the incident notification was "
    "submitted for a severe incident (Art. 14(4)(c)).",
    "Notifications go to the CSIRT designated as coordinator and to ENISA through the single "
    "reporting platform (Art. 14(1), 14(3), 14(7), Art. 16).",
    "Reporting also covers products placed on the market before 11 December 2027 (Art. 69(3)).",
    "A repository scan cannot tell whether a notification is due or was made. For the dates, "
    "run `antifragile-scan --cra-clock <time you became aware> --cra-event <event>`.",
]

APPLIES_LATER = [
    "From 11 December 2027 (CRA Art. 71(2)) the rest of the Regulation applies, including the "
    "vulnerability handling requirements of Annex I Part II that the two checks below look at.",
    "Technical documentation follows Annex VII and is kept for at least 10 years after placing "
    "on the market or for the support period, whichever is longer (Art. 13(13)).",
]

NOT_CHECKED = [
    "Security update delivery and the support period (Annex I Part II(2), (7), (8)).",
    "The Annex VII technical documentation and the EU declaration of conformity.",
    "The essential cybersecurity requirements of Annex I Part I.",
    "Whether a reportable event happened, and any draft or filing of an Art. 14 notification.",
]


class CraFinding(BaseModel):
    """One CRA check result: evidence found, partly found, or missing."""

    id: str
    title: str
    status: Literal["found", "partial", "missing"]
    citations: list[str] = Field(min_length=1)
    # Where the evidence is. Empty when nothing was found.
    file_path: str = ""
    # What to add. Set whenever the status is not "found".
    missing_artifact: str = ""
    detail: str
    # ISO date from which the cited duty applies (CRA Art. 71(2)).
    applies_from: str = FULL_APPLICATION_FROM.isoformat()

    @model_validator(mode="after")
    def _must_point_somewhere(self) -> CraFinding:
        if not all(c.startswith("CRA ") for c in self.citations):
            raise ValueError("every citation names a CRA article or annex")
        if not (self.file_path or self.missing_artifact):
            raise ValueError("a finding needs a file path or a named missing artefact")
        if self.status != "found" and not self.missing_artifact:
            raise ValueError("a partial or missing finding names the missing artefact")
        return self


class CraReport(BaseModel):
    """Result of a CRA scan. Has no score field, by design."""

    regulation: str = REGULATION
    project_name: str = "Project"
    scanner_version: str = ""
    scope: CraScopeAssessment
    findings: list[CraFinding] = Field(default_factory=list)
    live_now: list[str] = Field(default_factory=list)
    applies_later: list[str] = Field(default_factory=list)
    not_checked: list[str] = Field(default_factory=list)
    disclaimer: str = DISCLAIMER


# ─── Check 1: coordinated vulnerability disclosure policy + contact ─────

# Root, `.github/` and `docs/` are where forges and readers look for the policy;
# RFC 9116 puts security.txt under `.well-known/`.
_SECURITY_POLICY_RE = re.compile(r"^(\.github/|docs/)?security\.md$", re.IGNORECASE)
_SECURITY_TXT_RE = re.compile(r"^(\.well-known/)?security\.txt$", re.IGNORECASE)
_CONTACT_RE = re.compile(
    r"[\w.+-]+@[\w-]+(\.[\w-]+)+"  # an e-mail address
    r"|mailto:"
    r"|^\s*contact\s*:\s*\S+"  # security.txt field
    r"|/security/advisories"  # forge private-reporting form
    r"|https?://\S*(security|vulnerab|disclos|bounty|hackerone|bugcrowd)\S*",
    re.IGNORECASE | re.MULTILINE,
)
_CVD_CITATIONS = ["CRA Annex I Part II(5)", "CRA Annex I Part II(6)"]


def check_cvd_policy(ctx: AnalyzerContext) -> CraFinding:
    """A disclosure policy file with a way to report: Annex I Part II(5) and (6)."""
    candidates = sorted(
        path for path in ctx.file_list
        if _SECURITY_POLICY_RE.match(path) or _SECURITY_TXT_RE.match(path)
    )
    title = "Coordinated vulnerability disclosure policy and reporting contact"
    if not candidates:
        return CraFinding(
            id=CVD_CHECK_ID, title=title, status="missing", citations=_CVD_CITATIONS,
            missing_artifact="SECURITY.md or .well-known/security.txt",
            detail=(
                "No disclosure policy file was found at the repository root, in .github/, docs/ "
                "or .well-known/. Annex I Part II asks for a policy on coordinated vulnerability "
                "disclosure and a contact address for reporting vulnerabilities."
            ),
        )
    with_contact = [p for p in candidates if _CONTACT_RE.search(ctx.files.get(p, ""))]
    if with_contact:
        return CraFinding(
            id=CVD_CHECK_ID, title=title, status="found", citations=_CVD_CITATIONS,
            file_path=with_contact[0],
            detail=(
                "A disclosure policy file with a reporting contact is present. The scanner does "
                "not judge whether the policy is followed in practice."
            ),
        )
    return CraFinding(
        id=CVD_CHECK_ID, title=title, status="partial", citations=_CVD_CITATIONS,
        file_path=candidates[0],
        missing_artifact=f"a contact address for vulnerability reports in {candidates[0]}",
        detail=(
            "A disclosure policy file is present, but no e-mail address, reporting link or "
            "`Contact:` field was found in it (Annex I Part II(6))."
        ),
    )


# ─── Check 2: machine-readable SBOM (CycloneDX or SPDX) ─────────────────

_SBOM_NAME_RE = re.compile(
    r"(^|/)(s?bom)([._-][\w.-]*)?\.(json|xml)$"  # bom.json, sbom.xml, bom-1.2.json
    r"|\.cdx\.(json|xml)$"  # CycloneDX file naming convention
    r"|(^|/)[^/]*cyclonedx[^/]*\.(json|xml)$"
    r"|\.spdx(\.(json|ya?ml|rdf|xml))?$"  # SPDX file naming conventions
    r"|(^|/)[^/]*spdx[^/]*\.(json|ya?ml)$",
    re.IGNORECASE,
)
_SBOM_CI_SIGNALS = [
    r"\bcyclonedx[-_](bom|py|npm|gomod|cli)\b|\bcdxgen\b|CycloneDX/gh-",
    r"anchore/sbom-action|\bsyft\b|spdx-sbom-generator",
    r"--format[= ](cyclonedx|spdx)|--output-format[= ](cyclonedx|spdx)",
]
_SBOM_CITATIONS = ["CRA Annex I Part II(1)"]
_SBOM_MISSING = "a CycloneDX or SPDX SBOM file (for example bom.json or sbom.spdx.json)"


def _read_sbom_json(content: str) -> tuple[str, int] | None:
    """``(format, component count)`` for a CycloneDX or SPDX JSON document, else None."""
    try:
        data = json.loads(content)
    except (ValueError, RecursionError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get("bomFormat") == "CycloneDX":
        components = data.get("components")
        return "CycloneDX", len(components) if isinstance(components, list) else 0
    if str(data.get("spdxVersion", "")).startswith("SPDX-"):
        packages = data.get("packages")
        return "SPDX", len(packages) if isinstance(packages, list) else 0
    return None


def check_sbom(ctx: AnalyzerContext) -> CraFinding:
    """A machine-readable SBOM in the repository: Annex I Part II(1)."""
    title = "Machine-readable software bill of materials (SBOM)"
    named = sorted(
        path for path in ctx.file_list
        if _SBOM_NAME_RE.search(path) and not is_non_product_path(path)
    )
    empty: list[tuple[str, str]] = []
    unverified: list[str] = []
    for path in named:
        content = ctx.files.get(path)
        parsed = _read_sbom_json(content) if content is not None and path.lower().endswith(".json") else None
        if parsed is None:
            # A .json file that parses but is not an SBOM is just a file called bom.json.
            if content is None or not path.lower().endswith(".json"):
                unverified.append(path)
            continue
        fmt, count = parsed
        if count:
            return CraFinding(
                id=SBOM_CHECK_ID, title=title, status="found", citations=_SBOM_CITATIONS,
                file_path=path,
                detail=(
                    f"{fmt} SBOM listing {count} component(s). The scanner does not check that "
                    "it matches what is shipped or covers every top-level dependency."
                ),
            )
        empty.append((path, fmt))

    if empty:
        path, fmt = empty[0]
        return CraFinding(
            id=SBOM_CHECK_ID, title=title, status="partial", citations=_SBOM_CITATIONS,
            file_path=path,
            missing_artifact=f"components in {path} (at least the top-level dependencies)",
            detail=f"{fmt} SBOM file found, but it lists no components.",
        )
    if unverified:
        return CraFinding(
            id=SBOM_CHECK_ID, title=title, status="partial", citations=_SBOM_CITATIONS,
            file_path=unverified[0],
            missing_artifact="an SBOM whose format the scanner can read (CycloneDX or SPDX JSON)",
            detail=(
                "A file named like an SBOM is present, but its format was not verified: only "
                "CycloneDX and SPDX JSON under 2 MB are read."
            ),
        )
    for pattern in _SBOM_CI_SIGNALS:
        hits = search_code_files(ctx, pattern)
        if hits:
            path = sorted(hits)[0][0]
            return CraFinding(
                id=SBOM_CHECK_ID, title=title, status="partial", citations=_SBOM_CITATIONS,
                file_path=path,
                missing_artifact=_SBOM_MISSING + " kept with each release",
                detail=(
                    "A build step appears to generate an SBOM, but no SBOM file is in the "
                    "repository, so the scanner cannot read one."
                ),
            )
    return CraFinding(
        id=SBOM_CHECK_ID, title=title, status="missing", citations=_SBOM_CITATIONS,
        missing_artifact=_SBOM_MISSING,
        detail=(
            "No CycloneDX or SPDX file was found. Annex I Part II(1) asks for a software bill "
            "of materials in a commonly used, machine-readable format covering at least the "
            "top-level dependencies."
        ),
    )


# ─── Report ─────────────────────────────────────────────────────────────


def build_cra_report(ctx: AnalyzerContext, project_name: str = "Project") -> CraReport:
    """Scope first; checks only when the repository looks like a product."""
    from scanner import __version__

    scope = assess_cra_scope(ctx)
    if not scope.looks_like_product:
        return CraReport(project_name=project_name, scanner_version=__version__, scope=scope)
    return CraReport(
        project_name=project_name,
        scanner_version=__version__,
        scope=scope,
        findings=[check_cvd_policy(ctx), check_sbom(ctx)],
        live_now=list(LIVE_NOW),
        applies_later=list(APPLIES_LATER),
        not_checked=list(NOT_CHECKED),
    )


def cra_scan(root: Path | str, project_name: str | None = None) -> CraReport:
    """Run the CRA scan on a project directory. Offline and deterministic."""
    from scanner.orchestrator import build_analyzer_context

    root_path = Path(root).resolve()
    ctx = build_analyzer_context(root_path)
    return build_cra_report(ctx, project_name or root_path.name or "Project")


_STATUS_LABEL = {"found": "Evidence found", "partial": "Partly found", "missing": "Not found"}


def format_cra_report(report: CraReport) -> str:
    """Markdown rendering of a CRA report."""
    scope = report.scope
    lines = [
        f"# Cyber Resilience Act check: {report.project_name}",
        "",
        f"{report.regulation}. {report.disclaimer}",
        "",
        "## Scope",
        "",
        f"**Looks like a product with digital elements:** {'yes' if scope.looks_like_product else 'no'} "
        f"({', '.join(scope.citations)})",
        "",
        scope.reasoning,
        "",
    ]
    for signal in scope.signals:
        evidence = f": `{signal.evidence}`" if signal.evidence else ""
        lines.append(f"- {CRA_SIGNAL_LABELS[signal.kind]}: `{signal.path}`{evidence}")
    if scope.signals:
        lines.append("")
    lines.append(scope.caveat)
    if not scope.looks_like_product:
        lines.extend(["", "No CRA checks were run and no result is given for this repository."])
        return "\n".join(lines)

    lines.extend(["", "## Live now: Art. 14 reporting", ""])
    lines.extend(f"- {item}" for item in report.live_now)
    lines.extend(["", "## Applies from 11 December 2027", ""])
    lines.extend(f"- {item}" for item in report.applies_later)
    lines.extend(["", "## Checks", ""])
    for finding in report.findings:
        lines.append(f"### {finding.title} (`{finding.id}`)")
        lines.append("")
        lines.append(f"- **Result:** {_STATUS_LABEL[finding.status]}")
        lines.append(f"- **Citation:** {', '.join(finding.citations)}; applies from {finding.applies_from}")
        if finding.file_path:
            lines.append(f"- **File:** `{finding.file_path}`")
        if finding.missing_artifact:
            lines.append(f"- **Missing:** {finding.missing_artifact}")
        lines.append(f"- {finding.detail}")
        lines.append("")
    lines.extend(["## Not checked by this scan", ""])
    lines.extend(f"- {item}" for item in report.not_checked)
    return "\n".join(lines)
