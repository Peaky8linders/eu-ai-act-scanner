"""Cross-framework projection engine for EU AI Act Scanner.

Projects an EU AI Act `ScanResult` onto major international AI governance,
security, and risk management frameworks:
- NIST AI Risk Management Framework 1.0 (NIST AI RMF)
- ISO/IEC 42001:2023 (Artificial Intelligence Management System - AIMS)
- OWASP Top 10 for LLM Applications (2025)
- OWASP Top 10 for Agentic Applications (ASI01-ASI10)
- GDPR (EU 2016/679)
- MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
- SOC 2 Type II
- CSA AI Controls Matrix (AICM)

Provides 'Satisfy Once, Comply Everywhere' analysis to identify high-leverage
remediation targets that unlock multi-framework compliance simultaneously.
"""

from __future__ import annotations

from collections import defaultdict

from pydantic import BaseModel, Field

from scanner.data.frameworks import (
    CROSSWALK_CATALOGUE_VERSION,
    DIMENSION_CROSSWALK,
    FRAMEWORK_LABELS,
    normalize_framework_id,
)
from scanner.data.incident_corpus import INCIDENT_BY_ID
from scanner.models import ScanResult


class FrameworkControlProjection(BaseModel):
    """Projection for an individual control in a target framework."""

    control_id: str = Field(..., description="Framework control identifier (e.g. 'GV-1.4', '8.5', 'Art. 35').")
    framework_id: str = Field(..., description="Target framework slug.")
    framework_label: str = Field("", description="Human-readable framework name.")
    status: str = Field(..., description="'compliant' | 'partial' | 'gap' | 'unknown'.")
    source_dimensions: list[str] = Field(default_factory=list, description="Contributing EU AI Act KB dimensions.")
    score: float = Field(0.0, description="Highest score among contributing EU AI Act dimensions (0-100).")
    gap_count: int = Field(0, description="Number of contributing dimensions scoring below 60%.")
    # Documented incidents that exploited this control's gap class. Populated
    # for every non-compliant control — a gap that names no incident is a
    # normative claim; one that does is evidence (see scanner.incident_grounding).
    related_incidents: list[str] = Field(
        default_factory=list,
        description="Corpus incident IDs for this gap class (empty when compliant).",
    )


class FrameworkProjectionSummary(BaseModel):
    """Summary metrics for one target framework."""

    framework_id: str
    framework_label: str
    total_controls: int = 0
    compliant: int = 0
    partial: int = 0
    gap: int = 0
    unknown: int = 0
    coverage_pct: float = Field(0.0, description="(compliant + 0.5 * partial) / total_controls * 100")
    top_gaps: list[str] = Field(default_factory=list, description="Top priority gap control IDs.")


class SatisfyOnceLever(BaseModel):
    """A high-leverage compliance remediation closing gaps across multiple frameworks."""

    dimension_id: str
    dimension_label: str
    framework_count: int
    frameworks_helped: list[str]
    controls_closed_count: int
    impact_summary: str
    top_incidents: list[str] = Field(
        default_factory=list, description="Corpus incident IDs for this gap class.",
    )


class CrossFrameworkScanProjection(BaseModel):
    """Complete cross-framework compliance projection from a ScanResult."""

    scan_id: str
    project_name: str
    catalogue_version: str = CROSSWALK_CATALOGUE_VERSION
    total_frameworks_mapped: int = 0
    average_multi_framework_coverage_pct: float = 0.0
    frameworks: list[FrameworkProjectionSummary] = Field(default_factory=list)
    controls: list[FrameworkControlProjection] = Field(default_factory=list)
    satisfy_once_levers: list[SatisfyOnceLever] = Field(default_factory=list)
    evidence_reuse_opportunities: list[str] = Field(default_factory=list)
    # Scored KB dimensions with no crosswalk entry. Non-empty means the
    # coverage % does NOT see those dimensions — read it alongside the scan's
    # own compliance_scores, never as a standalone verdict.
    unmapped_dimensions: list[str] = Field(default_factory=list)

    def format_markdown(self) -> str:
        """Render a readable cross-framework compliance report."""
        lines = [
            f"# Cross-Framework Compliance Projection — {self.project_name}",
            "",
            f"- **Catalogue version**: `{self.catalogue_version}`",
            f"- **Target frameworks mapped**: {self.total_frameworks_mapped}",
            f"- **Average multi-framework readiness**: **{self.average_multi_framework_coverage_pct:.1f}%**",
            "",
            "## Framework Readiness Summary",
            "",
            "| Framework | Coverage | Compliant | Partial | Gap | Top Remediation Gaps |",
            "|---|---|---|---|---|---|",
        ]

        for fw in self.frameworks:
            top_gaps_str = ", ".join(f"`{g}`" for g in fw.top_gaps[:3]) or "None"
            lines.append(
                f"| **{fw.framework_label}** | **{fw.coverage_pct:.1f}%** | "
                f"{fw.compliant} | {fw.partial} | {fw.gap} | {top_gaps_str} |"
            )

        if self.satisfy_once_levers:
            lines += [
                "",
                "## Satisfy Once, Comply Everywhere — Top Levers",
                "",
                "_Remediating these single EU AI Act dimensions unlocks compliance across multiple global standards simultaneously._",
                "",
            ]
            for lever in self.satisfy_once_levers:
                lines.append(
                    f"- **{lever.dimension_label}** (`{lever.dimension_id}`): "
                    f"{lever.impact_summary}"
                )
                titles = [
                    INCIDENT_BY_ID[i].title for i in lever.top_incidents if i in INCIDENT_BY_ID
                ]
                if titles:
                    lines.append(f"  - _Grounding: {titles[0]}_ (incident corpus)")

        grounded_controls = [c for c in self.controls if c.related_incidents]
        if grounded_controls:
            lines += [
                "",
                "## Gap controls, grounded in real-world incidents",
                "",
                "_Each control below is marked gap/partial by the projection and names "
                "the documented incidents (vendored corpus) that exploited its class._",
                "",
                "| Framework | Control | Status | Documented incidents |",
                "|---|---|---|---|",
            ]
            shown = grounded_controls[:15]
            for ctrl in shown:
                incidents = "; ".join(
                    f"{INCIDENT_BY_ID[i].title} (`{i}`)"
                    for i in ctrl.related_incidents
                    if i in INCIDENT_BY_ID
                )
                lines.append(
                    f"| {ctrl.framework_label} | `{ctrl.control_id}` | {ctrl.status} | {incidents} |"
                )
            if len(grounded_controls) > len(shown):
                lines.append(
                    f"| … | _+{len(grounded_controls) - len(shown)} more gap controls_ | | |"
                )

        if self.unmapped_dimensions:
            lines += [
                "",
                "## Unmapped dimensions (not in coverage %)",
                "",
                "_These scored dimensions have no crosswalk entry (catalogue "
                f"`{self.catalogue_version}`) and are invisible to the readiness "
                "percentages above — check the scan's own scores for them._",
                "",
            ]
            for dim_id in self.unmapped_dimensions:
                lines.append(f"- `{dim_id}`")

        if self.evidence_reuse_opportunities:
            lines += [
                "",
                "## Evidence Harmonization & Reuse",
                "",
            ]
            for opp in self.evidence_reuse_opportunities:
                lines.append(f"- {opp}")

        return "\n".join(lines)


def _band(score: float) -> str:
    """Classify dimension score into compliance band."""
    if score >= 60.0:
        return "compliant"
    if score >= 30.0:
        return "partial"
    return "gap"


def project_scan_to_frameworks(
    scan: ScanResult,
    target_framework_ids: list[str] | None = None,
) -> CrossFrameworkScanProjection:
    """Project a ScanResult onto cross-framework controls and standards.

    Args:
        scan: The ScanResult produced by `scan_project`.
        target_framework_ids: Optional list of framework ids to restrict projection to.

    Returns:
        CrossFrameworkScanProjection with per-framework readiness and control mappings.
    """
    from scanner.kb import DIMENSIONS

    bucket: dict[tuple[str, str], FrameworkControlProjection] = {}
    unmapped = sorted(
        dim_id for dim_id in scan.compliance_scores
        if dim_id not in DIMENSION_CROSSWALK
    )

    wanted = {normalize_framework_id(f) for f in target_framework_ids} if target_framework_ids else None

    for dim_id, score in scan.compliance_scores.items():
        crosswalk = DIMENSION_CROSSWALK.get(dim_id)
        if not crosswalk:
            continue

        dim_band = _band(score)
        for raw_fw_id, control_ids in crosswalk.items():
            fw_id = normalize_framework_id(raw_fw_id)
            if wanted and fw_id not in wanted:
                continue

            for ctrl_id in control_ids:
                key = (fw_id, ctrl_id)
                existing = bucket.get(key)
                if existing is None:
                    bucket[key] = FrameworkControlProjection(
                        control_id=ctrl_id,
                        framework_id=fw_id,
                        framework_label=FRAMEWORK_LABELS.get(fw_id, fw_id.replace("_", " ").title()),
                        status=dim_band,
                        source_dimensions=[dim_id],
                        score=round(score, 1),
                        gap_count=1 if dim_band != "compliant" else 0,
                    )
                else:
                    if score > existing.score:
                        existing.score = round(score, 1)
                    if dim_id not in existing.source_dimensions:
                        existing.source_dimensions.append(dim_id)
                    # Status escalates to worst-band if any contributing dimension is non-compliant
                    priority = {"gap": 3, "partial": 2, "compliant": 1, "unknown": 0}
                    if priority[dim_band] > priority[existing.status]:
                        existing.status = dim_band
                    if dim_band != "compliant":
                        existing.gap_count += 1

    # ── Real-world incident grounding ───────────────────────────────────
    # Attach the documented incidents that exploited each non-compliant
    # control's gap class, so the projection reports evidence rather than only
    # a normative "you are missing X".
    from scanner.incident_grounding import incidents_for_dimension

    _incident_cache: dict[str, list[str]] = {}

    def _incidents_for_dim(dim_id: str, limit: int = 3) -> list[str]:
        if dim_id not in _incident_cache:
            _incident_cache[dim_id] = [
                inc.id for inc in incidents_for_dimension(dim_id, limit=limit)
            ]
        return _incident_cache[dim_id]

    # Round-robin across the control's contributing dimensions rather than
    # filling every slot from the first one: a control mapped from both
    # `logging` and `data_gov` should cite a record-keeping incident *and* a
    # data-governance one, not three from whichever dimension happens to match
    # the most corpus entries.
    _MAX_GROUNDING = 3
    for ctrl in bucket.values():
        if ctrl.status == "compliant":
            continue
        pools = [_incidents_for_dim(dim_id) for dim_id in ctrl.source_dimensions]
        grounded: list[str] = []
        for depth in range(_MAX_GROUNDING):
            for pool in pools:
                if depth < len(pool) and pool[depth] not in grounded:
                    grounded.append(pool[depth])
                if len(grounded) >= _MAX_GROUNDING:
                    break
            if len(grounded) >= _MAX_GROUNDING:
                break
        ctrl.related_incidents = grounded

    controls = sorted(
        bucket.values(),
        key=lambda c: (c.framework_id, c.status != "gap", -c.score, c.control_id),
    )

    by_fw: dict[str, list[FrameworkControlProjection]] = defaultdict(list)
    for c in controls:
        by_fw[c.framework_id].append(c)

    framework_summaries: list[FrameworkProjectionSummary] = []
    total_coverage = 0.0

    for fw_id, fw_controls in by_fw.items():
        total = len(fw_controls)
        compliant = sum(1 for c in fw_controls if c.status == "compliant")
        partial = sum(1 for c in fw_controls if c.status == "partial")
        gap = sum(1 for c in fw_controls if c.status == "gap")
        unknown = sum(1 for c in fw_controls if c.status == "unknown")
        cov = round(((compliant + 0.5 * partial) / total) * 100, 1) if total else 0.0
        total_coverage += cov

        top_gaps = [c.control_id for c in fw_controls if c.status == "gap"][:5]

        framework_summaries.append(
            FrameworkProjectionSummary(
                framework_id=fw_id,
                framework_label=FRAMEWORK_LABELS.get(fw_id, fw_id.replace("_", " ").title()),
                total_controls=total,
                compliant=compliant,
                partial=partial,
                gap=gap,
                unknown=unknown,
                coverage_pct=cov,
                top_gaps=top_gaps,
            )
        )

    framework_summaries.sort(key=lambda s: (-s.coverage_pct, s.framework_label))
    avg_cov = (
        round(total_coverage / len(framework_summaries), 1)
        if framework_summaries
        else 0.0
    )

    # Derive Satisfy-Once Levers
    by_dim_gaps: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for ctrl in controls:
        if ctrl.status in ("gap", "partial"):
            for d in ctrl.source_dimensions:
                by_dim_gaps[d].add((ctrl.framework_id, ctrl.control_id))

    satisfy_once_levers: list[SatisfyOnceLever] = []
    for d, hits in by_dim_gaps.items():
        fws = sorted({fw for fw, _ in hits})
        if len(fws) >= 2:
            dim_meta = DIMENSIONS.get(d)
            dim_lbl = dim_meta.label if dim_meta else d
            fw_names = [FRAMEWORK_LABELS.get(f, f) for f in fws]
            summary = (
                f"Closing this gap directly satisfies {len(hits)} controls across {len(fws)} "
                f"frameworks ({', '.join(fw_names[:3])}{'...' if len(fw_names) > 3 else ''})."
            )
            satisfy_once_levers.append(
                SatisfyOnceLever(
                    dimension_id=d,
                    dimension_label=dim_lbl,
                    framework_count=len(fws),
                    frameworks_helped=fws,
                    controls_closed_count=len(hits),
                    impact_summary=summary,
                    top_incidents=_incidents_for_dim(d, limit=1),
                )
            )

    satisfy_once_levers.sort(key=lambda lever: (-lever.framework_count, -lever.controls_closed_count))

    # Evidence harmonization & reuse observations
    reuse_opps: list[str] = [
        "**Art. 10 Data Governance ↔ GDPR Art. 5/25 ↔ NIST AI RMF MP-3.4**: A single data quality and provenance datasheet satisfies AI Act technical documentation, GDPR data protection by design, and NIST mapping requirements.",
        "**Art. 14 Human Oversight ↔ GDPR Art. 22 ↔ OWASP Agentic ASI02**: Implementing a human approval circuit breaker simultaneously addresses EU AI Act operator oversight and GDPR automated decision rights.",
        "**Art. 12 Logging ↔ SOC 2 CC7.2 ↔ ISO 27002 8.15**: Structured logging with session IDs and model prompt hashing fulfills AI Act record-keeping and SOC 2 / ISO audit logging criteria.",
        "**Art. 27 FRIA ↔ GDPR Art. 35 DPIA**: A Fundamental Rights Impact Assessment directly reuses data protection impact assessment findings, preventing redundant compliance cycles.",
    ]

    return CrossFrameworkScanProjection(
        scan_id=scan.scan_id,
        project_name=scan.project_name,
        unmapped_dimensions=unmapped,
        total_frameworks_mapped=len(framework_summaries),
        average_multi_framework_coverage_pct=avg_cov,
        frameworks=framework_summaries,
        controls=controls,
        satisfy_once_levers=satisfy_once_levers[:5],
        evidence_reuse_opportunities=reuse_opps,
    )
