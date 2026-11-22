"""Cross-framework projection engine for EU AI Act Scanner.

Projects an EU AI Act `ScanResult` onto other AI governance, security and
privacy frameworks: NIST AI RMF 1.0, NIST AI 600-1, ISO/IEC 42001:2023,
ISO/IEC 27002:2022, NIST SP 800-53 Rev. 5, SOC 2, CSA AI Controls Matrix,
OWASP LLM Top 10 (2025), OWASP Agentic Top 10, MITRE ATLAS, CEN-CENELEC JTC 21
harmonised standards and GDPR.

Legal force (ported from the legit-ai parent project, see
:mod:`scanner.data.normative_force`): an AI Act code-evidence score is
*evidence* for another framework's control, never an assessment of it.
Voluntary and guidance controls are reported as ``supported`` / ``partial`` /
``gap``; binding law (GDPR) is ``not_assessed`` and stays out of the average.

Provides 'Satisfy Once, Comply Everywhere' analysis: single fixes whose
evidence supports controls in several frameworks at once.
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
from scanner.data.normative_force import (
    FORCE_EXPLANATION,
    FORCE_RANK,
    PRESUMPTION_OF_CONFORMITY_NOTE,
    NormativeForce,
    force_of,
)
from scanner.models import ScanResult

_STATUS_PRIORITY = {"gap": 3, "partial": 2, "supported": 1, "not_assessed": 0, "unknown": 0}


class FrameworkControlProjection(BaseModel):
    """Projection for an individual control in a target framework."""

    control_id: str = Field(..., description="Framework control identifier (e.g. 'GV-1.4', 'A.7.4', 'Art. 35').")
    framework_id: str = Field(..., description="Target framework slug.")
    framework_label: str = Field("", description="Human-readable framework name.")
    status: str = Field(
        ...,
        description=(
            "'supported' (strong AI Act evidence for this control) | 'partial' | 'gap' | "
            "'not_assessed' (binding law: evidence is relevant but cannot assess compliance)."
        ),
    )
    force: str = Field(default="", description="Legal force of the control: binding_law, harmonised_standard, ...")
    source_dimensions: list[str] = Field(default_factory=list, description="Contributing EU AI Act KB dimensions.")
    score: float = Field(0.0, description="Highest score among contributing EU AI Act dimensions (0-100).")
    gap_count: int = Field(0, description="Number of contributing dimensions scoring below 60%.")
    # Documented incidents that exploited this control's gap class. Populated
    # for every non-supported control — a gap that names no incident is a
    # normative claim; one that does is evidence (see scanner.incident_grounding).
    related_incidents: list[str] = Field(
        default_factory=list,
        description="Corpus incident IDs for this gap class (empty when supported).",
    )
    lead_finding: str = Field(
        default="",
        description="The most actionable scanner gap behind this control, as 'title (file:line)'.",
    )


class FrameworkProjectionSummary(BaseModel):
    """Summary metrics for one target framework."""

    framework_id: str
    framework_label: str
    force: str = Field(default="", description="Legal force: binding_law | harmonised_standard | voluntary_standard | guidance.")
    assessed: bool = Field(
        default=True,
        description="False for binding law: coverage_pct is related evidence, not an assessment.",
    )
    total_controls: int = 0
    supported: int = 0
    compliant: int = Field(
        default=0,
        description="Always 0: code evidence never establishes another framework's compliance (kept for compatibility).",
    )
    partial: int = 0
    gap: int = 0
    not_assessed: int = 0
    unknown: int = 0
    coverage_pct: float = Field(
        0.0,
        description="Evidence coverage: (strong + 0.5 * partial evidence) / total_controls * 100.",
    )
    top_gaps: list[str] = Field(default_factory=list, description="Top priority gap control IDs.")


class SatisfyOnceLever(BaseModel):
    """A high-leverage fix whose evidence supports controls across several frameworks."""

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
    """Complete cross-framework projection from a ScanResult."""

    scan_id: str
    project_name: str
    catalogue_version: str = CROSSWALK_CATALOGUE_VERSION
    total_frameworks_mapped: int = 0
    average_multi_framework_coverage_pct: float = Field(
        0.0, description="Average evidence coverage over assessed (non-binding) frameworks.",
    )
    frameworks: list[FrameworkProjectionSummary] = Field(default_factory=list)
    controls: list[FrameworkControlProjection] = Field(default_factory=list)
    satisfy_once_levers: list[SatisfyOnceLever] = Field(default_factory=list)
    evidence_reuse_opportunities: list[str] = Field(default_factory=list)
    presumption_of_conformity_note: str = PRESUMPTION_OF_CONFORMITY_NOTE
    # Scored KB dimensions with no crosswalk entry. Non-empty means the
    # coverage % does NOT see those dimensions — read it alongside the scan's
    # own compliance_scores, never as a standalone verdict.
    unmapped_dimensions: list[str] = Field(default_factory=list)

    def format_markdown(self) -> str:
        """Render a readable cross-framework report."""
        lines = [
            f"# Cross-Framework Projection — {self.project_name}",
            "",
            f"- **Catalogue version**: `{self.catalogue_version}`",
            f"- **Target frameworks mapped**: {self.total_frameworks_mapped}",
            f"- **Average evidence coverage (voluntary frameworks)**: "
            f"**{self.average_multi_framework_coverage_pct:.1f}%**",
            "",
            "_Code evidence supports a framework's controls; it never proves compliance. "
            "Audits, certification bodies and lawyers decide that._",
            "",
            "## Framework Evidence Summary",
            "",
            "| Framework | Legal force | Evidence coverage | Supported | Partial | Gap | Top gaps |",
            "|---|---|---|---|---|---|---|",
        ]

        for fw in self.frameworks:
            top_gaps_str = ", ".join(f"`{g}`" for g in fw.top_gaps[:3]) or "None"
            force = fw.force.replace("_", " ")
            if not fw.assessed:
                lines.append(
                    f"| **{fw.framework_label}** | {force} | not assessed "
                    f"(related evidence {fw.coverage_pct:.0f}%) | — | — | — | {top_gaps_str} |"
                )
                continue
            lines.append(
                f"| **{fw.framework_label}** | {force} | **{fw.coverage_pct:.1f}%** | "
                f"{fw.supported} | {fw.partial} | {fw.gap} | {top_gaps_str} |"
            )

        lines += ["", f"_{self.presumption_of_conformity_note}_"]

        if self.satisfy_once_levers:
            lines += [
                "",
                "## Satisfy Once, Comply Everywhere — Top Levers",
                "",
                "_Fixing these single EU AI Act areas produces evidence that supports controls in "
                "several frameworks at once._",
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
                "_Each control below has weak AI Act evidence and names the documented incidents "
                "(vendored corpus) that exploited its class._",
                "",
                "| Framework | Control | Status | Behind it | Documented incidents |",
                "|---|---|---|---|---|",
            ]
            shown = grounded_controls[:15]
            for ctrl in shown:
                incidents = "; ".join(
                    f"{INCIDENT_BY_ID[i].title} (`{i}`)"
                    for i in ctrl.related_incidents
                    if i in INCIDENT_BY_ID
                )
                lines.append(
                    f"| {ctrl.framework_label} | `{ctrl.control_id}` | {ctrl.status} | "
                    f"{ctrl.lead_finding or '—'} | {incidents} |"
                )
            if len(grounded_controls) > len(shown):
                lines.append(
                    f"| … | _+{len(grounded_controls) - len(shown)} more gap controls_ | | | |"
                )

        if self.unmapped_dimensions:
            lines += [
                "",
                "## Unmapped dimensions (not in coverage %)",
                "",
                "_These scored dimensions have no crosswalk entry (catalogue "
                f"`{self.catalogue_version}`) and are invisible to the coverage "
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


# Evidence-reuse observations, each paired with the EU AI Act articles it
# cites. The Act refs are data rather than prose because the same sentences
# cite GDPR articles that share the ``Art. N`` surface form (GDPR Art. 5 is
# data-protection principles; Act Art. 5 is prohibited practices), so a test
# that scraped the sentence would resolve the wrong statute. Worded as reuse of
# evidence, never as satisfying the other law (AI Act Art. 2(7): GDPR applies
# in full; Art. 26(9) and 27(4) are the Act's own reuse provisions).
EVIDENCE_REUSE_OBSERVATIONS: tuple[tuple[tuple[str, ...], str], ...] = (
    (
        ("Art. 10",),
        "**Art. 10 Data Governance ↔ GDPR Art. 5/25 ↔ NIST AI RMF MP-3.4**: one data quality and "
        "provenance datasheet can serve as evidence for AI Act data governance, a GDPR "
        "data-protection-by-design review and NIST mapping. GDPR still applies in full (AI Act Art. 2(7)).",
    ),
    (
        ("Art. 14",),
        "**Art. 14 Human Oversight ↔ GDPR Art. 22 ↔ OWASP Agentic ASI02**: a human approval step before "
        "consequential actions is evidence for AI Act oversight and supports GDPR Art. 22 safeguards for "
        "automated decisions; whether Art. 22 is met is a separate legal assessment.",
    ),
    (
        ("Art. 12",),
        "**Art. 12 Logging ↔ SOC 2 CC7.2 ↔ ISO/IEC 27002 8.15**: structured logs with session IDs serve AI "
        "Act record-keeping and are the logging evidence SOC 2 and ISO auditors ask for.",
    ),
    (
        ("Art. 26", "Art. 27"),
        "**Art. 27 FRIA ↔ GDPR Art. 35 DPIA**: where a DPIA already covers the system, the FRIA complements "
        "it rather than repeating it (AI Act Art. 27(4)), and deployers can use the provider's Art. 13 "
        "information for the DPIA (Art. 26(9)).",
    ),
)


def _band(score: float) -> str:
    """Classify a dimension score into an evidence band."""
    if score >= 60.0:
        return "supported"
    if score >= 30.0:
        return "partial"
    return "gap"


def _status(force: NormativeForce, band: str) -> str:
    """Binding law is never assessed from AI Act evidence; other controls carry the band."""
    return "not_assessed" if force is NormativeForce.BINDING else band


def project_scan_to_frameworks(
    scan: ScanResult,
    target_framework_ids: list[str] | None = None,
) -> CrossFrameworkScanProjection:
    """Project a ScanResult onto cross-framework controls and standards.

    Args:
        scan: The ScanResult produced by `scan_project`.
        target_framework_ids: Optional list of framework ids to restrict projection to.

    Returns:
        CrossFrameworkScanProjection with per-framework evidence coverage and control mappings.
    """
    from scanner.agent_views import prioritized_gaps, where
    from scanner.kb import DIMENSIONS

    bucket: dict[tuple[str, str], FrameworkControlProjection] = {}
    bands: dict[tuple[str, str], str] = {}
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
                force = force_of(fw_id, ctrl_id)
                existing = bucket.get(key)
                if existing is None:
                    bands[key] = dim_band
                    bucket[key] = FrameworkControlProjection(
                        control_id=ctrl_id,
                        framework_id=fw_id,
                        framework_label=FRAMEWORK_LABELS.get(fw_id, fw_id.replace("_", " ").title()),
                        status=_status(force, dim_band),
                        force=force.value,
                        source_dimensions=[dim_id],
                        score=round(score, 1),
                        gap_count=1 if dim_band != "supported" else 0,
                    )
                else:
                    if score > existing.score:
                        existing.score = round(score, 1)
                    if dim_id not in existing.source_dimensions:
                        existing.source_dimensions.append(dim_id)
                    # The evidence band escalates to the worst contributing dimension.
                    if _STATUS_PRIORITY[dim_band] > _STATUS_PRIORITY[bands[key]]:
                        bands[key] = dim_band
                        existing.status = _status(force, dim_band)
                    if dim_band != "supported":
                        existing.gap_count += 1

    # ── The concrete finding behind each weak control ───────────────────
    # A founder should be able to go from "SOC 2 CC6.1: gap" straight to the
    # file and line (legit-ai port). Worst = most actionable per agent_views.
    lead_by_dim: dict[str, str] = {}
    for comp in prioritized_gaps(scan):
        for dim_id in comp.compliance_dimensions:
            lead_by_dim.setdefault(dim_id, f"{comp.name} ({where(comp.file_path, comp.line_number)})")

    # ── Real-world incident grounding ───────────────────────────────────
    # Attach the documented incidents that exploited each weak control's gap
    # class, so the projection reports evidence rather than only a normative
    # "you are missing X".
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
    for key, ctrl in bucket.items():
        if bands[key] == "supported":
            continue
        ctrl.lead_finding = next(
            (lead_by_dim[d] for d in ctrl.source_dimensions if d in lead_by_dim), ""
        )
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
        key=lambda c: (c.framework_id, bands[(c.framework_id, c.control_id)] != "gap", -c.score, c.control_id),
    )

    by_fw: dict[str, list[FrameworkControlProjection]] = defaultdict(list)
    for c in controls:
        by_fw[c.framework_id].append(c)

    framework_summaries: list[FrameworkProjectionSummary] = []
    assessed_coverage: list[float] = []

    for fw_id, fw_controls in by_fw.items():
        total = len(fw_controls)
        fw_bands = [bands[(fw_id, c.control_id)] for c in fw_controls]
        strong = sum(1 for b in fw_bands if b == "supported")
        some = sum(1 for b in fw_bands if b == "partial")
        weak = sum(1 for b in fw_bands if b == "gap")
        cov = round(((strong + 0.5 * some) / total) * 100, 1) if total else 0.0
        force = force_of(fw_id)
        assessed = force is not NormativeForce.BINDING
        if assessed:
            assessed_coverage.append(cov)

        top_gaps = [c.control_id for c in fw_controls if bands[(fw_id, c.control_id)] == "gap"][:5]

        framework_summaries.append(
            FrameworkProjectionSummary(
                framework_id=fw_id,
                framework_label=FRAMEWORK_LABELS.get(fw_id, fw_id.replace("_", " ").title()),
                force=force.value,
                assessed=assessed,
                total_controls=total,
                supported=strong if assessed else 0,
                partial=some if assessed else 0,
                gap=weak if assessed else 0,
                not_assessed=0 if assessed else total,
                unknown=sum(1 for c in fw_controls if c.status == "unknown"),
                coverage_pct=cov,
                top_gaps=top_gaps,
            )
        )

    framework_summaries.sort(
        key=lambda s: (FORCE_RANK[NormativeForce(s.force)], -s.coverage_pct, s.framework_label)
    )
    avg_cov = round(sum(assessed_coverage) / len(assessed_coverage), 1) if assessed_coverage else 0.0

    # Derive Satisfy-Once Levers — only frameworks where AI Act evidence can
    # actually help close a control (binding law is assessed on its own).
    by_dim_gaps: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for ctrl in controls:
        if ctrl.force == NormativeForce.BINDING.value:
            continue
        if bands[(ctrl.framework_id, ctrl.control_id)] in ("gap", "partial"):
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
                f"Closing this gap supports {len(hits)} controls across {len(fws)} "
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
    reuse_opps: list[str] = [text for _refs, text in EVIDENCE_REUSE_OBSERVATIONS]

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


__all__ = [
    "EVIDENCE_REUSE_OBSERVATIONS",
    "FORCE_EXPLANATION",
    "CrossFrameworkScanProjection",
    "FrameworkControlProjection",
    "FrameworkProjectionSummary",
    "SatisfyOnceLever",
    "project_scan_to_frameworks",
]
