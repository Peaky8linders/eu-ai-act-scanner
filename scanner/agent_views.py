"""Compact, agent-facing views of scanner results.

The engine's result models are complete by design (``ScanResult`` lists every
component; a cross-framework projection lists every control). An agent rarely
needs all of that, and every token it reads costs time and money and dilutes
its attention. These views follow Anthropic's tool-design guidance
("Writing effective tools for agents"): return the high-signal subset by
default, prefer human-readable fields over internal identifiers, never echo a
payload that was just written to disk, and when a list is truncated say how to
get the rest. ``response_format="detailed"`` on the MCP tools returns the full
models unchanged.

Pure functions over existing models: no I/O, no scanning, deterministic.
"""

from __future__ import annotations

from typing import Any, Literal

from scanner.kb import DIMENSIONS
from scanner.models import DiscoveredComponent, ScanResult

ResponseFormat = Literal["concise", "detailed"]
RESPONSE_FORMATS: tuple[str, ...] = ("concise", "detailed")

GAP_LIMIT = 8
INCIDENT_DESCRIPTION_CHARS = 180
_SENTINEL_PATHS = {"", "project", "(no file)", "n/a", "repository", "unknown"}
_SEVERITY_RANK = {"critical": 0, "high": 1, "error": 1, "medium": 2, "warning": 2, "low": 3, "info": 4}
# Impact-weighted ordering for gaps without an explicit severity: live
# obligations and exploitable security issues first, paperwork last.
_DIMENSION_RANK = {
    "content_transparency": 0, "transparency": 0, "security": 1, "access_control": 1,
    "tool_governance": 1, "supply_chain": 2, "human_oversight": 2, "logging": 3,
}


def normalize_response_format(value: object) -> ResponseFormat:
    """Map user/agent input to a response format; anything unknown is concise."""
    text = str(value or "").strip().lower()
    return "detailed" if text in {"detailed", "full", "verbose"} else "concise"


def where(file_path: str | None, line: int | None = None) -> str:
    """Human-readable location: ``path:line``, ``path``, or ``project-wide``."""
    path = (file_path or "").replace("\\", "/").strip()
    if path.lower() in _SENTINEL_PATHS:
        return "project-wide"
    return f"{path}:{line}" if line else path


def _severity(comp: DiscoveredComponent) -> str:
    details = comp.details if isinstance(comp.details, dict) else {}
    return str(details.get("severity", "")).lower().strip()


def _gap_sort_key(comp: DiscoveredComponent) -> tuple:
    dims_rank = min((_DIMENSION_RANK.get(d, 5) for d in comp.compliance_dimensions), default=6)
    located = 0 if where(comp.file_path) != "project-wide" else 1
    return (_SEVERITY_RANK.get(_severity(comp), 5), dims_rank, -comp.confidence, located, comp.name)


def compact_gap(comp: DiscoveredComponent) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "title": comp.name,
        "where": where(comp.file_path, comp.line_number),
        "areas": list(comp.compliance_dimensions),
    }
    severity = _severity(comp)
    if severity:
        entry["severity"] = severity
    return entry


def prioritized_gaps(result: ScanResult) -> list[DiscoveredComponent]:
    """Gap components, most actionable first, de-duplicated by title + location."""
    seen: set[tuple[str, str]] = set()
    ordered: list[DiscoveredComponent] = []
    for comp in sorted((c for c in result.components if c.compliance_impact == "gap"), key=_gap_sort_key):
        key = (comp.name, where(comp.file_path, comp.line_number))
        if key not in seen:
            seen.add(key)
            ordered.append(comp)
    return ordered


def concise_scan(
    result: ScanResult,
    *,
    gap_limit: int = GAP_LIMIT,
    offset: int = 0,
    areas: set[str] | None = None,
) -> dict[str, Any]:
    """High-signal scan summary: scope, score, lowest areas, top gaps, next step.

    ``offset`` pages through the prioritised gap list; ``areas`` restricts
    gaps and scores to those KB dimensions (an area or an article's areas).
    """
    if not result.is_ai_system:
        return {
            "project": result.project_name,
            "is_ai_system": False,
            "scope_note": result.scope_note
            or "No AI/ML framework, model, or agent signal was detected; EU AI Act scoring was skipped.",
            "files_scanned": result.total_files,
            "more": "No EU AI Act obligations appear to apply. Do not report a compliance percentage.",
        }
    gaps = prioritized_gaps(result)
    if areas:
        gaps = [c for c in gaps if set(c.compliance_dimensions) & areas]
    offset = max(0, offset)
    top = [compact_gap(c) for c in gaps[offset: offset + gap_limit]]
    scores = {
        dim: round(score, 1)
        for dim, score in sorted(result.compliance_scores.items(), key=lambda kv: kv[1])
        if not areas or dim in areas
    }
    out: dict[str, Any] = {
        "project": result.project_name,
        "is_ai_system": True,
        "overall_compliance_pct": round(result.overall_compliance_pct, 1),
        "files_scanned": result.total_files,
        "roles": list(result.inferred_roles),
        "scores_lowest_first": scores,
        "gap_count": len(gaps),
        "positive_evidence_count": sum(1 for c in result.components if c.compliance_impact == "positive"),
        "top_gaps": top,
    }
    if result.active_role:
        out["role"] = result.active_role
    if result.external_security_sources:
        out["external_sources"] = list(result.external_security_sources)
    if result.suppressed_findings:
        out["suppressed_count"] = len(result.suppressed_findings)
        out["suppressed_example"] = (
            f"{result.suppressed_findings[0].title}: {result.suppressed_findings[0].reason}"
        )
    if result.suppression_problems:
        out["suppression_problems"] = list(result.suppression_problems)
    if areas:
        out["filtered_to_areas"] = sorted(areas)
    end = offset + len(top)
    if offset and not top:
        shown = f"No gaps at offset {offset}; there are {len(gaps)} in total. "
    elif end < len(gaps):
        shown = f"Showing gaps {offset + 1}-{end} of {len(gaps)}; pass offset={end} for the next page. "
    elif offset:
        shown = f"Showing gaps {offset + 1}-{end} of {len(gaps)}. "
    else:
        shown = ""
    out["more"] = (
        f"{shown}Narrow with area='security' or area='art50'. Call founder_triage for a "
        "plain-English action plan, or response_format='detailed' for every finding."
    )
    return out


def concise_founder(triage: Any) -> dict[str, Any]:
    """The founder brief already is the human summary: return it plus counts."""
    return {
        "is_ai_system": triage.is_ai_system,
        "operator_role": triage.operator_role,
        "headline": triage.headline,
        "summary_counts": dict(triage.summary_counts),
        "brief_markdown": triage.brief_markdown,
        "more": "Call founder_triage with response_format='detailed' for structured items "
        "(file, line, effort, suggested PR title, articles).",
    }


def concise_cross_framework(projection: Any, *, lever_limit: int = 3) -> dict[str, Any]:
    data = projection.model_dump() if hasattr(projection, "model_dump") else dict(projection)
    first_gap: dict[str, str] = {}
    for ctrl in data.get("controls", []):
        if ctrl.get("lead_finding") and ctrl.get("framework_id") not in first_gap and ctrl.get("status") == "gap":
            first_gap[ctrl["framework_id"]] = f"{ctrl['control_id']}: {ctrl['lead_finding']}"
    frameworks = []
    for fw in data.get("frameworks", []):  # already ordered: binding law first, then coverage
        entry: dict[str, Any] = {
            "framework": fw.get("framework_label") or fw.get("framework_id"),
            "force": fw.get("force", ""),
        }
        if fw.get("assessed", True):
            entry.update({
                "coverage_pct": round(float(fw.get("coverage_pct", 0.0)), 1),
                "gaps": fw.get("gap", 0),
                "partial": fw.get("partial", 0),
            })
        else:
            entry.update({
                "coverage_pct": None,
                "status": "not assessed (binding law)",
                "related_evidence_pct": round(float(fw.get("coverage_pct", 0.0)), 1),
            })
        if fw.get("framework_id") in first_gap:
            entry["first_gap"] = first_gap[fw["framework_id"]]
        frameworks.append(entry)
    levers = [
        {
            "fix_area": lv.get("dimension_label") or lv.get("dimension_id"),
            "frameworks_helped": lv.get("framework_count", len(lv.get("frameworks_helped", []))),
            "controls_closed": lv.get("controls_closed_count", 0),
            "why": lv.get("impact_summary", ""),
        }
        for lv in data.get("satisfy_once_levers", [])[:lever_limit]
    ]
    reuse = [
        str(r).split("**:", 1)[0].strip("* ")  # the heading, e.g. "Art. 12 Logging ↔ SOC 2 CC7.2 ↔ ..."
        for r in data.get("evidence_reuse_opportunities", [])[:3]
    ]
    out: dict[str, Any] = {
        "project": data.get("project_name"),
        "average_coverage_pct": round(float(data.get("average_multi_framework_coverage_pct", 0.0)), 1),
        "note": "Coverage is code evidence supporting each framework's controls, not compliance.",
        "frameworks": frameworks,
        "top_levers": levers,
        "presumption_of_conformity": data.get("presumption_of_conformity_note", ""),
    }
    if reuse:
        out["evidence_reuse"] = reuse
    out["more"] = "Call project_cross_framework with response_format='detailed' for every control mapping."
    return out


def dossier_receipt(dossier: Any, output_path: str) -> dict[str, Any]:
    data = dossier.model_dump() if hasattr(dossier, "model_dump") else dict(dossier)
    return {
        "status": "success",
        "output_path": output_path,
        "dossier_id": data.get("dossier_id"),
        "integrity_hash": data.get("dossier_integrity_hash"),
        "git_commit": data.get("git_commit"),
        "is_ai_system": data.get("is_ai_system"),
        "overall_compliance_pct": data.get("overall_compliance_pct"),
        "files_covered": len(data.get("file_manifest") or []),
        "more": "The full dossier is in the file; response_format='detailed' returns it inline.",
    }


def remediation_summary(fix_result: Any) -> dict[str, Any]:
    data = fix_result.model_dump() if hasattr(fix_result, "model_dump") else dict(fix_result)
    proposals = [
        {
            "title": p.get("title"),
            "target_path": p.get("target_path"),
            "area": p.get("dimension"),
            "article": p.get("article"),
            "why": p.get("rationale"),
        }
        for p in data.get("proposals", [])
    ]
    out: dict[str, Any] = {
        "project": data.get("project_name"),
        "is_ai_system": data.get("is_ai_system"),
        "baseline_overall": data.get("baseline_overall"),
        "final_overall": data.get("final_overall"),
        "applied": len(data.get("applied") or []),
        "regressions_avoided": len(data.get("skipped_regressions") or []),
        "proposals": proposals,
    }
    if data.get("scope_note"):
        out["scope_note"] = data["scope_note"]
    out["more"] = "Call remediation_loop with response_format='detailed' for each proposal's full file content."
    return out


def compact_incident(incident: dict[str, Any]) -> dict[str, Any]:
    description = str(incident.get("description") or "").strip()
    if len(description) > INCIDENT_DESCRIPTION_CHARS:
        description = description[: INCIDENT_DESCRIPTION_CHARS - 1].rstrip() + "…"
    entry: dict[str, Any] = {
        "id": incident.get("id"),
        "title": incident.get("title"),
        "year": incident.get("year"),
        "severity": incident.get("severity"),
        "real_world": incident.get("corpus") == "real-world",
        "summary": description,
    }
    mitigations = [m for m in (incident.get("mitigations") or []) if m][:2]
    if mitigations:
        entry["mitigations"] = mitigations
    return entry


def dimension_label(dim_id: str) -> str:
    dim = DIMENSIONS.get(dim_id)
    return dim.label if dim else dim_id


__all__ = [
    "RESPONSE_FORMATS",
    "ResponseFormat",
    "compact_gap",
    "compact_incident",
    "concise_cross_framework",
    "concise_founder",
    "concise_scan",
    "dimension_label",
    "dossier_receipt",
    "normalize_response_format",
    "prioritized_gaps",
    "remediation_summary",
    "where",
]
