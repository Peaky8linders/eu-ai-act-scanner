"""Top-level scanner orchestration.

Walks a project directory, builds an AnalyzerContext, runs all 14 analyzers,
aggregates findings into a ScanResult.

No network calls, no database writes, no telemetry. Purely local static analysis.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

import structlog

from scanner.analyzers import (
    AnalyzerContext,
    collect_pre_filled_answers,
    compute_dimension_scores,
    run_all_analyzers,
)
from scanner.incident_grounding import incidents_for_dimension
from scanner.models import (
    ArchitectureNode,
    DiscoveredComponent,
    FileFinding,
    ScanResult,
)

logger = structlog.get_logger()

_LANGUAGE_EXTENSIONS = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
    ".tsx": "TypeScript", ".jsx": "JavaScript", ".java": "Java",
    ".rs": "Rust", ".go": "Go", ".r": "R", ".jl": "Julia",
    ".rb": "Ruby", ".c": "C", ".cpp": "C++", ".cs": "C#",
    ".swift": "Swift", ".kt": "Kotlin", ".scala": "Scala",
}

_TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".rs", ".go", ".r", ".jl",
    ".md", ".txt", ".yaml", ".yml", ".toml", ".cfg", ".json", ".ini", ".sh",
    ".dockerfile", ".tf", ".hcl", ".rb", ".c", ".cpp", ".cs", ".swift", ".kt",
}

_SPECIAL_FILENAMES = {
    "dockerfile", "makefile", "jenkinsfile", "procfile",
    ".gitignore", ".dockerignore", ".env.example",
}

_EXCLUDED_PATH_PARTS = (
    "__pycache__", "node_modules", ".git", ".venv", "venv", ".tox",
    ".pytest_cache", ".mypy_cache", "dist", "build",
)

_MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MB — skip generated/bundled files


def _safe_read(path: Path) -> str | None:
    """Read a text file, returning None on failure or if it exceeds size cap."""
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return None


def scan_project(root: Path | str, project_name: str | None = None) -> ScanResult:
    """Run the full EU AI Act scanner on a project directory.

    Args:
        root: Path to the project root directory.
        project_name: Display name. Defaults to the directory name.

    Returns:
        ScanResult with architecture, compliance scores, and findings.
    """
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise ValueError(f"Not a directory: {root_path}")

    name = project_name or root_path.name or "Project"

    languages: Counter = Counter()
    total_files = 0
    total_size = 0
    files: dict[str, str] = {}
    file_list: list[str] = []
    binary_files: dict[str, int] = {}

    for file_path in root_path.rglob("*"):
        if not file_path.is_file():
            continue
        path_str = str(file_path)
        if any(part in path_str for part in _EXCLUDED_PATH_PARTS):
            continue

        total_files += 1
        try:
            total_size += file_path.stat().st_size
        except OSError:
            continue
        rel_path = str(file_path.relative_to(root_path)).replace("\\", "/")
        ext = file_path.suffix.lower()
        file_list.append(rel_path)

        if ext in _LANGUAGE_EXTENSIONS:
            languages[_LANGUAGE_EXTENSIONS[ext]] += 1

        if ext in _TEXT_EXTENSIONS or file_path.name.lower() in _SPECIAL_FILENAMES:
            content = _safe_read(file_path)
            if content is not None:
                files[rel_path] = content
            else:
                binary_files[rel_path] = file_path.stat().st_size
        else:
            try:
                binary_files[rel_path] = file_path.stat().st_size
            except OSError:
                pass

    ctx = AnalyzerContext(
        files=files,
        file_list=file_list,
        binary_files=binary_files,
        languages=dict(languages),
    )
    analyzer_results = run_all_analyzers(ctx)

    # Deterministically infer which operator role(s) the scanned codebase
    # occupies (provider / deployer / GPAI provider) from code signals. Drives
    # which obligations apply and which roles owe each gap. Lazy import to keep
    # the package import graph acyclic (obligations pulls scanner.grounding).
    from scanner import obligations
    inferred_roles = obligations.infer_roles(ctx)

    all_findings = []
    for ar in analyzer_results:
        all_findings.extend(ar.findings)

    components: list[DiscoveredComponent] = []
    seen_keys: set[tuple[str, str]] = set()
    for finding in all_findings:
        key = (finding.category, finding.title)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        components.append(DiscoveredComponent(
            name=finding.title,
            component_type=finding.category,
            file_path=finding.file_path,
            confidence=finding.confidence,
            compliance_dimensions=finding.compliance_dimensions,
            compliance_impact=finding.compliance_impact,
            details={"evidence": finding.evidence_snippet} if finding.evidence_snippet else {},
        ))

    active_ids = {ar.analyzer_id for ar in analyzer_results if ar.findings}
    architecture: list[ArchitectureNode] = []
    for ar in analyzer_results:
        if not ar.findings:
            continue
        connections = [c for c in ar.connected_categories if c in active_ids]
        status = (
            "compliant" if ar.score >= 60 else
            "partial" if ar.score >= 30 else
            "gap"
        )
        architecture.append(ArchitectureNode(
            id=ar.analyzer_id,
            label=ar.label,
            type=ar.graph_node_type,
            compliance_status=status,
            connected_to=sorted(connections),
            file_count=ar.file_count,
            icon=ar.graph_icon,
        ))

    compliance_scores = compute_dimension_scores(all_findings)
    overall = (
        sum(compliance_scores.values()) / len(compliance_scores)
        if compliance_scores else 0.0
    )

    evidence_map: dict[str, list[str]] = defaultdict(list)
    for f in all_findings:
        if f.file_path:
            for dim in f.compliance_dimensions:
                evidence_map[dim].append(f.file_path)
    evidence_map_clean = {
        k: sorted(set(v))[:10]
        for k, v in evidence_map.items()
    }

    file_finding_map: dict[str, dict] = {}
    for f in all_findings:
        if not f.file_path:
            continue
        entry = file_finding_map.setdefault(
            f.file_path,
            {"findings": [], "gaps": [], "dims": set()},
        )
        entry["dims"].update(f.compliance_dimensions)
        if f.compliance_impact == "gap":
            entry["gaps"].append(f.title)
        else:
            entry["findings"].append(f.title)

    file_findings: list[FileFinding] = []
    for fp, data in sorted(file_finding_map.items()):
        if data["gaps"] and not data["findings"]:
            status = "gap"
        elif data["gaps"]:
            status = "partial"
        else:
            status = "compliant"
        file_findings.append(FileFinding(
            file_path=fp,
            findings=data["findings"][:10],
            gaps=data["gaps"][:10],
            compliance_dimensions=sorted(data["dims"]),
            status=status,
        ))

    risk_indicators: list[str] = []
    has_ai = any(ar.analyzer_id == "ai_frameworks" and ar.findings for ar in analyzer_results)
    for ar in analyzer_results:
        if has_ai and not ar.findings and ar.analyzer_id in (
            "test_suite", "documentation", "human_oversight",
            "logging_monitoring", "security_controls",
        ):
            risk_indicators.append(f"AI system detected but no {ar.label.lower()} found")
    for f in all_findings:
        if f.compliance_impact == "gap":
            risk_indicators.append(f.title)
    risk_indicators = risk_indicators[:10]

    recommendations: list[str] = []
    for dim_id, score in sorted(compliance_scores.items(), key=lambda x: x[1]):
        if score < 30:
            recommendations.append(
                f"Critical gap in {dim_id}: strengthen evidence before deployment"
            )
        elif score < 60:
            recommendations.append(
                f"Partial evidence for {dim_id}: additional controls recommended"
            )

    pre_filled = collect_pre_filled_answers(all_findings)

    # Ground the actionable (gap / partial-evidence) dimensions in documented
    # real-world incidents. Deterministic, offline — top-3 incident IDs per
    # dimension scoring below the "broad evidence" band. Resolve IDs via
    # scanner.incident_grounding / scanner.data.incident_corpus.
    incident_grounding_map: dict[str, list[str]] = {}
    for dim_id, score in compliance_scores.items():
        if score >= 80:
            continue
        matches = incidents_for_dimension(dim_id, limit=3)
        if matches:
            incident_grounding_map[dim_id] = [inc.id for inc in matches]

    from scanner import __version__
    logger.info(
        "scan_complete",
        project=name,
        total_files=total_files,
        components=len(components),
        analyzers_active=len([ar for ar in analyzer_results if ar.findings]),
        overall_compliance=round(overall, 1),
    )

    return ScanResult(
        project_name=name,
        scanner_version=__version__,
        total_files=total_files,
        total_size_bytes=total_size,
        languages=dict(languages.most_common(20)),
        components=components,
        architecture=architecture,
        compliance_scores=compliance_scores,
        overall_compliance_pct=round(overall, 1),
        risk_indicators=risk_indicators,
        recommendations=recommendations,
        evidence_map=evidence_map_clean,
        file_findings=file_findings,
        pre_filled_answers=pre_filled,
        incident_grounding=incident_grounding_map,
        inferred_roles=inferred_roles,
    )
