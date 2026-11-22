"""Top-level scanner orchestration.

Walks a project directory, builds an AnalyzerContext, runs all 22 analyzers,
aggregates findings into a ScanResult.

No network calls, no database writes, no telemetry. Purely local static analysis.
"""

from __future__ import annotations

import os
from collections import Counter, defaultdict
from collections.abc import Iterator
from pathlib import Path

import structlog

from scanner.analyzers import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    collect_pre_filled_answers,
    compute_dimension_scores,
    detect_ai_system,
    run_all_analyzers,
)
from scanner.incident_grounding import incidents_for_dimension
from scanner.models import (
    ArchitectureNode,
    DiscoveredComponent,
    FileFinding,
    ScanResult,
    TaggedRecommendation,
)
from scanner.paths import is_excluded

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

_MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MB — skip generated/bundled files

# Use/mention discipline for gaps. A code-level analyzer whose gap points at a
# README, a planning doc or an env template is describing a *mention*, not the
# product's code: real repos produced "hardcoded secret" from README snippets,
# "print() in source files" from README examples and "lethal trifecta" from an
# ARCHITECTURE.md. Positive evidence from docs is unaffected.
_PROSE_SUFFIXES = (".md", ".mdx", ".rst", ".txt", ".adoc")
_ENV_TEMPLATE_NAMES = frozenset({".env.example", ".env.sample", ".env.template", ".env.dist"})
_CODE_LEVEL_ANALYZERS = frozenset({
    "security_controls", "logging_monitoring", "agent_cascade", "lethal_trifecta",
    "privilege_minimization", "runtime_drift", "adversarial_robustness", "model_typology",
    "human_oversight", "data_pipeline", "mcp_toolchain", "ai_frameworks", "cloud_deployment",
    "article_50_transparency", "agent_inventory",
})


def _is_prose_location(path: str) -> bool:
    low = (path or "").lower().replace("\\", "/")
    return low.endswith(_PROSE_SUFFIXES) or low.rsplit("/", 1)[-1] in _ENV_TEMPLATE_NAMES


def _drop_prose_located_gaps(results: list[AnalyzerResult]) -> int:
    """Remove code-level gaps whose location is prose or an env template; return the count."""
    dropped = 0
    for ar in results:
        if ar.analyzer_id not in _CODE_LEVEL_ANALYZERS:
            continue
        kept = [
            f for f in ar.findings
            if not (f.compliance_impact == "gap" and _is_prose_location(f.file_path))
        ]
        dropped += len(ar.findings) - len(kept)
        ar.findings = kept
    return dropped
_MAX_AGENT_CONFIG_BYTES = 512 * 1024  # 512 KB cap for allowlisted .claude/ configs
_MIN_PREFIX_MATCH = 40
_SKIPPED_CLAUDE_PARTS = frozenset({"worktrees", "state", "memory"})


def _safe_read(path: Path) -> str | None:
    """Read a text file, returning None on failure or if it exceeds size cap."""
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return None


def _collect_agent_config_files(root: Path) -> dict[str, str]:
    """Safely read allowlisted project-level ``.claude/`` configuration files.

    Reads ONLY:
    - ``.claude/settings.json``
    - ``.claude/hooks/*.json``
    - ``.claude/commands/*.md``
    - ``.claude/security-scan-instructions.md``
    - ``.claude/false-positive-filter.md``
    - ``.claude/threat-model.md``

    Explicitly skips ``.claude/worktrees/``, ``.claude/hooks/state/``,
    ``.claude/memory/``, and ``.claude/settings.local.json``. Enforces a
    symlink escape check against ``root`` and a byte-size cap. Returned files
    are attached to ``AnalyzerContext.agent_config_files`` without incrementing
    ``ScanResult.total_files`` or polluting ``ctx.files`` / ``ctx.file_list``.
    """
    root_resolved = root.resolve()
    claude_dir = root_resolved / ".claude"
    if not claude_dir.is_dir():
        return {}
    try:
        if not claude_dir.resolve().is_relative_to(root_resolved):
            return {}
    except OSError:
        return {}

    candidates: list[Path] = [
        claude_dir / "settings.json",
        claude_dir / "security-scan-instructions.md",
        claude_dir / "false-positive-filter.md",
        claude_dir / "threat-model.md",
    ]

    hooks_dir = claude_dir / "hooks"
    if hooks_dir.is_dir():
        try:
            if hooks_dir.resolve().is_relative_to(root_resolved):
                candidates.extend(sorted(hooks_dir.glob("*.json")))
        except OSError:
            pass

    commands_dir = claude_dir / "commands"
    if commands_dir.is_dir():
        try:
            if commands_dir.resolve().is_relative_to(root_resolved):
                candidates.extend(sorted(commands_dir.glob("*.md")))
        except OSError:
            pass

    collected: dict[str, str] = {}
    for candidate in candidates:
        if not candidate.is_file():
            continue
        if candidate.name == "settings.local.json":
            continue
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if not resolved.is_relative_to(root_resolved):
            continue
        try:
            rel_obj = candidate.relative_to(root_resolved)
        except ValueError:
            continue
        if _SKIPPED_CLAUDE_PARTS & set(rel_obj.parts):
            continue
        try:
            if resolved.stat().st_size > _MAX_AGENT_CONFIG_BYTES:
                continue
            content = resolved.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            continue
        collected[str(rel_obj).replace("\\", "/")] = content
    return collected


def _recover_line_number(
    f: Finding,
    files: dict[str, str],
    stripped_lines: dict[str, list[str]] | None = None,
) -> Finding:
    """Pin ``f.line_number`` when an analyzer cited a source line without its number.

    Uses a per-scan stripped-lines cache over ``files``: exact stripped-line match
    first, then ``>= _MIN_PREFIX_MATCH`` char prefix match (stripping trailing
    ``...``/``…``). Never overwrites an existing analyzer-pinned ``line_number``.
    """
    if f.line_number is not None or not f.evidence_snippet.strip():
        return f
    content = files.get(f.file_path)
    if not content:
        return f
    lines = stripped_lines.get(f.file_path) if stripped_lines is not None else None
    if lines is None:
        lines = [line.strip() for line in content.split("\n")]
        if stripped_lines is not None:
            stripped_lines[f.file_path] = lines
    cited = f.evidence_snippet.strip()
    for number, text in enumerate(lines, start=1):
        if text == cited:
            return f.model_copy(update={"line_number": number})
    prefix = cited.removesuffix("...").removesuffix("…").rstrip()
    if len(prefix) >= _MIN_PREFIX_MATCH:
        for number, text in enumerate(lines, start=1):
            if text.startswith(prefix):
                return f.model_copy(update={"line_number": number})
    return f


def _build_external_analyzer_result(
    external_findings: list[Finding],
    sources: list[str],
) -> AnalyzerResult:
    """Wrap externally ingested security/compliance findings into an AnalyzerResult."""
    positives = [f for f in external_findings if f.compliance_impact == "positive"]
    gaps = [f for f in external_findings if f.compliance_impact == "gap"]
    if gaps and not positives:
        score = max(10.0, 25.0 - (len(gaps) - 1) * 5)
    elif gaps and positives:
        score = max(20.0, min(95.0, 65.0 - len(gaps) * 15 + len(positives) * 10))
    elif positives:
        score = min(100.0, 80.0 + len(positives) * 5)
    else:
        score = 80.0
    score = max(0.0, min(100.0, score))
    return AnalyzerResult(
        analyzer_id="external_security",
        label="External Security & Compliance Findings",
        findings=list(external_findings),
        score=round(score, 1),
        file_count=len({f.file_path for f in external_findings if f.file_path}),
        graph_node_type="security",
        graph_icon="🛡",
        connected_categories=["security_controls", "claude_code_security"],
        metadata={"sources": sources, "external": True},
    )


def _walk_project_files(root: Path) -> Iterator[Path]:
    """Yield regular files under ``root``, never descending into excluded dirs.

    ``Path.rglob("*")`` enumerated every file inside ``.venv/``, ``.git/`` and
    caches before ``is_excluded`` threw them away — tens of thousands of stat
    calls on a typical Python checkout. ``os.walk`` lets us prune those
    directories in place. Symlinked directories are not followed (no escape
    outside the scan root, no cycles); traversal order is sorted so scans stay
    deterministic across platforms.
    """
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        rel_dir = current.relative_to(root)
        dirnames[:] = sorted(d for d in dirnames if not is_excluded(rel_dir / d))
        for name in sorted(filenames):
            candidate = current / name
            if candidate.is_file():
                yield candidate


def _component_details(finding: Finding) -> dict:
    """Details carried onto a DiscoveredComponent.

    ``severity`` and ``article_paragraphs`` must survive here: founder triage
    reads them from ``details`` to put a confirmed critical finding (e.g. a
    ``/claude-security`` SQL injection) in the ship-now bucket. Dropping them
    demoted critical vulnerabilities to the enterprise-deals bucket.
    """
    details: dict = {}
    if finding.evidence_snippet:
        details["evidence"] = finding.evidence_snippet
    if finding.severity:
        details["severity"] = finding.severity
    if finding.article_paragraphs:
        details["article_paragraphs"] = list(finding.article_paragraphs)
    return details


def scan_project(
    root: Path | str,
    project_name: str | None = None,
    *,
    role: str | None = None,
    deep: bool = False,
    cross_framework: bool = False,
    external_findings: list[Finding] | None = None,
    external_sources: list[str] | None = None,
) -> ScanResult:
    """Run the full EU AI Act scanner on a project directory.

    Args:
        root: Path to the project root directory.
        project_name: Display name. Defaults to the directory name.
        role: Explicit operator role (any id in scanner.data.role_obligations.CANONICAL_ROLE_IDS);
            scopes recommendations to the dimensions that role owes and activates
            role-vs-codebase reconciliation in ``regulatory_perimeter``.
        deep: Deprecated, ignored. Semantic depth now comes from the host
            Claude Code session (assisted mode, your existing subscription)
            or any MCP client calling the scanner over MCP.
        cross_framework: Project findings across NIST AI RMF, ISO 42001, GDPR, OWASP.
        external_findings: Optional pre-parsed external security/compliance findings
            (e.g., SARIF, Claude Code Security, Claude Compliance API) to merge into
            scores, risk indicators, file findings, and discovered components.
        external_sources: Optional labels identifying the external sources ingested.

    Returns:
        ScanResult with architecture, compliance scores, findings, and cross-framework projections.
    """
    if role is not None:
        from scanner.data.role_obligations import CANONICAL_ROLE_IDS
        if role not in CANONICAL_ROLE_IDS:
            raise ValueError(
                f"Unknown operator role {role!r}; expected one of {', '.join(CANONICAL_ROLE_IDS)}"
            )
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

    for file_path in _walk_project_files(root_path):
        # Compare components *below* the root: matching the absolute path would
        # exclude every file in a project that lives under `.hidden/` or `build/`.
        rel_path_obj = file_path.relative_to(root_path)
        if is_excluded(rel_path_obj):
            continue

        total_files += 1
        try:
            total_size += file_path.stat().st_size
        except OSError:
            continue
        rel_path = str(rel_path_obj).replace("\\", "/")
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

    agent_config_files = _collect_agent_config_files(root_path)

    ctx = AnalyzerContext(
        files=files,
        file_list=file_list,
        binary_files=binary_files,
        languages=dict(languages),
        agent_config_files=agent_config_files,
        extracted_role=role,
    )
    analyzer_results = run_all_analyzers(ctx)
    dropped_prose_gaps = _drop_prose_located_gaps(analyzer_results)
    if dropped_prose_gaps:
        logger.debug("dropped_prose_located_gaps", count=dropped_prose_gaps)

    # Incorporate optional externally ingested findings (SARIF, Claude Security,
    # Claude Compliance API) as a first-class synthetic analyzer result so they
    # flow cleanly into scores, components, file findings, and risk indicators.
    resolved_external_sources: list[str] = list(dict.fromkeys(external_sources or ()))
    if external_findings:
        if not resolved_external_sources:
            inferred_sources = list(
                dict.fromkeys(f.category for f in external_findings if f.category)
            )
            resolved_external_sources = inferred_sources or ["external_security"]
        analyzer_results.append(
            _build_external_analyzer_result(external_findings, resolved_external_sources)
        )

    # Deterministically infer which operator role(s) the scanned codebase
    # occupies (provider / deployer / GPAI provider) from code signals. Drives
    # which obligations apply and which roles owe each gap. Lazy import to keep
    # the package import graph acyclic (obligations pulls scanner.grounding).
    from scanner import obligations
    inferred_roles = obligations.infer_roles(ctx)

    lookup_files = (
        {**ctx.files, **ctx.agent_config_files}
        if ctx.agent_config_files
        else ctx.files
    )
    stripped_lines: dict[str, list[str]] = {}
    all_findings: list[Finding] = []
    for ar in analyzer_results:
        recovered = [
            _recover_line_number(f, lookup_files, stripped_lines)
            for f in ar.findings
        ]
        ar.findings = recovered
        all_findings.extend(recovered)

    # Tag the taxonomy recommendations for the compound-risk axes this scan
    # actually detected. Provenance is structural, not prose: every row says
    # whether the Act requires it (with the article) or the paper suggests it
    # (with the line reference). Empty when no axis is present.
    from scanner.data.agentic_taxonomy import all_recommendations

    detected_risks = {f.compound_risk_type for f in all_findings if f.compound_risk_type}
    agentic_recommendations = [
        TaggedRecommendation(**rec)
        for rec in all_recommendations()
        if rec["risk_id"] in detected_risks
    ]

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
            details=_component_details(finding),
            line_number=finding.line_number,
            matched_pattern=finding.matched_pattern,
        ))

    active_ids = {ar.analyzer_id for ar in analyzer_results if ar.findings}
    architecture: list[ArchitectureNode] = []
    for ar in analyzer_results:
        if not ar.findings:
            continue
        connections = [c for c in ar.connected_categories if c in active_ids]
        if ar.metadata.get("emits_gaps") is False:
            status = "info"
        else:
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
            finding_count=len(ar.findings),
            icon=ar.graph_icon,
        ))

    # ── AI-system scope gate (EU AI Act Art. 3(1)) ─────────────────────────
    # The Regulation only governs "AI systems". A codebase with no AI/ML/agent
    # signal is out of scope: skip scoring entirely rather than report a
    # misleading "compliance %" (and stop the fix loop from gaming it with
    # boilerplate evidence). detect_ai_system keys on the purpose-built AI
    # detectors and errs toward in-scope when a signal is ambiguous (a false
    # negative would wrongly drop a real AI system out of scope).
    is_ai_system, ai_system_signals = detect_ai_system(analyzer_results)
    if not is_ai_system:
        # The conservative deployer fallback is useful for AI projects with no
        # role-specific evidence. An out-of-scope codebase has no AI Act role.
        inferred_roles = []
    scope_note = ""
    if is_ai_system:
        compliance_scores = compute_dimension_scores(all_findings)
        overall = (
            sum(compliance_scores.values()) / len(compliance_scores)
            if compliance_scores else 0.0
        )
    else:
        compliance_scores = {}
        overall = 0.0
        scope_note = (
            "No AI system detected (EU AI Act Art. 3(1)): no AI/ML framework, "
            "model typology, or agent-runtime signal was found. Compliance "
            "scoring is not applicable and has been skipped — this is not a "
            "measure of (non-)compliance. Add the AI/ML components, then re-scan."
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
            {
                "findings": [],
                "gaps": [],
                "dims": set(),
                "gap_line": None,
                "gap_pattern": "",
                "any_line": None,
                "any_pattern": "",
            },
        )
        entry["dims"].update(f.compliance_dimensions)
        if f.compliance_impact == "gap":
            entry["gaps"].append(f.title)
            if entry["gap_line"] is None and f.line_number is not None:
                entry["gap_line"] = f.line_number
            if not entry["gap_pattern"] and f.matched_pattern:
                entry["gap_pattern"] = f.matched_pattern
        else:
            entry["findings"].append(f.title)
        if entry["any_line"] is None and f.line_number is not None:
            entry["any_line"] = f.line_number
        if not entry["any_pattern"] and f.matched_pattern:
            entry["any_pattern"] = f.matched_pattern

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
            line_number=data["gap_line"] if data["gap_line"] is not None else data["any_line"],
            matched_pattern=data["gap_pattern"] or data["any_pattern"],
        ))

    # Compliance-framed risk indicators only make sense for an in-scope AI
    # system. For an out-of-scope project they would misrepresent ordinary
    # "missing test/doc" findings as regulatory risk, so leave them empty.
    risk_indicators: list[str] = []
    if is_ai_system:
        for ar in analyzer_results:
            if not ar.findings and ar.analyzer_id in (
                "test_suite", "documentation", "human_oversight",
                "logging_monitoring", "security_controls",
            ):
                risk_indicators.append(f"AI system detected but no {ar.label.lower()} found")
        by_title: dict[str, dict] = {}
        for f in all_findings:
            if f.compliance_impact != "gap":
                continue
            bucket = by_title.setdefault(f.title, {"paths": [], "count": 0})
            bucket["count"] += 1
            if f.file_path and f.file_path not in bucket["paths"]:
                bucket["paths"].append(f.file_path)
        for title, bucket in by_title.items():
            paths: list[str] = bucket["paths"]
            count: int = bucket["count"]
            if not paths:
                row = f"{title} (+{count - 1} more)" if count > 1 else title
                risk_indicators.append(row)
                continue
            head = paths[0]
            parts = head.replace("\\", "/").split("/")
            short = "/".join(parts[-3:]) if len(parts) > 3 else head
            more = max(len(paths) - 1, count - 1)
            row = f"{title} — {short}"
            if more > 0:
                row += f" (+{more} more)"
            risk_indicators.append(row)
        risk_indicators = risk_indicators[:10]

    # Role determination: an explicit role scopes obligations; otherwise the
    # inferred role(s) are only reported (never used to hide gaps). The
    # extraterritorial role is a modifier layered on the inferred core roles.
    role_scope: dict = {}
    if is_ai_system:
        from scanner.data.role_obligations import is_extraterritorial_modifier
        if role and not is_extraterritorial_modifier(role):
            effective_roles = [role]
        elif role:
            effective_roles = list(dict.fromkeys([*inferred_roles, role]))
        else:
            effective_roles = list(inferred_roles)
        role_scope = obligations.compute_role_scope(
            effective_roles, compliance_scores, explicit=bool(role),
        )
    deferred_dims = set(role_scope.get("out_of_scope_dimensions", [])) if role else set()

    recommendations: list[str] = []
    for dim_id, score in sorted(compliance_scores.items(), key=lambda x: x[1]):
        if dim_id in deferred_dims:
            continue
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
        is_ai_system=is_ai_system,
        overall_compliance=round(overall, 1),
    )

    # Cross-framework readiness summary
    cross_framework_summary: dict[str, float] = {}
    if cross_framework and is_ai_system:
        from scanner.cross_framework import project_scan_to_frameworks
        temp_res = ScanResult(
            project_name=name,
            compliance_scores=compliance_scores,
            is_ai_system=is_ai_system,
        )
        cross_proj = project_scan_to_frameworks(temp_res)
        cross_framework_summary = {
            fw.framework_label: fw.coverage_pct for fw in cross_proj.frameworks if fw.assessed
        }

    # Semantic audit is intentionally NOT run headlessly here. When deep=True
    # (legacy flag) record a pointer so callers know where semantic review
    # lives: the host Claude Code session or an MCP client.
    semantic_audit_dict: dict | None = None
    if deep:
        semantic_audit_dict = {
            "summary": (
                "Semantic review lives in your own Claude Code session "
                "(assisted mode, `/ai-act-scan --deep` narrative) or any "
                "MCP client over the `scan_project` tool — no separate "
                "subscription wrapper required."
            ),
            "findings": [],
            "cleared_false_positives": [],
            "error": None,
        }

    return ScanResult(
        project_name=name,
        scanner_version=__version__,
        total_files=total_files,
        total_size_bytes=total_size,
        languages=dict(languages.most_common(20)),
        is_ai_system=is_ai_system,
        ai_system_signals=ai_system_signals,
        scope_note=scope_note,
        components=components,
        architecture=architecture,
        compliance_scores=compliance_scores,
        overall_compliance_pct=round(overall, 1),
        risk_indicators=risk_indicators,
        recommendations=recommendations,
        agentic_recommendations=agentic_recommendations,
        evidence_map=evidence_map_clean,
        file_findings=file_findings,
        pre_filled_answers=pre_filled,
        incident_grounding=incident_grounding_map,
        inferred_roles=inferred_roles,
        active_role=role,
        role_scope=role_scope,
        cross_framework_summary=cross_framework_summary,
        semantic_audit=semantic_audit_dict,
        external_security_sources=resolved_external_sources,
    )
