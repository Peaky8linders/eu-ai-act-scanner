"""MCP server for the Antifragile Harness.

Exposes the scanner's deterministic engine as Model Context Protocol tools so
any MCP-capable agent (Claude Code, Claude Desktop, Cursor, custom agents) can
call the scanner with its **own model subscription** — no API key, no local
subscription wrapper.

Transport: stdio by default (``antifragile-scan-mcp``). The same ``FastMCP`` app
can be served over Streamable HTTP behind your own authenticated proxy; see
``build_server()`` notes on Origin/Host validation (MCP spec 2025-11 / 2026).

Security posture (aligned with MCP spec 2025-11-25 + 2026 hardening guidance):

* stdio: stdout carries **only** MCP messages — all logs go to stderr.
* All ``path`` inputs must resolve to an existing directory; symlinks resolved;
  a filesystem root is refused so a stray call cannot walk the whole disk.
* ``output_path`` writes are validated on the **resolved** target: allowlisted
  suffix (``.json`` / ``.html`` / ``.sarif``) checked after resolution, no write through a
  symlink, no NUL bytes, existing parent. Absolute paths are permitted by
  design — the caller is the local user, and the CLI writes beside the project
  — so this is a data-loss guard (a scan must not clobber ``package.json``),
  not a sandbox. Deployers fronting this server over HTTP must confine writes
  at the proxy layer.
* ``limit`` clamped to 1-50; ``max_iterations`` clamped to 1-5; oversized
  strings truncated. Unknown enum values return structured ``{"error": ...}``
  instead of raising.
* Write-capable tools (``remediation_loop`` with ``apply=True``, dossier/graph
  export) are annotated destructive and default to read-only dry-run.
* No network calls, no telemetry, no secrets in tool surfaces.

Install the MCP extra from this repository (there is no PyPI package):

    git clone https://github.com/Peaky8linders/antifragile-harness
    cd antifragile-harness && pip install -e ".[mcp]"

Run the server (stdio transport):
    antifragile-scan-mcp
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Any, Literal

from scanner import agent_views as views
from scanner.cross_framework import project_scan_to_frameworks
from scanner.dossier import generate_dossier
from scanner.fix_loop import run_fix_loop
from scanner.incident_grounding import (
    incident_corpus_stats,
    incidents_for_article,
    incidents_for_dimension,
    incidents_for_key,
    incidents_for_threat,
)
from scanner.kb import DIMENSIONS, dimensions_for_article
from scanner.orchestrator import scan_project

try:
    from scanner.data.role_obligations import CANONICAL_ROLE_IDS as _ROLE_IDS

    _VALID_ROLES: frozenset[str] = frozenset(_ROLE_IDS)
except Exception:  # pragma: no cover — data module always present in practice
    _VALID_ROLES = frozenset({"provider", "deployer", "gpai_provider"})

try:
    from scanner.data.frameworks import CANONICAL_FRAMEWORK_IDS
    from scanner.data.frameworks import normalize_framework_id as _normalize_fw

    _VALID_FRAMEWORKS: frozenset[str] = frozenset(CANONICAL_FRAMEWORK_IDS)
except Exception:  # pragma: no cover
    _VALID_FRAMEWORKS = frozenset({
        "nist_ai_rmf", "iso_42001", "owasp_llm", "owasp_agentic",
        "gdpr", "mitre_atlas", "soc2", "csa_aicm",
    })

    def _normalize_fw(fw_id: str) -> str:  # type: ignore[no-redef]
        return (fw_id or "").strip().lower()
_ARTICLE_RE = re.compile(r"^art\d{1,3}$")
_MAX_STR = 512
_MAX_INGEST_FILES = 20
_MAX_INPUT_FILE_BYTES = 20 * 1024 * 1024  # 20 MB cap on external report files
_OUTPUT_SUFFIXES = (".json", ".html", ".sarif")

# ---------------------------------------------------------------------------
# Validation helpers — NO mcp dependency
# ---------------------------------------------------------------------------


def _clamp_limit(limit: int, default: int = 5) -> int:
    try:
        n = int(limit)
    except (TypeError, ValueError):
        return default
    return max(1, min(50, n))


def _clean_str(value: object, max_len: int = _MAX_STR) -> str:
    return str(value or "").strip()[:max_len]


def _validate_scan_path(path: str) -> Path:
    """Resolve *path* and require an existing directory (symlinks resolved).

    Raises ValueError with a safe message (no stack trace) on any problem.
    """
    cleaned = _clean_str(path, 1024)
    if not cleaned:
        raise ValueError("path is required")
    candidate = Path(cleaned).expanduser()
    resolved = candidate.resolve() if candidate.is_absolute() else (Path.cwd() / candidate).resolve()
    if not resolved.is_dir():
        raise ValueError(f"not a directory: {cleaned[:120]}")
    if resolved.parent == resolved:
        # `/` or `C:\` — a scan of the whole filesystem is never the intent and
        # would read outside any project the user meant to check.
        raise ValueError("refusing to scan a filesystem root")
    return resolved


def _validate_output_path(
    output_path: str,
    *,
    expected_suffix: str | tuple[str, ...],
) -> Path:
    """Validate export writes: allowlisted suffix, existing parent, no symlink.

    Relative paths resolve under the process cwd; absolute paths are allowed
    (the caller is the local user and the CLI writes beside the project). The
    suffix is checked on the **resolved** target, not the raw string, and the
    final component must not be a symlink: otherwise `report.json` pointing at
    a shell profile, or a path that resolves into one, would be written
    through. HTTP deployments fronting this server must additionally confine
    writes at the proxy layer.
    """
    cleaned = _clean_str(output_path, 512)
    if not cleaned:
        raise ValueError("output_path is required")
    if "\x00" in cleaned:
        raise ValueError("invalid output_path")
    allowed = (expected_suffix,) if isinstance(expected_suffix, str) else tuple(expected_suffix)
    for suffix in allowed:
        if suffix not in _OUTPUT_SUFFIXES:
            raise ValueError(f"unsupported suffix: {suffix!r}")
    base = Path.cwd().resolve()
    candidate = Path(cleaned).expanduser()
    unresolved = candidate if candidate.is_absolute() else base / candidate
    if unresolved.is_symlink():
        raise ValueError(f"refusing to write through a symlink: {cleaned[:120]}")
    resolved = unresolved.resolve()
    # Check the resolved path: `x.json/../evil.sh` and symlinked parents both
    # change the real target after a raw-string suffix check.
    if resolved.suffix.lower() not in allowed:
        expected_label = " or ".join(allowed)
        raise ValueError(f"output_path must resolve to a {expected_label} file")
    if not resolved.parent.is_dir():
        raise ValueError(f"output parent does not exist: {str(resolved.parent)[:120]}")
    return resolved


def _validate_input_file(
    file_path: str,
    *,
    allowed_suffixes: tuple[str, ...],
    root_dir: Path | None = None,
) -> Path:
    """Validate an external local report file before ingestion.

    Guards against empty paths, NUL bytes, symlinks, relative traversal escapes
    outside *root_dir* / process cwd, unexpected suffixes after resolution,
    missing/non-file targets, and oversized inputs.
    """
    cleaned = _clean_str(file_path, 1024)
    if not cleaned:
        raise ValueError("input file path is required")
    if "\x00" in cleaned:
        raise ValueError("invalid input file path")

    candidate = Path(cleaned).expanduser()
    if candidate.is_absolute():
        if candidate.is_symlink():
            raise ValueError(f"refusing to read through a symlink: {cleaned[:120]}")
        resolved = candidate.resolve()
        if resolved.parent == resolved:
            raise ValueError("refusing to read a filesystem root")
    else:
        cwd = Path.cwd().resolve()
        resolved = None
        if root_dir is not None:
            in_root = root_dir / candidate
            if in_root.is_symlink():
                raise ValueError(f"refusing to read through a symlink: {cleaned[:120]}")
            cand_root = in_root.resolve()
            if cand_root.is_relative_to(root_dir) and cand_root.is_file():
                resolved = cand_root
        if resolved is None:
            in_cwd = cwd / candidate
            if in_cwd.is_symlink():
                raise ValueError(f"refusing to read through a symlink: {cleaned[:120]}")
            cand_cwd = in_cwd.resolve()
            if not cand_cwd.is_relative_to(cwd):
                raise ValueError(f"input path escapes allowed directory: {cleaned[:120]}")
            resolved = cand_cwd

    if resolved is None:  # pragma: no cover - both branches above assign it
        raise ValueError(f"unable to resolve input file: {cleaned[:120]}")
    if resolved.suffix.lower() not in allowed_suffixes:
        expected_label = ", ".join(allowed_suffixes)
        raise ValueError(
            f"input file must resolve to one of ({expected_label}): {cleaned[:120]}"
        )
    if not resolved.is_file():
        raise ValueError(f"input file not found: {cleaned[:120]}")
    try:
        if resolved.stat().st_size > _MAX_INPUT_FILE_BYTES:
            raise ValueError(f"input file exceeds size limit: {cleaned[:120]}")
    except OSError as exc:
        raise ValueError(f"unable to stat input file: {cleaned[:120]}") from exc
    return resolved


def _validate_input_file_list(
    paths: list[str] | tuple[str, ...] | str | None,
    *,
    allowed_suffixes: tuple[str, ...],
    root_dir: Path | None = None,
    field_name: str = "paths",
) -> list[Path]:
    """Validate a sequence of external local report file paths."""
    if paths is None:
        return []
    if isinstance(paths, str):
        raw_list = [paths]
    elif isinstance(paths, (list, tuple)):
        raw_list = list(paths)
    else:
        raise ValueError(f"{field_name} must be a list of file paths")
    if len(raw_list) > _MAX_INGEST_FILES:
        raise ValueError(f"{field_name} exceeds maximum of {_MAX_INGEST_FILES} files")
    return [
        _validate_input_file(str(p), allowed_suffixes=allowed_suffixes, root_dir=root_dir)
        for p in raw_list
    ]


def _validate_frameworks(target_frameworks: list[str] | None) -> list[str] | None:
    if target_frameworks is None:
        return None
    cleaned = [_normalize_fw(_clean_str(f, 64)) for f in target_frameworks][:16]
    unknown = [f for f in cleaned if f not in _VALID_FRAMEWORKS]
    if unknown:
        raise ValueError(
            f"unknown frameworks: {', '.join(unknown[:5])}; expected some of {sorted(_VALID_FRAMEWORKS)}"
        )
    return cleaned


def _resolve_area(area: str | None) -> set[str] | None:
    """Map an area filter (dimension id or any article spelling) to KB dimension ids."""
    raw = _clean_str(area, 64)
    if not raw:
        return None
    if raw.lower() in DIMENSIONS:
        return {raw.lower()}
    from scanner.refs import article_key

    key = article_key(raw if not raw.isdigit() else f"Art. {raw}")
    dims = {d.id for d in dimensions_for_article(key)} if key else set()
    if not dims:
        raise ValueError(
            f"unknown area {raw!r}; use an area id such as 'security' or 'human_oversight' "
            "(see list_dimensions) or an article such as 'art50'"
        )
    return dims


# ---------------------------------------------------------------------------
# Scan cache — paging/filtering calls reuse a scan until the project changes
# ---------------------------------------------------------------------------

_SCAN_CACHE: OrderedDict[tuple, Any] = OrderedDict()
_SCAN_CACHE_SIZE = 4
_CLAUDE_CONFIG_GLOBS = ("settings.json", "settings.local.json", "*.md", "hooks/*.json", "commands/*.md")


def _project_fingerprint(root: Path) -> str:
    """Hash of (path, size, mtime) for every file a scan would read.

    Cheap next to a scan (stat only, no reads), and any edit — including one
    the agent just applied — changes it, so a cached result is never stale.
    """
    from scanner.orchestrator import _walk_project_files

    digest = hashlib.sha256()
    entries: list[Path] = list(_walk_project_files(root))
    claude_dir = root / ".claude"
    if claude_dir.is_dir():
        for pattern in _CLAUDE_CONFIG_GLOBS:
            entries.extend(sorted(claude_dir.glob(pattern)))
    for path in entries:
        try:
            stat = path.stat()
        except OSError:
            continue
        digest.update(f"{path.as_posix()}|{stat.st_size}|{stat.st_mtime_ns}\n".encode())
    return digest.hexdigest()


def _scan(
    resolved: Path,
    *,
    role: str | None = None,
    cross_framework: bool = False,
    project_name: str | None = None,
):
    """``scan_project`` with a small fingerprint-keyed LRU cache."""
    key = (str(resolved), role, bool(cross_framework), project_name, _project_fingerprint(resolved))
    cached = _SCAN_CACHE.get(key)
    if cached is not None:
        _SCAN_CACHE.move_to_end(key)
        return cached
    result = scan_project(
        resolved,
        project_name=project_name,
        role=role,
        deep=False,  # semantic depth lives in the MCP client, never headless
        cross_framework=bool(cross_framework),
    )
    _SCAN_CACHE[key] = result
    while len(_SCAN_CACHE) > _SCAN_CACHE_SIZE:
        _SCAN_CACHE.popitem(last=False)
    return result


def _is_detailed(response_format: object) -> bool:
    return views.normalize_response_format(response_format) == "detailed"


# ---------------------------------------------------------------------------
# Plain tool functions — NO mcp dependency
# ---------------------------------------------------------------------------


def tool_scan_project(
    path: str,
    project_name: str | None = None,
    role: str | None = None,
    deep: bool = False,
    cross_framework: bool = False,
    response_format: str = "detailed",
    area: str | None = None,
    limit: int = views.GAP_LIMIT,
    offset: int = 0,
) -> dict:
    """Scan a codebase at *path* for EU AI Act compliance evidence and gaps.

    ``response_format="detailed"`` (the library default) returns the full
    :class:`scanner.models.ScanResult` as a dict. ``"concise"`` (the MCP
    default) returns scope, overall score, scores lowest-first and the top
    ``limit`` prioritised gaps from ``offset`` with ``where`` = file:line.
    ``area`` (a dimension id or any article spelling) filters gaps and scores
    in both formats.

    Check ``is_ai_system`` first: when ``False`` the codebase is out of EU AI
    Act scope (no AI/ML/agent signal), ``compliance_scores`` is empty, and
    ``overall_compliance_pct`` is ``0.0`` but **not** a compliance measure —
    ``scope_note`` explains why scoring was skipped.
    """
    try:
        resolved = _validate_scan_path(path)
        areas = _resolve_area(area)
    except ValueError as exc:
        return {"error": str(exc), "path": _clean_str(path, 120)}
    if role is not None and role not in _VALID_ROLES:
        return {"error": f"unknown role {role!r}; expected one of {sorted(_VALID_ROLES)}"}
    result = _scan(
        resolved,
        role=role,
        cross_framework=bool(cross_framework),
        project_name=_clean_str(project_name, 128) or None,
    )
    if not _is_detailed(response_format):
        try:
            offset_n = max(0, int(offset))
        except (TypeError, ValueError):
            offset_n = 0
        return views.concise_scan(
            result, gap_limit=_clamp_limit(limit, default=views.GAP_LIMIT), offset=offset_n, areas=areas
        )
    data = result.model_dump()
    if areas:
        data["components"] = [c for c in data["components"] if set(c["compliance_dimensions"]) & areas]
        data["file_findings"] = [f for f in data["file_findings"] if set(f["compliance_dimensions"]) & areas]
        data["filtered_to_areas"] = sorted(areas)
    return data


def tool_project_cross_framework(
    path: str,
    target_frameworks: list[str] | None = None,
    response_format: str = "detailed",
) -> dict:
    """Scan codebase and project findings onto other AI, security and privacy frameworks.

    Maps the scan to NIST AI RMF, NIST AI 600-1, ISO/IEC 42001, ISO/IEC 27002, NIST SP
    800-53, SOC 2, CSA AICM, OWASP LLM and Agentic Top 10, MITRE ATLAS, CEN-CENELEC JTC 21
    and GDPR, each tagged with its legal force. AI Act evidence *supports* voluntary
    controls; binding law (GDPR) is reported as not assessed. ``"concise"`` returns
    per-framework coverage and the top 'satisfy once' levers; ``"detailed"`` adds
    every control with its incident grounding.
    """
    try:
        resolved = _validate_scan_path(path)
        frameworks = _validate_frameworks(target_frameworks)
    except ValueError as exc:
        return {"error": str(exc)}
    result = _scan(resolved, cross_framework=True)
    projection = project_scan_to_frameworks(result, target_framework_ids=frameworks)
    if not _is_detailed(response_format):
        return views.concise_cross_framework(projection)
    return projection.model_dump()


def tool_generate_dossier(
    path: str,
    output_path: str = "compliance-dossier.json",
    response_format: str = "detailed",
) -> dict:
    """Generate and seal a cryptographic, tamper-evident compliance release dossier.

    Binds SHA-256 file digests, git provenance, compliance scores, and statutory grounding
    under Regulation (EU) 2024/1689 and Digital Omnibus Regulation (EU) 2026/1744.
    ``"concise"`` returns a receipt (path, integrity hash, commit, files covered); the
    sealed dossier itself is always in the written file.
    """
    try:
        resolved = _validate_scan_path(path)
        out = _validate_output_path(output_path, expected_suffix=".json")
    except ValueError as exc:
        return {"error": str(exc)}
    result = _scan(resolved, cross_framework=True)
    dossier = generate_dossier(result, resolved)
    dossier.export_json(str(out))
    if not _is_detailed(response_format):
        return views.dossier_receipt(dossier, str(out))
    return dossier.model_dump()


def tool_remediation_loop(
    path: str,
    apply: bool = False,
    max_iterations: int = 3,
    response_format: str = "detailed",
) -> dict:
    """Run autonomous scan -> fix -> rescan remediation pipeline with regression guard.

    When *apply* is False, returns ranked proposals and verification instructions (safe preview).
    When *apply* is True, writes production-grade remediation artifacts and re-evaluates scores.
    ``"concise"`` lists proposals without their file contents.
    """
    try:
        resolved = _validate_scan_path(path)
    except ValueError as exc:
        return {"error": str(exc)}
    try:
        iters = max(1, min(5, int(max_iterations)))
    except (TypeError, ValueError):
        iters = 3
    fix_result = run_fix_loop(resolved, apply=bool(apply), max_iterations=iters)
    if not _is_detailed(response_format):
        return views.remediation_summary(fix_result)
    return fix_result.model_dump()


def tool_generate_visual_graph(
    path: str,
    output_path: str = "context-graph.html",
    response_format: str = "detailed",
) -> dict:
    """Generate an interactive visual context graph browser for the scanned codebase.

    Allows users to inspect nodes for compliance gaps, regulatory articles, cross-framework
    linkages, grounded real-world incidents, and copyable recommended fixes.
    ``"concise"`` returns the file path plus node and gap counts.
    """
    try:
        resolved = _validate_scan_path(path)
        out = _validate_output_path(output_path, expected_suffix=".html")
    except ValueError as exc:
        return {"error": str(exc)}
    from scanner.visual_graph import build_graph_data, generate_visual_graph
    result = _scan(resolved, cross_framework=True)
    generate_visual_graph(result, output_path=out, root_path=resolved)
    if not _is_detailed(response_format):
        gap_nodes = [n.label for n in result.architecture if n.compliance_status == "gap"]
        return {
            "status": "success",
            "output_path": str(out),
            "nodes": len(result.architecture),
            "gap_nodes": gap_nodes[:8],
            "more": "Open the HTML file in a browser; response_format='detailed' returns the graph data.",
        }
    return {
        "status": "success",
        "output_path": str(out),
        "graph_summary": build_graph_data(result, resolved),
    }


def tool_list_dimensions() -> list[dict]:
    """List all EU AI Act compliance dimensions tracked by the scanner.

    Each entry has ``id``, ``label``, ``article``, and ``description``.
    """
    return [
        {
            "id": dim.id,
            "label": dim.label,
            "article": dim.article,
            "description": dim.description,
        }
        for dim in DIMENSIONS.values()
    ]


def tool_get_article(article: str, response_format: str = "detailed") -> dict:
    """Get compliance dimensions, cross-framework controls, and incidents for an article.

    *article* accepts any spelling: ``art15``, ``Art. 15``, ``Article 15.4`` or
    ``15``. Returns ``{article, dimensions, frameworks, incidents}``; if the article is
    unknown the response also contains an ``error`` key and empty lists.
    ``frameworks`` maps canonical framework IDs (NIST AI RMF, ISO 42001, OWASP
    LLM/Agentic, GDPR, ...) to control IDs from crosswalk catalogue
    ``scanner.data.frameworks.CROSSWALK_CATALOGUE_VERSION``. ``"concise"`` lists
    incidents as id/title/year/severity only.
    """
    from scanner.data.frameworks import get_crosswalk_for_article
    from scanner.refs import article_key as _kb_article_key

    raw = _clean_str(article, 32)
    article_key = _kb_article_key(raw)
    dims = dimensions_for_article(article_key) if article_key else []
    if not dims:
        return {
            "article": article_key or raw.lower(),
            "dimensions": [],
            "frameworks": {},
            "incidents": [],
            "error": f"unknown article {raw!r} — use 'artNN' (e.g. 'art15') or 'Art. 15'",
        }
    incs = incidents_for_article(article_key)
    frameworks: dict[str, list[str]] = {
        _normalize_fw(k): sorted(v)
        for k, v in get_crosswalk_for_article(raw).items()
    }
    if not _is_detailed(response_format):
        return {
            "article": article_key,
            "dimensions": [{"id": d.id, "label": d.label} for d in dims],
            "frameworks": frameworks,
            "incidents": [
                {"id": inc.id, "title": inc.title, "year": inc.year, "severity": inc.severity}
                for inc in incs
            ],
            "more": "Call incidents(key=...) for mitigations, or response_format='detailed' for full records.",
        }
    return {
        "article": article_key,
        "dimensions": [
            {"id": d.id, "label": d.label, "article": d.article, "description": d.description}
            for d in dims
        ],
        "frameworks": frameworks,
        "incidents": [inc.to_dict() for inc in incs],
    }


def tool_incidents_for_dimension(dim_id: str, limit: int = 5) -> list[dict]:
    """Return up to *limit* incidents relevant to a KB compliance dimension.

    *dim_id* is a dimension identifier such as ``"security"``, ``"logging"``,
    or ``"tool_governance"``. Unknown ids return an empty list.
    """
    return [inc.to_dict() for inc in incidents_for_dimension(_clean_str(dim_id, 64), limit=_clamp_limit(limit))]


def tool_incidents_for_threat(threat_id: str, limit: int = 5) -> list[dict]:
    """Return up to *limit* incidents that exploited an agentic threat category.

    *threat_id* is a :class:`scanner.data.agentic_taxonomy.ThreatCategory`
    value, e.g. ``"prompt_injection"`` or ``"tool_misuse_privilege_escalation"``.
    Unknown ids return an empty list.
    """
    return [inc.to_dict() for inc in incidents_for_threat(_clean_str(threat_id, 128), limit=_clamp_limit(limit))]


def tool_incidents_for_article(article: str, limit: int = 5) -> list[dict]:
    """Return up to *limit* incidents relevant to an EU AI Act article.

    *article* should be in canonical ``artNN`` form (e.g. ``art15``).
    Unions across all KB dimensions mapped to the article and deduplicates.
    Unknown articles return an empty list.
    """
    key = _clean_str(article, 16).lower()
    if not _ARTICLE_RE.match(key):
        return []
    return [inc.to_dict() for inc in incidents_for_article(key, limit=_clamp_limit(limit))]


def tool_incident_corpus_stats() -> dict:
    """Summary of the bundled incident corpus.

    Includes count, real-world vs research split, provenance, license
    (CC-BY-4.0), and taxonomy coverage (OWASP LLM, OWASP ASI, MITRE ATLAS).
    """
    return incident_corpus_stats()


def tool_incidents(
    key: str | None = None,
    limit: int = 5,
    response_format: str = "detailed",
) -> dict:
    """Documented AI security incidents for an area, article or threat — one lookup.

    *key* may be a KB dimension (``security``), any article spelling (``art15``,
    ``Art. 15``, ``Article 15(4)``) or an agentic threat (``prompt_injection``).
    Without a key, returns corpus statistics. ``"concise"`` entries carry id,
    title, year, severity, a short summary and up to two mitigations.
    """
    raw = _clean_str(key, 128)
    if not raw:
        stats = dict(incident_corpus_stats())
        stats["usage"] = "Pass key='security', 'art15' or 'prompt_injection' to list incidents."
        return stats
    resolved_as, incidents = incidents_for_key(raw, limit=_clamp_limit(limit))
    if not incidents:
        return {
            "key": raw,
            "resolved_as": None,
            "incidents": [],
            "error": (
                f"No incidents found for {raw!r}. Use an area (e.g. 'security', 'human_oversight'), "
                "an article (e.g. 'art15') or a threat (e.g. 'prompt_injection')."
            ),
        }
    records = [inc.to_dict() for inc in incidents]
    if not _is_detailed(response_format):
        records = [views.compact_incident(r) for r in records]
    return {"key": raw, "resolved_as": resolved_as, "count": len(records), "incidents": records}


def tool_agentic_taxonomy(risk_id: str | None = None) -> dict:
    """Browse agentic compound-risk guidance with machine-readable provenance.

    Every mitigation and evidence item is tagged ``act_required`` (the item
    implements an EU AI Act duty; ``ref`` cites the provision) or
    ``paper_suggested`` (the working paper recommends it beyond the Act;
    ``ref`` cites the paper). Pass *risk_id* (``cascading``, ``emergent``,
    ``attribution`` or ``temporal``) to narrow the response; an unknown id
    returns an ``error`` plus an empty list.
    """
    from scanner.data.agentic_taxonomy import COMPOUND_RISK_BY_ID, TAXONOMY_VERSION

    key = _clean_str(risk_id, 64) if risk_id else ""
    if key and key not in COMPOUND_RISK_BY_ID:
        return {
            "taxonomy_version": TAXONOMY_VERSION,
            "compound_risks": [],
            "error": (
                f"unknown compound risk {key!r}; expected one of "
                f"{sorted(COMPOUND_RISK_BY_ID)}"
            ),
        }
    selected = (
        [COMPOUND_RISK_BY_ID[key]] if key else list(COMPOUND_RISK_BY_ID.values())
    )
    recs = [rec for entry in selected for rec in entry.get("recommendations", [])]
    return {
        "taxonomy_version": TAXONOMY_VERSION,
        "provenance_legend": {
            "act_required": "EU AI Act duty implemented by the item; ref cites the provision",
            "paper_suggested": "Working-paper recommendation beyond the Act; ref cites the paper",
        },
        "provenance_counts": {
            "act_required": sum(1 for r in recs if r["source"] == "act_required"),
            "paper_suggested": sum(1 for r in recs if r["source"] == "paper_suggested"),
        },
        "compound_risks": [
            {
                "id": entry["id"],
                "label": entry.get("label", entry["id"]),
                "summary": entry.get("summary", ""),
                "article_refs": entry.get("article_refs", []),
                "recommendations": entry.get("recommendations", []),
            }
            for entry in selected
        ],
    }


def tool_founder_triage(
    path: str = ".",
    role: str | None = None,
    response_format: str = "detailed",
) -> dict:
    """Return a plain-English 3-bucket Founder/Startup compliance triage.

    Splits gaps into ``ship_now`` (live Art. 50 transparency + MCP/Claude Code/
    security blockers), ``enterprise_deals`` (SOC 2 / GDPR / OWASP blockers plus
    top 3 cross-framework levers and deployer vendor-contract checklist), and
    ``later_2027`` (Annex III obligations deferred to 2 Dec 2027 under Digital
    Omnibus Regulation (EU) 2026/1744). Includes copy-pasteable ``brief_markdown``.
    ``"concise"`` returns the brief plus counts, without the structured buckets.
    """
    from scanner.founder_triage import build_founder_triage

    try:
        resolved = _validate_scan_path(path)
    except ValueError as exc:
        return {"error": str(exc), "path": _clean_str(path, 120)}
    if role is not None and role not in _VALID_ROLES:
        return {"error": f"unknown role {role!r}; expected one of {sorted(_VALID_ROLES)}"}
    result = _scan(resolved, role=role, cross_framework=True)
    triage = build_founder_triage(result)
    if not _is_detailed(response_format):
        return views.concise_founder(triage)
    return triage.model_dump()


def tool_export_sarif(
    path: str = ".",
    output_path: str = "eu-ai-act.sarif.json",
    role: str | None = None,
    response_format: str = "detailed",
) -> dict:
    """Scan *path* and export an offline SARIF 2.1.0 report to *output_path*.

    Emits strictly offline SARIF 2.1.0 JSON (zero remote URLs). Output target
    must resolve to a ``.json`` or ``.sarif`` file without traversing a symlink.
    ``"concise"`` returns a receipt; ``"detailed"`` also echoes the document.
    """
    from scanner.sarif import scan_to_sarif, write_sarif

    try:
        resolved = _validate_scan_path(path)
        out = _validate_output_path(output_path, expected_suffix=(".json", ".sarif"))
    except ValueError as exc:
        return {"error": str(exc)}
    if role is not None and role not in _VALID_ROLES:
        return {"error": f"unknown role {role!r}; expected one of {sorted(_VALID_ROLES)}"}

    result = _scan(resolved, role=role)
    sarif_doc = scan_to_sarif(result)
    write_sarif(result, out)
    run = sarif_doc["runs"][0]
    levels: dict[str, int] = {}
    for entry in run["results"]:
        levels[entry.get("level", "warning")] = levels.get(entry.get("level", "warning"), 0) + 1
    payload: dict = {
        "status": "success",
        "output_path": str(out),
        "sarif_version": sarif_doc["version"],
        "is_ai_system": result.is_ai_system,
        "results_count": len(run["results"]),
        "rules_count": len(run["tool"]["driver"]["rules"]),
        "results_by_level": levels,
    }
    if _is_detailed(response_format):
        payload["sarif"] = sarif_doc
    return payload


_SARIF_SUFFIXES = (".sarif", ".json")
_COMPLIANCE_API_SUFFIXES = (".json", ".jsonl", ".ndjson")
_CLAUDE_SECURITY_SUFFIXES = (".sarif", ".json", ".jsonl", ".ndjson", ".md", ".markdown", ".txt")


def tool_ingest_security_reports(
    path: str = ".",
    claude_security_paths: list[str] | None = None,
    sarif_paths: list[str] | None = None,
    compliance_api_paths: list[str] | None = None,
    role: str | None = None,
    output_dossier: str | None = None,
    response_format: str = "detailed",
) -> dict:
    """Merge local security / compliance reports into a scan of *path*.

    Accepts any mix of: ``claude_security_paths`` (Claude Code Security JSONL /
    JSON / Markdown / SARIF, or ``/security-review`` output; findings refuted by
    its verification panel are dropped), ``sarif_paths`` (Semgrep, Bandit, Snyk,
    CodeQL, GitHub Advanced Security) and ``compliance_api_paths`` (Claude
    Compliance API exports). Strictly offline: reads local files only. Confirmed
    findings map to Art. 15(4) / Art. 9(2); Compliance API exports are audited for
    Art. 12 / 26(6) log retention, unsafe user instructions and unreviewed remote
    actions. Optionally seals a release dossier at *output_dossier*.
    """
    from scanner.claude_ecosystem import (
        ingest_claude_security_report,
        ingest_compliance_api_export,
    )
    from scanner.sarif import ingest_sarif_files

    try:
        resolved = _validate_scan_path(path)
        validated_cs = _validate_input_file_list(
            claude_security_paths, allowed_suffixes=_CLAUDE_SECURITY_SUFFIXES,
            root_dir=resolved, field_name="claude_security_paths",
        )
        validated_sarif = _validate_input_file_list(
            sarif_paths, allowed_suffixes=_SARIF_SUFFIXES, root_dir=resolved, field_name="sarif_paths",
        )
        validated_cca = _validate_input_file_list(
            compliance_api_paths, allowed_suffixes=_COMPLIANCE_API_SUFFIXES,
            root_dir=resolved, field_name="compliance_api_paths",
        )
        if not (validated_cs or validated_sarif or validated_cca):
            raise ValueError(
                "provide at least one report: claude_security_paths (Claude Code Security), "
                "sarif_paths (Semgrep/Bandit/Snyk/CodeQL) or compliance_api_paths (Claude Compliance API)"
            )
        dossier_out = (
            _validate_output_path(output_dossier, expected_suffix=".json") if output_dossier else None
        )
    except ValueError as exc:
        return {"error": str(exc)}
    if role is not None and role not in _VALID_ROLES:
        return {"error": f"unknown role {role!r}; expected one of {sorted(_VALID_ROLES)}"}

    external_findings: list = []
    external_sources: list[str] = []
    compliance_meta: dict | None = None
    claude_sec_meta: dict | None = None
    sarif_tools: list[str] = []

    def _add_source(label: str) -> None:
        if label and label not in external_sources:
            external_sources.append(label)

    try:
        if validated_cca:
            cca_findings, compliance_meta = ingest_compliance_api_export(validated_cca)
            external_findings.extend(cca_findings)
            _add_source(str(compliance_meta.get("source") or "anthropic_claude_compliance_api"))
        if validated_cs:
            cs_findings, claude_sec_meta = ingest_claude_security_report(validated_cs)
            external_findings.extend(cs_findings)
            for tool_name in claude_sec_meta.get("source_tools") or ["claude-security"]:
                _add_source(str(tool_name))
        if validated_sarif:
            sarif_findings, sarif_tools = ingest_sarif_files(validated_sarif)
            external_findings.extend(sarif_findings)
            for tool_name in sarif_tools:
                _add_source(str(tool_name))
    except ValueError as exc:
        return {"error": str(exc)}

    result = scan_project(
        resolved,
        role=role,
        cross_framework=True,
        external_findings=external_findings,
        external_sources=external_sources,
    )
    dossier_fields: dict = {}
    if dossier_out is not None:
        dossier = generate_dossier(result, resolved)
        dossier.export_json(str(dossier_out))
        dossier_fields = {
            "dossier_path": str(dossier_out),
            "dossier_integrity_hash": dossier.dossier_integrity_hash,
        }

    if not _is_detailed(response_format):
        ranked = sorted(
            external_findings,
            key=lambda f: (views._SEVERITY_RANK.get((f.severity or "").lower(), 5), -f.confidence),
        )
        out: dict = {
            "status": "success",
            "external_sources": external_sources,
            "external_findings_count": len(external_findings),
            "top_external_findings": [
                {"title": f.title, "severity": f.severity or None, "where": views.where(f.file_path, f.line_number)}
                for f in ranked[: views.GAP_LIMIT]
            ],
            "is_ai_system": result.is_ai_system,
            "overall_compliance_pct": result.overall_compliance_pct if result.is_ai_system else None,
        }
        if compliance_meta:
            out["compliance_api"] = {
                k: compliance_meta.get(k)
                for k in ("counts", "retention_days", "unsafe_preferences_count", "unreviewed_remote_actions_count")
            }
        if claude_sec_meta:
            out["claude_security"] = {
                k: claude_sec_meta.get(k)
                for k in ("confirmed_findings", "filtered_by_adversarial_panel", "severity_counts")
            }
        out.update(dossier_fields)
        out["more"] = "Call founder_triage to see where these land in the action plan, or response_format='detailed'."
        return out

    payload: dict = {
        "status": "success",
        "ingested_files": [str(p) for p in (*validated_cs, *validated_sarif, *validated_cca)],
        "external_sources": external_sources,
        "source_tools": sarif_tools if validated_sarif and not (validated_cs or validated_cca) else external_sources,
        "external_findings_count": len(external_findings),
        "external_findings": [f.model_dump() for f in external_findings],
        "compliance_api_metadata": compliance_meta,
        "claude_security_metadata": claude_sec_meta,
        "is_ai_system": result.is_ai_system,
        "overall_compliance_pct": result.overall_compliance_pct,
        "compliance_scores": result.compliance_scores,
        "scan_result": result.model_dump(),
    }
    payload.update(dossier_fields)
    return payload


def tool_ingest_sarif(
    path: str = ".",
    sarif_paths: list[str] | None = None,
    role: str | None = None,
    output_dossier: str | None = None,
) -> dict:
    """Compatibility wrapper: SARIF-only :func:`tool_ingest_security_reports`."""
    if not sarif_paths:
        return {"error": "sarif_paths must contain at least one local SARIF file path"}
    return tool_ingest_security_reports(
        path, sarif_paths=sarif_paths, role=role, output_dossier=output_dossier,
    )


def tool_ingest_claude_ecosystem(
    path: str = ".",
    compliance_api_paths: list[str] | None = None,
    claude_security_paths: list[str] | None = None,
    role: str | None = None,
    output_dossier: str | None = None,
) -> dict:
    """Compatibility wrapper: Claude Security / Compliance API :func:`tool_ingest_security_reports`."""
    if not compliance_api_paths and not claude_security_paths:
        return {"error": "provide at least one of compliance_api_paths or claude_security_paths"}
    return tool_ingest_security_reports(
        path,
        claude_security_paths=claude_security_paths,
        compliance_api_paths=compliance_api_paths,
        role=role,
        output_dossier=output_dossier,
    )


def tool_regulatory_applicability(
    risk_class: str,
    role: str,
    as_of: str | None = None,
) -> dict:
    """Resolve EU AI Act / Digital Omnibus (Reg. 2026/1744) applicability dates & duties.

    Deterministically returns ``phases_in_force``, ``phases_pending``,
    ``duties_in_force``, and ``duties_pending`` for *risk_class* and *role* on
    ISO date *as_of* (defaults to today).
    """
    from datetime import date

    from scanner.data.omnibus import resolve_applicability
    from scanner.data.ontology import OPERATOR_ROLES, ActorRole, RiskClass

    raw_rc = _clean_str(risk_class, 64).lower()
    try:
        rc_enum = RiskClass(raw_rc)
    except ValueError:
        return {
            "error": (
                f"unknown risk_class {risk_class!r}; expected one of "
                f"{[r.value for r in RiskClass]}"
            )
        }

    raw_role = _clean_str(role, 64).lower()
    if raw_role == "authorized_representative":
        raw_role = "authorised_representative"
    try:
        role_enum = ActorRole(raw_role)
    except ValueError:
        return {
            "error": (
                f"unknown role {role!r}; expected one of "
                f"{[r.value for r in OPERATOR_ROLES]}"
            )
        }
    if role_enum not in OPERATOR_ROLES:
        return {
            "error": (
                f"role {role_enum.value!r} is not a value-chain operator; expected one of "
                f"{[r.value for r in OPERATOR_ROLES]}"
            )
        }

    if as_of is None or not _clean_str(as_of, 32):
        parsed_date = date.today()
    else:
        raw_date = _clean_str(as_of, 32)
        try:
            parsed_date = date.fromisoformat(raw_date)
        except ValueError:
            return {"error": f"invalid as_of date {as_of!r}; expected ISO YYYY-MM-DD"}

    return resolve_applicability(parsed_date, rc_enum, role_enum).model_dump()


# ---------------------------------------------------------------------------
# MCP server wiring — lazy import so tests run without the mcp package
# ---------------------------------------------------------------------------


def _tool_meta(read_only: bool, destructive: bool = False) -> dict:
    """Tool annotations for MCP clients (hint; server still enforces)."""
    return {
        "readOnlyHint": read_only,
        "destructiveHint": destructive,
        "openWorldHint": False,
    }


def _load_server_class():
    """Return the SDK's server class across MCP SDK generations.

    The MCP Python SDK renamed ``FastMCP`` to ``MCPServer`` in 2.0
    (``mcp.server.mcpserver``). 1.x exposes ``mcp.server.fastmcp.FastMCP``.
    Both accept ``(name, instructions=...)`` and a ``tool(name=...,
    annotations=...)`` decorator, so the registration code below is shared.
    """
    try:  # mcp >= 2.0
        from mcp.server.mcpserver import MCPServer

        return MCPServer
    except ImportError:
        pass
    try:  # mcp 1.x
        from mcp.server.fastmcp import FastMCP

        return FastMCP
    except ImportError as exc:
        raise RuntimeError(
            "MCP SDK not installed. Install the engine from this repository: "
            "pip install -e \".[mcp]\" (there is no PyPI package; no PyPI "
            "package is this project)"
        ) from exc


def build_server():  # noqa: ANN201  (returns MCPServer/FastMCP — type only available with extras)
    """Construct and return a configured MCP server (``MCPServer`` / ``FastMCP``).

    Raises :exc:`RuntimeError` if the ``mcp`` optional dependency is not
    installed.  Install it from this repository with::

        git clone https://github.com/Peaky8linders/antifragile-harness
        cd antifragile-harness && pip install -e ".[mcp]"

    HTTP serving (Streamable HTTP) is left to the deployer: serve the app
    returned by ``mcp.http_app()`` behind TLS + authentication, bind
    loopback for local-only use, and enable Host/Origin validation so
    DNS-rebinding from a browser origin returns 403. See MCP spec
    Streamable HTTP security considerations.
    """
    server_cls = _load_server_class()

    from scanner import __version__

    _name = "antifragile-harness"
    _instructions = (
        "Local, offline EU AI Act (Reg. 2024/1689 as amended by Reg. 2026/1744) and AI-security "
        "checks for a codebase. Start with founder_triage for a plain-English action plan, or "
        "scan_project for scores and gaps. Also available: project_cross_framework (SOC 2, ISO "
        "27002/42001, NIST AI RMF, GDPR, OWASP), ingest_security_reports (Claude Code Security, "
        "SARIF, Claude Compliance API), remediation_loop (fix plan; writes only with apply=true), "
        "export_sarif, generate_dossier, generate_visual_graph, regulatory_applicability, "
        "get_article, list_dimensions, incidents, agentic_taxonomy. Responses are concise by "
        "default; pass response_format='detailed' for full data. If is_ai_system is false the Act "
        "does not apply: never quote a compliance percentage for it."
    )
    try:  # mcp >= 2.0 takes version as a constructor field
        mcp = server_cls(_name, instructions=_instructions, version=__version__)
    except TypeError:  # mcp 1.x has no version parameter
        mcp = server_cls(_name, instructions=_instructions)
    # Version surface for discovery. mcp>=2 takes it as a constructor field;
    # on 1.x it is a plain attribute set here.
    if getattr(mcp, "version", None) != __version__:
        mcp.version = __version__  # type: ignore[attr-defined]

    # The SDK forwards a ToolError's message to the model as an isError result;
    # any other exception becomes a generic "Error executing tool" and the
    # guidance (valid values, next step) would be lost.
    tool_error: type[Exception]
    try:
        from mcp.server.mcpserver.exceptions import ToolError as tool_error
    except ImportError:
        try:
            from mcp.server.fastmcp.exceptions import ToolError as tool_error  # type: ignore[no-redef]
        except ImportError:  # pragma: no cover - very old SDKs
            tool_error = ValueError

    def _respond(payload: Any) -> str:
        """Compact text for the model; an error payload raises so the client sees isError.

        Tools return strings with structured output off: the SDK pretty-prints
        dict results (indent=2) and Claude Code forwards only structuredContent
        when both are present, so a compact string is both smaller and exact.
        """
        if isinstance(payload, dict) and payload.get("error") and payload.get("status") != "success":
            raise tool_error(str(payload["error"]))
        if isinstance(payload, str):
            return payload
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)

    def _register(name: str, fn, *, read_only: bool, destructive: bool = False, always_load: bool = False):
        """Register with the richest options the installed SDK accepts."""
        options: dict[str, Any] = {
            "annotations": _tool_meta(read_only, destructive),
            "structured_output": False,
        }
        if always_load:
            options["meta"] = {"anthropic/alwaysLoad": True}
        for dropped in ((), ("meta",), ("meta", "structured_output"), tuple(options)):
            try:
                return mcp.tool(name=name, **{k: v for k, v in options.items() if k not in dropped})(fn)
            except TypeError:
                continue
        return mcp.tool(name=name)(fn)

    def founder_triage(path: str = ".", role: str | None = None, response_format: Literal["concise", "detailed"] = "concise") -> str:
        """Plain-English EU AI Act and AI-security action plan for a codebase; start here.

        Sorts gaps into fix before shipping (live Art. 50 duties, exposed secrets, risky MCP or
        Claude Code settings), enterprise-deal blockers (SOC 2, GDPR, OWASP) and the 2 Dec 2027
        roadmap, explains the operator role, and leaves out duties owed only by other roles.
        Concise returns a ready-to-share markdown brief; 'detailed' returns structured items.
        """
        out = tool_founder_triage(path, role, response_format)
        if views.normalize_response_format(response_format) == "concise" and "brief_markdown" in out:
            return (
                out["brief_markdown"]
                + "\n\n_More: response_format='detailed' gives file, line, effort and PR title per item._"
            )
        return _respond(out)

    def scan_project(
        path: str,
        response_format: Literal["concise", "detailed"] = "concise",
        area: str | None = None,
        limit: int = views.GAP_LIMIT,
        offset: int = 0,
        role: str | None = None,
    ) -> str:
        """Scan a local codebase for EU AI Act evidence and gaps.

        Concise returns the overall score, scores per area (lowest first) and the top gaps with
        file:line; page with offset, filter with area ('security', 'human_oversight' or an article
        such as 'art50'). 'detailed' returns every finding. If is_ai_system is false the Act does
        not apply and no score is given. For a plain-English plan use founder_triage.
        """
        return _respond(tool_scan_project(
            path, role=role, response_format=response_format, area=area, limit=limit, offset=offset,
        ))

    def project_cross_framework(
        path: str,
        target_frameworks: list[str] | None = None,
        response_format: Literal["concise", "detailed"] = "concise",
    ) -> str:
        """Map a scan onto the frameworks customers ask about, each with its legal force.

        SOC 2, ISO/IEC 27002 and 42001, NIST AI RMF and SP 800-53, CSA AICM, OWASP LLM and
        Agentic, MITRE ATLAS, CEN-CENELEC and GDPR. Code evidence supports voluntary controls
        but never proves compliance; binding law (GDPR) is shown as not assessed. Concise returns
        coverage per framework and the top 'satisfy once' fixes; 'detailed' adds every control.
        """
        return _respond(tool_project_cross_framework(path, target_frameworks, response_format))

    def ingest_security_reports(
        path: str = ".",
        claude_security_paths: list[str] | None = None,
        sarif_paths: list[str] | None = None,
        compliance_api_paths: list[str] | None = None,
        role: str | None = None,
        output_dossier: str | None = None,
        response_format: Literal["concise", "detailed"] = "concise",
    ) -> str:
        """Merge local security and compliance reports into a scan of path.

        Claude Code Security (CLAUDE-SECURITY-RESULTS.jsonl, .sarif or .md; /security-review
        JSON), SARIF from Semgrep, Bandit, Snyk or CodeQL, and Claude Compliance API exports.
        Offline; findings refuted by Claude Security's verification panel are dropped. Returns
        sources, top external findings and the updated score; optionally seals a dossier.
        """
        return _respond(tool_ingest_security_reports(
            path, claude_security_paths, sarif_paths, compliance_api_paths, role, output_dossier,
            response_format,
        ))

    def remediation_loop(
        path: str,
        apply: bool = False,
        max_iterations: int = 3,
        response_format: Literal["concise", "detailed"] = "concise",
    ) -> str:
        """Plan, and optionally apply, fixes for the top compliance gaps.

        Scans, proposes fixes, re-scans and rolls back any fix that lowers another score.
        The default is a read-only preview; apply=true writes files into the project. Concise
        lists proposals (title, target file, why); 'detailed' includes each file's content.
        """
        return _respond(tool_remediation_loop(path, apply, max_iterations, response_format))

    def export_sarif(
        path: str = ".",
        output_path: str = "eu-ai-act.sarif.json",
        role: str | None = None,
        response_format: Literal["concise", "detailed"] = "concise",
    ) -> str:
        """Write the scan's gaps as an offline SARIF 2.1.0 file for GitHub Code Scanning or CI.

        Returns the path and result counts by level; 'detailed' also returns the document.
        output_path must end in .json or .sarif.
        """
        return _respond(tool_export_sarif(path, output_path, role, response_format))

    def generate_dossier(
        path: str,
        output_path: str = "compliance-dossier.json",
        response_format: Literal["concise", "detailed"] = "concise",
    ) -> str:
        """Seal a tamper-evident compliance record of this release into output_path.

        Binds SHA-256 file digests, the git commit, scores and the legal basis, for customers
        or auditors. Concise returns a receipt with the integrity hash; the dossier is in the file.
        """
        return _respond(tool_generate_dossier(path, output_path, response_format))

    def generate_visual_graph(
        path: str,
        output_path: str = "context-graph.html",
        response_format: Literal["concise", "detailed"] = "concise",
    ) -> str:
        """Write an interactive, offline HTML map of the system to output_path.

        Each node shows its gaps, articles, related frameworks and a suggested fix. Returns
        the file path and the nodes with gaps.
        """
        return _respond(tool_generate_visual_graph(path, output_path, response_format))

    def regulatory_applicability(risk_class: str, role: str, as_of: str | None = None) -> str:
        """Which EU AI Act phases and duties apply on a date (default today), with Omnibus dates.

        risk_class: prohibited, high_risk_annex_i, high_risk_annex_iii, limited_risk,
        minimal_risk, gpai or gpai_systemic. role: provider, deployer, importer, distributor,
        authorised_representative or product_manufacturer. as_of: YYYY-MM-DD.
        """
        return _respond(tool_regulatory_applicability(risk_class, role, as_of))

    def get_article(article: str, response_format: Literal["concise", "detailed"] = "concise") -> str:
        """Look up one EU AI Act article without scanning.

        Accepts any spelling (art15, 'Art. 15', 'Article 15(4)', 15). Returns the scanner areas it
        maps to, matching controls in other frameworks, and related incidents.
        """
        return _respond(tool_get_article(article, response_format))

    def list_dimensions() -> str:
        """List the scanner's compliance areas (id, label, article, description).

        Use an id as area in scan_project or as key in incidents.
        """
        return _respond(tool_list_dimensions())

    def incidents(key: str | None = None, limit: int = 5, response_format: Literal["concise", "detailed"] = "concise") -> str:
        """Documented real-world AI security incidents, with mitigations.

        key: an area ('security'), an article ('art15') or a threat ('prompt_injection'); omit
        it for corpus statistics. Useful to show why a gap matters. Source: GenAI & Agentic AI
        Security Incidents dataset (CC-BY-4.0), bundled offline.
        """
        return _respond(tool_incidents(key, limit, response_format))

    def agentic_taxonomy(risk_id: str | None = None) -> str:
        """Agentic compound-risk guidance with provenance for each mitigation.

        Axes: cascading, emergent, attribution, temporal. Each item is tagged act_required (an
        EU AI Act duty, citing the provision) or paper_suggested. Pass risk_id to narrow.
        """
        return _respond(tool_agentic_taxonomy(risk_id))

    # Order is fixed and definitions are static so clients can cache them.
    _register("founder_triage", founder_triage, read_only=True, always_load=True)
    _register("scan_project", scan_project, read_only=True, always_load=True)
    _register("project_cross_framework", project_cross_framework, read_only=True)
    _register("ingest_security_reports", ingest_security_reports, read_only=False)
    _register("remediation_loop", remediation_loop, read_only=False, destructive=True)
    _register("export_sarif", export_sarif, read_only=False)
    _register("generate_dossier", generate_dossier, read_only=False)
    _register("generate_visual_graph", generate_visual_graph, read_only=False)
    _register("regulatory_applicability", regulatory_applicability, read_only=True)
    _register("get_article", get_article, read_only=True)
    _register("list_dimensions", list_dimensions, read_only=True)
    _register("incidents", incidents, read_only=True)
    _register("agentic_taxonomy", agentic_taxonomy, read_only=True)
    _compact_registered_schemas(mcp)

    return mcp


def _compact_schema(node: Any) -> Any:
    """Drop JSON-schema noise from generated tool inputs (titles, anyOf-null wrappers).

    Every client already has the parameter names, so per-property ``title``s and
    the ``anyOf: [{type: X}, {type: null}]`` shape of optional parameters are pure
    token overhead in each tool definition.
    """
    if isinstance(node, list):
        return [_compact_schema(item) for item in node]
    if not isinstance(node, dict):
        return node
    out = {k: _compact_schema(v) for k, v in node.items() if not (k == "title" and isinstance(v, str))}
    variants = out.get("anyOf")
    if isinstance(variants, list) and len(variants) == 2 and {"type": "null"} in variants:
        other = next(v for v in variants if v != {"type": "null"})
        if set(other) == {"type"} and isinstance(other["type"], str):
            del out["anyOf"]
            out["type"] = [other["type"], "null"]
    return out


def _compact_registered_schemas(server: Any) -> None:
    """Apply :func:`_compact_schema` to every registered tool (best effort across SDKs)."""
    tools = getattr(getattr(server, "_tool_manager", None), "_tools", None)
    if not isinstance(tools, dict):
        return
    for tool in tools.values():
        params = getattr(tool, "parameters", None)
        if isinstance(params, dict):
            tool.parameters = _compact_schema(params)


def main() -> None:
    """Entry point for the ``antifragile-scan-mcp`` console script (stdio transport)."""
    from scanner.log_config import configure_console_logging

    # stdio hygiene: MCP messages own stdout. Both stdlib logging and structlog
    # (whose default printer writes to stdout) go to stderr.
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    configure_console_logging()
    build_server().run()


if __name__ == "__main__":
    main()
