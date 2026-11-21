"""MCP server for the EU AI Act Scanner.

Exposes the scanner's deterministic engine as Model Context Protocol tools so
any MCP-capable agent (Claude Code, Claude Desktop, Cursor, custom agents) can
call the scanner with its **own model subscription** — no API key, no local
subscription wrapper.

Transport: stdio by default (``eu-ai-act-scan-mcp``). The same ``FastMCP`` app
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

    git clone https://github.com/Peaky8linders/eu-ai-act-scanner
    cd eu-ai-act-scanner && pip install -e ".[mcp]"

Run the server (stdio transport):
    eu-ai-act-scan-mcp
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from scanner.cross_framework import project_scan_to_frameworks
from scanner.dossier import generate_dossier
from scanner.fix_loop import run_fix_loop
from scanner.incident_grounding import (
    incident_corpus_stats,
    incidents_for_article,
    incidents_for_dimension,
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
        raise ValueError(f"unknown frameworks: {', '.join(unknown[:5])}")
    return cleaned


# ---------------------------------------------------------------------------
# Plain tool functions — NO mcp dependency
# ---------------------------------------------------------------------------


def tool_scan_project(
    path: str,
    project_name: str | None = None,
    role: str | None = None,
    deep: bool = False,
    cross_framework: bool = False,
) -> dict:
    """Scan a codebase at *path* for EU AI Act compliance evidence and gaps.

    Returns the full :class:`scanner.models.ScanResult` serialised as a dict,
    including per-dimension compliance scores, architecture graph, file
    findings, and incident grounding links. ``agentic_recommendations`` holds
    the compound-risk taxonomy mitigations/evidence for the risk axes the scan
    detected, each tagged ``act_required`` (with the Act provision) or
    ``paper_suggested`` (with the paper line).

    Check ``is_ai_system`` first: when ``False`` the codebase is out of EU AI
    Act scope (no AI/ML/agent signal), ``compliance_scores`` is empty, and
    ``overall_compliance_pct`` is ``0.0`` but **not** a compliance measure —
    ``scope_note`` explains why scoring was skipped.
    """
    try:
        resolved = _validate_scan_path(path)
    except ValueError as exc:
        return {"error": str(exc), "path": _clean_str(path, 120)}
    if role is not None and role not in _VALID_ROLES:
        return {"error": f"unknown role {role!r}; expected one of {sorted(_VALID_ROLES)}"}
    result = scan_project(
        resolved,
        project_name=_clean_str(project_name, 128) or None,
        role=role,
        deep=False,  # semantic depth lives in the MCP client, never headless
        cross_framework=bool(cross_framework),
    )
    return result.model_dump()


def tool_project_cross_framework(
    path: str,
    target_frameworks: list[str] | None = None,
) -> dict:
    """Scan codebase and project findings onto international AI governance frameworks.

    Maps to NIST AI RMF 1.0, ISO/IEC 42001:2023, OWASP LLM 2025, OWASP Agentic Top 10,
    GDPR, MITRE ATLAS, SOC 2, and CSA AICM. Identifies high-leverage 'Satisfy Once,
    Comply Everywhere' remediation targets, and grounds every gap/partial control in
    the documented incidents that exploited its class (``related_incidents`` on each
    control, ``top_incidents`` on each lever — ids from the vendored incident corpus).
    """
    try:
        resolved = _validate_scan_path(path)
        frameworks = _validate_frameworks(target_frameworks)
    except ValueError as exc:
        return {"error": str(exc)}
    result = scan_project(resolved, cross_framework=True)
    projection = project_scan_to_frameworks(result, target_framework_ids=frameworks)
    return projection.model_dump()


def tool_generate_dossier(
    path: str,
    output_path: str = "compliance-dossier.json",
) -> dict:
    """Generate and seal a cryptographic, tamper-evident compliance release dossier.

    Binds SHA-256 file digests, git provenance, compliance scores, and statutory grounding
    under Regulation (EU) 2024/1689 and Digital Omnibus Regulation (EU) 2026/1744.
    """
    try:
        resolved = _validate_scan_path(path)
        out = _validate_output_path(output_path, expected_suffix=".json")
    except ValueError as exc:
        return {"error": str(exc)}
    result = scan_project(resolved, cross_framework=True)
    dossier = generate_dossier(result, resolved)
    dossier.export_json(str(out))
    return dossier.model_dump()


def tool_remediation_loop(
    path: str,
    apply: bool = False,
    max_iterations: int = 3,
) -> dict:
    """Run autonomous scan -> fix -> rescan remediation pipeline with regression guard.

    When *apply* is False, returns ranked proposals and verification instructions (safe preview).
    When *apply* is True, writes production-grade remediation artifacts and re-evaluates scores.
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
    return fix_result.model_dump()


def tool_generate_visual_graph(
    path: str,
    output_path: str = "context-graph.html",
) -> dict:
    """Generate an interactive visual context graph browser for the scanned codebase.

    Allows users to inspect nodes for compliance gaps, regulatory articles, cross-framework
    linkages, grounded real-world incidents, and copyable recommended fixes.
    """
    try:
        resolved = _validate_scan_path(path)
        out = _validate_output_path(output_path, expected_suffix=".html")
    except ValueError as exc:
        return {"error": str(exc)}
    from scanner.visual_graph import build_graph_data, generate_visual_graph
    result = scan_project(resolved, cross_framework=True)
    generate_visual_graph(result, output_path=out, root_path=resolved)
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


def tool_get_article(article: str) -> dict:
    """Get compliance dimensions, cross-framework controls, and incidents for an article.

    *article* accepts any spelling: ``art15``, ``Art. 15``, ``Article 15.4`` or
    ``15``. Returns ``{article, dimensions, frameworks, incidents}``; if the article is
    unknown the response also contains an ``error`` key and empty lists.
    ``frameworks`` maps canonical framework IDs (NIST AI RMF, ISO 42001, OWASP
    LLM/Agentic, GDPR, ...) to control IDs from crosswalk catalogue
    ``scanner.data.frameworks.CROSSWALK_CATALOGUE_VERSION``.
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
) -> dict:
    """Return a plain-English 3-bucket Founder/Startup compliance triage.

    Splits gaps into ``ship_now`` (live Art. 50 transparency + MCP/Claude Code/
    security blockers), ``enterprise_deals`` (SOC 2 / GDPR / OWASP blockers plus
    top 3 cross-framework levers and deployer vendor-contract checklist), and
    ``later_2027`` (Annex III obligations deferred to 2 Dec 2027 under Digital
    Omnibus Regulation (EU) 2026/1744). Includes copy-pasteable ``brief_markdown``.
    """
    from scanner.founder_triage import build_founder_triage

    try:
        resolved = _validate_scan_path(path)
    except ValueError as exc:
        return {"error": str(exc), "path": _clean_str(path, 120)}
    if role is not None and role not in _VALID_ROLES:
        return {"error": f"unknown role {role!r}; expected one of {sorted(_VALID_ROLES)}"}
    result = scan_project(resolved, role=role, cross_framework=True)
    triage = build_founder_triage(result)
    return triage.model_dump()


def tool_export_sarif(
    path: str = ".",
    output_path: str = "eu-ai-act.sarif.json",
    role: str | None = None,
) -> dict:
    """Scan *path* and export an offline SARIF 2.1.0 report to *output_path*.

    Emits strictly offline SARIF 2.1.0 JSON (zero remote URLs). Output target
    must resolve to a ``.json`` or ``.sarif`` file without traversing a symlink.
    """
    from scanner.sarif import scan_to_sarif, write_sarif

    try:
        resolved = _validate_scan_path(path)
        out = _validate_output_path(output_path, expected_suffix=(".json", ".sarif"))
    except ValueError as exc:
        return {"error": str(exc)}
    if role is not None and role not in _VALID_ROLES:
        return {"error": f"unknown role {role!r}; expected one of {sorted(_VALID_ROLES)}"}

    result = scan_project(resolved, role=role)
    sarif_doc = scan_to_sarif(result)
    write_sarif(result, out)
    run = sarif_doc["runs"][0]
    return {
        "status": "success",
        "output_path": str(out),
        "sarif_version": sarif_doc["version"],
        "is_ai_system": result.is_ai_system,
        "results_count": len(run["results"]),
        "rules_count": len(run["tool"]["driver"]["rules"]),
        "sarif": sarif_doc,
    }


def tool_ingest_sarif(
    path: str = ".",
    sarif_paths: list[str] | None = None,
    role: str | None = None,
    output_dossier: str | None = None,
) -> dict:
    """Ingest local SARIF 2.1.0 files (Semgrep, Bandit, Snyk, CodeQL, GHAS) into a scan.

    Maps external cybersecurity findings to EU AI Act Art. 15(4), merges them into
    ``scan_project(...)``, and optionally seals a cryptographic release dossier
    at *output_dossier*.
    """
    from scanner.sarif import ingest_sarif_files

    try:
        resolved = _validate_scan_path(path)
        validated_sarif = _validate_input_file_list(
            sarif_paths,
            allowed_suffixes=(".sarif", ".json"),
            root_dir=resolved,
            field_name="sarif_paths",
        )
        if not validated_sarif:
            raise ValueError("sarif_paths must contain at least one local SARIF file path")
        dossier_out = (
            _validate_output_path(output_dossier, expected_suffix=".json")
            if output_dossier
            else None
        )
    except ValueError as exc:
        return {"error": str(exc)}

    if role is not None and role not in _VALID_ROLES:
        return {"error": f"unknown role {role!r}; expected one of {sorted(_VALID_ROLES)}"}

    try:
        external_findings, source_tools = ingest_sarif_files(validated_sarif)
    except ValueError as exc:
        return {"error": str(exc)}

    result = scan_project(
        resolved,
        role=role,
        cross_framework=True,
        external_findings=external_findings,
        external_sources=source_tools,
    )

    payload: dict = {
        "status": "success",
        "ingested_files": [str(p) for p in validated_sarif],
        "source_tools": source_tools,
        "external_findings_count": len(external_findings),
        "is_ai_system": result.is_ai_system,
        "overall_compliance_pct": result.overall_compliance_pct,
        "compliance_scores": result.compliance_scores,
        "scan_result": result.model_dump(),
    }

    if dossier_out is not None:
        dossier = generate_dossier(result, resolved)
        dossier.export_json(str(dossier_out))
        payload["dossier_path"] = str(dossier_out)
        payload["dossier_integrity_hash"] = dossier.dossier_integrity_hash

    return payload


def tool_ingest_claude_ecosystem(
    path: str = ".",
    compliance_api_paths: list[str] | None = None,
    claude_security_paths: list[str] | None = None,
    role: str | None = None,
    output_dossier: str | None = None,
) -> dict:
    """Ingest local Claude Compliance API exports and/or /claude-security reports.

    Strictly offline: reads only local files exported by the user (e.g. from
    ``scripts/fetch_claude_compliance.py`` or ``claude-security@claude-plugins-official``).
    Honors Claude Security's adversarial verification panel, audits Art. 26(6)
    retention & user preferences, merges findings into ``scan_project(...)``,
    and returns grounded findings, metadata, and updated dimension scores.
    """
    from scanner.claude_ecosystem import (
        ingest_claude_security_report,
        ingest_compliance_api_export,
    )

    try:
        resolved = _validate_scan_path(path)
        validated_cca = _validate_input_file_list(
            compliance_api_paths,
            allowed_suffixes=(".json", ".jsonl", ".ndjson"),
            root_dir=resolved,
            field_name="compliance_api_paths",
        )
        validated_cs = _validate_input_file_list(
            claude_security_paths,
            allowed_suffixes=(".sarif", ".json", ".jsonl", ".ndjson", ".md", ".markdown", ".txt"),
            root_dir=resolved,
            field_name="claude_security_paths",
        )
        if not validated_cca and not validated_cs:
            raise ValueError(
                "provide at least one of compliance_api_paths or claude_security_paths"
            )
        dossier_out = (
            _validate_output_path(output_dossier, expected_suffix=".json")
            if output_dossier
            else None
        )
    except ValueError as exc:
        return {"error": str(exc)}

    if role is not None and role not in _VALID_ROLES:
        return {"error": f"unknown role {role!r}; expected one of {sorted(_VALID_ROLES)}"}

    external_findings = []
    external_sources: list[str] = []
    compliance_meta: dict | None = None
    claude_sec_meta: dict | None = None

    try:
        if validated_cca:
            cca_findings, compliance_meta = ingest_compliance_api_export(validated_cca)
            external_findings.extend(cca_findings)
            external_sources.append(
                str(compliance_meta.get("source") or "anthropic_claude_compliance_api")
            )
        if validated_cs:
            cs_findings, claude_sec_meta = ingest_claude_security_report(validated_cs)
            external_findings.extend(cs_findings)
            for tool_name in claude_sec_meta.get("source_tools") or ["claude-security"]:
                if tool_name not in external_sources:
                    external_sources.append(str(tool_name))
    except ValueError as exc:
        return {"error": str(exc)}

    result = scan_project(
        resolved,
        role=role,
        cross_framework=True,
        external_findings=external_findings,
        external_sources=external_sources,
    )

    payload: dict = {
        "status": "success",
        "external_sources": external_sources,
        "external_findings_count": len(external_findings),
        "external_findings": [f.model_dump() for f in external_findings],
        "compliance_api_metadata": compliance_meta,
        "claude_security_metadata": claude_sec_meta,
        "is_ai_system": result.is_ai_system,
        "overall_compliance_pct": result.overall_compliance_pct,
        "compliance_scores": result.compliance_scores,
        "scan_result": result.model_dump(),
    }

    if dossier_out is not None:
        dossier = generate_dossier(result, resolved)
        dossier.export_json(str(dossier_out))
        payload["dossier_path"] = str(dossier_out)
        payload["dossier_integrity_hash"] = dossier.dossier_integrity_hash

    return payload


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
            "pip install -e \".[mcp]\" (there is no PyPI package — the "
            "`eu-ai-act-scanner` name on PyPI is an unrelated project)"
        ) from exc


def build_server():  # noqa: ANN201  (returns MCPServer/FastMCP — type only available with extras)
    """Construct and return a configured MCP server (``MCPServer`` / ``FastMCP``).

    Raises :exc:`RuntimeError` if the ``mcp`` optional dependency is not
    installed.  Install it from this repository with::

        git clone https://github.com/Peaky8linders/eu-ai-act-scanner
        cd eu-ai-act-scanner && pip install -e ".[mcp]"

    HTTP serving (Streamable HTTP) is left to the deployer: serve the app
    returned by ``mcp.http_app()`` behind TLS + authentication, bind
    loopback for local-only use, and enable Host/Origin validation so
    DNS-rebinding from a browser origin returns 403. See MCP spec
    Streamable HTTP security considerations.
    """
    server_cls = _load_server_class()

    from scanner import __version__

    _name = "eu-ai-act-scanner"
    _instructions = (
        "EU AI Act (Regulation 2024/1689 + Digital Omnibus 2026/1744) code scanner. "
        "Call scan_project first and check is_ai_system before quoting any compliance %. "
        "Remediation writes only when apply=True; default is read-only dry-run."
    )
    try:  # mcp >= 2.0 takes version as a constructor field
        mcp = server_cls(_name, instructions=_instructions, version=__version__)
    except TypeError:  # mcp 1.x has no version parameter
        mcp = server_cls(_name, instructions=_instructions)
    # Version surface for discovery. mcp>=2 takes it as a constructor field;
    # on 1.x it is a plain attribute set here.
    if getattr(mcp, "version", None) != __version__:
        mcp.version = __version__  # type: ignore[attr-defined]

    def _register(name: str, fn, *, read_only: bool, destructive: bool = False):
        """Register with annotations on new SDKs, plain on old ones."""
        try:
            return mcp.tool(name=name, annotations=_tool_meta(read_only, destructive))(fn)
        except TypeError:
            return mcp.tool(name=name)(fn)

    def scan_project_tool(path: str, project_name: str | None = None) -> dict:
        """Scan a codebase at *path* for EU AI Act compliance evidence and gaps.

        Returns per-dimension compliance scores, overall compliance percentage,
        architecture graph, file findings, and incident grounding links. Runs
        entirely locally — no network calls, no telemetry.
        """
        return tool_scan_project(path, project_name)

    def list_dimensions() -> list[dict]:
        """List all EU AI Act compliance dimensions tracked by the scanner.

        Returns every dimension with its ``id``, ``label``, linked ``article``,
        and ``description``. Use the ids with ``incidents_for_dimension``.
        """
        return tool_list_dimensions()

    def get_article(article: str) -> dict:
        """Get compliance dimensions and relevant incidents for an EU AI Act article.

        *article* should be in canonical lowercase ``artNN`` form (e.g.
        ``art15``, ``art53``). Returns ``dimensions`` (list) and ``incidents``
        (list) from the vendored incident corpus. Unknown articles return empty
        lists plus an ``error`` key.
        """
        return tool_get_article(article)

    def incidents_for_dimension_tool(dim_id: str, limit: int = 5) -> list[dict]:
        """Return real-world incidents relevant to a KB compliance dimension.

        *dim_id* examples: ``"security"``, ``"logging"``, ``"tool_governance"``.
        Each returned incident includes OWASP LLM / ASI codes, MITRE ATLAS
        technique IDs, severity, and published mitigations where available.
        Unknown ids return an empty list.
        """
        return tool_incidents_for_dimension(dim_id, limit)

    def incidents_for_threat_tool(threat_id: str, limit: int = 5) -> list[dict]:
        """Return incidents that exploited an agentic threat category.

        *threat_id* is an agentic threat identifier such as
        ``"prompt_injection"`` or ``"tool_misuse_privilege_escalation"``.
        Unknown ids return an empty list.
        """
        return tool_incidents_for_threat(threat_id, limit)

    def incidents_for_article_tool(article: str, limit: int = 5) -> list[dict]:
        """Return incidents relevant to an EU AI Act article (e.g. ``art15``).

        Unions incidents across all KB dimensions mapped to the article and
        returns the top *limit* (deduplicated by relevance score). Unknown
        articles return an empty list.
        """
        return tool_incidents_for_article(article, limit)

    def agentic_taxonomy_tool(risk_id: str | None = None) -> dict:
        """Browse agentic compound-risk mitigations and evidence, with provenance.

        Every item carries ``source`` (``act_required`` or ``paper_suggested``)
        and ``ref`` (the Act provision or paper line). Pass *risk_id* to filter
        to one compound-risk axis.
        """
        return tool_agentic_taxonomy(risk_id)

    def incident_corpus_stats_tool() -> dict:
        """Return a summary of the bundled GenAI incident corpus.

        Includes total count, real-world vs research split, provenance, license
        (CC-BY-4.0), and taxonomy coverage across OWASP LLM, OWASP ASI, and
        MITRE ATLAS techniques.
        """
        return tool_incident_corpus_stats()

    def project_cross_framework_tool(
        path: str,
        target_frameworks: list[str] | None = None,
    ) -> dict:
        """Project EU AI Act scan onto NIST AI RMF, ISO 42001, GDPR, and OWASP.

        Outputs framework readiness percentages, control mappings, and 'Satisfy Once,
        Comply Everywhere' levers.
        """
        return tool_project_cross_framework(path, target_frameworks)

    def generate_dossier_tool(
        path: str,
        output_path: str = "compliance-dossier.json",
    ) -> dict:
        """Generate and export a cryptographic, tamper-evident compliance release dossier.

        Binds git commit, file SHA-256 digests, and statutory grounding under
        Regulation (EU) 2024/1689 and Digital Omnibus Regulation (EU) 2026/1744.
        """
        return tool_generate_dossier(path, output_path)

    def remediation_loop_tool(
        path: str,
        apply: bool = False,
        max_iterations: int = 3,
    ) -> dict:
        """Run autonomous scan -> fix -> rescan remediation pipeline with regression guard.

        When *apply* is False, previews proposals. When *apply* is True, writes fixes to disk.
        """
        return tool_remediation_loop(path, apply, max_iterations)

    def generate_visual_graph_tool(
        path: str,
        output_path: str = "context-graph.html",
    ) -> dict:
        """Generate an interactive visual context graph browser for the scanned codebase.

        Allows users to browse the architecture, click nodes to view gaps, and inspect recommended fixes.
        """
        return tool_generate_visual_graph(path, output_path)

    def founder_triage_tool(
        path: str = ".",
        role: str | None = None,
    ) -> dict:
        """Build a plain-English 3-bucket Founder/Startup EU AI Act triage brief.

        Splits findings into ship_now (live Art. 50 + MCP/Claude Code/security blockers),
        enterprise_deals (SOC 2 / GDPR / OWASP quick wins + deployer vendor checklist),
        and later_2027 (Annex III deferred to 2 Dec 2027 under Reg. 2026/1744).
        """
        return tool_founder_triage(path, role)

    def export_sarif_tool(
        path: str = ".",
        output_path: str = "eu-ai-act.sarif.json",
        role: str | None = None,
    ) -> dict:
        """Export an offline SARIF 2.1.0 report for GitHub Code Scanning or security pipelines.

        Strictly offline (zero remote URLs). Output path must resolve to .json or .sarif.
        """
        return tool_export_sarif(path, output_path, role)

    def ingest_sarif_tool(
        path: str = ".",
        sarif_paths: list[str] | None = None,
        role: str | None = None,
        output_dossier: str | None = None,
    ) -> dict:
        """Ingest local SARIF 2.1.0 reports (Semgrep, Bandit, Snyk, CodeQL, GHAS) into a scan.

        Merges external cybersecurity findings into Art. 15(4) compliance scoring and
        optionally exports a sealed cryptographic release dossier.
        """
        return tool_ingest_sarif(path, sarif_paths, role, output_dossier)

    def ingest_claude_ecosystem_tool(
        path: str = ".",
        compliance_api_paths: list[str] | None = None,
        claude_security_paths: list[str] | None = None,
        role: str | None = None,
        output_dossier: str | None = None,
    ) -> dict:
        """Ingest local Anthropic Claude Compliance API exports and/or /claude-security reports.

        Honors Claude Security's adversarial verification panel, audits Art. 26(6) log
        retention and user preferences, and merges grounded findings into scan scores.
        """
        return tool_ingest_claude_ecosystem(
            path,
            compliance_api_paths,
            claude_security_paths,
            role,
            output_dossier,
        )

    def regulatory_applicability_tool(
        risk_class: str,
        role: str,
        as_of: str | None = None,
    ) -> dict:
        """Resolve exact EU AI Act / Digital Omnibus (Reg. 2026/1744) applicability dates & duties.

        Returns phases_in_force, phases_pending, duties_in_force, and duties_pending
        for the given risk_class, operator role, and optional ISO date as_of.
        """
        return tool_regulatory_applicability(risk_class, role, as_of)

    _register("scan_project", scan_project_tool, read_only=True)
    _register("list_dimensions", list_dimensions, read_only=True)
    _register("get_article", get_article, read_only=True)
    _register("incidents_for_dimension", incidents_for_dimension_tool, read_only=True)
    _register("incidents_for_threat", incidents_for_threat_tool, read_only=True)
    _register("incidents_for_article", incidents_for_article_tool, read_only=True)
    _register("incident_corpus_stats", incident_corpus_stats_tool, read_only=True)
    _register("agentic_taxonomy", agentic_taxonomy_tool, read_only=True)
    _register("project_cross_framework", project_cross_framework_tool, read_only=True)
    _register("generate_dossier", generate_dossier_tool, read_only=False)
    _register("remediation_loop", remediation_loop_tool, read_only=False, destructive=True)
    _register("generate_visual_graph", generate_visual_graph_tool, read_only=False)
    _register("founder_triage", founder_triage_tool, read_only=True)
    _register("export_sarif", export_sarif_tool, read_only=False)
    _register("ingest_sarif", ingest_sarif_tool, read_only=False)
    _register("ingest_claude_ecosystem", ingest_claude_ecosystem_tool, read_only=False)
    _register("regulatory_applicability", regulatory_applicability_tool, read_only=True)

    return mcp


def main() -> None:
    """Entry point for the ``eu-ai-act-scan-mcp`` console script (stdio transport)."""
    # stdio hygiene: MCP messages own stdout — force all logs to stderr so a
    # stray print never corrupts the JSON-RPC stream.
    logging.basicConfig(level=logging.WARNING, stream=__import__("sys").stderr)
    build_server().run()


if __name__ == "__main__":
    main()
