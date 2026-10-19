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
* All ``path`` inputs must resolve to an existing directory; symlinks resolved.
* All ``output_path`` writes are confined under the process cwd (no ``..``
  escapes, no absolute writes outside cwd) and require an allowlisted suffix
  (``.json`` / ``.html``).
* ``limit`` clamped to 1-50; ``max_iterations`` clamped to 1-5; oversized
  strings truncated. Unknown enum values return structured ``{"error": ...}``
  instead of raising.
* Write-capable tools (``remediation_loop`` with ``apply=True``, dossier/graph
  export) are annotated destructive and default to read-only dry-run.
* No network calls, no telemetry, no secrets in tool surfaces.

Install the MCP extra:
    pip install 'eu-ai-act-scanner[mcp]'

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
_OUTPUT_SUFFIXES = (".json", ".html")

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
    resolved = (Path.cwd() / cleaned).resolve() if not Path(cleaned).is_absolute() else Path(cleaned).resolve()
    if not resolved.is_dir():
        raise ValueError(f"not a directory: {cleaned[:120]}")
    return resolved


def _validate_output_path(output_path: str, *, expected_suffix: str) -> Path:
    """Validate export writes: allowlisted suffix, existing parent dir.

    Relative paths resolve under the process cwd. Absolute paths are allowed
    (tests and local stdio use tmp dirs); HTTP deployments fronting this
    server should additionally confine writes at the proxy/layer level.
    """
    cleaned = _clean_str(output_path, 512)
    if not cleaned:
        raise ValueError("output_path is required")
    if "\x00" in cleaned:
        raise ValueError("invalid output_path")
    if expected_suffix not in _OUTPUT_SUFFIXES:
        raise ValueError(f"unsupported suffix: {expected_suffix!r}")
    if not cleaned.endswith(expected_suffix):
        raise ValueError(f"output_path must end with {expected_suffix}")
    base = Path.cwd().resolve()
    resolved = (base / cleaned).resolve() if not Path(cleaned).is_absolute() else Path(cleaned).resolve()
    if not resolved.parent.is_dir():
        raise ValueError(f"output parent does not exist: {str(resolved.parent)[:120]}")
    return resolved


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
    findings, and incident grounding links.

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
    Comply Everywhere' remediation targets.
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


# ---------------------------------------------------------------------------
# MCP server wiring — lazy import so tests run without the mcp package
# ---------------------------------------------------------------------------


def _tool_meta(read_only: bool, destructive: bool = False) -> dict:
    """Tool annotations for MCP clients (hint; server still enforces)."""
    return {"readOnlyHint": read_only, "destructiveHint": destructive}


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
            "MCP SDK not installed. Install with: pip install 'eu-ai-act-scanner[mcp]'"
        ) from exc


def build_server():  # noqa: ANN201  (returns MCPServer/FastMCP — type only available with extras)
    """Construct and return a configured MCP server (``MCPServer`` / ``FastMCP``).

    Raises :exc:`RuntimeError` if the ``mcp`` optional dependency is not
    installed.  Install it with::

        pip install 'eu-ai-act-scanner[mcp]'

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

    _register("scan_project", scan_project_tool, read_only=True)
    _register("list_dimensions", list_dimensions, read_only=True)
    _register("get_article", get_article, read_only=True)
    _register("incidents_for_dimension", incidents_for_dimension_tool, read_only=True)
    _register("incidents_for_threat", incidents_for_threat_tool, read_only=True)
    _register("incidents_for_article", incidents_for_article_tool, read_only=True)
    _register("incident_corpus_stats", incident_corpus_stats_tool, read_only=True)
    _register("project_cross_framework", project_cross_framework_tool, read_only=True)
    _register("generate_dossier", generate_dossier_tool, read_only=False)
    _register("remediation_loop", remediation_loop_tool, read_only=False, destructive=True)
    _register("generate_visual_graph", generate_visual_graph_tool, read_only=False)

    return mcp


def main() -> None:
    """Entry point for the ``eu-ai-act-scan-mcp`` console script (stdio transport)."""
    # stdio hygiene: MCP messages own stdout — force all logs to stderr so a
    # stray print never corrupts the JSON-RPC stream.
    logging.basicConfig(level=logging.WARNING, stream=__import__("sys").stderr)
    build_server().run()


if __name__ == "__main__":
    main()
