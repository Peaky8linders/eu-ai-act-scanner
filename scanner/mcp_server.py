"""MCP server for the EU AI Act Scanner.

Exposes the scanner's full public API as Model Context Protocol tools so that
any MCP-capable agent (Claude Desktop, Cursor, custom agents) can call the
scanner without going through the CLI.

Local-only, no network calls, no telemetry. Wraps the same scanner API as the
Python library and CLI. The incident-grounding tools surface the vendored
GenAI/agentic-AI incident corpus (CC-BY-4.0) crosswalked to OWASP LLM Top 10,
OWASP Agentic (ASI), NIST AI RMF, and MITRE ATLAS.

Architecture: all tool logic lives in plain, importable functions below (no
``mcp`` dependency). The MCP SDK is imported lazily only inside
``build_server()`` / ``main()``, so this module — and its test suite — works
even when the optional ``[mcp]`` extra is not installed.

Install the MCP extra:
    pip install 'eu-ai-act-scanner[mcp]'

Run the server (stdio transport):
    eu-ai-act-scan-mcp
"""

from __future__ import annotations

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
    result = scan_project(
        path,
        project_name=project_name,
        role=role,
        deep=deep,
        cross_framework=cross_framework,
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
    result = scan_project(path, cross_framework=True)
    projection = project_scan_to_frameworks(result, target_framework_ids=target_frameworks)
    return projection.model_dump()


def tool_generate_dossier(
    path: str,
    output_path: str = "compliance-dossier.json",
) -> dict:
    """Generate and seal a cryptographic, tamper-evident compliance release dossier.

    Binds SHA-256 file digests, git provenance, compliance scores, and statutory grounding
    under Regulation (EU) 2024/1689 and Digital Omnibus Regulation (EU) 2026/1744.
    """
    result = scan_project(path, cross_framework=True)
    dossier = generate_dossier(result, path)
    dossier.export_json(output_path)
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
    fix_result = run_fix_loop(path, apply=apply, max_iterations=max_iterations)
    return fix_result.model_dump()


def tool_generate_visual_graph(
    path: str,
    output_path: str = "context-graph.html",
) -> dict:
    """Generate an interactive visual context graph browser for the scanned codebase.

    Allows users to inspect nodes for compliance gaps, regulatory articles, cross-framework
    linkages, grounded real-world incidents, and copyable recommended fixes.
    """
    from scanner.visual_graph import build_graph_data, generate_visual_graph
    result = scan_project(path, cross_framework=True)
    generate_visual_graph(result, output_path=output_path, root_path=path)
    return {
        "status": "success",
        "output_path": output_path,
        "graph_summary": build_graph_data(result, Path(path)),
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
    """Get compliance dimensions and relevant incidents for an EU AI Act article.

    *article* should be in canonical ``artNN`` form (e.g. ``art15``, ``art53``).
    Returns ``{article, dimensions, incidents}``; if the article is unknown the
    response also contains an ``error`` key and empty lists.
    """
    article_key = article.lower()
    dims = dimensions_for_article(article_key)
    if not dims:
        return {
            "article": article,
            "dimensions": [],
            "incidents": [],
            "error": f"unknown article {article!r} — use canonical 'artNN' form (e.g. 'art15')",
        }
    incs = incidents_for_article(article_key)
    return {
        "article": article,
        "dimensions": [
            {"id": d.id, "label": d.label, "article": d.article, "description": d.description}
            for d in dims
        ],
        "incidents": [inc.to_dict() for inc in incs],
    }


def tool_incidents_for_dimension(dim_id: str, limit: int = 5) -> list[dict]:
    """Return up to *limit* incidents relevant to a KB compliance dimension.

    *dim_id* is a dimension identifier such as ``"security"``, ``"logging"``,
    or ``"tool_governance"``. Unknown ids return an empty list.
    """
    return [inc.to_dict() for inc in incidents_for_dimension(dim_id, limit=limit)]


def tool_incidents_for_threat(threat_id: str, limit: int = 5) -> list[dict]:
    """Return up to *limit* incidents that exploited an agentic threat category.

    *threat_id* is a :class:`scanner.data.agentic_taxonomy.ThreatCategory`
    value, e.g. ``"prompt_injection"`` or ``"tool_misuse_privilege_escalation"``.
    Unknown ids return an empty list.
    """
    return [inc.to_dict() for inc in incidents_for_threat(threat_id, limit=limit)]


def tool_incidents_for_article(article: str, limit: int = 5) -> list[dict]:
    """Return up to *limit* incidents relevant to an EU AI Act article.

    *article* should be in canonical ``artNN`` form (e.g. ``art15``).
    Unions across all KB dimensions mapped to the article and deduplicates.
    Unknown articles return an empty list.
    """
    return [inc.to_dict() for inc in incidents_for_article(article.lower(), limit=limit)]


def tool_incident_corpus_stats() -> dict:
    """Summary of the bundled incident corpus.

    Includes count, real-world vs research split, provenance, license
    (CC-BY-4.0), and taxonomy coverage (OWASP LLM, OWASP ASI, MITRE ATLAS).
    """
    return incident_corpus_stats()


# ---------------------------------------------------------------------------
# MCP server wiring — lazy import so tests run without the mcp package
# ---------------------------------------------------------------------------


def build_server():  # noqa: ANN201  (returns FastMCP — type only available with extras)
    """Construct and return a configured :class:`mcp.server.fastmcp.FastMCP` instance.

    Raises :exc:`RuntimeError` if the ``mcp`` optional dependency is not
    installed.  Install it with::

        pip install 'eu-ai-act-scanner[mcp]'
    """
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore[import-untyped]
    except ImportError as exc:
        raise RuntimeError(
            "MCP SDK not installed. Install with: pip install 'eu-ai-act-scanner[mcp]'"
        ) from exc

    mcp = FastMCP("eu-ai-act-scanner")

    @mcp.tool()
    def scan_project_tool(path: str, project_name: str | None = None) -> dict:
        """Scan a codebase at *path* for EU AI Act compliance evidence and gaps.

        Returns per-dimension compliance scores, overall compliance percentage,
        architecture graph, file findings, and incident grounding links. Runs
        entirely locally — no network calls, no telemetry.
        """
        return tool_scan_project(path, project_name)

    @mcp.tool()
    def list_dimensions() -> list[dict]:
        """List all EU AI Act compliance dimensions tracked by the scanner.

        Returns every dimension with its ``id``, ``label``, linked ``article``,
        and ``description``. Use the ids with ``incidents_for_dimension``.
        """
        return tool_list_dimensions()

    @mcp.tool()
    def get_article(article: str) -> dict:
        """Get compliance dimensions and relevant incidents for an EU AI Act article.

        *article* should be in canonical lowercase ``artNN`` form (e.g.
        ``art15``, ``art53``). Returns ``dimensions`` (list) and ``incidents``
        (list) from the vendored incident corpus. Unknown articles return empty
        lists plus an ``error`` key.
        """
        return tool_get_article(article)

    @mcp.tool()
    def incidents_for_dimension_tool(dim_id: str, limit: int = 5) -> list[dict]:
        """Return real-world incidents relevant to a KB compliance dimension.

        *dim_id* examples: ``"security"``, ``"logging"``, ``"tool_governance"``.
        Each returned incident includes OWASP LLM / ASI codes, MITRE ATLAS
        technique IDs, severity, and published mitigations where available.
        Unknown ids return an empty list.
        """
        return tool_incidents_for_dimension(dim_id, limit)

    @mcp.tool()
    def incidents_for_threat_tool(threat_id: str, limit: int = 5) -> list[dict]:
        """Return incidents that exploited an agentic threat category.

        *threat_id* is an agentic threat identifier such as
        ``"prompt_injection"`` or ``"tool_misuse_privilege_escalation"``.
        Unknown ids return an empty list.
        """
        return tool_incidents_for_threat(threat_id, limit)

    @mcp.tool()
    def incidents_for_article_tool(article: str, limit: int = 5) -> list[dict]:
        """Return incidents relevant to an EU AI Act article (e.g. ``art15``).

        Unions incidents across all KB dimensions mapped to the article and
        returns the top *limit* (deduplicated by relevance score). Unknown
        articles return an empty list.
        """
        return tool_incidents_for_article(article, limit)

    @mcp.tool()
    def incident_corpus_stats_tool() -> dict:
        """Return a summary of the bundled GenAI incident corpus.

        Includes total count, real-world vs research split, provenance, license
        (CC-BY-4.0), and taxonomy coverage across OWASP LLM, OWASP ASI, and
        MITRE ATLAS techniques.
        """
        return tool_incident_corpus_stats()

    @mcp.tool()
    def project_cross_framework_tool(
        path: str,
        target_frameworks: list[str] | None = None,
    ) -> dict:
        """Project EU AI Act scan onto NIST AI RMF, ISO 42001, GDPR, and OWASP.

        Outputs framework readiness percentages, control mappings, and 'Satisfy Once,
        Comply Everywhere' levers.
        """
        return tool_project_cross_framework(path, target_frameworks)

    @mcp.tool()
    def generate_dossier_tool(
        path: str,
        output_path: str = "compliance-dossier.json",
    ) -> dict:
        """Generate and export a cryptographic, tamper-evident compliance release dossier.

        Binds git commit, file SHA-256 digests, and statutory grounding under
        Regulation (EU) 2024/1689 and Digital Omnibus Regulation (EU) 2026/1744.
        """
        return tool_generate_dossier(path, output_path)

    @mcp.tool()
    def remediation_loop_tool(
        path: str,
        apply: bool = False,
        max_iterations: int = 3,
    ) -> dict:
        """Run autonomous scan -> fix -> rescan remediation pipeline with regression guard.

        When *apply* is False, previews proposals. When *apply* is True, writes fixes to disk.
        """
        return tool_remediation_loop(path, apply, max_iterations)

    @mcp.tool()
    def generate_visual_graph_tool(
        path: str,
        output_path: str = "context-graph.html",
    ) -> dict:
        """Generate an interactive visual context graph browser for the scanned codebase.

        Allows users to browse the architecture, click nodes to view gaps, and inspect recommended fixes.
        """
        return tool_generate_visual_graph(path, output_path)

    return mcp


def main() -> None:
    """Entry point for the ``eu-ai-act-scan-mcp`` console script (stdio transport)."""
    build_server().run()


if __name__ == "__main__":
    main()
