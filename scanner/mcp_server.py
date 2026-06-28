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


def tool_scan_project(path: str, project_name: str | None = None) -> dict:
    """Scan a codebase at *path* for EU AI Act compliance evidence and gaps.

    Returns the full :class:`scanner.models.ScanResult` serialised as a dict,
    including per-dimension compliance scores, architecture graph, file
    findings, and incident grounding links.

    Check ``is_ai_system`` first: when ``False`` the codebase is out of EU AI
    Act scope (no AI/ML/agent signal), ``compliance_scores`` is empty, and
    ``overall_compliance_pct`` is ``0.0`` but **not** a compliance measure —
    ``scope_note`` explains why scoring was skipped.
    """
    result = scan_project(path, project_name=project_name)
    return result.model_dump()


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

    return mcp


def main() -> None:
    """Entry point for the ``eu-ai-act-scan-mcp`` console script (stdio transport)."""
    build_server().run()


if __name__ == "__main__":
    main()
