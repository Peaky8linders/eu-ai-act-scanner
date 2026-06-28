"""Command-line interface for the EU AI Act scanner.

Usage:
    eu-ai-act-scan [PATH] [--json | --markdown] [--article ARTN]
    eu-ai-act-scan --incidents KEY [--limit N]   # KEY = dimension | artNN | threat
    python -m scanner.cli ./my-project --json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import structlog

# CLI mode: suppress info-level structlog output so stdout stays clean for
# the JSON/markdown payload. Library users can re-enable logs by calling
# structlog.configure() themselves.
structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING),
)

from scanner import __version__, scan_project  # noqa: E402
from scanner.data.incident_corpus import get_incident  # noqa: E402
from scanner.incident_grounding import (  # noqa: E402
    incidents_for_article,
    incidents_for_dimension,
    incidents_for_threat,
)
from scanner.kb import DIMENSIONS, dimensions_for_article  # noqa: E402


def _format_markdown(result, top_gaps: int = 10) -> str:
    """Render a human-readable scan summary."""
    lines = [
        f"# EU AI Act Scan — {result.project_name}",
        "",
        f"- **Scanner version**: {result.scanner_version}",
        f"- **Files scanned**: {result.total_files:,}",
        f"- **Overall compliance**: **{result.overall_compliance_pct}%**",
        f"- **Languages**: {', '.join(f'{k} ({v})' for k, v in list(result.languages.items())[:5]) or 'none detected'}",
        f"- **Inferred operator role(s)**: {', '.join(result.inferred_roles) or 'none detected'}",
        "",
        "## Compliance by dimension",
        "",
        "| Dimension | Article | Score |",
        "|---|---|---|",
    ]
    for dim_id, score in sorted(result.compliance_scores.items(), key=lambda x: -x[1]):
        dim = DIMENSIONS.get(dim_id)
        label = dim.label if dim else dim_id
        article = dim.article if dim else "—"
        lines.append(f"| {label} | {article} | {score:.1f}% |")

    if result.risk_indicators:
        lines += ["", "## Risk indicators", ""]
        for r in result.risk_indicators[:top_gaps]:
            lines.append(f"- {r}")

    if result.recommendations:
        lines += ["", "## Recommendations", ""]
        for r in result.recommendations[:top_gaps]:
            lines.append(f"- {r}")

    if result.incident_grounding:
        lines += [
            "",
            "## Real-world incident grounding",
            "",
            "_Documented incidents that exploited these gap classes "
            "(source: emmanuelgjr/genai-incidents, CC-BY-4.0)._",
            "",
        ]
        for dim_id, ids in list(result.incident_grounding.items())[:top_gaps]:
            dim = DIMENSIONS.get(dim_id)
            label = dim.label if dim else dim_id
            lines.append(f"- **{label}**")
            for iid in ids:
                inc = get_incident(iid)
                if inc is None:
                    continue
                tag = "/".join(inc.owasp_llm[:2]) or inc.attack_vector or "—"
                lines.append(f"  - `{inc.id}` [{inc.severity}] {inc.title} ({tag})")

    return "\n".join(lines)


def _incidents_payload(key: str, limit: int = 5) -> dict:
    """Resolve a dimension id / article (artNN) / threat id to grounded incidents.

    Backs the `/ai-act-incidents` command. Tries article -> dimension -> threat
    so a single argument form covers all three lookup vocabularies.
    """
    key = key.strip()
    incidents = []
    resolved = None
    if key.lower().startswith("art"):
        incidents = incidents_for_article(key, limit)
        resolved = "article"
    if not incidents and key in DIMENSIONS:
        incidents = incidents_for_dimension(key, limit)
        resolved = "dimension"
    if not incidents:
        threat = incidents_for_threat(key, limit)
        if threat:
            incidents, resolved = threat, "threat"
    if not incidents:
        return {
            "key": key,
            "resolved_as": None,
            "incidents": [],
            "error": (
                f"No incidents found for '{key}'. Try a dimension id (e.g. security), "
                "an article (e.g. art15), or a threat category (e.g. prompt_injection)."
            ),
        }
    return {
        "key": key,
        "resolved_as": resolved,
        "count": len(incidents),
        "incidents": [inc.to_dict() for inc in incidents],
    }


def _filter_by_article(result, article: str) -> dict:
    """Return a dict containing only findings/scores relevant to one article."""
    dims = {d.id for d in dimensions_for_article(article)}
    if not dims:
        return {"error": f"Unknown article '{article}'. Try art9, art15, art50, etc."}

    return {
        "article": article,
        "dimensions": sorted(dims),
        "compliance_scores": {k: v for k, v in result.compliance_scores.items() if k in dims},
        "components": [
            c.model_dump()
            for c in result.components
            if dims.intersection(c.compliance_dimensions)
        ],
        "evidence_map": {k: v for k, v in result.evidence_map.items() if k in dims},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="eu-ai-act-scan",
        description="Scan a codebase for EU AI Act (Regulation 2024/1689) compliance evidence and gaps.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Project directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Emit full scan result as JSON (default format).",
    )
    parser.add_argument(
        "--markdown", "-m",
        action="store_true",
        help="Emit human-readable markdown summary instead of JSON.",
    )
    parser.add_argument(
        "--article", "-a",
        metavar="ARTN",
        help="Filter output to a single EU AI Act article (e.g. art9, art15, art50).",
    )
    parser.add_argument(
        "--name",
        metavar="NAME",
        help="Project display name (default: directory name).",
    )
    parser.add_argument(
        "--incidents", "-i",
        metavar="KEY",
        help=(
            "Surface real-world incidents for a dimension id (security), an "
            "article (art15), or a threat category (prompt_injection). Does not "
            "scan a codebase. Source: emmanuelgjr/genai-incidents (CC-BY-4.0)."
        ),
    )
    parser.add_argument(
        "--limit", "-l",
        type=int,
        default=5,
        help="Max incidents to return for --incidents (default: 5).",
    )
    parser.add_argument(
        "--llm-status",
        action="store_true",
        help=(
            "Report the Claude Max LLM-bridge configuration and probe the "
            "wrapper's /health endpoint. Does not scan a codebase."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    args = parser.parse_args(argv)

    # LLM-bridge diagnostics — config + live health probe, no codebase scan.
    if args.llm_status:
        from scanner.llm_bridge import bridge_config, bridge_health

        payload = {"config": bridge_config(), "health": bridge_health()}
        print(json.dumps(payload, indent=2, default=str))
        return 0 if payload["health"]["reachable"] else 1

    # Incident lookup is a corpus query — no codebase scan required.
    if args.incidents:
        payload = _incidents_payload(args.incidents, limit=max(1, args.limit))
        print(json.dumps(payload, indent=2, default=str))
        return 0 if payload.get("incidents") else 2

    path = Path(args.path)
    if not path.exists():
        print(f"error: path does not exist: {path}", file=sys.stderr)
        return 2

    try:
        result = scan_project(path, project_name=args.name)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.article:
        payload = _filter_by_article(result, args.article)
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return 0

    if args.markdown:
        print(_format_markdown(result))
        return 0

    print(result.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
