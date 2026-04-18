"""Command-line interface for the EU AI Act scanner.

Usage:
    eu-ai-act-scan [PATH] [--json | --markdown] [--article ARTN]
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

    return "\n".join(lines)


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
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    args = parser.parse_args(argv)

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
